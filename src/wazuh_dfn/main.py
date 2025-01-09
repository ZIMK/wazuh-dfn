"""Main entry point for Wazuh DFN service."""

import argparse
import json
import logging
import logging.config
import logging.handlers
import os
import signal
import sys
import threading
import time
from dataclasses import field
from importlib.metadata import PackageNotFoundError, version
from queue import Queue
from typing import Any

from dotenv import load_dotenv

from .config import Config, DFNConfig, KafkaConfig, LogConfig, MiscConfig, WazuhConfig
from .exceptions import ConfigValidationError
from .services import (
    AlertsService,
    AlertsWatcherService,
    AlertsWorkerService,
    KafkaService,
    LoggingService,
    WazuhService,
)
from .validators import ConfigValidator

# Logging
LOGGER = logging.getLogger(__name__)

LOG_FORMAT = "%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s"

# Load environment variables from .env file if present
load_dotenv()


def parse_args() -> argparse.Namespace:  # NOSONAR
    """Load configuration from all sources.

    Args:
        args: Optional list of command line arguments.

    Returns:
        Config: Configuration instance.
    """
    parser = argparse.ArgumentParser(description="Wazuh DFN Configuration")
    parser.add_argument(
        "-c",
        "--config",
        dest="config",
        default=None,
        help="Path to configuration file",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {version('wazuh-dfn')}",
    )
    parser.add_argument(
        "--print-config-only",
        action="store_true",
        default=False,
        help="Prints only config to console",
    )
    parser.add_argument(
        "--skip-path-validation",
        action="store_true",
        default=False,
        help="Skip validation of paths in config files",
    )
    parser.add_argument("--generate-sample-config", action="store_true", help="Generate a sample configuration file")
    parser.add_argument(
        "--help-all",
        action="store_true",
        help="Show all configuration fields with their CLI arguments and environment variables",
    )

    # Add arguments from field metadata
    config_fields = []
    for cls_obj in [WazuhConfig, DFNConfig, KafkaConfig, LogConfig, MiscConfig]:
        cls_name = cls_obj.__name__.replace("Config", "")  # Remove "Config" suffix for cleaner display
        for field_name, field_obj in cls_obj.__dataclass_fields__.items():  # pylint: disable=no-member
            metadata = field_obj.metadata
            if "cli" in metadata:  # Check if field has CLI argument
                parser.add_argument(metadata["cli"], help=metadata["help"], type=field_obj.type, default=None)
                # Store field info for help-all
                default_val = field_obj.default
                if default_val is field:  # Check if it's the MISSING sentinel
                    default_val = "None"
                elif isinstance(default_val, str):
                    default_val = f'"{default_val}"'  # Quote string defaults
                config_fields.append(
                    {
                        "section": cls_name,
                        "field": field_name,
                        "cli": metadata["cli"],
                        "env": metadata.get("env_var", ""),
                        "help": metadata.get("help", ""),
                        "type": str(field_obj.type).replace("<class '", "").replace("'>", ""),  # Clean up type display
                        "default": str(default_val),
                    }
                )

    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.help_all:
        if not config_fields:
            print("\nNo configuration fields found with CLI arguments or environment variables.")
            sys.exit(0)

        print("\nWazuh DFN Configuration Fields:")
        print("==============================\n")
        current_section = None
        for cfield in sorted(config_fields, key=lambda x: (x["section"], x["field"])):
            if current_section != cfield["section"]:
                current_section = cfield["section"]
                print(f"\n{current_section}:")
                print("-" * len(current_section))
            print(f"\nField: {cfield['field']}")
            print(f"  CLI argument:      {cfield['cli']}")
            print(f"  Environment var:   {cfield['env']}")
            print(f"  Description:       {cfield['help']}")
            print(f"  Type:             {cfield['type']}")
            print(f"  Default value:    {cfield['default']}")
        sys.exit(0)

    return args


def load_config(args: argparse.Namespace) -> Config:
    """Load configuration from YAML file.

    Args:
        args: command line arguments.

    Returns:
        Config: Configuration object.

    Raises:
        ConfigValidationError: If configuration validation fails.
    """
    print(f"Loading config from {args.config}")
    ConfigValidator.skip_path_validation = args.skip_path_validation

    config = Config.from_yaml(args.config)

    # Load from environment variables
    Config._load_from_env(config)

    # Load from CLI arguments
    Config._load_from_cli(config, args)

    ConfigValidator.validate(config)

    return config


def setup_logging(config: Config) -> None:
    """Configure logging based on configuration.

    Args:
        config: Application configuration
    """
    handlers = []

    # Convert string level to logging level
    log_level = getattr(logging, config.log.level.upper(), logging.INFO)

    # Add console handler if enabled
    if config.log.console:
        console_handler = logging.StreamHandler(stream=sys.stdout)
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        handlers.append(console_handler)

    # Add file handler if path is specified
    if config.log.file_path:
        if os.path.exists(config.log.file_path):
            try:
                file_handler = logging.handlers.TimedRotatingFileHandler(
                    filename=config.log.file_path, when="midnight", interval=2
                )
                file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
                handlers.append(file_handler)
            except Exception as e:
                print(f"Failed to create log file handler: {e}", file=sys.stderr)
        else:
            print(f"Log file {config.log.file_path} does not exist. Skip adding to loggers", file=sys.stderr)

    # Update root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    for handler in handlers:
        handler.setLevel(log_level)
        root_logger.addHandler(handler)


def setup_directories(config: Config) -> None:
    """Set up required directories for the service.

    Args:
        config: Service configuration

    Raises:
        ConfigValidationError: If required directory creation fails
    """

    # Optional directories that should be created if configured
    optional_dirs = []
    if config.log.file_path:
        optional_dirs.append(os.path.dirname(config.log.file_path))

    # Create optional directories - log warning if this fails
    for directory in optional_dirs:
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            LOGGER.info(f"Ensured optional directory exists: {directory}")
        except Exception as e:
            LOGGER.warning(f"Failed to create optional directory {directory}: {e}")


def setup_service(config: Config) -> None:
    """Set up and run the Wazuh DFN service.

    Initializes and runs the core service components using the new service classes
    that follow the principle of least privilege.

    Args:
        config: Service configuration.

    Raises:
        ConfigValidationError: If configuration validation fails.
    """

    shutdown_event = threading.Event()
    alert_queue = Queue()
    service_threads = []  # Initialize service_threads list at the start

    LOGGER.info("Starting services...")
    try:
        # Initialize core services
        LOGGER.debug("Initializing WazuhService...")
        wazuh_service = WazuhService(config=config.wazuh)
        wazuh_service.start()

        LOGGER.debug("Initializing KafkaService...")
        kafka_service = KafkaService(
            config=config.kafka,
            dfn_config=config.dfn,  # Pass DFN config
            wazuh_handler=wazuh_service,
            shutdown_event=shutdown_event,
        )

        # Initialize alert processing services
        LOGGER.debug("Initializing AlertsService...")
        alerts_service = AlertsService(
            config=config.misc,
            kafka_service=kafka_service,
            wazuh_service=wazuh_service,
        )
        LOGGER.debug("Initializing AlertsWorkerService...")
        alerts_worker_service = AlertsWorkerService(
            config=config.misc,
            alert_queue=alert_queue,
            alerts_service=alerts_service,
            shutdown_event=shutdown_event,
        )
        LOGGER.debug("Initializing AlertsWatcherService...")
        alerts_watcher_service = AlertsWatcherService(
            config=config.wazuh,
            alert_queue=alert_queue,
            shutdown_event=shutdown_event,
        )

        # Initialize logging service
        LOGGER.debug("Initializing LoggingService...")
        logging_service = LoggingService(
            config=config.log,
            alert_queue=alert_queue,
            kafka_service=kafka_service,
            alerts_watcher_service=alerts_watcher_service,
            alerts_worker_service=alerts_worker_service,
            shutdown_event=shutdown_event,
        )

        # Start Kafka service
        LOGGER.debug("Starting KafkaService...")
        kafka_thread = threading.Thread(
            target=kafka_service.start,
            daemon=True,
            name="KafkaService",
        )
        service_threads.append(kafka_thread)
        kafka_thread.start()

        # Start alerts worker service
        LOGGER.debug("Starting AlertsWorkerService...")
        alerts_worker_thread = threading.Thread(
            target=alerts_worker_service.start,
            daemon=True,
            name="AlertsWorkerService",
        )
        service_threads.append(alerts_worker_thread)
        alerts_worker_thread.start()

        # Start observer service
        LOGGER.debug("Starting AlertsWatcherService...")
        observer_thread = threading.Thread(
            target=alerts_watcher_service.start,
            daemon=True,
            name="AlertsWatcherService",
        )
        service_threads.append(observer_thread)
        observer_thread.start()

        # Start logging service
        time.sleep(10)
        LOGGER.debug("Starting LoggingService...")
        logging_thread = threading.Thread(
            target=logging_service.start,
            daemon=True,
            name="LoggingService",
        )
        service_threads.append(logging_thread)
        logging_thread.start()

        def signal_handler(signum: int, frame: Any) -> None:
            """Handle shutdown signals.

            Args:
                signum: Signal number
                frame: Current stack frame
            """
            LOGGER.info(f"Received signal {signum}")
            shutdown_event.set()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Keep main thread alive
        LOGGER.debug("All services initialized. Waiting for shutdown event...")
        while not shutdown_event.is_set():
            shutdown_event.wait(1)

    except Exception as e:
        LOGGER.error(f"Error in service setup: {e}")
        shutdown_event.set()
        raise

    finally:
        # Wait for threads to finish
        LOGGER.debug("Waiting for threads to finish...")
        for thread in service_threads:
            thread.join(timeout=1)
        LOGGER.info("Service shutdown complete")


def main() -> None:
    """Main entry point for the Wazuh DFN service."""
    try:
        LOGGER.info(f"Starting Wazuh DFN service version {version('wazuh-dfn')}")
    except PackageNotFoundError:
        LOGGER.info("Starting Wazuh DFN service (development version)")

    try:
        args = parse_args()

        # Load config from file
        config = load_config(args)

        if args.print_config_only:
            json_config = json.dumps(config.__dict__, default=lambda o: o.__dict__, sort_keys=True, indent=4)
            print(f"Loaded config: {json_config}")
        else:
            if not config.dfn.dfn_id:
                print("DFN ID not specified in config. Please set it in the config file.")
                return sys.exit(1)

            # Set up required directories first
            setup_directories(config)

            # Setup logging
            setup_logging(config)

            LOGGER.info(f"Starting Wazuh DFN version {version('wazuh-dfn')}")
            setup_service(config)
    except ConfigValidationError as e:
        LOGGER.error(f"Configuration validation failed: {e}")
        sys.exit(1)
    except Exception as e:
        LOGGER.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
