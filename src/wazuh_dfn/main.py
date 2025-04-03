"""Main entry point for Wazuh DFN service."""

import argparse
import asyncio
import json
import logging
import logging.config
import logging.handlers
import signal
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Union, get_args, get_origin

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
from .services.max_size_queue import AsyncMaxSizeQueue

# Logging
LOGGER = logging.getLogger(__name__)

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Load environment variables from .env file if present
load_dotenv()


def get_argparse_type(field_type):
    """Extract a usable type for argparse from a type annotation.

    Analyzes a field's type annotation and returns an appropriate type
    for use with argparse. Handles Union types and booleans specially.

    Args:
        field_type: The type annotation from a model field

    Returns:
        A callable type that can be used with argparse
    """
    # Handle Union types (like str | None or Union[str, None])
    origin = get_origin(field_type)
    if origin is Union:
        args = get_args(field_type)
        # Find the first non-None type in the Union
        for arg in args:
            if arg is not type(None):  # Check if it's not NoneType
                return arg

    # If the type is bool, use a custom parser to handle string values correctly
    if field_type is bool:
        return lambda x: str(x).lower() in ("true", "1", "yes", "y")

    # If the type is directly callable, use it
    if isinstance(field_type, type):
        # With type narrowing, the compiler knows field_type is a type in this block
        return field_type

    # Fallback to str for any other case
    return str


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
        "-t",
        "--config-format",
        dest="config_format",
        choices=["yaml", "toml"],
        default="yaml",
        help="Configuration file format (yaml or toml)",
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
        "--output-format",
        choices=["yaml", "toml"],
        default="toml",
        help="Format for sample configuration (yaml or toml)",
    )
    parser.add_argument(
        "--help-all",
        action="store_true",
        help="Show all configuration fields with their CLI arguments and environment variables",
    )

    # Add arguments from field metadata
    config_fields = []
    for cls_obj in [WazuhConfig, DFNConfig, KafkaConfig, LogConfig, MiscConfig]:
        cls_name = cls_obj.__name__.replace("Config", "")  # Remove "Config" suffix for cleaner display
        for field_name, field_info in cls_obj.model_fields.items():
            if field_name.startswith("_"):  # Skip private fields
                continue

            json_schema_extra = field_info.json_schema_extra or {}
            if "cli" in json_schema_extra:  # Check if field has CLI argument
                # Get appropriate type for argparse
                field_type = field_info.annotation
                arg_type = get_argparse_type(field_type)
                parser.add_argument(json_schema_extra["cli"], help=field_info.description, type=arg_type, default=None)

                # Store field info for help-all
                default_val = field_info.default
                if default_val is None:
                    default_val = "None"
                elif isinstance(default_val, str):
                    default_val = f'"{default_val}"'  # Quote string defaults

                config_fields.append(
                    {
                        "section": cls_name,
                        "field": field_name,
                        "cli": json_schema_extra["cli"],
                        "env": json_schema_extra.get("env_var", ""),
                        "help": field_info.description or "",
                        "type": str(field_type).replace("<class '", "").replace("'>", ""),  # Clean up type display
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
    """Load configuration from file.

    Creates a Config object and loads settings from config file, environment variables,
    and command-line arguments, in that order of precedence.

    Args:
        args: Command line arguments from argparse

    Returns:
        Config: Fully populated configuration object

    Raises:
        ConfigValidationError: If configuration validation fails
    """
    print(f"Loading config from {args.config}")

    # Set DFNConfig's skip_path_validation attribute
    config = Config()
    config.dfn.skip_path_validation = args.skip_path_validation  # Update reference here

    # Load from file based on format
    if args.config_format == "toml":
        config = Config.from_toml(args.config, config)
    else:
        config = Config.from_yaml(args.config, config)

    # Load from environment variables
    Config._load_from_env(config)

    # Load from CLI arguments
    Config._load_from_cli(config, args)

    return config


def setup_logging(config: Config) -> None:
    """Configure logging based on configuration.

    Sets up the logging system according to the provided configuration, including
    console logging and file logging with rotation when enabled.

    Args:
        config: Application configuration object containing logging settings
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
        log_file_path = Path(config.log.file_path)
        log_file_path.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists

        if log_file_path.exists():
            try:
                file_handler = logging.handlers.TimedRotatingFileHandler(
                    filename=str(log_file_path),
                    when="midnight",
                    interval=1,
                    backupCount=config.log.keep_files,  # Use config value instead of hardcoded 5
                )
                file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
                handlers.append(file_handler)
            except Exception as e:
                print(f"Failed to create log file handler: {e}", file=sys.stderr)
        else:
            print(f"Log file {log_file_path} does not exist. Skip adding to loggers", file=sys.stderr)

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

    Creates necessary directories for logs and failed alerts storage.

    Args:
        config: Service configuration containing directory paths

    Raises:
        ConfigValidationError: If critical directory creation fails
    """
    # Optional directories that should be created if configured
    optional_dirs = []
    if config.log.file_path:
        optional_dirs.append(Path(config.log.file_path).parent)
    if config.wazuh.store_failed_alerts and config.wazuh.failed_alerts_path:
        optional_dirs.append(Path(config.wazuh.failed_alerts_path))

    # Create optional directories - log warning if this fails
    for directory in optional_dirs:
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            LOGGER.info(f"Ensured optional directory exists: {directory}")
        except Exception as e:
            LOGGER.warning(f"Failed to create optional directory {directory}: {e}")


async def shutdown(shutdown_event: asyncio.Event) -> None:
    """Handle shutdown gracefully.

    Logs shutdown request and signals to all services that shutdown is requested.

    Args:
        shutdown_event: Event to signal shutdown to all service components
    """
    LOGGER.info("Shutdown requested")
    shutdown_event.set()


async def setup_service(config: Config) -> None:
    """Set up and run the Wazuh DFN service using asyncio.

    Initializes and orchestrates all service components using asyncio tasks.
    This is the main entry point for the asynchronous service architecture.
    Tasks are managed using Python 3.11+ task groups for clean task management.

    Args:
        config: Service configuration with all settings

    Raises:
        ConfigValidationError: If configuration validation fails
    """
    shutdown_event = asyncio.Event()
    alert_queue = AsyncMaxSizeQueue(maxsize=config.wazuh.json_alert_queue_size)

    LOGGER.info("Starting services...")
    try:
        # Initialize core services
        LOGGER.debug("Initializing WazuhService...")
        wazuh_service = WazuhService(config=config.wazuh)
        await wazuh_service.start()

        LOGGER.debug("Initializing KafkaService...")
        kafka_service = KafkaService(
            config=config.kafka,
            dfn_config=config.dfn,
            wazuh_service=wazuh_service,
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

        # Set up signal handlers for clean shutdown
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(shutdown_event)))

        # Use Python 3.11+ task groups for cleaner task management
        async with asyncio.TaskGroup() as tg:
            # Start all services as concurrent tasks
            tg.create_task(kafka_service.start(), name="KafkaService")
            tg.create_task(alerts_worker_service.start(), name="AlertsWorkerService")
            tg.create_task(alerts_watcher_service.start(), name="AlertsWatcherService")

            # Give the other services a moment to initialize
            await asyncio.sleep(10)

            tg.create_task(logging_service.start(), name="LoggingService")

            # Wait until shutdown is signaled
            await shutdown_event.wait()

    except asyncio.CancelledError:
        LOGGER.info("Tasks cancelled")
    except Exception as e:
        LOGGER.error(f"Error in service setup: {e}", exc_info=True)
        shutdown_event.set()
        raise
    finally:
        LOGGER.info("Service shutdown complete")


def main() -> None:
    """Main entry point for the Wazuh DFN service."""
    try:
        LOGGER.info(f"Starting Wazuh DFN service version {version('wazuh-dfn')}")
    except PackageNotFoundError:
        LOGGER.info("Starting Wazuh DFN service (development version)")

    try:
        args = parse_args()

        # Handle command-line arguments with pattern matching for Python 3.12+
        match args:
            case argparse.Namespace() if getattr(args, "generate_sample_config", False):
                output_path = getattr(args, "output_path", "config." + args.output_format)
                Config._generate_sample_config(output_path, args.output_format)
                LOGGER.info(f"Generated sample configuration at {output_path}")
                return
            case argparse.Namespace() if getattr(args, "print_config_only", False):
                # Load config from file
                config = load_config(args)
                # Convert Pydantic model to dict for JSON serialization with exclude options
                config_dict = config.model_dump(exclude_none=True, exclude_unset=True)
                json_config = json.dumps(config_dict, sort_keys=True, indent=4)
                print(f"Loaded config: {json_config}")
                return
            case _:
                # Regular execution path
                # Load config from file
                config = load_config(args)

                if not config.dfn.dfn_id:
                    LOGGER.warning("No DFN ID has been configured. This is required for operation.")
                    LOGGER.warning("Please set dfn_id in your configuration.")
                    sys.exit(1)

                # Set up required directories first
                setup_directories(config)

                # Setup logging
                setup_logging(config)

                LOGGER.info(f"Starting Wazuh DFN version {version('wazuh-dfn')}")

                # Run the async setup_service using asyncio.run
                asyncio.run(setup_service(config))
    except ConfigValidationError as e:
        LOGGER.error(f"Configuration validation failed: {e}")
        sys.exit(1)
    except Exception as e:
        LOGGER.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
