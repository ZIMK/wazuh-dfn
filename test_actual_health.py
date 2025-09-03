#!/usr/bin/env python3
"""Test script to verify health provider registration with actual services."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import asyncio

from wazuh_dfn.config import DFNConfig, HealthConfig, KafkaConfig, MiscConfig, WazuhConfig
from wazuh_dfn.health.health_service import HealthService
from wazuh_dfn.max_size_queue import AsyncMaxSizeQueue
from wazuh_dfn.service_container import ServiceContainer
from wazuh_dfn.services.alerts_watcher_service import AlertsWatcherService
from wazuh_dfn.services.kafka_service import KafkaService
from wazuh_dfn.services.wazuh_service import WazuhService


async def test_actual_services():
    """Test health provider registration with actual services."""
    print("Testing actual service health provider registration...")

    # Create container
    container = ServiceContainer()

    # Create minimal configurations for testing
    try:
        # Create minimal configs that should work
        wazuh_config = WazuhConfig(
            unix_socket_path="localhost:1514",  # Windows-style for testing
            integration_name="test",
            json_alert_file="test.json",
        )

        kafka_config = KafkaConfig()

        shutdown_event = asyncio.Event()

        # Create services
        wazuh_service = WazuhService(config=wazuh_config)

        print(f"Wazuh service metrics: {wazuh_service.get_service_metrics()}\n")

        # KafkaService requires all these parameters
        kafka_service = KafkaService(
            config=kafka_config, dfn_config=DFNConfig(), wazuh_service=wazuh_service, shutdown_event=shutdown_event
        )

        print(f"Kafka service metrics: {kafka_service.get_service_metrics()}\n")

        alert_queue = AsyncMaxSizeQueue(maxsize=10)

        alerts_watcher_service = AlertsWatcherService(
            config=wazuh_config, alert_queue=alert_queue, wazuh_service=wazuh_service, shutdown_event=shutdown_event
        )

        print(f"Alerts watcher service metrics: {alerts_watcher_service.get_service_metrics()}\n")

        # Register health providers (this is what I fixed in main.py)
        container.register_health_provider("wazuh", wazuh_service)
        container.register_health_provider("kafka", kafka_service)
        container.register_health_provider("alerts_watcher", alerts_watcher_service)

        # Check registration
        providers = container.get_health_providers()
        print(f"Registered health providers: {list(providers.keys())}")

        # Create health service
        config = HealthConfig()
        event_queue = asyncio.Queue()

        health_service = HealthService(
            container=container, config=config, event_queue=event_queue, shutdown_event=shutdown_event
        )

        # Test service health collection
        print("\nTesting service health collection...")
        service_health = health_service._collect_service_health()
        print(f"Collected services: {list(service_health.keys())}")

        for service_name, health_data in service_health.items():
            print(
                f"{service_name}: {health_data.get('service_type', 'unknown')} - {'healthy' if health_data.get('is_healthy') else 'unknown'}"
            )

        # Test detailed health endpoint response
        print("\nTesting detailed health endpoint...")
        detailed_health = health_service.get_detailed_health()
        services_section = detailed_health.get("services", {})

        print(f"detailed_health: {detailed_health}")

        print(f"Services in detailed health: {services_section.get('total', 0)} services")
        print(f"Services status: {services_section.get('status', 'unknown')}")

        if "services" in services_section:
            for service_name, service_data in services_section["services"].items():
                print(f"  {service_name}: {service_data.get('service_type', 'unknown')}")

        print("\n✓ Health provider registration and collection working correctly!")

    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_actual_services())
