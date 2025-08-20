"""Enhanced ServiceContainer with health monitoring integration.

This module provides a dependency injection container that:
- Eliminates circular dependencies through service container pattern
- Manages service lifecycle and health monitoring
- Provides centralized access to health metrics providers
- Supports automatic service discovery and registration
- Implements the planned hybrid push/pull architecture from TODO
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, TypeVar, cast

from .health.protocols import (
    HealthMetricsProvider,
    KafkaMetricsProvider,
    QueueMetricsProvider,
    WorkerMetricsProvider,
)

T = TypeVar("T")


class ServiceContainer:
    """Enhanced ServiceContainer implementing planned architecture from TODO.

    This container:
    - Eliminates circular dependencies through service container pattern
    - Manages service lifecycle and health monitoring
    - Provides centralized access to health metrics providers
    - Supports automatic service discovery and registration
    - Implements the planned hybrid push/pull architecture

    The container allows services to register themselves and be discovered by
    health monitoring components without creating circular import dependencies.
    """

    def __init__(self) -> None:
        """Initialize the service container."""
        self.logger = logging.getLogger(f"{__name__}.ServiceContainer")
        self._services: dict[str, Any] = {}
        self._service_factories: dict[str, Callable[[], Any]] = {}
        self._worker_providers: dict[str, WorkerMetricsProvider] = {}
        self._queue_providers: dict[str, QueueMetricsProvider] = {}
        self._kafka_providers: dict[str, KafkaMetricsProvider] = {}
        self._health_providers: dict[str, HealthMetricsProvider] = {}

    def register_service(self, name: str, service: Any) -> None:
        """Register a service instance.

        Args:
            name: Service name for lookup
            service: Service instance
        """
        self._services[name] = service
        self.logger.debug(f"Registered service: {name}")

    def register_service_factory(self, name: str, factory: Callable[[], Any]) -> None:
        """Register a service factory for lazy initialization.

        Args:
            name: Service name for lookup
            factory: Factory function that creates the service
        """
        self._service_factories[name] = factory
        self.logger.debug(f"Registered service factory: {name}")

    def get_service(self, name: str, service_type: type[T] | None = None) -> T | None:  # noqa: PLR0911
        """Get a service by name.

        Args:
            name: Service name to lookup
            service_type: Optional type for type checking

        Returns:
            Service instance or None if not found
        """
        # Try registered services first
        if name in self._services:
            service = self._services[name]
            if service_type is None:
                return cast(T, service)
            elif isinstance(service, service_type):
                return service
            else:
                self.logger.warning(f"Service {name} is not of type {service_type}")
                return None

        # Try service factories
        if name in self._service_factories:
            factory = self._service_factories[name]
            try:
                service = factory()
                self._services[name] = service  # Cache the created service
                if service_type is None:
                    return cast(T, service)
                elif isinstance(service, service_type):
                    return service
                else:
                    self.logger.warning(f"Factory service {name} is not of type {service_type}")
                    return None
            except Exception as e:
                self.logger.error(f"Error creating service {name} from factory: {e}")
                return None

        self.logger.debug(f"Service not found: {name}")
        return None

    def register_worker_provider(self, name: str, provider: WorkerMetricsProvider) -> None:
        """Register a worker metrics provider.

        Args:
            name: Provider name
            provider: Worker metrics provider
        """
        self._worker_providers[name] = provider
        self.logger.debug(f"Registered worker provider: {name}")

    def register_queue_provider(self, name: str, provider: QueueMetricsProvider) -> None:
        """Register a queue metrics provider.

        Args:
            name: Provider name
            provider: Queue metrics provider
        """
        self._queue_providers[name] = provider
        self.logger.debug(f"Registered queue provider: {name}")

    def register_kafka_provider(self, name: str, provider: KafkaMetricsProvider) -> None:
        """Register a Kafka metrics provider.

        Args:
            name: Provider name
            provider: Kafka metrics provider
        """
        self._kafka_providers[name] = provider
        self.logger.debug(f"Registered Kafka provider: {name}")

    def register_health_provider(self, name: str, provider: HealthMetricsProvider) -> None:
        """Register a health metrics provider.

        Args:
            name: Provider name
            provider: Health metrics provider
        """
        self._health_providers[name] = provider
        self.logger.debug(f"Registered health provider: {name}")

    def get_worker_providers(self) -> dict[str, WorkerMetricsProvider]:
        """Get all registered worker metrics providers.

        Returns:
            Dictionary of worker providers
        """
        return dict(self._worker_providers)

    def get_queue_providers(self) -> dict[str, QueueMetricsProvider]:
        """Get all registered queue metrics providers.

        Returns:
            Dictionary of queue providers
        """
        return dict(self._queue_providers)

    def get_kafka_providers(self) -> dict[str, KafkaMetricsProvider]:
        """Get all registered Kafka metrics providers.

        Returns:
            Dictionary of Kafka providers
        """
        return dict(self._kafka_providers)

    def get_health_providers(self) -> dict[str, HealthMetricsProvider]:
        """Get all registered health metrics providers.

        Returns:
            Dictionary of health providers
        """
        return dict(self._health_providers)

    def get_all_providers(self) -> dict[str, HealthMetricsProvider]:
        """Get all registered providers as health metrics providers.

        Returns:
            Combined dictionary of all providers
        """
        all_providers: dict[str, HealthMetricsProvider] = {}

        # Add worker providers
        for name, provider in self._worker_providers.items():
            if isinstance(provider, HealthMetricsProvider):
                all_providers[f"worker_{name}"] = provider

        # Add queue providers
        for name, provider in self._queue_providers.items():
            if isinstance(provider, HealthMetricsProvider):
                all_providers[f"queue_{name}"] = provider

        # Add Kafka providers
        for name, provider in self._kafka_providers.items():
            if isinstance(provider, HealthMetricsProvider):
                all_providers[f"kafka_{name}"] = provider

        # Add explicit health providers
        all_providers.update(self._health_providers)

        return all_providers

    def list_services(self) -> list[str]:
        """List all registered service names.

        Returns:
            List of service names
        """
        services = list(self._services.keys())
        factories = list(self._service_factories.keys())
        return sorted(services + factories)

    def clear(self) -> None:
        """Clear all registered services and providers."""
        self._services.clear()
        self._service_factories.clear()
        self._worker_providers.clear()
        self._queue_providers.clear()
        self._kafka_providers.clear()
        self._health_providers.clear()
        self.logger.debug("Container cleared")

    async def start_all_services(self) -> None:
        """Start all registered services in proper order."""
        # 1. Start HealthEventService first (lightweight, no dependencies)
        health_event_service = self._services.get("health_event")
        if health_event_service and hasattr(health_event_service, "start"):
            try:
                self.logger.debug("Starting service: health_event")
                await health_event_service.start()
                self.logger.info("Service health_event started successfully")
            except Exception as e:
                self.logger.error(f"Failed to start service health_event: {e}")
                raise

        # 2. Start other services (they can immediately push to HealthEventService)
        other_services = []
        for name, service in self._services.items():
            if name not in ("health_event", "health") and hasattr(service, "start"):
                other_services.append((name, service))

        for name, service in other_services:
            try:
                self.logger.debug(f"Starting service: {name}")
                await service.start()
                self.logger.info(f"Service {name} started successfully")
            except Exception as e:
                self.logger.error(f"Failed to start service {name}: {e}")
                raise

        # 3. Start HealthService last (subscribes to events + pulls from providers)
        health_service = self._services.get("health")
        if health_service and hasattr(health_service, "start"):
            try:
                self.logger.debug("Starting service: health")
                await health_service.start()
                self.logger.info("Service health started successfully")
            except Exception as e:
                self.logger.error(f"Failed to start service health: {e}")
                raise

    async def stop_all_services(self) -> None:
        """Stop all registered services that have a stop() method."""
        for name, service in reversed(list(self._services.items())):
            if hasattr(service, "stop"):
                try:
                    self.logger.debug(f"Stopping service: {name}")
                    await service.stop()
                    self.logger.info(f"Service {name} stopped successfully")
                except Exception as e:
                    self.logger.error(f"Failed to stop service {name}: {e}")
                    # Continue stopping other services even if one fails
