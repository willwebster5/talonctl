"""
Provider Registry

Manages the registration and retrieval of resource providers.
Enables dynamic provider loading and configuration.
"""

from typing import Dict, Type, Optional, Any
import logging

from core.base_provider import BaseResourceProvider

logger = logging.getLogger(__name__)


class ProviderRegistry:
    """
    Registry for resource providers.

    Allows providers to be registered by resource type and retrieved
    for use by the deployment orchestrator.
    """

    def __init__(self):
        """Initialize an empty provider registry"""
        self._providers: Dict[str, Type[BaseResourceProvider]] = {}
        self._provider_configs: Dict[str, Dict[str, Any]] = {}

    def register(
        self,
        resource_type: str,
        provider_class: Type[BaseResourceProvider],
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Register a provider for a resource type.

        Args:
            resource_type: Type identifier (e.g., 'detection', 'workflow')
            provider_class: Class that implements BaseResourceProvider
            config: Optional configuration for the provider

        Raises:
            ValueError: If resource_type is already registered
            TypeError: If provider_class doesn't inherit from BaseResourceProvider
        """
        if not issubclass(provider_class, BaseResourceProvider):
            raise TypeError(
                f"Provider class must inherit from BaseResourceProvider, "
                f"got {provider_class.__name__}"
            )

        if resource_type in self._providers:
            logger.warning(
                f"Overwriting existing provider for '{resource_type}' "
                f"({self._providers[resource_type].__name__} -> {provider_class.__name__})"
            )

        self._providers[resource_type] = provider_class
        self._provider_configs[resource_type] = config or {}

        logger.debug(
            f"Registered provider {provider_class.__name__} for resource type '{resource_type}'"
        )

    def unregister(self, resource_type: str) -> bool:
        """
        Unregister a provider.

        Args:
            resource_type: Type to unregister

        Returns:
            True if provider was unregistered, False if not found
        """
        if resource_type in self._providers:
            del self._providers[resource_type]
            self._provider_configs.pop(resource_type, None)
            logger.debug(f"Unregistered provider for '{resource_type}'")
            return True
        return False

    def get_provider_class(self, resource_type: str) -> Optional[Type[BaseResourceProvider]]:
        """
        Get the provider class for a resource type.

        Args:
            resource_type: Type to look up

        Returns:
            Provider class or None if not registered
        """
        return self._providers.get(resource_type)

    def create_provider(
        self,
        resource_type: str,
        falcon_client: Any,
        config: Optional[Dict[str, Any]] = None
    ) -> Optional[BaseResourceProvider]:
        """
        Create a provider instance for a resource type.

        Args:
            resource_type: Type of resource
            falcon_client: FalconPy client instance
            config: Optional config to override registered config

        Returns:
            Provider instance or None if type not registered

        Raises:
            Exception: If provider initialization fails
        """
        provider_class = self._providers.get(resource_type)

        if not provider_class:
            logger.warning(f"No provider registered for resource type '{resource_type}'")
            return None

        # Merge registered config with override config
        final_config = {**self._provider_configs.get(resource_type, {})}
        if config:
            final_config.update(config)

        try:
            provider = provider_class(falcon_client, final_config)
            logger.debug(f"Created provider instance for '{resource_type}'")
            return provider
        except Exception as e:
            logger.error(f"Failed to create provider for '{resource_type}': {e}")
            raise

    def get_registered_types(self) -> list:
        """
        Get list of all registered resource types.

        Returns:
            List of resource type strings
        """
        return list(self._providers.keys())

    def is_registered(self, resource_type: str) -> bool:
        """
        Check if a resource type has a registered provider.

        Args:
            resource_type: Type to check

        Returns:
            True if registered
        """
        return resource_type in self._providers

    def __contains__(self, resource_type: str) -> bool:
        """Check if resource type is registered"""
        return self.is_registered(resource_type)

    def __len__(self) -> int:
        """Return number of registered providers"""
        return len(self._providers)

    def __repr__(self) -> str:
        """String representation"""
        types = ', '.join(self._providers.keys()) if self._providers else 'none'
        return f"ProviderRegistry(providers=[{types}])"


# Global registry instance (singleton pattern)
_global_registry: Optional[ProviderRegistry] = None


def get_global_registry() -> ProviderRegistry:
    """
    Get the global provider registry instance.

    Returns:
        Global ProviderRegistry instance
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = ProviderRegistry()
    return _global_registry


def register_provider(
    resource_type: str,
    provider_class: Type[BaseResourceProvider],
    config: Optional[Dict[str, Any]] = None
) -> None:
    """
    Register a provider with the global registry.

    Convenience function for global registry access.

    Args:
        resource_type: Type identifier
        provider_class: Provider class
        config: Optional configuration
    """
    registry = get_global_registry()
    registry.register(resource_type, provider_class, config)
