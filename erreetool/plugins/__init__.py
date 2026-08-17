"""
Plugin Architecture for ERREETOOL.

Allows dynamic loading of custom tools, skills, and LLM providers
from external Python packages or local directories.
"""
import os
import sys
import importlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Type
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


@dataclass
class PluginMetadata:
    """Metadata for a plugin."""
    name: str
    version: str
    description: str
    author: str = ""
    license: str = ""
    dependencies: List[str] = field(default_factory=list)
    entry_points: Dict[str, str] = field(default_factory=dict)


class PluginBase(ABC):
    """Base class for all plugins."""
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin with configuration."""
        pass
    
    @abstractmethod
    def shutdown(self) -> None:
        """Cleanup on shutdown."""
        pass


class ToolPlugin(PluginBase):
    """Plugin interface for custom tools."""
    
    @abstractmethod
    def get_tool_class(self) -> Type:
        """Return the tool wrapper class."""
        pass
    
    @abstractmethod
    def get_tool_name(self) -> str:
        """Return the tool name (e.g., 'my-custom-tool')."""
        pass


class SkillPlugin(PluginBase):
    """Plugin interface for custom skills."""
    
    @abstractmethod
    def get_skill_definition(self) -> Dict[str, Any]:
        """Return the skill definition as a dictionary."""
        pass
    
    @abstractmethod
    def get_skill_name(self) -> str:
        """Return the skill name."""
        pass


class ProviderPlugin(PluginBase):
    """Plugin interface for custom LLM providers."""
    
    @abstractmethod
    def get_provider_class(self) -> Type:
        """Return the LLM provider class."""
        pass
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the provider name."""
        pass


class HookPlugin(PluginBase):
    """Plugin interface for lifecycle hooks."""
    
    @abstractmethod
    def get_hooks(self) -> Dict[str, Callable]:
        """Return a dictionary of hook_name -> callable."""
        pass


@dataclass
class LoadedPlugin:
    """Information about a loaded plugin."""
    metadata: PluginMetadata
    plugin: PluginBase
    path: Path
    enabled: bool = True
    error: Optional[str] = None


class PluginManager:
    """
    Manages plugin discovery, loading, and lifecycle.
    
    Plugins can be loaded from:
    - Entry points (pip installed packages)
    - Local plugin directories
    - Explicit module paths
    """
    
    def __init__(self, plugin_dirs: List[Path] = None):
        self.plugin_dirs = plugin_dirs or []
        self._plugins: Dict[str, LoadedPlugin] = {}
        self._hooks: Dict[str, List[Callable]] = {}
        
        # Add default plugin directories
        self._add_default_dirs()
    
    def _add_default_dirs(self):
        """Add default plugin directories."""
        # User config directory
        if sys.platform == "win32":
            base = Path(os.getenv("APPDATA", str(Path.home() / "AppData" / "Roaming")))
        else:
            base = Path(os.getenv("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
        user_plugin_dir = base / "erreetool" / "plugins"
        if user_plugin_dir.exists():
            self.plugin_dirs.append(user_plugin_dir)
        
        # Project plugin directory (erreetool/plugins)
        project_root = Path(__file__).resolve().parent.parent.parent
        project_plugin_dir = project_root / "erreetool" / "plugins"
        if project_plugin_dir.exists():
            self.plugin_dirs.append(project_plugin_dir)
        
        # Also check for plugins at project root
        project_root_plugins = project_root / "plugins"
        if project_root_plugins.exists():
            self.plugin_dirs.append(project_root_plugins)
    
    def add_plugin_dir(self, path: Path) -> None:
        """Add a plugin directory."""
        path = Path(path).resolve()
        if path.exists() and path not in self.plugin_dirs:
            self.plugin_dirs.append(path)
    
    def discover_plugins(self) -> List[Path]:
        """Discover all plugin files in plugin directories."""
        plugin_files = []
        
        for plugin_dir in self.plugin_dirs:
            if not plugin_dir.exists():
                continue
            
            # Look for Python files
            for py_file in plugin_dir.rglob("*.py"):
                if py_file.name.startswith("_"):
                    continue
                plugin_files.append(py_file)
            
            # Look for plugin directories with __init__.py
            for subdir in plugin_dir.iterdir():
                if subdir.is_dir() and (subdir / "__init__.py").exists():
                    plugin_files.append(subdir / "__init__.py")
        
        return plugin_files
    
    def load_plugin(self, plugin_path: Path) -> Optional[LoadedPlugin]:
        """Load a single plugin from a file or directory."""
        try:
            # Get module name from path
            if plugin_path.name == "__init__.py":
                module_name = plugin_path.parent.name
            else:
                module_name = plugin_path.stem
            
            # Load the module
            spec = importlib.util.spec_from_file_location(f"erreetool.plugins.{module_name}", plugin_path)
            if not spec or not spec.loader:
                return None
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[f"erreetool.plugins.{module_name}"] = module
            spec.loader.exec_module(module)
            
            # Find plugin classes in module
            plugin_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, PluginBase) and 
                    attr is not PluginBase and
                    attr is not ToolPlugin and
                    attr is not SkillPlugin and
                    attr is not ProviderPlugin and
                    attr is not HookPlugin):
                    plugin_class = attr
                    break
            
            if not plugin_class:
                logger.warning(f"No plugin class found in {plugin_path}")
                return None
            
            # Instantiate plugin
            plugin_instance = plugin_class()
            metadata = plugin_instance.metadata
            
            # Initialize plugin
            config = self._get_plugin_config(metadata.name)
            if not plugin_instance.initialize(config):
                logger.error(f"Plugin {metadata.name} failed to initialize")
                return None
            
            # Register hooks
            if isinstance(plugin_instance, HookPlugin):
                for hook_name, hook_func in plugin_instance.get_hooks().items():
                    if hook_name not in self._hooks:
                        self._hooks[hook_name] = []
                    self._hooks[hook_name].append(hook_func)
            
            loaded = LoadedPlugin(
                metadata=metadata,
                plugin=plugin_instance,
                path=plugin_path,
                enabled=True,
            )
            
            self._plugins[metadata.name] = loaded
            
            # Auto-register tool plugins
            if isinstance(plugin_instance, ToolPlugin):
                try:
                    register_tool_plugin(plugin_instance)
                except Exception as e:
                    logger.warning(f"Failed to register tool plugin {metadata.name}: {e}")
            
            # Auto-register skill plugins
            if isinstance(plugin_instance, SkillPlugin):
                try:
                    register_skill_plugin(plugin_instance)
                except Exception as e:
                    logger.warning(f"Failed to register skill plugin {metadata.name}: {e}")
            
            # Auto-register provider plugins
            if isinstance(plugin_instance, ProviderPlugin):
                try:
                    register_provider_plugin(plugin_instance)
                except Exception as e:
                    logger.warning(f"Failed to register provider plugin {metadata.name}: {e}")
            
            logger.info(f"Loaded plugin: {metadata.name} v{metadata.version}")
            
            return loaded
            
        except Exception as e:
            logger.error(f"Failed to load plugin from {plugin_path}: {e}")
            return LoadedPlugin(
                metadata=PluginMetadata(name=plugin_path.stem, version="0.0.0", description=""),
                plugin=None,
                path=plugin_path,
                enabled=False,
                error=str(e),
            )
    
    def load_all_plugins(self) -> Dict[str, LoadedPlugin]:
        """Load all discovered plugins."""
        plugin_files = self.discover_plugins()
        
        for plugin_file in plugin_files:
            self.load_plugin(plugin_file)
        
        # Also load from entry points
        self._load_entry_point_plugins()
        
        return self._plugins
    
    def _load_entry_point_plugins(self):
        """Load plugins from setuptools entry points."""
        try:
            import importlib.metadata as metadata
            
            for entry_point in metadata.entry_points(group="erreetool.plugins"):
                try:
                    plugin_class = entry_point.load()
                    if issubclass(plugin_class, PluginBase):
                        plugin_instance = plugin_class()
                        plugin_instance.initialize(self._get_plugin_config(plugin_instance.metadata.name))
                        
                        loaded = LoadedPlugin(
                            metadata=plugin_instance.metadata,
                            plugin=plugin_instance,
                            path=Path(entry_point.module),
                            enabled=True,
                        )
                        self._plugins[plugin_instance.metadata.name] = loaded
                        logger.info(f"Loaded entry point plugin: {plugin_instance.metadata.name}")
                except Exception as e:
                    logger.error(f"Failed to load entry point plugin {entry_point.name}: {e}")
        except ImportError:
            pass  # importlib.metadata not available
    
    def _get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """Get configuration for a plugin."""
        # Could be extended to load from config file
        return {}
    
    def get_plugin(self, name: str) -> Optional[LoadedPlugin]:
        """Get a loaded plugin by name."""
        return self._plugins.get(name)
    
    def get_tool_plugins(self) -> Dict[str, ToolPlugin]:
        """Get all loaded tool plugins."""
        return {
            name: loaded.plugin 
            for name, loaded in self._plugins.items() 
            if isinstance(loaded.plugin, ToolPlugin) and loaded.enabled
        }
    
    def get_skill_plugins(self) -> Dict[str, SkillPlugin]:
        """Get all loaded skill plugins."""
        return {
            name: loaded.plugin 
            for name, loaded in self._plugins.items() 
            if isinstance(loaded.plugin, SkillPlugin) and loaded.enabled
        }
    
    def get_provider_plugins(self) -> Dict[str, ProviderPlugin]:
        """Get all loaded provider plugins."""
        return {
            name: loaded.plugin 
            for name, loaded in self._plugins.items() 
            if isinstance(loaded.plugin, ProviderPlugin) and loaded.enabled
        }
    
    def get_hooks(self, hook_name: str) -> List[Callable]:
        """Get all hooks registered for a hook name."""
        return self._hooks.get(hook_name, [])
    
    def call_hooks(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """Call all hooks for a hook name and return results."""
        results = []
        for hook in self.get_hooks(hook_name):
            try:
                result = hook(*args, **kwargs)
                results.append(result)
            except Exception as e:
                logger.error(f"Hook {hook_name} failed: {e}")
        return results
    
    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin."""
        if name in self._plugins:
            self._plugins[name].enabled = True
            if self._plugins[name].plugin:
                config = self._get_plugin_config(name)
                return self._plugins[name].plugin.initialize(config)
        return False
    
    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin."""
        if name in self._plugins:
            if self._plugins[name].plugin:
                self._plugins[name].plugin.shutdown()
            self._plugins[name].enabled = False
            return True
        return False
    
    def unload_plugin(self, name: str) -> bool:
        """Unload a plugin completely."""
        if name in self._plugins:
            if self._plugins[name].plugin:
                self._plugins[name].plugin.shutdown()
            
            # Remove hooks
            if isinstance(self._plugins[name].plugin, HookPlugin):
                for hook_name, hook_func in self._plugins[name].plugin.get_hooks().items():
                    if hook_name in self._hooks:
                        self._hooks[hook_name] = [
                            h for h in self._hooks[hook_name] if h != hook_func
                        ]
            
            del self._plugins[name]
            return True
        return False
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all loaded plugins."""
        return [
            {
                "name": loaded.metadata.name,
                "version": loaded.metadata.version,
                "description": loaded.metadata.description,
                "author": loaded.metadata.author,
                "enabled": loaded.enabled,
                "error": loaded.error,
                "path": str(loaded.path),
                "type": type(loaded.plugin).__name__ if loaded.plugin else "unknown",
            }
            for loaded in self._plugins.values()
        ]


# Global plugin manager instance
_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager instance."""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
        _plugin_manager.load_all_plugins()
    return _plugin_manager


def register_tool_plugin(plugin: ToolPlugin) -> None:
    """Register a tool plugin with the tool registry."""
    from erreetool.agent.tools.base import tool_registry
    
    tool_class = plugin.get_tool_class()
    tool_name = plugin.get_tool_name()
    
    # Create instance and register
    tool_instance = tool_class()
    tool_registry.register(tool_instance)
    logger.info(f"Registered tool plugin: {tool_name}")


def register_skill_plugin(plugin: SkillPlugin) -> None:
    """Register a skill plugin with the skill registry."""
    from erreetool.agent.skills.loader import skill_loader
    from erreetool.agent.skills.schema import parse_skill
    
    skill_def = plugin.get_skill_definition()
    skill = parse_skill(skill_def, source_file=f"plugin:{plugin.get_skill_name()}")
    skill_loader.add_plugin_skill(skill)
    logger.info(f"Registered skill plugin: {plugin.get_skill_name()}")


def register_provider_plugin(plugin: ProviderPlugin) -> None:
    """Register a provider plugin."""
    # Providers are registered with MultiProvider.from_env()
    # This would need modification to support dynamic providers
    logger.info(f"Provider plugin available: {plugin.get_provider_name()}")


# Initialize plugin manager on import
get_plugin_manager()