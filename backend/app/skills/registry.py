"""
Skill Registry - Manages skill directories and provides extensibility.
"""

import os
from pathlib import Path
from typing import Optional

from .loader import SkillLoader


class SkillRegistry:
    """Registry for skill directories and loader management."""
    
    def __init__(self):
        self._loader: Optional[SkillLoader] = None
        self._custom_dirs: list[str] = []
    
    @property
    def loader(self) -> SkillLoader:
        if self._loader is None:
            self._loader = SkillLoader(skill_dirs=self._get_all_dirs())
        return self._loader
    
    def _get_all_dirs(self) -> list[str]:
        dirs = [SkillLoader._default_skill_dir()]
        dirs.extend(self._custom_dirs)
        return dirs
    
    def register_skill_dir(self, path: str) -> bool:
        """Register a custom skill directory (user-contributed skills)."""
        path = os.path.expanduser(path)
        if not os.path.isdir(path):
            return False
        if path not in self._custom_dirs:
            self._custom_dirs.append(path)
            self._loader = None  # Force reload
        return True
    
    def unregister_skill_dir(self, path: str) -> bool:
        """Unregister a custom skill directory."""
        path = os.path.expanduser(path)
        if path in self._custom_dirs:
            self._custom_dirs.remove(path)
            self._loader = None  # Force reload
            return True
        return False
    
    def list_skill_dirs(self) -> list[str]:
        """List all registered skill directories."""
        return self._get_all_dirs()
    
    def reload(self) -> None:
        """Force reload of all skills."""
        self._loader = None
        _ = self.loader  # Trigger initialization


# Global registry instance
_registry: Optional[SkillRegistry] = None


def get_registry() -> SkillRegistry:
    global _registry
    if _registry is None:
        _registry = SkillRegistry()
    return _registry


def register_skill_dir(path: str) -> bool:
    """Register a custom skill directory."""
    return get_registry().register_skill_dir(path)


def reload_skills() -> None:
    """Reload all skills from all registered directories."""
    get_registry().reload()