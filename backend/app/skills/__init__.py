"""
PhantomScan Skills System

Structured knowledge packages for LLM agents (AI Analyst, Explainer, Fixer).
Skills are loaded from YAML files and injected into agent prompts at runtime.
"""

from .loader import SkillLoader, load_skill, list_skills, get_skills_for_prompt
from .registry import SkillRegistry, get_registry

__all__ = [
    "SkillLoader",
    "SkillRegistry", 
    "load_skill",
    "list_skills",
    "get_skills_for_prompt",
    "get_registry",
]