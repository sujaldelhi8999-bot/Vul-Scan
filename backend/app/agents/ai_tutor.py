"""
AI Tutor Agent - Provides interactive teaching and explanations for security findings.
"""

import asyncio
from typing import Any

from app.agents import Agent
from app.config import get_settings
from app.services.openrouter_client import call_openrouter
from app.skills import load_skill, get_skills_for_prompt


class AITutorAgent(Agent):
    """Interactive AI tutor for explaining security findings and teaching remediation."""

    def __init__(self) -> None:
        super().__init__("AI Tutor Agent")
        self.settings = get_settings()

    async def run(
        self,
        finding_id: int,
        question: str,
        context: dict[str, Any] | None = None,
        scan_id: int | None = None,
        user_level: str = "intermediate",
    ) -> dict[str, Any]:
        """Answer a question about a security finding."""
        self.scan_id = scan_id or 0
        self.status = "active"
        await self.log_action("started", f"Tutoring session for finding {finding_id}")

        # Load finding context
        finding_context = context or {}
        finding_title = finding_context.get("title", "")
        finding_category = finding_context.get("category", "")
        finding_severity = finding_context.get("severity", "")
        finding_evidence = finding_context.get("evidence", "")
        finding_recommendation = finding_context.get("recommendation", "")
        file_path = finding_context.get("file_path", "")
        code_snippet = finding_context.get("code_snippet", "")

        # Load relevant skill for context
        vuln_key = self._map_to_skill(finding_title, finding_category)
        skill_context = ""
        if vuln_key:
            skill = load_skill(vuln_key)
            if skill:
                from app.skills.loader import get_loader
                loader = get_loader()
                skill_context = loader.format_skill_for_prompt(skill)

        system_prompt = self._build_system_prompt(user_level, skill_context)
        user_prompt = self._build_user_prompt(
            question=question,
            finding_title=finding_title,
            finding_category=finding_category,
            finding_severity=finding_severity,
            finding_evidence=finding_evidence,
            finding_recommendation=finding_recommendation,
            file_path=file_path,
            code_snippet=code_snippet,
            user_level=user_level,
        )

        try:
            result = await call_openrouter(
                user_prompt, system_prompt,
                scan_id=self.scan_id, max_tokens=2000
            )

            if not result or not result.strip():
                self.status = "complete"
                await self.log_action("completed", f"Answered question for finding {finding_id}")
                return {
                    "finding_id": finding_id,
                    "question": question,
                    "answer": "AI answer unavailable — the LLM returned no response. Configure OPENROUTER_API_KEY in backend/.env and restart, then try again.",
                    "explanation": "",
                    "code_examples": [],
                    "references": [],
                    "follow_up_questions": [],
                    "confidence": 0.0,
                }

            # Parse the response for structured output
            parsed = self._parse_tutor_response(result)

            self.status = "complete"
            await self.log_action("completed", f"Answered question for finding {finding_id}")

            return {
                "finding_id": finding_id,
                "question": question,
                "answer": parsed.get("answer", result),
                "explanation": parsed.get("explanation", ""),
                "code_examples": parsed.get("code_examples", []),
                "references": parsed.get("references", []),
                "follow_up_questions": parsed.get("follow_up_questions", []),
                "confidence": parsed.get("confidence", 0.8),
            }

        except Exception as e:
            await self.log_action("error", f"Tutoring failed: {e}")
            return {
                "finding_id": finding_id,
                "question": question,
                "answer": f"I encountered an error while generating the answer: {str(e)}",
                "explanation": "",
                "code_examples": [],
                "references": [],
                "follow_up_questions": [],
                "confidence": 0.0,
            }

    def _map_to_skill(self, title: str, category: str) -> str | None:
        """Map finding title/category to skill name."""
        t = (title + " " + category).lower()
        skill_map = {
            "sql_injection": ["sql", "injection", "sqli"],
            "xss": ["xss", "cross-site scripting"],
            "ssrf": ["ssrf", "server-side request forgery"],
            "idor": ["idor", "insecure direct object reference", "object reference"],
            "jwt": ["jwt", "json web token", "token"],
            "race_conditions": ["race condition", "race"],
            "business_logic": ["business logic", "workflow", "logic flaw"],
            "file_upload": ["file upload", "upload", "webshell"],
            "ssti": ["ssti", "server-side template injection", "template injection"],
            "xxe": ["xxe", "xml external entity", "xml injection"],
            "prototype_pollution": ["prototype pollution", "prototype"],
            "http_request_smuggling": ["request smuggling", "smuggling", "desync"],
        }
        for skill_name, keywords in skill_map.items():
            if any(kw in t for kw in keywords):
                return skill_name
        return None

    def _build_system_prompt(self, user_level: str, skill_context: str) -> str:
        """Build system prompt for the AI tutor."""
        level_guidance = {
            "beginner": "Explain concepts simply, avoid jargon, provide analogies. Assume no prior security knowledge.",
            "intermediate": "Use standard security terminology, explain the 'why' behind concepts, show practical examples.",
            "expert": "Use technical language, focus on advanced details, edge cases, and deep technical explanations.",
        }

        return (
            f"You are PhantomScan's AI Security Tutor. Your role is to teach developers about security vulnerabilities, "
            f"explain how to fix them, and answer follow-up questions. "
            f"\n\nTARGET AUDIENCE: {user_level.upper()} - {level_guidance.get(user_level, level_guidance['intermediate'])}"
            f"\n\nTEACHING PRINCIPLES:"
            f"\n1. Always explain the ROOT CAUSE, not just the symptom"
            f"\n2. Show VULNERABLE code vs SECURE code side-by-side"
            f"\n3. Explain the ATTACK VECTOR - how an attacker would exploit this"
            f"\n4. Provide CONCRETE REMEDIATION with code examples"
            f"\n5. Reference relevant standards (OWASP, CWE, etc.)"
            f"\n6. Encourage questions - end with follow-up prompts"
            f"\n\nEXPERT KNOWLEDGE BASE:"
            f"\n{skill_context}"
            f"\n\nRESPONSE FORMAT (JSON):"
            f"\n{{"
            f'\n  "answer": "Direct answer to the question",'
            f'\n  "explanation": "Detailed explanation of the concept",'
            f'\n  "code_examples": ['
            f'\n    {{"language": "python", "title": "Vulnerable Code", "code": "..."}},'
            f'\n    {{"language": "python", "title": "Secure Code", "code": "..."}}'
            f'\n  ],'
            f'\n  "references": ["OWASP Top 10 A03:2021", "CWE-89: SQL Injection"],'
            f'\n  "follow_up_questions": ["How does parameterized queries prevent this?", "What about ORM safety?"]'
            f'\n}}'
        )

    def _build_user_prompt(
        self,
        question: str,
        finding_title: str,
        finding_category: str,
        finding_severity: str,
        finding_evidence: str,
        finding_recommendation: str,
        file_path: str,
        code_snippet: str,
        user_level: str,
    ) -> str:
        """Build user prompt with finding context."""
        parts = [
            f"QUESTION: {question}",
            "",
            "FINDING CONTEXT:",
            f"- Title: {finding_title}",
            f"- Category: {finding_category}",
            f"- Severity: {finding_severity}",
        ]

        if file_path:
            parts.append(f"- File: {file_path}")
        if code_snippet:
            parts.append(f"- Code Snippet:\n```\n{code_snippet}\n```")
        if finding_evidence:
            parts.append(f"- Evidence: {finding_evidence[:1000]}")
        if finding_recommendation:
            parts.append(f"- Current Recommendation: {finding_recommendation}")

        parts.extend([
            "",
            "Please answer the question following the JSON response format specified in the system prompt.",
        ])

        return "\n".join(parts)

    def _parse_tutor_response(self, response: str) -> dict[str, Any]:
        """Parse tutor response for structured output."""
        import json
        import re

        # Try to extract JSON from response
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        # Fallback: treat entire response as answer
        return {
            "answer": response,
            "explanation": "",
            "code_examples": [],
            "references": [],
            "follow_up_questions": [],
            "confidence": 0.7,
        }


async def create_ai_tutor_agent() -> AITutorAgent:
    """Factory function to create AI Tutor Agent."""
    return AITutorAgent()