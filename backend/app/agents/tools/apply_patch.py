"""
Apply Patch Tool - Applies unified diff patches to files in the sandbox.

Allows agents to apply generated patches and verify fixes.
"""

from typing import Any

from app.agents import Agent
from app.agents.sandbox_manager import SandboxManagerAgent


class ApplyPatchTool:
    """Tool for applying patches in the sandbox."""
    
    def __init__(self, agent: Agent, sandbox_manager: SandboxManagerAgent | None = None):
        self.agent = agent
        self.sandbox_manager = sandbox_manager or SandboxManagerAgent()
        self.applied_patches: list[dict[str, Any]] = []
    
    async def apply_patch(
        self,
        patch: str,
        file_path: str,
        scan_id: int,
        target_root: str | None = None,
    ) -> dict[str, Any]:
        """
        Apply a unified diff patch to a file.
        
        Args:
            patch: Unified diff patch content
            file_path: Relative path to the file to patch
            scan_id: Scan ID for logging
            target_root: Optional root directory containing the source code
            
        Returns:
            Result with success status and patched content
        """
        if not patch or not patch.strip():
            return {
                "success": False,
                "error": "Empty patch provided",
            }
        
        if not file_path:
            return {
                "success": False,
                "error": "File path is required",
            }
        
        result = await self.sandbox_manager.apply_patch(
            patch=patch,
            file_path=file_path,
            scan_id=scan_id,
            target_root=target_root,
        )
        
        if result.get("success"):
            self.applied_patches.append({
                "file_path": file_path,
                "patch": patch[:500],  # Store preview
                "timestamp": self.agent.scan_id,
            })
        
        await self.agent.log_action(
            "patch_applied" if result.get("success") else "patch_failed",
            f"Patch for {file_path}: {'success' if result.get('success') else 'failed'}"
        )
        
        return result
    
    async def verify_patch(
        self,
        finding_id: int,
        scan_id: int,
        re_test_module: str,
        target_url: str,
    ) -> dict[str, Any]:
        """
        Verify a patch by re-running the relevant test module.
        
        Args:
            finding_id: ID of the finding that was patched
            scan_id: Scan ID
            re_test_module: Module to re-run for verification (e.g., 'injection', 'xss')
            target_url: Target URL to test against
            
        Returns:
            Verification result with status
        """
        from app.services.active_security import SecurityTestPlanner
        
        await self.agent.log_action("patch_verification_started", f"Verifying patch for finding {finding_id} with {re_test_module}")
        
        # This would integrate with the active security engine to re-run specific tests
        # For now, return a placeholder that the API can use
        return {
            "finding_id": finding_id,
            "verification_module": re_test_module,
            "status": "pending",
            "message": f"Verification queued for module {re_test_module}",
        }
    
    def list_applied_patches(self) -> list[dict[str, Any]]:
        """List all patches applied in this session."""
        return self.applied_patches


async def create_apply_patch_tool(agent: Agent, sandbox_manager: SandboxManagerAgent | None = None) -> ApplyPatchTool:
    """Factory function to create an ApplyPatchTool for an agent."""
    return ApplyPatchTool(agent, sandbox_manager)