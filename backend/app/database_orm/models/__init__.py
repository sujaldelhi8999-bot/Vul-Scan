# Database Models Package
# All SQLAlchemy models for PhantomScan

from app.database_orm.models.user import User, UserRole, SubscriptionTier, SubscriptionStatus
from app.database_orm.models.authorized_target import AuthorizedTarget, VerificationMethod, VerificationStatus
from app.database_orm.models.scan import Scan, ScanMode, ScanIntensity, ScanStatus
from app.database_orm.models.finding import Finding, FindingSeverity, FindingConfidence, RemediationStatus, VerificationStatus as FindingVerificationStatus, RiskStatus
from app.database_orm.models.scan_artifact import ScanArtifact
from app.database_orm.models.audit_log import AuditLog
from app.database_orm.models.agent_run import AgentRun, AgentRunStatus
from app.database_orm.models.scan_event_log import ScanEventLog
from app.database_orm.models.authorized_test_job import AuthorizedTestJob, JobStatus
from app.database_orm.models.job_event import JobEvent
from app.database_orm.models.execution_status import ExecutionStatus, ExecutionType, ExecutionLifecycle
from app.database_orm.models.evidence_record import EvidenceRecord
from app.database_orm.models.learning_insight import LearningInsight, LearningKind, LearningStatus
from app.database_orm.models.dos_job import DosJob
from app.database_orm.models.private_scope import PrivateScope
from app.database_orm.models.shadow_recon import ShadowReconResult
from app.database_orm.models.exploitation_result import ExploitationResult
from app.database_orm.models.scan_source import ScanSource, SourceType, ScanSourceStatus
from app.database_orm.models.source_correlation import SourceCorrelation, CorrelationType
from app.database_orm.models.finding_source import FindingSource
from app.database_orm.models.sast_finding import SASTFinding, Language, Framework, SastTool
from app.database_orm.models.secret_finding import SecretFinding
from app.database_orm.models.iac_finding import IaCFinding, IaCPlatform
from app.database_orm.models.sca_finding import SCAFinding
from app.database_orm.models.ai_code_fix import AICodeFix, AIFixStatus, AIFixType
from app.database_orm.models.ai_tutor_session import AITutorSession
from app.database_orm.models.pr_description import PRDescription, PRDescriptionStatus
from app.database_orm.models.github_oauth import GitHubOAuthToken
from app.database_orm.models.github_app import GitHubAppInstallation

__all__ = [
    # User
    "User", "UserRole", "SubscriptionTier", "SubscriptionStatus",
    # Authorized Target
    "AuthorizedTarget", "VerificationMethod", "VerificationStatus",
    # Scan
    "Scan", "ScanMode", "ScanIntensity", "ScanStatus",
    # Finding
    "Finding", "FindingSeverity", "FindingConfidence", "RemediationStatus", "FindingVerificationStatus", "RiskStatus",
    # Scan Artifact
    "ScanArtifact",
    # Audit Log
    "AuditLog",
    # Agent Run
    "AgentRun", "AgentRunStatus",
    # Scan Event Log
    "ScanEventLog",
    # Authorized Test Job
    "AuthorizedTestJob", "JobStatus",
    # Job Event
    "JobEvent",
    # Execution Status
    "ExecutionStatus", "ExecutionType", "ExecutionLifecycle",
    # Evidence Record
    "EvidenceRecord",
    # Learning Insight
    "LearningInsight", "LearningKind", "LearningStatus",
    # DoS Job
    "DosJob",
    # Private Scope
    "PrivateScope",
    # Shadow Recon
    "ShadowReconResult",
    # Exploitation Result
    "ExploitationResult",
    # Multi-source
    "ScanSource", "SourceType", "ScanSourceStatus",
    "SourceCorrelation", "CorrelationType",
    "FindingSource",
    "SASTFinding", "Language", "Framework", "SastTool",
    "SecretFinding",
    "IaCFinding", "IaCPlatform",
    "SCAFinding",
    "AICodeFix", "AIFixStatus", "AIFixType",
    "AITutorSession",
    "PRDescription", "PRDescriptionStatus",
    "GitHubOAuthToken",
    "GitHubAppInstallation",
]
