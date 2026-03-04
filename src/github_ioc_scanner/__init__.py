"""GitHub IOC Scanner - A tool to scan GitHub repositories for compromised packages."""

__version__ = "1.8.0"

from .ioc_loader import IOCLoader, IOCLoaderError, IOCDirectoryNotFoundError, IOCFileError
from .models import (
    ScanConfig,
    Repository,
    FileInfo,
    PackageDependency,
    IOCMatch,
    IOCDefinition,
    CacheStats,
    ScanResults,
    FileContent,
    APIResponse,
    WorkflowFinding,
)
from .workflow_scanner import WorkflowScanner
from .batch_models import (
    BatchRequest,
    BatchResult,
    BatchMetrics,
    BatchConfig,
    BatchStrategy,
    NetworkConditions,
    PrioritizedFile,
    AsyncBatchContext,
    BatchRecoveryPlan,
    CrossRepoBatch,
)
from .async_github_client import AsyncGitHubClient

__all__ = [
    "IOCLoader",
    "IOCLoaderError", 
    "IOCDirectoryNotFoundError",
    "IOCFileError",
    "ScanConfig",
    "Repository",
    "FileInfo",
    "PackageDependency",
    "IOCMatch",
    "IOCDefinition",
    "CacheStats",
    "ScanResults",
    "FileContent",
    "APIResponse",
    "WorkflowFinding",
    # Batch processing models
    "BatchRequest",
    "BatchResult",
    "BatchMetrics",
    "BatchConfig",
    "BatchStrategy",
    "NetworkConditions",
    "PrioritizedFile",
    "AsyncBatchContext",
    "BatchRecoveryPlan",
    "CrossRepoBatch",
    # Async client
    "AsyncGitHubClient",
    # Workflow scanning
    "WorkflowScanner",
]