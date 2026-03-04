"""Core scanning engine for the GitHub IOC Scanner."""

import asyncio
import time
from typing import Any, Dict, List, Optional

from .async_github_client import AsyncGitHubClient
from .batch_coordinator import BatchCoordinator
from .batch_models import BatchConfig, BatchStrategy
from .cache import CacheManager
from .event_loop_context import EventLoopContext
from .exceptions import (
    AuthenticationError,
    NetworkError,
    IOCLoaderError,
    ScanError,
    ConfigurationError,
    UnsupportedFileFormatError,
    ParsingError,
    wrap_exception,
    get_error_context
)
from .github_client import GitHubClient
from .ioc_loader import IOCLoader
from .logging_config import (
    get_logger, log_exception, log_performance, log_user_message, 
    log_rate_limit_debug, log_exception_with_user_message
)
from .models import ScanConfig, ScanResults, Repository, IOCMatch, CacheStats, FileContent, FileInfo, PackageDependency, WorkflowFinding, SecretFinding
from .parsers.factory import get_parser, parse_file_safely
# Import parsers module to ensure all parsers are registered
from . import parsers
from .workflow_scanner import WorkflowScanner
from .secrets_scanner import SecretsScanner

logger = get_logger(__name__)


class GitHubIOCScanner:
    """Main scanner class that orchestrates the scanning workflow."""

    # Common lockfile patterns to search for
    # Base lockfile patterns
    _BASE_LOCKFILE_PATTERNS = [
        "package.json",
        "package-lock.json", 
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb",
        "requirements.txt",
        "Pipfile.lock",
        "poetry.lock",
        "pyproject.toml",
        "Gemfile.lock",
        "composer.lock",
        "go.mod",
        "go.sum",
        "Cargo.lock",
        "pom.xml",  # Maven support
    ]
    
    # SBOM file patterns
    _SBOM_PATTERNS = [
        "sbom.json",
        "bom.json", 
        "cyclonedx.json",
        "spdx.json",
        "sbom.xml",
        "bom.xml",
        "cyclonedx.xml",
        "spdx.xml",
        "software-bill-of-materials.json",
        "software-bill-of-materials.xml",
        ".sbom",
        ".spdx",
        "SBOM.json",
        "BOM.json"
    ]
    
    # Common subdirectories to check
    _COMMON_SUBDIRS = ['', 'frontend/', 'backend/', 'client/', 'server/', 'web/', 'api/', 'app/', 'src/', 'cdk/']
    
    # Generate full list of patterns including subdirectories
    LOCKFILE_PATTERNS = []
    for subdir in _COMMON_SUBDIRS:
        for pattern in _BASE_LOCKFILE_PATTERNS:
            LOCKFILE_PATTERNS.append(subdir + pattern)
    
    # Generate SBOM patterns with subdirectories
    SBOM_PATTERNS = []
    for subdir in _COMMON_SUBDIRS:
        for pattern in _SBOM_PATTERNS:
            SBOM_PATTERNS.append(subdir + pattern)
    
    # Combined patterns for comprehensive scanning
    ALL_PATTERNS = LOCKFILE_PATTERNS + SBOM_PATTERNS

    def __init__(self, config: ScanConfig, github_client: GitHubClient, cache_manager: CacheManager, ioc_loader: Optional[IOCLoader] = None, progress_callback: Optional[callable] = None, batch_config: Optional[BatchConfig] = None, enable_batch_processing: bool = False, enable_sbom_scanning: bool = True) -> None:
        """Initialize the scanner with configuration and dependencies."""
        self.config = config
        self.github_client = github_client
        self.cache_manager = cache_manager
        self.ioc_loader = ioc_loader or IOCLoader(config.issues_dir)
        self.progress_callback = progress_callback
        self.enable_batch_processing = enable_batch_processing
        self.enable_sbom_scanning = enable_sbom_scanning
        
        # Initialize scan state manager if state saving is enabled
        self.scan_state_manager = None
        self.current_scan_state = None
        self.resume_state = None  # For resuming previous scans
        if config.save_state and not config.no_save_state:
            from .scan_state import ScanStateManager
            self.scan_state_manager = ScanStateManager()
        
        # Initialize batch processing components if enabled
        self.batch_coordinator: Optional[BatchCoordinator] = None
        self.async_github_client: Optional[AsyncGitHubClient] = None
        
        if self.enable_batch_processing:
            # Create async GitHub client for batch operations
            self.async_github_client = AsyncGitHubClient(
                token=github_client.token,
                config=batch_config or BatchConfig()
            )
            
            # Initialize batch coordinator with progress callback integration
            self.batch_coordinator = BatchCoordinator(
                github_client=self.async_github_client,
                cache_manager=cache_manager,
                config=batch_config or BatchConfig()
            )
            
            # Set scanner reference for repository discovery
            self.batch_coordinator.scanner = self
            
            # Configure progress monitoring if callback is provided
            if self.progress_callback:
                self._setup_batch_progress_monitoring()
        
        # Initialize workflow scanner if workflow scanning is enabled
        self.workflow_scanner: Optional[WorkflowScanner] = None
        if config.scan_workflows:
            self.workflow_scanner = WorkflowScanner()
        
        # Initialize secrets scanner if secrets scanning is enabled
        self.secrets_scanner: Optional[SecretsScanner] = None
        if config.scan_secrets:
            self.secrets_scanner = SecretsScanner()
    
    def _scan_team_repositories_sequential(self, repos_to_scan, team_name, ioc_hash, remaining_repos, total_repos_scanned, total_files_scanned):
        """Scan team repositories using sequential processing."""
        team_matches = []
        team_workflow_findings = []
        team_secret_findings = []
        team_files_scanned = 0
        
        for j, repo in enumerate(repos_to_scan, 1):
            if not self.config.quiet:
                print(f"\r[Team {team_name}] [{j:3d}/{len(repos_to_scan):3d}] Scanning {repo.full_name}...", end='', flush=True)
            
            matches, files_scanned = self.scan_repository_for_iocs(repo, ioc_hash)
            team_matches.extend(matches)
            team_files_scanned += files_scanned
            
            # Scan workflows if enabled
            if self.config.scan_workflows and self.workflow_scanner:
                logger.info(f"Scanning workflows in {repo.full_name}...")
                workflow_findings = self._scan_workflows(repo)
                team_workflow_findings.extend(workflow_findings)
                if workflow_findings:
                    logger.info(f"Found {len(workflow_findings)} workflow security issues in {repo.full_name}")
                else:
                    logger.debug(f"No workflow issues found in {repo.full_name}")
            
            # Scan for secrets if enabled
            if self.config.scan_secrets and self.secrets_scanner:
                logger.info(f"Scanning secrets in {repo.full_name}...")
                secret_findings = self._scan_secrets(repo)
                team_secret_findings.extend(secret_findings)
                if secret_findings:
                    logger.info(f"Found {len(secret_findings)} secrets in {repo.full_name}")
                else:
                    logger.debug(f"No secrets found in {repo.full_name}")
            
            # Update scan state with progress
            if self.current_scan_state:
                self.current_scan_state.repositories_scanned = total_repos_scanned + j
                self.current_scan_state.files_scanned = total_files_scanned + team_files_scanned
                
                # Add to completed repositories
                if not self.current_scan_state.completed_repositories:
                    self.current_scan_state.completed_repositories = []
                self.current_scan_state.completed_repositories.append(repo.full_name)
                
                # Add matches to state
                if matches:
                    from .scan_state import add_ioc_match_to_state
                    for match in matches:
                        add_ioc_match_to_state(self.current_scan_state, match)
                
                # Save state periodically
                self.scan_state_manager.save_state(self.current_scan_state)
            
            # Remove from remaining repositories
            remaining_repos.pop(repo.full_name, None)
        
        if not self.config.quiet and repos_to_scan:
            print()  # New line after progress
            
        return team_matches, team_files_scanned, team_workflow_findings, team_secret_findings

    def _run_team_batch_processing(self, repositories, strategy, file_patterns):
        """Run batch processing for team repositories synchronously."""
        from .event_loop_context import EventLoopContext
        import asyncio
        import concurrent.futures
        
        event_loop_context = EventLoopContext()
        
        async def run_batch():
            # Ensure we have a fresh batch coordinator for this event loop
            if not self.batch_coordinator or self.batch_coordinator.github_client.client:
                # Reset the HTTP client to avoid event loop conflicts
                if self.batch_coordinator and self.batch_coordinator.github_client.client:
                    try:
                        await self.batch_coordinator.github_client.client.aclose()
                    except Exception as e:
                        logger.debug(f"Error closing HTTP client during cleanup: {e}")
                    self.batch_coordinator.github_client.client = None
            
            return await self.batch_coordinator.process_repositories_batch(
                repositories, strategy=strategy, file_patterns=file_patterns
            )
        
        try:
            # Check if we're already in an event loop
            if event_loop_context.is_event_loop_running():
                # We're in an event loop, need to run in a separate thread with its own loop
                def run_in_thread():
                    # Use EventLoopContext to manage the new event loop
                    thread_event_context = EventLoopContext()
                    
                    try:
                        with thread_event_context.managed_event_loop() as loop:
                            # Create a fresh batch coordinator for this thread's event loop
                            from .async_github_client import AsyncGitHubClient
                            from .batch_coordinator import BatchCoordinator
                            
                            # Create new async client for this event loop
                            fresh_async_client = AsyncGitHubClient(
                                token=self.batch_coordinator.github_client.token,
                                config=self.batch_coordinator.config
                            )
                            
                            # Create new batch coordinator
                            fresh_batch_coordinator = BatchCoordinator(
                                github_client=fresh_async_client,
                                cache_manager=self.cache_manager,
                                config=self.batch_coordinator.config
                            )
                            fresh_batch_coordinator.scanner = self
                            
                            async def run_with_fresh_coordinator():
                                await fresh_batch_coordinator.start()
                                try:
                                    return await fresh_batch_coordinator.process_repositories_batch(
                                        repositories, strategy=strategy, file_patterns=file_patterns
                                    )
                                finally:
                                    await fresh_batch_coordinator.stop()
                            
                            return loop.run_until_complete(run_with_fresh_coordinator())
                    except Exception as e:
                        logger.error(f"Error in thread event loop: {e}")
                        raise
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_in_thread)
                    return future.result()
                    
            else:
                # No event loop running, use EventLoopContext to run safely
                with event_loop_context.managed_event_loop() as loop:
                    return loop.run_until_complete(run_batch())
                    
        except Exception as e:
            logger.warning(f"Event loop handling failed, falling back to sequential processing: {e}")
            # Fall back to sequential processing if async fails
            return {}

    def _run_async_operation_safely(self, coro, operation_name: str = "async operation"):
        """
        Run an async operation safely with proper event loop context management.
        
        This method ensures proper async context during rate limit recovery and
        prevents "no running event loop" errors.
        
        Args:
            coro: The coroutine to run
            operation_name: Name of the operation for logging
            
        Returns:
            The result of the coroutine
        """
        event_loop_context = EventLoopContext()
        
        try:
            if event_loop_context.is_event_loop_running():
                # We're already in an async context, create a task
                logger.debug(f"Running {operation_name} as task in existing event loop")
                return asyncio.create_task(coro)
            else:
                # No running loop, use managed event loop
                logger.debug(f"Running {operation_name} with managed event loop")
                with event_loop_context.managed_event_loop() as loop:
                    return loop.run_until_complete(coro)
        except Exception as e:
            logger.error(f"Error running {operation_name} safely: {e}")
            raise

    def _get_scan_patterns(self) -> List[str]:
        """Get file patterns to scan based on configuration."""
        # Use a more focused set of patterns for better performance
        if self.config.fast_mode:
            # Fast mode: only root-level files
            patterns = [
                "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                "requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml",
                "Gemfile.lock", "composer.lock", "go.mod", "go.sum", "Cargo.lock"
            ]
            if self.enable_sbom_scanning:
                patterns.extend([
                    "sbom.json", "bom.json", "cyclonedx.json", "spdx.json"
                ])
        else:
            # Comprehensive mode: use optimized pattern set
            patterns = self._get_optimized_patterns()
            
        return patterns
    
    def _get_optimized_patterns(self) -> List[str]:
        """Get an optimized set of patterns using intelligent recursive search."""
        # Instead of 280 specific path patterns, use filename-based recursive search
        # This covers ALL possible locations while being much more efficient
        
        base_filenames = [
            # JavaScript/Node.js
            "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
            
            # Python
            "requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml",
            
            # Other languages
            "Gemfile.lock",      # Ruby
            "composer.lock",     # PHP
            "go.mod", "go.sum",  # Go
            "Cargo.lock",        # Rust
        ]
        
        if self.enable_sbom_scanning:
            base_filenames.extend([
                # SBOM files
                "sbom.json", "bom.json", "cyclonedx.json", "spdx.json",
                "sbom.xml", "bom.xml", "cyclonedx.xml", "spdx.xml",
                "software-bill-of-materials.json", "software-bill-of-materials.xml",
                ".sbom", ".spdx", "SBOM.json", "BOM.json"
            ])
        
        return base_filenames

    def scan(self) -> ScanResults:
        """Execute the scan based on the configuration."""
        # Use batch processing if enabled and multiple repositories
        # BUT: team-first-org scans must use sequential processing for proper team grouping
        if self.enable_batch_processing and self.batch_coordinator and not self.config.team_first_org:
            return self._run_async_scan_safely()
        else:
            return self._scan_sequential()
    
    def _run_async_scan_safely(self) -> ScanResults:
        """Run async scan with proper event loop handling."""
        from .event_loop_context import EventLoopContext
        import asyncio
        import concurrent.futures
        
        event_loop_context = EventLoopContext()
        
        try:
            # Check if we're already in an event loop
            if event_loop_context.is_event_loop_running():
                # We're in an event loop, need to run in a separate thread with its own loop
                def run_in_thread():
                    # Use EventLoopContext to manage the new event loop
                    thread_event_context = EventLoopContext()
                    
                    try:
                        with thread_event_context.managed_event_loop() as loop:
                            # Create fresh async components for this event loop
                            from .async_github_client import AsyncGitHubClient
                            from .batch_coordinator import BatchCoordinator
                            
                            # Create new async client for this event loop
                            fresh_async_client = AsyncGitHubClient(
                                token=self.batch_coordinator.github_client.token,
                                config=self.batch_coordinator.config
                            )
                            
                            # Create new batch coordinator
                            fresh_batch_coordinator = BatchCoordinator(
                                github_client=fresh_async_client,
                                cache_manager=self.cache_manager,
                                config=self.batch_coordinator.config
                            )
                            fresh_batch_coordinator.scanner = self
                            
                            # Temporarily replace the batch coordinator
                            original_coordinator = self.batch_coordinator
                            self.batch_coordinator = fresh_batch_coordinator
                            
                            try:
                                return loop.run_until_complete(self._scan_with_batch_processing())
                            finally:
                                # Restore original coordinator
                                self.batch_coordinator = original_coordinator
                    except Exception as e:
                        logger.error(f"Error in thread event loop: {e}")
                        raise
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_in_thread)
                    return future.result()
                    
            else:
                # No event loop running, use EventLoopContext to run safely
                with event_loop_context.managed_event_loop() as loop:
                    return loop.run_until_complete(self._scan_with_batch_processing())
                    
        except Exception as e:
            logger.warning(f"Async scan failed, falling back to sequential processing: {e}")
            # Fall back to sequential processing if async fails
            return self._scan_sequential()
    
    async def _scan_with_batch_processing(self) -> ScanResults:
        """Execute scan using batch processing for improved performance."""
        import time
        start_time = time.time()
        
        try:
            # Validate configuration
            self._validate_scan_config()
            
            # Load IOC definitions
            logger.info("Loading IOC definitions...")
            try:
                ioc_definitions = self.ioc_loader.load_iocs()
                ioc_hash = self.ioc_loader.get_ioc_hash()
                logger.info(f"Loaded IOC definitions from {len(ioc_definitions)} files")
            except IOCLoaderError:
                raise
            except Exception as e:
                log_exception(logger, "Failed to load IOC definitions", e)
                raise wrap_exception(e, "Failed to load IOC definitions", IOCLoaderError)
            
            # Start batch coordinator
            await self.batch_coordinator.start()
            
            try:
                # Discover repositories to scan
                logger.info("🔍 Starting repository discovery...")
                repositories = await self._discover_repositories_batch()
                logger.info(f"✅ Repository discovery completed: {len(repositories)} repositories found")
                
                # Debug: Log first few repository names
                if repositories:
                    sample_repos = [repo.full_name for repo in repositories[:5]]
                    logger.info(f"📋 Sample repositories: {sample_repos}")
                    if len(repositories) > 5:
                        logger.info(f"📊 Total repositories: {len(repositories)} (showing first 5)")
                else:
                    logger.info("No repositories found during discovery")
                
                if not repositories:
                    logger.warning("🚫 No repositories to scan, returning empty results")
                    return ScanResults(
                        matches=[],
                        cache_stats=self.cache_manager.get_cache_stats(),
                        repositories_scanned=0,
                        files_scanned=0
                    )
                
                # Start budget redistribution task if intelligent rate limiting is enabled
                redistribution_task = None
                if self.async_github_client and hasattr(self.config, 'enable_intelligent_rate_limiting') and self.config.enable_intelligent_rate_limiting:
                    redistribution_task = asyncio.create_task(self._periodic_budget_redistribution())
                
                try:
                    # Execute batch scanning workflow with progress monitoring
                    file_patterns = self._get_scan_patterns()
                    batch_results = await self.batch_coordinator.process_repositories_batch(
                        repositories, 
                        strategy=self._select_batch_strategy(repositories),
                        file_patterns=file_patterns
                    )
                finally:
                    # Cancel budget redistribution task
                    if redistribution_task:
                        redistribution_task.cancel()
                        try:
                            await redistribution_task
                        except asyncio.CancelledError:
                            pass
                
                # Convert batch results to IOC matches
                all_matches = []
                all_workflow_findings = []
                all_secret_findings = []
                successful_repos = len(batch_results)  # All repositories that were processed
                total_files_scanned = 0
                
                for repo_name, matches in batch_results.items():
                    if matches:
                        all_matches.extend(matches)
                
                # Get actual number of files processed from batch coordinator
                total_files_scanned = self.batch_coordinator.get_total_files_processed() if self.batch_coordinator else len(batch_results)

                # Scan workflows and secrets for each repository
                scan_workflows = self.config.scan_workflows and self.workflow_scanner
                scan_secrets = self.config.scan_secrets and self.secrets_scanner
                
                if scan_workflows or scan_secrets:
                    scan_types = []
                    if scan_workflows:
                        scan_types.append("workflows")
                    if scan_secrets:
                        scan_types.append("secrets")
                    
                    if not self.config.quiet:
                        print(f"\n🔍 Scanning {' & '.join(scan_types)} in {len(repositories)} repositories (parallel)...")
                    
                    # Use parallel scanning for better performance
                    workflow_findings_batch, secret_findings_batch = self._scan_workflows_and_secrets_parallel(
                        repositories,
                        scan_workflows=scan_workflows,
                        scan_secrets=scan_secrets,
                        max_workers=min(10, len(repositories))  # More workers for larger batches
                    )
                    all_workflow_findings.extend(workflow_findings_batch)
                    all_secret_findings.extend(secret_findings_batch)
                    
                    if not self.config.quiet:
                        print()  # New line after progress
                
                # Log workflow findings summary
                if all_workflow_findings:
                    logger.info(f"Found {len(all_workflow_findings)} workflow security issues across all repositories")
                
                # Log secret findings summary
                if all_secret_findings:
                    logger.info(f"Found {len(all_secret_findings)} secrets across all repositories")
                
                scan_duration = time.time() - start_time
                log_performance(
                    logger, "batch_scan", scan_duration,
                    repositories=len(repositories),
                    successful=successful_repos,
                    failed=len(repositories) - successful_repos,
                    matches=len(all_matches),
                    files=total_files_scanned
                )
                
                # Get batch metrics for additional insights
                batch_metrics = self.batch_coordinator.get_batch_metrics()
                logger.info(f"Batch scan completed: {len(all_matches)} matches, "
                          f"{batch_metrics.cache_hit_rate:.1f}% cache hit rate, "
                          f"{batch_metrics.parallel_efficiency:.2f} parallel efficiency")
                
                return ScanResults(
                    matches=all_matches,
                    cache_stats=self.cache_manager.get_cache_stats(),
                    repositories_scanned=successful_repos,
                    files_scanned=total_files_scanned,
                    workflow_findings=all_workflow_findings if all_workflow_findings else None,
                    secret_findings=all_secret_findings if all_secret_findings else None
                )
                
            finally:
                # Always stop batch coordinator
                await self.batch_coordinator.stop()
                
        except (AuthenticationError, IOCLoaderError, ConfigurationError, ScanError):
            raise
        except Exception as e:
            log_exception(logger, "Unexpected error during batch scan", e)
            raise wrap_exception(e, "Unexpected error during batch scan", ScanError)
    
    def _scan_team_first_organization(self, ioc_hash: str, start_time: float) -> ScanResults:
        """Execute team-first organization scan.
        
        This method:
        1. Discovers all repositories in the organization
        2. Discovers all teams in the organization
        3. Iterates through teams and scans their repositories
        4. Removes processed repositories from the main list
        5. Shows team results and accumulates overall results
        6. Scans remaining repositories not assigned to any team
        """
        logger.info(f"Starting team-first organization scan for {self.config.org}")
        
        # Initialize or resume scan state
        if self.scan_state_manager:
            from .scan_state import ScanState, add_ioc_match_to_state, convert_state_matches_to_ioc_matches
            
            if self.resume_state:
                # Resuming from previous scan
                self.current_scan_state = self.resume_state
                if not self.config.quiet:
                    print(f"🔄 Resuming scan ID: {self.current_scan_state.scan_id}")
                    print(f"   Progress: {self.current_scan_state.repositories_scanned}/{self.current_scan_state.total_repositories} repositories")
                    if self.current_scan_state.current_team_index is not None:
                        print(f"   Current team: {self.current_scan_state.current_team_index + 1}/{self.current_scan_state.total_teams}")
            else:
                # Create new scan state
                config_dict = {
                    'org': self.config.org,
                    'team_first_org': self.config.team_first_org,
                    'enable_sbom': self.config.enable_sbom,
                    'include_archived': self.config.include_archived
                }
                
                self.current_scan_state = self.scan_state_manager.create_scan_state(
                    org=self.config.org,
                    scan_type='team-first-org',
                    target=self.config.org,
                    config=config_dict
                )
                
                if not self.config.quiet:
                    print(f"💾 Scan ID: {self.current_scan_state.scan_id}")
                    print(f"   (Use --resume {self.current_scan_state.scan_id} to resume if interrupted)")
        
        # Step 1: Get all repositories in the organization
        if not self.config.quiet:
            print("🔍 Discovering repositories in organization...")
        logger.info(f"Discovering all repositories in organization {self.config.org}")
        all_repositories = self.discover_organization_repositories(self.config.org)
        remaining_repos = {repo.full_name: repo for repo in all_repositories}
        
        if not self.config.quiet:
            print(f"✅ Found {len(all_repositories)} repositories in organization")
        
        # Step 2: Get all teams in the organization
        if not self.config.quiet:
            print("👥 Discovering teams in organization...")
        logger.info(f"Discovering all teams in organization {self.config.org}")
        teams = self.github_client.get_organization_teams(self.config.org)
        
        if not self.config.quiet:
            print(f"✅ Found {len(teams)} teams in organization")
            print(f"🚀 Starting team-by-team scan...")
        
        # Update scan state with discovery results
        if self.current_scan_state:
            self.current_scan_state.total_repositories = len(all_repositories)
            self.current_scan_state.total_teams = len(teams)
            self.scan_state_manager.save_state(self.current_scan_state)
        
        # Initialize overall results
        all_matches = []
        all_workflow_findings = []
        all_secret_findings = []
        total_files_scanned = 0
        total_repos_scanned = 0
        
        # Initialize results from resume state if available
        if self.resume_state and self.resume_state.matches:
            from .scan_state import convert_state_matches_to_ioc_matches
            all_matches = convert_state_matches_to_ioc_matches(self.resume_state.matches)
            total_files_scanned = self.resume_state.files_scanned
            total_repos_scanned = self.resume_state.repositories_scanned
            
            if not self.config.quiet and all_matches:
                print(f"\n📋 PREVIOUSLY FOUND THREATS ({len(all_matches)} threats)")
                print("=" * 60)
                for match in all_matches:
                    print(f"   ⚠️  {match.repo} | {match.file_path} | {match.package_name} | {match.version}")
                print(f"Previous scan found {len(all_matches)} threats in {total_repos_scanned} repositories")
                print("Continuing scan to find additional threats...")
        
        # Step 3-5: Iterate through teams and scan their repositories
        start_team_index = 0
        if self.resume_state and self.resume_state.current_team_index is not None:
            start_team_index = self.resume_state.current_team_index
            if not self.config.quiet:
                print(f"🔄 Resuming from team {start_team_index + 1}/{len(teams)}")
        
        for i, team in enumerate(teams, 1):
            # Skip already processed teams when resuming
            if i - 1 < start_team_index:
                continue
                
            team_name = team.get('name', team.get('slug', 'unknown'))
            
            # Skip already completed teams when resuming
            if (self.resume_state and self.resume_state.completed_teams and 
                team_name in self.resume_state.completed_teams):
                if not self.config.quiet:
                    print(f"\n[{i:3d}/{len(teams):3d}] ✅ Team '{team_name}' already completed (skipping)")
                continue
            
            if not self.config.quiet:
                print(f"\n[{i:3d}/{len(teams):3d}] 👥 Processing team '{team_name}'...")
            
            logger.info(f"Scanning team {i}/{len(teams)}: {team_name}")
            
            # Update current team in scan state
            if self.current_scan_state:
                self.current_scan_state.current_team_index = i - 1
                self.current_scan_state.current_team_name = team_name
            
            # Get team repositories
            try:
                team_repos_data = self.github_client.get_team_repositories(self.config.org, team_name)
                if not team_repos_data:
                    logger.info(f"  No repositories found for team {team_name}")
                    continue
                
                # Convert to Repository objects
                team_repos = []
                for repo_data in team_repos_data:
                    if repo_data['full_name'] in remaining_repos:
                        team_repos.append(remaining_repos[repo_data['full_name']])
                
                if not team_repos:
                    if not self.config.quiet:
                        print(f"     ⚠️  No unprocessed repositories for team '{team_name}'")
                    logger.info(f"  No unprocessed repositories found for team {team_name}")
                    continue
                
                if not self.config.quiet:
                    print(f"     📦 Found {len(team_repos)} repositories to scan")
                    
                logger.info(f"  Found {len(team_repos)} repositories for team {team_name}")
                
                # Scan team repositories using batch processing if available
                team_matches = []
                team_files_scanned = 0
                
                # Filter out already processed repositories when resuming
                repos_to_scan = []
                for repo in team_repos:
                    if (self.resume_state and self.resume_state.completed_repositories and 
                        repo.full_name in self.resume_state.completed_repositories):
                        if not self.config.quiet:
                            print(f"     ✅ {repo.full_name} already completed")
                        # Still remove from remaining repositories
                        remaining_repos.pop(repo.full_name, None)
                        continue
                    repos_to_scan.append(repo)
                
                if not repos_to_scan:
                    if not self.config.quiet:
                        print(f"     ⚠️  All repositories for team '{team_name}' already processed")
                    continue
                
                # Use batch processing for team repositories if enabled and available
                if self.enable_batch_processing and self.batch_coordinator and len(repos_to_scan) > 1:
                    try:
                        if not self.config.quiet:
                            print(f"     🚀 Using batch processing for {len(repos_to_scan)} repositories")
                        
                        # Use batch processing for this team's repositories
                        file_patterns = self._get_scan_patterns()
                        batch_results = self._run_team_batch_processing(
                            repos_to_scan, 
                            strategy=self._select_batch_strategy(repos_to_scan),
                            file_patterns=file_patterns
                        )
                        
                        # Process batch results
                        for repo_name, matches in batch_results.items():
                            if matches:
                                team_matches.extend(matches)
                            # Count files scanned (approximate)
                            team_files_scanned += len(matches) if matches else 0
                            total_repos_scanned += 1
                            
                            # Update scan state
                            if self.current_scan_state:
                                self.current_scan_state.repositories_scanned = total_repos_scanned
                                self.current_scan_state.files_scanned = total_files_scanned + team_files_scanned
                                
                                # Add to completed repositories
                                if not self.current_scan_state.completed_repositories:
                                    self.current_scan_state.completed_repositories = []
                                self.current_scan_state.completed_repositories.append(repo_name)
                                
                                # Add matches to state
                                if matches:
                                    from .scan_state import add_ioc_match_to_state
                                    for match in matches:
                                        add_ioc_match_to_state(self.current_scan_state, match)
                            
                            # Remove from remaining repositories
                            remaining_repos.pop(repo_name, None)
                        
                        # Scan workflows and secrets for batch-processed repositories
                        # (batch processing only handles IOC matching, not workflow/secrets scanning)
                        team_workflow_findings = []
                        team_secret_findings = []
                        
                        scan_workflows = self.config.scan_workflows and self.workflow_scanner
                        scan_secrets = self.config.scan_secrets and self.secrets_scanner
                        
                        if scan_workflows or scan_secrets:
                            scan_types = []
                            if scan_workflows:
                                scan_types.append("workflows")
                            if scan_secrets:
                                scan_types.append("secrets")
                            
                            if not self.config.quiet:
                                print()  # New line after batch processing progress
                                print(f"     🔍 Scanning {' & '.join(scan_types)} (parallel)...")
                            
                            # Use parallel scanning for better performance
                            team_workflow_findings, team_secret_findings = self._scan_workflows_and_secrets_parallel(
                                repos_to_scan,
                                scan_workflows=scan_workflows,
                                scan_secrets=scan_secrets,
                                max_workers=min(5, len(repos_to_scan))  # Limit workers to avoid rate limiting
                            )
                            
                            if not self.config.quiet:
                                print()  # New line after progress
                        
                        all_workflow_findings.extend(team_workflow_findings)
                        all_secret_findings.extend(team_secret_findings)
                        
                        # Save state after batch processing
                        if self.current_scan_state:
                            self.scan_state_manager.save_state(self.current_scan_state)
                            
                    except Exception as e:
                        logger.warning(f"Batch processing failed for team {team_name}, falling back to sequential: {e}")
                        # Fall back to sequential processing
                        team_matches, team_files_scanned, team_workflow_findings, team_secret_findings = self._scan_team_repositories_sequential(
                            repos_to_scan, team_name, ioc_hash, remaining_repos, total_repos_scanned, total_files_scanned
                        )
                        all_workflow_findings.extend(team_workflow_findings)
                        all_secret_findings.extend(team_secret_findings)
                        total_repos_scanned += len(repos_to_scan)
                else:
                    # Use sequential processing for single repository or when batch processing is disabled
                    team_matches, team_files_scanned, team_workflow_findings, team_secret_findings = self._scan_team_repositories_sequential(
                        repos_to_scan, team_name, ioc_hash, remaining_repos, total_repos_scanned, total_files_scanned
                    )
                    all_workflow_findings.extend(team_workflow_findings)
                    all_secret_findings.extend(team_secret_findings)
                    total_repos_scanned += len(repos_to_scan)
                
                if not self.config.quiet:
                    print()  # New line after progress
                
                # Display team results
                if team_matches:
                    print(f"\n🚨 TEAM '{team_name}' - THREATS DETECTED")
                    print("=" * 60)
                    for match in team_matches:
                        print(f"   ⚠️  {match.repo} | {match.file_path} | {match.package_name} | {match.version}")
                    print(f"Team Summary: {len(team_matches)} threats in {len(team_repos)} repositories")
                else:
                    print(f"\n✅ TEAM '{team_name}' - NO THREATS DETECTED")
                    print(f"Team Summary: {len(team_repos)} repositories scanned, no threats found")
                
                # Accumulate results
                all_matches.extend(team_matches)
                total_files_scanned += team_files_scanned
                
                # Mark team as completed
                if self.current_scan_state:
                    if not self.current_scan_state.completed_teams:
                        self.current_scan_state.completed_teams = []
                    self.current_scan_state.completed_teams.append(team_name)
                    self.scan_state_manager.save_state(self.current_scan_state)
                
            except Exception as e:
                logger.warning(f"Error scanning team {team_name}: {e}")
                continue
        
        # Step 6: Scan remaining repositories not assigned to any team
        remaining_repo_list = list(remaining_repos.values())
        if remaining_repo_list:
            print(f"\n📋 SCANNING REMAINING REPOSITORIES ({len(remaining_repo_list)} repos)")
            print("=" * 60)
            
            remaining_matches = []
            remaining_files_scanned = 0
            
            for i, repo in enumerate(remaining_repo_list, 1):
                if not self.config.quiet:
                    print(f"\r[Remaining] [{i:3d}/{len(remaining_repo_list):3d}] Scanning {repo.full_name}...", end='', flush=True)
                
                matches, files_scanned = self.scan_repository_for_iocs(repo, ioc_hash)
                remaining_matches.extend(matches)
                remaining_files_scanned += files_scanned
                
                # Scan workflows if enabled
                if self.config.scan_workflows and self.workflow_scanner:
                    workflow_findings = self._scan_workflows(repo)
                    all_workflow_findings.extend(workflow_findings)
                    if workflow_findings:
                        logger.info(f"Found {len(workflow_findings)} workflow security issues in {repo.full_name}")
                
                # Scan for secrets if enabled
                if self.config.scan_secrets and self.secrets_scanner:
                    secret_findings = self._scan_secrets(repo)
                    all_secret_findings.extend(secret_findings)
                    if secret_findings:
                        logger.info(f"Found {len(secret_findings)} secrets in {repo.full_name}")
            
            if not self.config.quiet:
                print()  # New line after progress
            
            # Display remaining repositories results
            if remaining_matches:
                print(f"\n🚨 REMAINING REPOSITORIES - THREATS DETECTED")
                print("=" * 60)
                for match in remaining_matches:
                    print(f"   ⚠️  {match.repo} | {match.file_path} | {match.package_name} | {match.version}")
                print(f"Remaining Summary: {len(remaining_matches)} threats in {len(remaining_repo_list)} repositories")
            else:
                print(f"\n✅ REMAINING REPOSITORIES - NO THREATS DETECTED")
                print(f"Remaining Summary: {len(remaining_repo_list)} repositories scanned, no threats found")
            
            # Accumulate final results
            all_matches.extend(remaining_matches)
            total_files_scanned += remaining_files_scanned
            total_repos_scanned += len(remaining_repo_list)
        
        # Log workflow findings summary
        if all_workflow_findings:
            logger.info(f"Found {len(all_workflow_findings)} workflow security issues across all repositories")
        
        # Log secret findings summary
        if all_secret_findings:
            logger.info(f"Found {len(all_secret_findings)} secrets across all repositories")
        
        # Create final results
        end_time = time.time()
        scan_duration = end_time - start_time
        
        return ScanResults(
            matches=all_matches,
            repositories_scanned=total_repos_scanned,
            files_scanned=total_files_scanned,
            cache_stats=self.cache_manager.get_cache_stats() if self.cache_manager else None,
            workflow_findings=all_workflow_findings if all_workflow_findings else None,
            secret_findings=all_secret_findings if all_secret_findings else None
        )

    def _scan_sequential(self) -> ScanResults:
        """Execute scan using sequential processing (original implementation)."""
        import time
        start_time = time.time()
        
        try:
            # Validate configuration
            self._validate_scan_config()
            
            # Load IOC definitions
            logger.info("Loading IOC definitions...")
            try:
                ioc_definitions = self.ioc_loader.load_iocs()
                ioc_hash = self.ioc_loader.get_ioc_hash()
                logger.info(f"Loaded IOC definitions from {len(ioc_definitions)} files")
            except IOCLoaderError:
                raise
            except Exception as e:
                log_exception(logger, "Failed to load IOC definitions", e)
                raise wrap_exception(e, "Failed to load IOC definitions", IOCLoaderError)
            
            # Discover repositories to scan and create scan state
            repositories = []
            scan_type = None
            target = None
            
            try:
                if self.config.org and self.config.team:
                    # Scan team repositories
                    repositories = self.discover_team_repositories(self.config.org, self.config.team)
                    scan_type = 'team'
                    target = self.config.team
                elif self.config.org and self.config.repo:
                    # Scan specific repository
                    repo = Repository(
                        name=self.config.repo,
                        full_name=f"{self.config.org}/{self.config.repo}",
                        archived=False,  # We'll fetch actual data if needed
                        default_branch="main",  # Will be updated when we fetch repo data
                        updated_at=None
                    )
                    repositories = [repo]
                    scan_type = 'repo'
                    target = self.config.repo
                elif self.config.org and self.config.team_first_org:
                    # Team-first organization scan
                    return self._scan_team_first_organization(ioc_hash, start_time)
                elif self.config.org:
                    # Scan organization repositories
                    repositories = self.discover_organization_repositories(self.config.org)
                    scan_type = 'org'
                    target = self.config.org
                else:
                    raise ConfigurationError("Must specify at least --org parameter")
                
                # Create scan state for resumability (except for team-first-org which handles it separately)
                if self.scan_state_manager and scan_type and not self.resume_state:
                    from .scan_state import ScanState
                    
                    config_dict = {
                        'org': self.config.org,
                        'team': getattr(self.config, 'team', None),
                        'repo': getattr(self.config, 'repo', None),
                        'team_first_org': self.config.team_first_org,
                        'enable_sbom': self.config.enable_sbom,
                        'include_archived': self.config.include_archived
                    }
                    
                    self.current_scan_state = self.scan_state_manager.create_scan_state(
                        org=self.config.org,
                        scan_type=scan_type,
                        target=target,
                        config=config_dict
                    )
                    
                    # Update scan state with repository count
                    self.current_scan_state.total_repositories = len(repositories)
                    self.scan_state_manager.save_state(self.current_scan_state)
                    
                    if not self.config.quiet:
                        print(f"💾 Scan ID: {self.current_scan_state.scan_id}")
                        print(f"   (Use --resume {self.current_scan_state.scan_id} to resume if interrupted)")
                elif self.resume_state:
                    # Resuming from previous scan
                    self.current_scan_state = self.resume_state
                    if not self.config.quiet:
                        print(f"🔄 Resuming scan ID: {self.current_scan_state.scan_id}")
                        print(f"   Progress: {self.current_scan_state.repositories_scanned}/{self.current_scan_state.total_repositories} repositories")
                    
                logger.info(f"Found {len(repositories)} repositories to scan")
                
            except (AuthenticationError, IOCLoaderError, ConfigurationError):
                raise
            except Exception as e:
                log_exception(logger, "Failed to discover repositories", e)
                raise wrap_exception(e, "Failed to discover repositories", ScanError)
            
            # Scan repositories for IOCs
            all_matches = []
            all_workflow_findings = []
            all_secret_findings = []
            total_files_scanned = 0
            successful_repos = 0
            failed_repos = 0
            total_repos = len(repositories)
            scan_start_time = start_time  # Use the same start time for ETA calculation
            
            for i, repo in enumerate(repositories, 1):
                try:
                    # Update progress
                    if self.progress_callback:
                        self.progress_callback(i, total_repos, repo.full_name, scan_start_time)
                    
                    logger.info(f"Scanning repository: {repo.full_name}")
                    repo_matches, files_scanned = self.scan_repository_for_iocs(repo, ioc_hash)
                    all_matches.extend(repo_matches)
                    total_files_scanned += files_scanned
                    successful_repos += 1
                    
                    # Scan workflows if enabled
                    if self.config.scan_workflows and self.workflow_scanner:
                        logger.info(f"[WORKFLOW] Scanning workflows in {repo.full_name}...")
                        workflow_findings = self._scan_workflows(repo)
                        all_workflow_findings.extend(workflow_findings)
                        if workflow_findings:
                            logger.info(f"[WORKFLOW] Found {len(workflow_findings)} workflow security issues in {repo.full_name}")
                        else:
                            logger.info(f"[WORKFLOW] No workflow issues found in {repo.full_name}")
                    else:
                        logger.debug(f"[WORKFLOW] Skipping workflow scan for {repo.full_name} (scan_workflows={self.config.scan_workflows}, scanner={self.workflow_scanner is not None})")
                    
                    # Scan for secrets if enabled
                    if self.config.scan_secrets and self.secrets_scanner:
                        logger.info(f"[SECRETS] Scanning secrets in {repo.full_name}...")
                        secret_findings = self._scan_secrets(repo)
                        all_secret_findings.extend(secret_findings)
                        if secret_findings:
                            logger.info(f"[SECRETS] Found {len(secret_findings)} secrets in {repo.full_name}")
                        else:
                            logger.info(f"[SECRETS] No secrets found in {repo.full_name}")
                    else:
                        logger.debug(f"[SECRETS] Skipping secrets scan for {repo.full_name} (scan_secrets={self.config.scan_secrets}, scanner={self.secrets_scanner is not None})")
                    
                    # Update scan state if available
                    if self.current_scan_state and self.scan_state_manager:
                        from .scan_state import add_ioc_match_to_state
                        
                        # Add repository to completed list
                        if self.current_scan_state.completed_repositories is None:
                            self.current_scan_state.completed_repositories = []
                        self.current_scan_state.completed_repositories.append(repo.full_name)
                        
                        # Add matches to state
                        for match in repo_matches:
                            add_ioc_match_to_state(self.current_scan_state, match)
                        
                        # Update progress counters
                        self.current_scan_state.repositories_scanned = successful_repos
                        self.current_scan_state.files_scanned = total_files_scanned
                        self.current_scan_state.last_update = time.time()
                        
                        # Save updated state
                        self.scan_state_manager.save_state(self.current_scan_state)
                    
                    if repo_matches:
                        logger.info(f"Found {len(repo_matches)} IOC matches in {repo.full_name}")
                    else:
                        logger.debug(f"No IOC matches found in {repo.full_name}")
                        
                except Exception as e:
                    failed_repos += 1
                    logger.error(f"Failed to scan repository {repo.full_name}: {e}")
                    # Continue with other repositories instead of failing completely
                    continue
            
            scan_duration = time.time() - start_time
            log_performance(
                logger, "sequential_scan", scan_duration,
                repositories=len(repositories),
                successful=successful_repos,
                failed=failed_repos,
                matches=len(all_matches),
                files=total_files_scanned
            )
            
            if failed_repos > 0:
                logger.warning(f"Scan completed with {failed_repos} failed repositories out of {len(repositories)} total")
            else:
                logger.info(f"Scan completed successfully: {len(all_matches)} total matches found across {total_files_scanned} files")
            
            # Log workflow findings summary
            if all_workflow_findings:
                logger.info(f"Found {len(all_workflow_findings)} workflow security issues across all repositories")
            
            # Log secret findings summary
            if all_secret_findings:
                logger.info(f"Found {len(all_secret_findings)} secrets across all repositories")
            
            return ScanResults(
                matches=all_matches,
                cache_stats=self.cache_manager.get_cache_stats(),
                repositories_scanned=successful_repos,
                files_scanned=total_files_scanned,
                workflow_findings=all_workflow_findings if all_workflow_findings else None,
                secret_findings=all_secret_findings if all_secret_findings else None
            )
            
        except (AuthenticationError, IOCLoaderError, ConfigurationError, ScanError):
            raise
        except Exception as e:
            log_exception(logger, "Unexpected error during scan", e)
            raise wrap_exception(e, "Unexpected error during scan", ScanError)

    def _validate_scan_config(self) -> None:
        """Validate scan configuration parameters."""
        # Team requires organization context
        if self.config.team and not self.config.org:
            raise ConfigurationError("Team scanning requires organization context. Use --org parameter with --team.")
        
        # Repository requires organization context
        if self.config.repo and not self.config.org:
            raise ConfigurationError("Repository scanning requires organization context. Use --org parameter with --repo.")
        
        # Validate issues directory (None means use built-in IOCs)
        if self.config.issues_dir is not None and not self.config.issues_dir.strip():
            raise ConfigurationError("Issues directory path cannot be empty")

    def discover_organization_repositories(self, org: str) -> List[Repository]:
        """Discover all repositories in an organization with incremental caching.
        
        Uses smart incremental fetching:
        - If cache exists, only fetches repos pushed since last cache update
        - Merges new repos with cached repos for complete list
        - Much faster for subsequent scans (only 1-2 API calls vs 10+ for large orgs)
        """
        logger.info(f"Discovering repositories for organization: {org}")
        
        # Check cache first
        use_cache = getattr(self.config, 'use_repo_cache', True)
        cached_data = self.cache_manager.get_repository_metadata(org, team="")
        
        cached_repos = None
        cache_timestamp = None
        
        if cached_data:
            cached_repos, _, cache_timestamp = cached_data
            logger.info(f"📦 Found {len(cached_repos)} cached repositories (cached at {cache_timestamp})")
        
        # If use_cache is False (--refresh-repos), do a full fetch
        if not use_cache:
            cached_repos = None
            cache_timestamp = None
            if not self.config.quiet:
                print(f"   🔄 Refreshing repository list (ignoring cache)...")
        
        # Use GraphQL API with incremental fetching
        # If we have cached repos, only fetch repos pushed since cache_timestamp
        response = self.github_client.get_organization_repos_graphql(
            org, 
            include_archived=self.config.include_archived,
            cached_repos=cached_repos,
            cache_cutoff=cache_timestamp
        )
        
        if response.data:
            repositories = response.data
            # Cache the results for future use
            self.cache_manager.store_repository_metadata(org, repositories, response.etag, team="")
            logger.info(f"Discovered {len(repositories)} repositories for {org}")
        else:
            logger.info(f"No repositories found for organization {org}")
            return []
        
        # Filter archived repositories if not included
        if not self.config.include_archived:
            original_count = len(repositories)
            repositories = [repo for repo in repositories if not repo.archived]
            archived_count = original_count - len(repositories)
            if archived_count > 0:
                logger.info(f"📦 Excluded {archived_count} archived repositories, scanning {len(repositories)} active repositories")
            else:
                logger.debug(f"All {len(repositories)} repositories are active (no archived repos found)")
        
        return repositories
    
    async def discover_organization_repositories_batch(self, org: str) -> List[Repository]:
        """Discover all repositories in an organization using batch processing."""
        logger.info(f"Batch discovering repositories for organization: {org}")
        
        if not self.batch_coordinator:
            # Fallback to sequential discovery
            return self.discover_organization_repositories(org)
        
        try:
            # Use batch coordinator's organization discovery with proper async context
            repositories = await self.batch_coordinator._discover_organization_repositories(
                org, repository_filter=None, max_repositories=None
            )
        except Exception as e:
            logger.warning(f"Batch organization discovery failed, falling back to sequential: {e}")
            # Fall back to sequential discovery if batch fails
            return self.discover_organization_repositories(org)
            
            # Filter archived repositories if not included
            if not self.config.include_archived:
                repositories = [repo for repo in repositories if not repo.archived]
                logger.debug(f"Filtered to {len(repositories)} non-archived repositories")
            
            logger.info(f"Batch discovered {len(repositories)} repositories for {org}")
            
            # If batch discovery returns empty, fallback to sequential
            if not repositories:
                logger.warning(f"Batch discovery returned no repositories, falling back to sequential")
                return self.discover_organization_repositories(org)
            
            return repositories
            
        except Exception as e:
            logger.warning(f"Batch repository discovery failed, falling back to sequential: {e}")
            return self.discover_organization_repositories(org)

    def discover_team_repositories(self, org: str, team: str) -> List[Repository]:
        """Discover repositories belonging to a specific team with caching."""
        logger.info(f"Discovering repositories for team: {org}/{team}")
        
        # Check cache first
        cached_data = self.cache_manager.get_repository_metadata(org, team)
        etag = None
        
        if cached_data:
            repositories, etag, _ = cached_data  # Unpack 3 values: repos, etag, timestamp
            logger.debug(f"Found {len(repositories)} cached repositories for team {org}/{team}")
        
        # Make API request with ETag for conditional request
        response = self.github_client.get_team_repos(org, team, etag=etag)
        
        if response.not_modified and cached_data:
            # Use cached data
            repositories, _, _ = cached_data  # Unpack 3 values: repos, etag, timestamp
            logger.debug(f"Repository list for team {org}/{team} not modified, using cache")
        elif response.data:
            # Update cache with new data
            repositories = response.data
            self.cache_manager.store_repository_metadata(org, repositories, response.etag, team)
            logger.info(f"Discovered {len(repositories)} repositories for team {org}/{team}")
        else:
            logger.info(f"No repositories found for team {org}/{team}")
            return []
        
        # Filter archived repositories if not included (same as organization discovery)
        if not self.config.include_archived:
            original_count = len(repositories)
            repositories = [repo for repo in repositories if not repo.archived]
            archived_count = original_count - len(repositories)
            if archived_count > 0:
                logger.info(f"📦 Excluded {archived_count} archived repositories from team {org}/{team}, scanning {len(repositories)} active repositories")
            else:
                logger.debug(f"All {len(repositories)} repositories in team {org}/{team} are active (no archived repos found)")
        
        return repositories
    
    async def discover_team_repositories_batch(self, org: str, team: str) -> List[Repository]:
        """Discover repositories belonging to a specific team using batch processing."""
        logger.info(f"🔍 Discovering repositories for team: {org}/{team}...")
        
        if not self.batch_coordinator or not self.async_github_client:
            # Fallback to sequential discovery
            return self.discover_team_repositories(org, team)
        
        try:
            # For now, use the async GitHub client directly for team repositories
            # In a full implementation, this would be optimized with batch processing
            repositories = await self._discover_team_repositories_async(org, team)
            
            logger.info(f"✅ Found {len(repositories)} repositories for team {org}/{team}")
            return repositories
            
        except Exception as e:
            logger.warning(f"Batch team repository discovery failed, falling back to sequential: {e}")
            return self.discover_team_repositories(org, team)
    
    async def _discover_team_repositories_async(self, org: str, team: str) -> List[Repository]:
        """Async helper for team repository discovery."""
        # This is a simplified implementation - in practice, this would use
        # the async GitHub client's team repository discovery methods
        # For now, we'll simulate with the existing sync method
        return self.discover_team_repositories(org, team)

    def discover_files_in_repository(self, repo: Repository) -> List[str]:
        """Discover relevant files in a repository using Code Search with Tree API fallback."""
        logger.debug(f"Discovering files in repository: {repo.full_name}")
        
        try:
            files = self.github_client.search_files(
                repo, 
                self.LOCKFILE_PATTERNS, 
                fast_mode=self.config.fast_mode
            )
            
            file_paths = [f.path for f in files]
            logger.debug(f"Found {len(file_paths)} relevant files in {repo.full_name}")
            
            return file_paths
            
        except Exception as e:
            logger.error(f"Failed to discover files in {repo.full_name}: {e}")
            return []
    
    async def discover_files_in_repository_batch(self, repo: Repository) -> List[str]:
        """Discover relevant files in a repository using batch processing."""
        logger.debug(f"Batch discovering files in repository: {repo.full_name}")
        
        if not self.batch_coordinator:
            # Fallback to sequential discovery
            return self.discover_files_in_repository(repo)
        
        try:
            # Use batch coordinator for file discovery (this uses the repaired Tree API logic)
            files = await self.batch_coordinator._discover_repository_files(repo, self.LOCKFILE_PATTERNS)
            
            logger.debug(f"Batch found {len(files)} relevant files in {repo.full_name}")
            
            return files
            
        except Exception as e:
            logger.warning(f"Batch file discovery failed, falling back to sequential: {e}")
            return self.discover_files_in_repository(repo)
    
    async def _discover_files_async(self, repo: Repository) -> List[FileInfo]:
        """Async helper for file discovery."""
        # This is a simplified implementation - in practice, this would use
        # the async GitHub client's file search methods
        # For now, we'll simulate with the existing sync method
        files = self.github_client.search_files(
            repo, 
            self.LOCKFILE_PATTERNS, 
            fast_mode=self.config.fast_mode
        )
        return files
    
    async def discover_files_in_repositories_batch(self, repositories: List[Repository]) -> Dict[str, List[str]]:
        """Discover relevant files across multiple repositories using batch processing."""
        logger.info(f"Batch discovering files across {len(repositories)} repositories")
        
        if not self.batch_coordinator:
            # Fallback to sequential discovery
            result = {}
            for repo in repositories:
                result[repo.full_name] = self.discover_files_in_repository(repo)
            return result
        
        try:
            # Use batch processing for file discovery across repositories
            result = {}
            
            # Process repositories in batches for optimal performance
            batch_size = min(5, len(repositories))  # Process up to 5 repos at once
            
            for i in range(0, len(repositories), batch_size):
                batch_repos = repositories[i:i + batch_size]
                
                # Discover files for this batch of repositories
                batch_tasks = [
                    self.discover_files_in_repository_batch(repo) 
                    for repo in batch_repos
                ]
                
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                # Process results
                for repo, files in zip(batch_repos, batch_results):
                    if isinstance(files, Exception):
                        logger.warning(f"Failed to discover files in {repo.full_name}: {files}")
                        result[repo.full_name] = []
                    else:
                        result[repo.full_name] = files
            
            total_files = sum(len(files) for files in result.values())
            logger.info(f"Batch discovered {total_files} total files across {len(repositories)} repositories")
            
            return result
            
        except Exception as e:
            logger.error(f"Batch file discovery across repositories failed: {e}")
            # Fallback to sequential processing
            result = {}
            for repo in repositories:
                result[repo.full_name] = self.discover_files_in_repository(repo)
            return result

    def scan_organization(self, org: str) -> List[Repository]:
        """Scan all repositories in an organization."""
        return self.discover_organization_repositories(org)

    def scan_team(self, org: str, team: str) -> List[Repository]:
        """Scan repositories belonging to a specific team."""
        return self.discover_team_repositories(org, team)

    def scan_repository_for_iocs(self, repo: Repository, ioc_hash: str) -> tuple[List[IOCMatch], int]:
        """Scan a repository for IOC matches.
        
        Args:
            repo: Repository to scan
            ioc_hash: Hash of IOC definitions for cache invalidation
            
        Returns:
            Tuple of (IOC matches found, number of files scanned)
        """
        try:
            # Check if SBOM-only mode is enabled
            if hasattr(self.config, 'sbom_only') and self.config.sbom_only:
                return self.scan_sbom_files(repo, ioc_hash)
            
            # Check if SBOM scanning is disabled
            if hasattr(self.config, 'disable_sbom') and self.config.disable_sbom:
                return self._scan_lockfiles_only(repo, ioc_hash)
            
            # Default: scan both lockfiles and SBOM files
            if self.enable_sbom_scanning:
                return self.scan_combined_files_for_iocs(repo, ioc_hash)
            else:
                return self._scan_lockfiles_only(repo, ioc_hash)
            
        except AuthenticationError as e:
            logger.warning(f"Access denied to repository {repo.full_name}: {e}")
            return [], 0
        except NetworkError as e:
            logger.warning(f"Network error scanning repository {repo.full_name} (after retries): {e}")
            return [], 0
        except Exception as e:
            logger.error(f"Failed to scan repository {repo.full_name}: {e}")
            return [], 0
    
    def _scan_lockfiles_only(self, repo: Repository, ioc_hash: str) -> tuple[List[IOCMatch], int]:
        """Scan only traditional lockfiles in a repository for IOC matches.
        
        Args:
            repo: Repository to scan
            ioc_hash: Hash of IOC definitions for cache invalidation
            
        Returns:
            Tuple of (IOC matches found, number of files scanned)
        """
        try:
            # Discover relevant lockfiles in the repository
            file_paths = self.discover_files_in_repository(repo)
            
            if not file_paths:
                logger.debug(f"No relevant lockfiles found in {repo.full_name}")
                return [], 0
            
            logger.debug(f"Found {len(file_paths)} lockfiles to scan in {repo.full_name}")
            
            all_matches = []
            files_scanned = 0
            
            for file_path in file_paths:
                try:
                    matches = self.scan_file_for_iocs(repo, file_path, ioc_hash)
                    all_matches.extend(matches)
                    files_scanned += 1
                    
                    if matches:
                        logger.debug(f"Found {len(matches)} IOC matches in {repo.full_name}/{file_path}")
                        
                except Exception as e:
                    logger.warning(f"Failed to scan file {repo.full_name}/{file_path}: {e}")
                    continue
            
            return all_matches, files_scanned
            
        except Exception as e:
            logger.error(f"Failed to scan lockfiles in repository {repo.full_name}: {e}")
            return [], 0

    def scan_file_for_iocs(self, repo: Repository, file_path: str, ioc_hash: str) -> List[IOCMatch]:
        """Scan a single file for IOC matches with caching.
        
        Args:
            repo: Repository containing the file
            file_path: Path to the file within the repository
            ioc_hash: Hash of IOC definitions for cache invalidation
            
        Returns:
            List of IOC matches found in the file
        """
        try:
            # First, get file content with ETag conditional requests
            file_content = self.fetch_file_content_with_cache(repo, file_path)
            
            if not file_content:
                logger.debug(f"Could not fetch content for {repo.full_name}/{file_path}")
                return []
            
            # Check cache for scan results first
            cached_results = self.cache_manager.get_scan_results(
                repo.full_name, file_path, file_content.sha, ioc_hash
            )
            
            if cached_results is not None:
                logger.debug(f"Using cached scan results for {repo.full_name}/{file_path}")
                return cached_results
            
            # Parse packages from file content
            packages = self.parse_packages_with_cache(repo, file_path, file_content)
            
            if not packages:
                # Cache empty results to avoid re-parsing
                self.cache_manager.store_scan_results(
                    repo.full_name, file_path, file_content.sha, ioc_hash, []
                )
                return []
            
            # Match packages against IOC definitions
            matches = self.match_packages_against_iocs(repo, file_path, packages)
            
            # Cache the scan results
            self.cache_manager.store_scan_results(
                repo.full_name, file_path, file_content.sha, ioc_hash, matches
            )
            
            return matches
            
        except Exception as e:
            logger.warning(f"Error scanning file {repo.full_name}/{file_path}: {e}")
            return []

    def fetch_file_content_with_cache(self, repo: Repository, file_path: str) -> Optional[FileContent]:
        """Fetch file content with ETag conditional requests and caching.
        
        Args:
            repo: Repository containing the file
            file_path: Path to the file within the repository
            
        Returns:
            FileContent object if successful, None otherwise
        """
        try:
            # Check if this is an API SBOM file
            if file_path.startswith("__github_api_sbom__"):
                return self._fetch_api_sbom_content(repo, file_path)
            
            # Regular file handling
            # Check if we have cached content first
            # We need the SHA to check cache, so we'll get it from the API response
            
            # Get ETag from cache for conditional request
            etag_key = f"file:{repo.full_name}/{file_path}"
            cached_etag = self.cache_manager.get_etag(etag_key)
            
            # Make API request with conditional ETag
            response = self.github_client.get_file_content(repo, file_path, etag=cached_etag)
            
            if response.not_modified:
                # File hasn't changed, but we need to get cached content
                # Since we don't have SHA from 304 response, we need to handle this differently
                logger.debug(f"File {repo.full_name}/{file_path} not modified, but need cached content")
                # For now, we'll make a fresh request if we get 304 but don't have cached content
                # This is a limitation we can optimize later
                response = self.github_client.get_file_content(repo, file_path)
            
            if not response.data:
                return None
            
            file_content = response.data
            
            # Check cache for existing content with this SHA
            cached_content = self.cache_manager.get_file_content(
                repo.full_name, file_path, file_content.sha
            )
            
            if cached_content is None:
                # Store new content in cache
                self.cache_manager.store_file_content(
                    repo.full_name, file_path, file_content.sha, 
                    file_content.content, response.etag
                )
            
            # Store/update ETag for future conditional requests
            if response.etag:
                self.cache_manager.store_etag(etag_key, response.etag)
            
            return file_content
            
        except Exception as e:
            logger.warning(f"Failed to fetch content for {repo.full_name}/{file_path}: {e}")
            return None

    def parse_packages_with_cache(self, repo: Repository, file_path: str, file_content: FileContent) -> List:
        """Parse packages from file content with caching.
        
        Args:
            repo: Repository containing the file
            file_path: Path to the file within the repository
            file_content: Content of the file to parse
            
        Returns:
            List of PackageDependency objects
        """
        try:
            # Check cache for parsed packages
            cached_packages = self.cache_manager.get_parsed_packages(
                repo.full_name, file_path, file_content.sha
            )
            
            if cached_packages is not None:
                logger.debug(f"Using cached parsed packages for {repo.full_name}/{file_path}")
                return cached_packages
            
            # Parse packages using the safe parser
            try:
                packages = parse_file_safely(file_path, file_content.content)
                
                # Cache the parsed packages
                self.cache_manager.store_parsed_packages(
                    repo.full_name, file_path, file_content.sha, packages
                )
                
                logger.debug(f"Parsed {len(packages)} packages from {repo.full_name}/{file_path}")
                return packages
                
            except UnsupportedFileFormatError:
                # This is expected for unknown file formats - log as debug, not warning
                logger.debug(f"No parser available for {file_path}")
                return []
            except ParsingError as e:
                # Log parsing errors as warnings but continue
                logger.warning(f"Failed to parse {repo.full_name}/{file_path}: {e.message}")
                return []
            
        except Exception as e:
            log_exception(logger, f"Unexpected error parsing packages from {repo.full_name}/{file_path}", e)
            return []

    def match_packages_against_iocs(self, repo: Repository, file_path: str, packages: List) -> List[IOCMatch]:
        """Match parsed packages against IOC definitions.
        
        Args:
            repo: Repository containing the file
            file_path: Path to the file within the repository
            packages: List of PackageDependency objects to check
            
        Returns:
            List of IOCMatch objects for compromised packages found
        """
        matches = []
        
        try:
            # Get all IOC packages
            all_ioc_packages = self.ioc_loader.get_all_packages()
            
            for package in packages:
                if self.ioc_loader.is_package_compromised(package.name, package.version):
                    # Find which IOC definition matched
                    ioc_source = "unknown"
                    for source_file, ioc_def in self.ioc_loader._ioc_definitions.items():
                        if package.name in ioc_def.packages:
                            ioc_source = source_file
                            break
                    
                    match = IOCMatch(
                        repo=repo.full_name,
                        file_path=file_path,
                        package_name=package.name,
                        version=package.version,
                        ioc_source=ioc_source
                    )
                    matches.append(match)
                    
                    logger.debug(f"IOC match: {package.name}@{package.version} in {repo.full_name}/{file_path}")
            
        except Exception as e:
            logger.warning(f"Error matching packages against IOCs for {repo.full_name}/{file_path}: {e}")
        
        return matches

    async def _discover_repositories_batch(self) -> List[Repository]:
        """Discover repositories using batch-optimized methods."""
        repositories = []
        
        logger.info(f"🔍 Repository discovery config: org={self.config.org}, team={self.config.team}, repo={self.config.repo}, team_first_org={self.config.team_first_org}")
        
        if self.config.org and self.config.team:
            # Scan team repositories using batch processing
            logger.info(f"📋 Discovering team repositories: {self.config.org}/{self.config.team}")
            repositories = await self.discover_team_repositories_batch(self.config.org, self.config.team)
            logger.info(f"✅ Team discovery completed: {len(repositories)} repositories")
        elif self.config.org and self.config.repo:
            # Scan specific repository
            logger.info(f"📋 Scanning specific repository: {self.config.org}/{self.config.repo}")
            repo = Repository(
                name=self.config.repo,
                full_name=f"{self.config.org}/{self.config.repo}",
                archived=False,  # We'll fetch actual data if needed
                default_branch="main",  # Will be updated when we fetch repo data
                updated_at=None
            )
            repositories = [repo]
            logger.info(f"✅ Single repository configured: {repo.full_name}")
        elif self.config.org:
            # Use batch processing for organization discovery
            logger.info(f"📋 Discovering organization repositories: {self.config.org}")
            repositories = await self.discover_organization_repositories_batch(self.config.org)
            logger.info(f"✅ Organization discovery completed: {len(repositories)} repositories")
        else:
            raise ConfigurationError("Must specify at least --org parameter")
        
        logger.info(f"🎯 Final repository count: {len(repositories)}")
        
        # Allocate rate limit budgets for intelligent throttling
        if self.async_github_client and repositories:
            repo_names = [repo.full_name for repo in repositories]
            self.async_github_client.allocate_repository_budgets(repo_names)
            logger.info(f"💰 Allocated rate limit budgets for {len(repo_names)} repositories")
        
        return repositories
    
    async def _periodic_budget_redistribution(self) -> None:
        """Periodically redistribute unused rate limit budget between repositories."""
        try:
            redistribution_interval = 300  # 5 minutes default
            if hasattr(self.config, 'budget_redistribution_interval'):
                redistribution_interval = self.config.budget_redistribution_interval
            
            while True:
                await asyncio.sleep(redistribution_interval)
                
                if self.async_github_client:
                    self.async_github_client.redistribute_unused_budget()
                    logger.debug("Redistributed unused rate limit budget")
                    
        except asyncio.CancelledError:
            logger.debug("Budget redistribution task cancelled")
            raise
        except Exception as e:
            logger.warning(f"Error in budget redistribution: {e}")
    
    async def _scan_single_repository_batch(self, repo: Repository, ioc_hash: str) -> List[IOCMatch]:
        """Scan a single repository using batch processing for files."""
        try:
            # Discover files in the repository
            file_paths = self.discover_files_in_repository(repo)
            
            if not file_paths:
                logger.debug(f"No relevant files found in {repo.full_name}")
                return []
            
            # Use batch coordinator to process files with proper async context
            try:
                batch_results = await self.batch_coordinator.process_files_batch(
                    repo, file_paths, priority_files=self._get_priority_files(file_paths)
                )
            except Exception as e:
                logger.error(f"Error during batch file processing for {repo.full_name}: {e}")
                # Fall back to sequential processing if batch fails
                return self.scan_repository_for_iocs(repo, ioc_hash)[0]
            
            # Process batch results to find IOC matches
            all_matches = []
            for file_path, file_data in batch_results.items():
                if file_data and 'content' in file_data:
                    # Parse packages and check for IOCs
                    matches = await self._process_file_for_iocs_batch(
                        repo, file_path, file_data['content'], ioc_hash
                    )
                    all_matches.extend(matches)
            
            return all_matches
            
        except Exception as e:
            logger.error(f"Failed to batch scan repository {repo.full_name}: {e}")
            return []
    
    def _get_priority_files(self, file_paths: List[str]) -> List[str]:
        """Identify priority files from the list of file paths."""
        priority_patterns = [
            'package.json', 'requirements.txt', 'go.mod', 'Cargo.toml',
            'composer.json', 'Gemfile', 'pyproject.toml'
        ]
        
        priority_files = []
        for file_path in file_paths:
            file_name = file_path.split('/')[-1]  # Get filename from path
            if file_name in priority_patterns:
                priority_files.append(file_path)
        
        return priority_files
    
    async def _process_file_for_iocs_batch(
        self, 
        repo: Repository, 
        file_path: str, 
        content: str, 
        ioc_hash: str
    ) -> List[IOCMatch]:
        """Process a single file for IOC matches in batch context."""
        try:
            # Parse packages from file content
            packages = parse_file_safely(file_path, content)
            
            if not packages:
                return []
            
            # Match packages against IOC definitions
            matches = self.match_packages_against_iocs(repo, file_path, packages)
            return matches
            
        except Exception as e:
            logger.warning(f"Error processing file {repo.full_name}/{file_path} in batch: {e}")
            return []
    
    def _select_batch_strategy(self, repositories: List[Repository]) -> BatchStrategy:
        """Select appropriate batch strategy based on scan characteristics."""
        repo_count = len(repositories)
        
        # Use conservative strategy for team scans to avoid rate limiting issues
        if self.config.team and repo_count > 20:
            logger.info(f"Using conservative strategy for team scan with {repo_count} repositories")
            return BatchStrategy.CONSERVATIVE
        elif repo_count == 1:
            return BatchStrategy.PARALLEL  # Use parallel for single repo file processing
        elif repo_count <= 5:
            return BatchStrategy.ADAPTIVE  # Balanced approach for small sets
        elif repo_count <= 20:
            return BatchStrategy.PARALLEL  # Parallel processing for medium sets
        else:
            return BatchStrategy.AGGRESSIVE  # Aggressive batching for large sets
    
    async def execute_end_to_end_batch_scan(
        self, 
        workflow_config: Optional[Dict[str, Any]] = None
    ) -> ScanResults:
        """Execute a complete end-to-end batch scanning workflow.
        
        Args:
            workflow_config: Optional workflow configuration
            
        Returns:
            Complete scan results with batch processing metrics
        """
        import time
        start_time = time.time()
        
        workflow_config = workflow_config or {}
        
        try:
            # Validate configuration
            self._validate_scan_config()
            
            # Load IOC definitions
            logger.info("Loading IOC definitions for batch workflow...")
            ioc_definitions = self.ioc_loader.load_iocs()
            ioc_hash = self.ioc_loader.get_ioc_hash()
            logger.info(f"Loaded IOC definitions from {len(ioc_definitions)} files")
            
            if not self.batch_coordinator:
                raise ConfigurationError("Batch coordinator not available for end-to-end workflow")
            
            # Start batch coordinator
            await self.batch_coordinator.start()
            
            try:
                # Phase 1: Repository Discovery with Batch Optimization
                logger.info("Phase 1: Batch repository discovery and optimization")
                repositories = await self._discover_repositories_batch()
                
                if not repositories:
                    logger.info("No repositories found for batch scanning")
                    return ScanResults(
                        matches=[],
                        cache_stats=self.cache_manager.get_cache_stats(),
                        repositories_scanned=0,
                        files_scanned=0
                    )
                
                logger.info(f"Discovered {len(repositories)} repositories for batch processing")
                
                # Phase 2: File Discovery Across All Repositories
                logger.info("Phase 2: Batch file discovery across repositories")
                repository_files = await self.discover_files_in_repositories_batch(repositories)
                
                total_files = sum(len(files) for files in repository_files.values())
                logger.info(f"Discovered {total_files} total files across {len(repositories)} repositories")
                
                # Phase 3: Execute End-to-End Batch Workflow
                logger.info("Phase 3: Executing comprehensive batch workflow")
                
                # Configure workflow parameters
                workflow_params = {
                    'scan_pattern': workflow_config.get('scan_pattern', 'security_scan'),
                    'enable_progress_tracking': workflow_config.get('enable_progress_tracking', True),
                    'enable_performance_monitoring': workflow_config.get('enable_performance_monitoring', True),
                    'file_patterns': self.LOCKFILE_PATTERNS
                }
                
                # Execute the comprehensive batch workflow
                batch_results = await self.batch_coordinator.execute_end_to_end_batch_workflow(
                    repositories, workflow_params
                )
                
                # Phase 4: Process Results and Generate IOC Matches
                logger.info("Phase 4: Processing batch results and generating IOC matches")
                all_matches = await self._process_batch_results_for_iocs(
                    batch_results['processing_results'], ioc_hash
                )
                
                # Phase 5: Compile Comprehensive Results
                logger.info("Phase 5: Compiling comprehensive scan results")
                
                scan_duration = time.time() - start_time
                successful_repos = len([repo for repo, matches in batch_results['processing_results'].items() if matches])
                
                # Get comprehensive metrics
                batch_metrics = self.batch_coordinator.get_batch_metrics()
                
                # Log comprehensive performance information
                log_performance(
                    logger, "end_to_end_batch_scan", scan_duration,
                    repositories=len(repositories),
                    successful=successful_repos,
                    failed=len(repositories) - successful_repos,
                    matches=len(all_matches),
                    files=total_files,
                    cache_hit_rate=batch_metrics.cache_hit_rate,
                    parallel_efficiency=batch_metrics.parallel_efficiency,
                    api_calls_saved=batch_metrics.api_calls_saved
                )
                
                logger.info(
                    f"End-to-end batch scan completed: {len(all_matches)} IOC matches found, "
                    f"{batch_metrics.cache_hit_rate:.1f}% cache hit rate, "
                    f"{batch_metrics.parallel_efficiency:.2f} parallel efficiency, "
                    f"{batch_metrics.api_calls_saved} API calls saved"
                )
                
                return ScanResults(
                    matches=all_matches,
                    cache_stats=self.cache_manager.get_cache_stats(),
                    repositories_scanned=successful_repos,
                    files_scanned=total_files
                )
                
            finally:
                # Always stop batch coordinator
                await self.batch_coordinator.stop()
                
        except Exception as e:
            log_exception(logger, "End-to-end batch scan failed", e)
            raise wrap_exception(e, "End-to-end batch scan failed", ScanError)
    
    async def _process_batch_results_for_iocs(
        self, 
        batch_results: Dict[str, List[IOCMatch]], 
        ioc_hash: str
    ) -> List[IOCMatch]:
        """Process batch results to extract and validate IOC matches.
        
        Args:
            batch_results: Results from batch processing
            ioc_hash: Hash of IOC definitions for validation
            
        Returns:
            List of validated IOC matches
        """
        all_matches = []
        
        for repo_name, matches in batch_results.items():
            if matches:
                # Validate and add matches
                for match in matches:
                    # Ensure match is properly formatted and valid
                    if isinstance(match, IOCMatch):
                        all_matches.append(match)
                    else:
                        logger.warning(f"Invalid match format in {repo_name}: {match}")
        
        logger.debug(f"Processed {len(all_matches)} total IOC matches from batch results")
        return all_matches
    
    async def execute_organization_batch_scan(
        self, 
        organization: str,
        scan_config: Optional[Dict[str, Any]] = None
    ) -> ScanResults:
        """Execute a complete batch scan for an entire organization.
        
        Args:
            organization: Organization name to scan
            scan_config: Optional scan configuration overrides
            
        Returns:
            Complete scan results for the organization
        """
        logger.info(f"Starting organization batch scan for: {organization}")
        
        # Update configuration for organization scan
        original_org = self.config.org
        self.config.org = organization
        
        try:
            # Configure workflow for organization scanning
            workflow_config = {
                'scan_pattern': 'organization_security_scan',
                'enable_progress_tracking': True,
                'enable_performance_monitoring': True,
                'repository_filter': scan_config.get('repository_filter') if scan_config else None,
                'max_repositories': scan_config.get('max_repositories') if scan_config else None
            }
            
            # Execute end-to-end batch scan
            results = await self.execute_end_to_end_batch_scan(workflow_config)
            
            logger.info(f"Organization batch scan completed for {organization}: "
                       f"{len(results.matches)} matches found across "
                       f"{results.repositories_scanned} repositories")
            
            return results
            
        finally:
            # Restore original configuration
            self.config.org = original_org
    
    async def execute_team_batch_scan(
        self, 
        organization: str, 
        team: str,
        scan_config: Optional[Dict[str, Any]] = None
    ) -> ScanResults:
        """Execute a complete batch scan for a specific team.
        
        Args:
            organization: Organization name
            team: Team name to scan
            scan_config: Optional scan configuration overrides
            
        Returns:
            Complete scan results for the team
        """
        logger.info(f"Starting team batch scan for: {organization}/{team}")
        
        # Store original configuration
        original_org = self.config.org
        original_team = self.config.team
        
        try:
            # Update configuration for team scan
            self.config.org = organization
            self.config.team = team
            
            # Configure workflow for team scanning
            workflow_config = {
                'scan_pattern': 'team_security_scan',
                'enable_progress_tracking': True,
                'enable_performance_monitoring': True
            }
            
            # Execute end-to-end batch scan
            results = await self.execute_end_to_end_batch_scan(workflow_config)
            
            logger.info(f"Team batch scan completed for {organization}/{team}: "
                       f"{len(results.matches)} matches found across "
                       f"{results.repositories_scanned} repositories")
            
            return results
            
        finally:
            # Restore original configuration
            self.config.org = original_org
            self.config.team = original_team
    
    async def execute_repository_batch_scan(
        self, 
        organization: str, 
        repository: str,
        scan_config: Optional[Dict[str, Any]] = None
    ) -> ScanResults:
        """Execute a complete batch scan for a specific repository.
        
        Args:
            organization: Organization name
            repository: Repository name to scan
            scan_config: Optional scan configuration overrides
            
        Returns:
            Complete scan results for the repository
        """
        logger.info(f"Starting repository batch scan for: {organization}/{repository}")
        
        # Store original configuration
        original_org = self.config.org
        original_repo = self.config.repo
        
        try:
            # Update configuration for repository scan
            self.config.org = organization
            self.config.repo = repository
            
            # Configure workflow for repository scanning
            workflow_config = {
                'scan_pattern': 'repository_security_scan',
                'enable_progress_tracking': True,
                'enable_performance_monitoring': True,
                'focus_on_priority_files': scan_config.get('focus_on_priority_files', True) if scan_config else True
            }
            
            # Execute end-to-end batch scan
            results = await self.execute_end_to_end_batch_scan(workflow_config)
            
            logger.info(f"Repository batch scan completed for {organization}/{repository}: "
                       f"{len(results.matches)} matches found across "
                       f"{results.files_scanned} files")
            
            return results
            
        finally:
            # Restore original configuration
            self.config.org = original_org
            self.config.repo = original_repo

    def scan_repository(self, org: str, repo: str) -> List[IOCMatch]:
        """Scan a specific repository for IOCs."""
        repo_obj = Repository(
            name=repo,
            full_name=f"{org}/{repo}",
            archived=False,
            default_branch="main",
            updated_at=None
        )
        
        try:
            # Load IOC definitions
            ioc_definitions = self.ioc_loader.load_iocs()
            ioc_hash = self.ioc_loader.get_ioc_hash()
            
            matches, _ = self.scan_repository_for_iocs(repo_obj, ioc_hash)
            return matches
            
        except Exception as e:
            logger.error(f"Failed to scan repository {org}/{repo}: {e}")
            return []
    
    def _setup_batch_progress_monitoring(self) -> None:
        """Setup batch progress monitoring to integrate with CLI progress callback."""
        if not self.batch_coordinator or not self.progress_callback:
            return
        
        # Create a wrapper function that converts batch progress to CLI progress format
        def batch_progress_callback(snapshot):
            """Convert batch progress snapshot to CLI progress callback format."""
            try:
                # Calculate progress information
                current = snapshot.completed_operations
                total = snapshot.total_operations
                
                # Create a repository name for display (use operation type if no specific repo)
                current_repo = getattr(snapshot, 'current_repository', 'batch_operation')
                
                # Get start time from the progress monitor and convert to timestamp
                start_time = self.batch_coordinator.progress_monitor.start_time
                start_timestamp = start_time.timestamp() if start_time else None
                
                # Call the original CLI progress callback
                self.progress_callback(current, total, current_repo, start_timestamp)
                
            except Exception as e:
                logger.warning(f"Error in batch progress callback: {e}")
        
        # Configure the batch coordinator's progress monitor with our callback
        self.batch_coordinator.progress_monitor.progress_callback = batch_progress_callback
        
        logger.debug("Batch progress monitoring configured with CLI integration") 
   
    # SBOM-specific scanning methods
    
    def scan_sbom_files(self, repo: Repository, ioc_hash: str) -> tuple[List[IOCMatch], int]:
        """Scan SBOM files in a repository for IOC matches.
        
        Args:
            repo: Repository to scan
            ioc_hash: Hash of IOC definitions for cache invalidation
            
        Returns:
            Tuple of (IOC matches found, number of SBOM files scanned)
        """
        try:
            # Discover SBOM files in the repository
            sbom_files = self.discover_sbom_files_in_repository(repo)
            
            if not sbom_files:
                logger.debug(f"No SBOM files found in {repo.full_name}")
                return [], 0
            
            logger.debug(f"Found {len(sbom_files)} SBOM files to scan in {repo.full_name}")
            
            all_matches = []
            files_scanned = 0
            
            for file_path in sbom_files:
                try:
                    matches = self.scan_sbom_file_for_iocs(repo, file_path, ioc_hash)
                    all_matches.extend(matches)
                    files_scanned += 1
                    
                    if matches:
                        logger.debug(f"Found {len(matches)} IOC matches in SBOM {repo.full_name}/{file_path}")
                        
                except Exception as e:
                    logger.warning(f"Failed to scan SBOM file {repo.full_name}/{file_path}: {e}")
                    continue
            
            return all_matches, files_scanned
            
        except Exception as e:
            logger.error(f"Failed to scan SBOM files in repository {repo.full_name}: {e}")
            return [], 0
    
    def discover_sbom_files_in_repository(self, repo: Repository) -> List[str]:
        """Discover SBOM files in a repository (both in-repo files and GitHub API SBOM)."""
        logger.debug(f"Discovering SBOM files in repository: {repo.full_name}")
        
        file_paths = []
        
        try:
            # 1. Search for SBOM files in the repository
            files = self.github_client.search_files(
                repo, 
                self.SBOM_PATTERNS, 
                fast_mode=self.config.fast_mode
            )
            
            repo_sbom_paths = [f.path for f in files]
            file_paths.extend(repo_sbom_paths)
            
            if repo_sbom_paths:
                logger.debug(f"Found {len(repo_sbom_paths)} SBOM files in repository: {repo_sbom_paths}")
            
            # 2. Try to get SBOM from GitHub Dependency Graph API
            try:
                sbom_content = self.github_client.get_sbom(repo)
                if sbom_content:
                    # Use a special path to indicate this is from the API
                    api_sbom_path = f"__github_api_sbom__.json"
                    file_paths.append(api_sbom_path)
                    
                    # Cache the SBOM content for later retrieval
                    self._cache_api_sbom(repo, api_sbom_path, sbom_content)
                    
                    logger.debug(f"Downloaded SBOM from GitHub API for {repo.full_name}")
                else:
                    logger.debug(f"No SBOM available via GitHub API for {repo.full_name}")
                    
            except Exception as e:
                logger.debug(f"Could not fetch SBOM via GitHub API for {repo.full_name}: {e}")
            
            logger.debug(f"Found {len(file_paths)} total SBOM sources in {repo.full_name}")
            return file_paths
            
        except Exception as e:
            logger.error(f"Failed to discover SBOM files in {repo.full_name}: {e}")
            return []
    
    async def discover_sbom_files_in_repository_batch(self, repo: Repository) -> List[str]:
        """Discover SBOM files in a repository using batch processing."""
        logger.debug(f"Batch discovering SBOM files in repository: {repo.full_name}")
        
        if not self.batch_coordinator:
            # Fallback to sequential discovery
            return self.discover_sbom_files_in_repository(repo)
        
        try:
            # Use batch coordinator for SBOM file discovery
            files = await self.batch_coordinator._discover_repository_files(repo, self.SBOM_PATTERNS)
            
            logger.debug(f"Batch found {len(files)} SBOM files in {repo.full_name}")
            
            return files
            
        except Exception as e:
            logger.warning(f"Batch SBOM file discovery failed, falling back to sequential: {e}")
            return self.discover_sbom_files_in_repository(repo)
    
    def scan_sbom_file_for_iocs(self, repo: Repository, file_path: str, ioc_hash: str) -> List[IOCMatch]:
        """Scan a single SBOM file for IOC matches with caching.
        
        Args:
            repo: Repository containing the SBOM file
            file_path: Path to the SBOM file within the repository
            ioc_hash: Hash of IOC definitions for cache invalidation
            
        Returns:
            List of IOC matches found in the SBOM file
        """
        try:
            # First, get file content with ETag conditional requests
            file_content = self.fetch_file_content_with_cache(repo, file_path)
            
            if not file_content:
                logger.debug(f"Could not fetch SBOM content for {repo.full_name}/{file_path}")
                return []
            
            # Check cache for SBOM scan results first
            cache_key = f"sbom:{repo.full_name}:{file_path}"
            cached_results = self.cache_manager.get_scan_results(
                cache_key, file_path, file_content.sha, ioc_hash
            )
            
            if cached_results is not None:
                logger.debug(f"Using cached SBOM scan results for {repo.full_name}/{file_path}")
                return cached_results
            
            # Parse packages from SBOM content
            packages = self.parse_sbom_packages_with_cache(repo, file_path, file_content)
            
            if not packages:
                # Cache empty results to avoid re-parsing
                self.cache_manager.store_scan_results(
                    cache_key, file_path, file_content.sha, ioc_hash, []
                )
                return []
            
            # Match packages against IOC definitions
            matches = self.match_packages_against_iocs(repo, file_path, packages)
            
            # Cache the SBOM scan results
            self.cache_manager.store_scan_results(
                cache_key, file_path, file_content.sha, ioc_hash, matches
            )
            
            return matches
            
        except Exception as e:
            logger.warning(f"Error scanning SBOM file {repo.full_name}/{file_path}: {e}")
            return []
    
    def parse_sbom_packages_with_cache(self, repo: Repository, file_path: str, file_content: FileContent) -> List[PackageDependency]:
        """Parse packages from SBOM file content with caching.
        
        Args:
            repo: Repository containing the file
            file_path: Path to the file within the repository
            file_content: File content object
            
        Returns:
            List of Package objects parsed from the SBOM
        """
        try:
            # Check cache for parsed packages first
            cache_key = f"sbom_packages:{repo.full_name}:{file_path}"
            cached_packages = self.cache_manager.get_parsed_packages(cache_key, file_path, file_content.sha)
            
            if cached_packages is not None:
                logger.debug(f"Using cached SBOM packages for {repo.full_name}/{file_path}")
                return cached_packages
            
            # Parse SBOM file using SBOM parser
            from .parsers.sbom import SBOMParser
            parser = SBOMParser()
            
            if not parser.can_parse(file_path):
                logger.debug(f"File {file_path} is not recognized as an SBOM file")
                return []
            
            packages = parser.parse(file_content.content, file_path)
            
            # Cache the parsed packages
            self.cache_manager.store_parsed_packages(cache_key, file_path, file_content.sha, packages)
            
            logger.debug(f"Parsed {len(packages)} packages from SBOM {repo.full_name}/{file_path}")
            
            return packages
            
        except Exception as e:
            logger.warning(f"Error parsing SBOM packages from {repo.full_name}/{file_path}: {e}")
            return []
    
    def scan_combined_files_for_iocs(self, repo: Repository, ioc_hash: str) -> tuple[List[IOCMatch], int]:
        """Scan both lockfiles and SBOM files in a repository for IOC matches.
        
        Args:
            repo: Repository to scan
            ioc_hash: Hash of IOC definitions for cache invalidation
            
        Returns:
            Tuple of (IOC matches found, number of files scanned)
        """
        try:
            all_matches = []
            total_files_scanned = 0
            
            # Scan traditional lockfiles
            lockfile_matches, lockfiles_scanned = self._scan_lockfiles_only(repo, ioc_hash)
            all_matches.extend(lockfile_matches)
            total_files_scanned += lockfiles_scanned
            
            # Scan SBOM files if enabled
            if self.enable_sbom_scanning:
                sbom_matches, sbom_files_scanned = self.scan_sbom_files(repo, ioc_hash)
                all_matches.extend(sbom_matches)
                total_files_scanned += sbom_files_scanned
                
                logger.debug(f"Combined scan of {repo.full_name}: "
                           f"{lockfiles_scanned} lockfiles + {sbom_files_scanned} SBOM files = "
                           f"{total_files_scanned} total files, {len(all_matches)} matches")
            
            return all_matches, total_files_scanned
            
        except Exception as e:
            logger.error(f"Failed to scan combined files in repository {repo.full_name}: {e}")
            return [], 0
    
    def get_sbom_scan_statistics(self) -> Dict[str, Any]:
        """Get statistics about SBOM scanning from cache."""
        try:
            cache_stats = self.cache_manager.get_cache_stats()
            
            # Extract SBOM-specific statistics
            sbom_stats = {
                'sbom_files_cached': 0,
                'sbom_packages_cached': 0,
                'sbom_scan_results_cached': 0,
                'sbom_cache_hit_rate': 0.0
            }
            
            # Count SBOM-related cache entries
            if hasattr(cache_stats, 'cache_entries'):
                for key in cache_stats.cache_entries:
                    if key.startswith('sbom:'):
                        if 'packages' in key:
                            sbom_stats['sbom_packages_cached'] += 1
                        else:
                            sbom_stats['sbom_scan_results_cached'] += 1
            
            return sbom_stats
            
        except Exception as e:
            logger.warning(f"Failed to get SBOM scan statistics: {e}")
            return {}
    
    def _cache_api_sbom(self, repo: Repository, sbom_path: str, sbom_content: str) -> None:
        """Cache SBOM content downloaded from GitHub API."""
        try:
            # Store in a simple in-memory cache for this scan session
            if not hasattr(self, '_api_sbom_cache'):
                self._api_sbom_cache = {}
            
            cache_key = f"{repo.full_name}:{sbom_path}"
            self._api_sbom_cache[cache_key] = sbom_content
            
            logger.debug(f"Cached API SBOM for {repo.full_name}")
            
        except Exception as e:
            logger.warning(f"Failed to cache API SBOM for {repo.full_name}: {e}")
    
    def _get_cached_api_sbom(self, repo: Repository, sbom_path: str) -> Optional[str]:
        """Retrieve cached SBOM content from GitHub API."""
        try:
            if not hasattr(self, '_api_sbom_cache'):
                return None
            
            cache_key = f"{repo.full_name}:{sbom_path}"
            return self._api_sbom_cache.get(cache_key)
            
        except Exception as e:
            logger.warning(f"Failed to retrieve cached API SBOM for {repo.full_name}: {e}")
            return None
    
    def _fetch_api_sbom_content(self, repo: Repository, sbom_path: str) -> Optional[FileContent]:
        """Fetch SBOM content from cached API download."""
        try:
            # Get cached SBOM content
            sbom_content = self._get_cached_api_sbom(repo, sbom_path)
            
            if not sbom_content:
                logger.debug(f"No cached API SBOM content for {repo.full_name}")
                return None
            
            # Create a FileContent object for the API SBOM
            # Use a hash of the content as SHA since we don't have a real git SHA
            import hashlib
            content_hash = hashlib.sha256(sbom_content.encode('utf-8')).hexdigest()
            
            file_content = FileContent(
                content=sbom_content,
                sha=content_hash,
                size=len(sbom_content)
            )
            
            logger.debug(f"Retrieved API SBOM content for {repo.full_name} ({len(sbom_content)} bytes)")
            return file_content
            
        except Exception as e:
            logger.warning(f"Failed to fetch API SBOM content for {repo.full_name}: {e}")
            return None
    
    def _scan_workflows(self, repo: Repository) -> List[WorkflowFinding]:
        """Scan GitHub Actions workflows in a repository for security issues.
        
        Args:
            repo: Repository to scan
            
        Returns:
            List of WorkflowFinding objects for detected security issues
        """
        if not self.workflow_scanner:
            return []
        
        findings: List[WorkflowFinding] = []
        
        try:
            # Discover workflow files in .github/workflows/
            workflow_files = self._discover_workflow_files(repo)
            
            if not workflow_files:
                logger.debug(f"No workflow files found in {repo.full_name}")
                return []
            
            logger.debug(f"Found {len(workflow_files)} workflow files in {repo.full_name}")
            
            for file_path in workflow_files:
                try:
                    # Fetch workflow file content
                    file_content = self.fetch_file_content_with_cache(repo, file_path)
                    
                    if not file_content:
                        logger.debug(f"Could not fetch workflow content for {repo.full_name}/{file_path}")
                        continue
                    
                    # Scan the workflow file
                    file_findings = self.workflow_scanner.scan_workflow_file(
                        repo.full_name, file_path, file_content.content
                    )
                    findings.extend(file_findings)
                    
                    if file_findings:
                        logger.info(f"Found {len(file_findings)} workflow security issues in {repo.full_name}/{file_path}")
                        
                except Exception as e:
                    logger.warning(f"Failed to scan workflow {repo.full_name}/{file_path}: {e}")
                    continue
            
            return findings
            
        except Exception as e:
            logger.warning(f"Failed to scan workflows in {repo.full_name}: {e}")
            return []
    
    def _discover_workflow_files(self, repo: Repository) -> List[str]:
        """Discover GitHub Actions workflow files in a repository.
        
        Args:
            repo: Repository to search
            
        Returns:
            List of workflow file paths
        """
        try:
            # Get the repository tree and filter for workflow files
            tree_response = self.github_client.get_tree(repo)
            if not tree_response.data:
                logger.debug(f"No tree data available for {repo.full_name}")
                return []
            
            logger.debug(f"Repository {repo.full_name} has {len(tree_response.data)} files in tree")
            
            workflow_files = []
            for file_info in tree_response.data:
                file_path = file_info.path
                # Check if file is in .github/workflows/ and is a YAML file
                if self.workflow_scanner.is_workflow_file(file_path):
                    workflow_files.append(file_path)
                    logger.debug(f"Found workflow file: {file_path}")
            
            if workflow_files:
                logger.info(f"Discovered {len(workflow_files)} workflow files in {repo.full_name}")
            
            return workflow_files
            
        except Exception as e:
            logger.warning(f"Failed to discover workflow files in {repo.full_name}: {e}")
            return []
    
    def _scan_secrets(self, repo: Repository) -> List[SecretFinding]:
        """Scan repository for Shai-Hulud exfiltration artifacts.
        
        This is an optimized scan that focuses on detecting Shai-Hulud attack
        artifacts (cloud.json, environment.json, etc.) rather than scanning
        all files for secrets. This makes the scan much faster while still
        detecting the most critical supply chain attack indicators.
        
        Args:
            repo: Repository to scan
            
        Returns:
            List of SecretFinding objects for detected Shai-Hulud artifacts
        """
        if not self.secrets_scanner:
            return []
        
        findings: List[SecretFinding] = []
        
        try:
            # Get the repository tree
            tree_response = self.github_client.get_tree(repo)
            if not tree_response.data:
                logger.debug(f"No tree data available for secrets scan in {repo.full_name}")
                return []
            
            # Only scan for Shai-Hulud artifact files (fast scan)
            shai_hulud_files = []
            for file_info in tree_response.data:
                # Skip directories
                if not hasattr(file_info, 'size') or file_info.size is None:
                    continue
                
                # Check if file is a Shai-Hulud artifact
                if self.secrets_scanner.is_shai_hulud_artifact(file_info.path):
                    shai_hulud_files.append(file_info)
            
            if not shai_hulud_files:
                logger.debug(f"No Shai-Hulud artifacts found in {repo.full_name}")
                return []
            
            logger.warning(f"⚠️ Found {len(shai_hulud_files)} potential Shai-Hulud artifacts in {repo.full_name}")
            
            for file_info in shai_hulud_files:
                try:
                    # Report the artifact without fetching content (the presence is enough)
                    file_findings = self.secrets_scanner._check_shai_hulud_artifacts(
                        repo.full_name, file_info.path
                    )
                    findings.extend(file_findings)
                    
                    if file_findings:
                        logger.warning(f"🚨 Shai-Hulud artifact detected: {repo.full_name}/{file_info.path}")
                        
                except Exception as e:
                    logger.warning(f"Failed to check artifact {repo.full_name}/{file_info.path}: {e}")
                    continue
            
            return findings
            
        except Exception as e:
            logger.warning(f"Failed to scan for Shai-Hulud artifacts in {repo.full_name}: {e}")
            return []

    def _scan_workflows_and_secrets_parallel(
        self, 
        repos: List[Repository],
        scan_workflows: bool = True,
        scan_secrets: bool = True,
        max_workers: int = 5
    ) -> tuple[List[WorkflowFinding], List[SecretFinding]]:
        """Scan workflows and secrets across multiple repositories in parallel.
        
        Uses ThreadPoolExecutor for parallel processing to speed up scanning.
        
        Args:
            repos: List of repositories to scan
            scan_workflows: Whether to scan for workflow security issues
            scan_secrets: Whether to scan for secrets
            max_workers: Maximum number of parallel workers
            
        Returns:
            Tuple of (workflow_findings, secret_findings)
        """
        import concurrent.futures
        
        all_workflow_findings: List[WorkflowFinding] = []
        all_secret_findings: List[SecretFinding] = []
        
        if not repos or (not scan_workflows and not scan_secrets):
            return all_workflow_findings, all_secret_findings
        
        def scan_repo(repo: Repository) -> tuple[List[WorkflowFinding], List[SecretFinding]]:
            """Scan a single repository for workflows and secrets."""
            workflow_findings = []
            secret_findings = []
            
            try:
                if scan_workflows and self.workflow_scanner:
                    workflow_findings = self._scan_workflows(repo)
                    
                if scan_secrets and self.secrets_scanner:
                    secret_findings = self._scan_secrets(repo)
            except Exception as e:
                logger.warning(f"Error scanning {repo.full_name}: {e}")
            
            return workflow_findings, secret_findings
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_repo = {
                executor.submit(scan_repo, repo): repo 
                for repo in repos
            }
            
            # Process results as they complete
            completed = 0
            total = len(repos)
            
            for future in concurrent.futures.as_completed(future_to_repo):
                repo = future_to_repo[future]
                completed += 1
                
                if not self.config.quiet:
                    print(f"\r     [{completed:3d}/{total:3d}] {repo.full_name[:50]:<50}", end='', flush=True)
                
                try:
                    workflow_findings, secret_findings = future.result()
                    all_workflow_findings.extend(workflow_findings)
                    all_secret_findings.extend(secret_findings)
                    
                    if workflow_findings:
                        logger.info(f"Found {len(workflow_findings)} workflow issues in {repo.full_name}")
                    if secret_findings:
                        logger.info(f"Found {len(secret_findings)} secrets in {repo.full_name}")
                        
                except Exception as e:
                    logger.warning(f"Failed to get results for {repo.full_name}: {e}")
        
        return all_workflow_findings, all_secret_findings
