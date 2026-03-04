"""Central batch coordinator for orchestrating all batch operations."""

import asyncio
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .async_github_client import AsyncGitHubClient
from .batch_cache_coordinator import BatchCacheCoordinator
from .batch_models import (
    BatchConfig, BatchMetrics, BatchRequest, BatchResult, BatchStrategy,
    CrossRepoBatch, NetworkConditions, PrioritizedFile
)
from .batch_strategy_manager import BatchStrategyManager
from .batch_progress_monitor import BatchProgressMonitor
from .cache_manager import CacheManager
from .exceptions import BatchProcessingError, ConfigurationError, RateLimitError
from .logging_config import get_logger, log_user_message, log_exception_with_user_message
from .models import Repository, IOCMatch
from .parallel_batch_processor import ParallelBatchProcessor
from .rate_limit_manager import RateLimitManager as BatchRateLimitManager
from .error_message_formatter import ErrorMessageFormatter

logger = get_logger(__name__)


class BatchCoordinator:
    """Central coordinator for all batch operations with unified interface."""
    
    def __init__(
        self,
        github_client: AsyncGitHubClient,
        cache_manager: CacheManager,
        config: Optional[BatchConfig] = None
    ):
        """Initialize the batch coordinator.
        
        Args:
            github_client: Async GitHub client for API requests
            cache_manager: Cache manager for caching operations
            config: Optional batch processing configuration
        """
        self.github_client = github_client
        self.cache_manager = cache_manager
        self.config = config or BatchConfig()
        
        # Validate configuration
        config_errors = self.config.validate()
        if config_errors:
            raise ConfigurationError(f"Invalid batch configuration: {', '.join(config_errors)}")
        
        # Initialize core components
        self.strategy_manager = BatchStrategyManager(self.config)
        self.parallel_processor = ParallelBatchProcessor(github_client, self.config)
        self.cache_coordinator = BatchCacheCoordinator(
            cache_manager=cache_manager,
            github_client=github_client,
            batch_config=self.config
        )
        self.progress_monitor = BatchProgressMonitor(
            enable_verbose_logging=True,
            update_interval_seconds=2.0
        )
        
        # Rate limit management
        self.rate_limit_manager = BatchRateLimitManager()
        self.error_formatter = ErrorMessageFormatter()
        
        # Coordination state
        self.active_operations: Dict[str, Dict[str, Any]] = {}
        self.operation_counter = 0
        self._coordination_lock = asyncio.Lock()
        
        # Performance tracking
        self.global_metrics = BatchMetrics()
        self.operation_history: List[Dict[str, Any]] = []
        
        # Strategy adaptation
        self.current_strategy = self.config.default_strategy
        self.strategy_adaptation_enabled = True
        
    def _report_progress(
        self,
        completed: int,
        total: int,
        current_batch_size: int,
        eta_seconds: Optional[float]
    ) -> None:
        """Report progress for batch operations.
        
        Args:
            completed: Number of completed items
            total: Total number of items
            current_batch_size: Size of the current batch
            eta_seconds: Estimated time remaining in seconds
        """
        if total > 0:
            percentage = (completed / total) * 100
            logger.debug(
                f"Batch progress: {completed}/{total} ({percentage:.1f}%) "
                f"batch_size={current_batch_size} eta={eta_seconds:.1f}s"
                if eta_seconds is not None
                else f"Batch progress: {completed}/{total} ({percentage:.1f}%) "
                     f"batch_size={current_batch_size}"
            )

    async def start(self) -> None:
        """Start the batch coordinator and all sub-components."""
        try:
            await self.cache_coordinator.start()
            logger.info("Batch coordinator started successfully")
        except Exception as e:
            logger.error(f"Failed to start batch coordinator: {e}")
            raise BatchProcessingError(f"Coordinator startup failed: {e}") from e
    
    async def stop(self) -> None:
        """Stop the batch coordinator and all sub-components."""
        try:
            # Wait for active operations to complete
            if self.active_operations:
                logger.info(f"Waiting for {len(self.active_operations)} active operations to complete")
                await self._wait_for_active_operations()
            
            # Close the GitHub client session
            if self.github_client:
                await self.github_client.aclose()
            
            await self.cache_coordinator.stop()
            logger.info("Batch coordinator stopped successfully")
        except Exception as e:
            logger.error(f"Error stopping batch coordinator: {e}")
            raise BatchProcessingError(f"Coordinator shutdown failed: {e}") from e
    
    async def process_repositories_batch(
        self,
        repositories: List[Repository],
        strategy: Optional[BatchStrategy] = None,
        file_patterns: Optional[List[str]] = None
    ) -> Dict[str, List[IOCMatch]]:
        """Process multiple repositories with optimal batching strategy.
        
        Args:
            repositories: List of repositories to process
            strategy: Optional batching strategy override
            file_patterns: Optional file patterns to focus on
            
        Returns:
            Dictionary mapping repository names to IOC matches
        """
        if not repositories:
            return {}
        
        operation_id = await self._create_operation("repositories_batch", {
            'repository_count': len(repositories),
            'strategy': strategy or self.current_strategy,
            'file_patterns': file_patterns
        })
        
        try:
            logger.info(f"Processing batch of {len(repositories)} repositories with strategy {strategy or self.current_strategy}")
            
            # For very large repository counts, use different strategies based on scan type
            if len(repositories) > 1000:
                if self._is_team_first_org_scan():
                    logger.info(f"Large team-first-org scan ({len(repositories)} repos), using simplified processing")
                    # Skip expensive cross-repo analysis for team-first-org scans
                    return await self._process_repositories_sequentially(
                        repositories, strategy or BatchStrategy.CONSERVATIVE, file_patterns
                    )
                else:
                    logger.info(f"Large repository count ({len(repositories)}), using chunked processing")
                    return await self._process_repositories_chunked(repositories, strategy, file_patterns)
            
            # Step 1: Analyze repositories for cross-repo batching opportunities
            cross_repo_opportunities = await self._analyze_cross_repo_opportunities(repositories)
            
            # Step 2: Optimize repository processing order
            optimized_repos = await self.optimize_repository_processing_order(
                repositories, cross_repo_opportunities
            )
            
            # Step 3: Determine optimal processing strategy
            effective_strategy = strategy or await self._select_optimal_strategy(repositories)
            
            # Step 4: Process repositories using selected strategy
            # TEMPORARY: Disable cross-repo batching for better performance
            if False and cross_repo_opportunities and self.config.enable_cross_repo_batching:
                results = await self._process_cross_repo_batches(
                    cross_repo_opportunities, effective_strategy, file_patterns
                )
            else:
                results = await self._process_repositories_sequentially(
                    optimized_repos, effective_strategy, file_patterns
                )
            
            # Step 5: Update strategy adaptation based on results
            if self.strategy_adaptation_enabled:
                await self._adapt_strategy_from_results(results)
            
            await self._complete_operation(operation_id, success=True)
            
            # Collect total files processed for statistics
            total_files_processed = 0
            if hasattr(self, '_files_processed_count'):
                total_files_processed = sum(self._files_processed_count.values())
                # Store for later retrieval
                self._last_batch_files_processed = total_files_processed
            
            logger.info(f"Completed repository batch processing: {len(results)} repositories processed, {total_files_processed} files analyzed")
            return results
            
        except Exception as e:
            await self._complete_operation(operation_id, success=False, error=str(e))
            logger.error(f"Repository batch processing failed: {e}")
            raise BatchProcessingError(f"Repository batch processing failed: {e}") from e
    
    async def process_organization_repositories_batch(
        self,
        organization: str,
        repository_filter: Optional[str] = None,
        max_repositories: Optional[int] = None,
        strategy: Optional[BatchStrategy] = None
    ) -> Dict[str, List[IOCMatch]]:
        """Process all repositories in an organization with batch optimization.
        
        Args:
            organization: Organization name to scan
            repository_filter: Optional filter pattern for repository names
            max_repositories: Optional maximum number of repositories to process
            strategy: Optional batching strategy override
            
        Returns:
            Dictionary mapping repository names to IOC matches
        """
        operation_id = await self._create_operation("organization_batch", {
            'organization': organization,
            'repository_filter': repository_filter,
            'max_repositories': max_repositories,
            'strategy': strategy or self.current_strategy
        })
        
        try:
            logger.info(f"Processing organization {organization} repositories with batch optimization")
            
            # Step 1: Discover repositories in the organization
            repositories = await self._discover_organization_repositories(
                organization, repository_filter, max_repositories
            )
            
            if not repositories:
                logger.info(f"No repositories found in organization {organization}")
                await self._complete_operation(operation_id, success=True)
                return {}
            
            # Step 2: Pre-warm cache for organization-wide scanning
            await self.cache_coordinator.optimize_cache_for_scan_pattern(
                repositories, "security_scan"
            )
            
            # Step 3: Process repositories using batch coordination
            results = await self.process_repositories_batch(
                repositories, strategy, file_patterns=None
            )
            
            await self._complete_operation(operation_id, success=True)
            
            logger.info(f"Completed organization batch processing: {len(results)} repositories processed")
            return results
            
        except Exception as e:
            await self._complete_operation(operation_id, success=False, error=str(e))
            logger.error(f"Organization batch processing failed: {e}")
            raise BatchProcessingError(f"Organization batch processing failed: {e}") from e
    
    async def _discover_organization_repositories(
        self,
        organization: str,
        repository_filter: Optional[str] = None,
        max_repositories: Optional[int] = None
    ) -> List[Repository]:
        """Discover repositories in an organization using async batch processing.
        
        Args:
            organization: Organization name
            repository_filter: Optional filter pattern
            max_repositories: Optional maximum number of repositories
            
        Returns:
            List of discovered repositories
        """
        logger.info(f"🔍 Async batch discovery for organization: {organization}")
        
        try:
            # Since we don't have async repository discovery yet, we need to use
            # the synchronous method but run it in a thread pool to avoid blocking
            import asyncio
            import functools
            
            # Get the synchronous GitHub client from the scanner
            if hasattr(self, 'scanner') and self.scanner:
                sync_discovery = functools.partial(
                    self.scanner.discover_organization_repositories,
                    organization
                )
                
                # Run the synchronous discovery in a thread pool
                loop = asyncio.get_running_loop()
                repositories = await loop.run_in_executor(
                    None, sync_discovery
                )
                
                logger.info(f"✅ Async batch discovery completed: {len(repositories)} repositories found")
                return repositories
            else:
                logger.error("No scanner reference available for repository discovery")
                raise Exception("Scanner reference not available")
            
        except Exception as e:
            logger.error(f"❌ Async batch repository discovery failed: {e}")
            # Don't return empty list, let the caller handle the fallback
            raise
    
    async def process_files_batch(
        self,
        repo: Repository,
        file_paths: List[str],
        priority_files: Optional[List[str]] = None,
        strategy: Optional[BatchStrategy] = None
    ) -> Dict[str, Any]:
        """Process multiple files with intelligent batching.
        
        Args:
            repo: Repository containing the files
            file_paths: List of file paths to process
            priority_files: Optional list of high-priority files
            strategy: Optional batching strategy override (currently informational)
            
        Returns:
            Dictionary mapping file paths to their content/result
        """
        if not file_paths:
            return {}
        
        operation_id = await self._create_operation("files_batch", {
            'repository': repo.full_name,
            'file_count': len(file_paths),
            'priority_files': priority_files or []
        })
        
        try:
            logger.info(f"Processing batch of {len(file_paths)} files from {repo.full_name}")
            
            # Step 1: Create batch requests with prioritization
            batch_requests = await self._create_prioritized_batch_requests(
                repo, file_paths, priority_files
            )
            
            # Step 2: Coordinate with cache for optimal performance
            cached_results, uncached_requests = await self.cache_coordinator.coordinate_batch_operation(
                batch_requests, operation_id
            )
            
            # Step 3: Process uncached requests if any
            api_results = []
            if uncached_requests:
                api_results = await self._process_uncached_requests(uncached_requests)
            
            # Step 4: Combine results and finalize
            all_results = cached_results + api_results
            await self.cache_coordinator.finalize_batch_operation(operation_id, all_results)
            
            # Step 5: Format results for return
            formatted_results = await self._format_file_batch_results(all_results)
            
            await self._complete_operation(operation_id, success=True)
            
            # Update global metrics
            self.global_metrics.total_requests += len(file_paths)
            self.global_metrics.successful_requests += len(formatted_results)
            self.global_metrics.failed_requests += len(file_paths) - len(formatted_results)
            
            # Report final progress
            self._report_progress(len(file_paths), len(file_paths), len(file_paths), 0.0)
            
            logger.info(
                f"Completed file batch processing: {len(cached_results)} cached, "
                f"{len(api_results)} from API"
            )
            return formatted_results
            
        except Exception as e:
            await self._complete_operation(operation_id, success=False, error=str(e))
            logger.error(f"File batch processing failed: {e}")
            raise BatchProcessingError(f"File batch processing failed: {e}") from e
    
    def get_batch_metrics(self) -> BatchMetrics:
        """Get comprehensive batch processing metrics.
        
        Returns:
            Current batch processing metrics
        """
        # Combine metrics from all components
        parallel_metrics = self.parallel_processor.get_metrics()
        coordination_stats = self.cache_coordinator.get_coordination_statistics()
        
        # Create comprehensive metrics
        comprehensive_metrics = BatchMetrics(
            total_requests=parallel_metrics.total_requests + self.global_metrics.total_requests,
            successful_requests=parallel_metrics.successful_requests + self.global_metrics.successful_requests,
            failed_requests=parallel_metrics.failed_requests + self.global_metrics.failed_requests,
            cache_hits=coordination_stats['batch_cache']['batch_cache_hits'],
            cache_misses=coordination_stats['batch_cache']['batch_cache_misses'],
            average_batch_size=self._calculate_average_batch_size(),
            total_processing_time=parallel_metrics.total_processing_time + self.global_metrics.total_processing_time,
            api_calls_saved=coordination_stats['batch_cache']['batch_cache_hits'],
            parallel_efficiency=parallel_metrics.parallel_efficiency,
            start_time=self.global_metrics.start_time,
            end_time=datetime.now()
        )
        
        return comprehensive_metrics
    
    async def execute_end_to_end_batch_workflow(
        self,
        repositories: List[Repository],
        workflow_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute a complete end-to-end batch processing workflow.
        
        Args:
            repositories: List of repositories to process
            workflow_config: Optional workflow configuration
            
        Returns:
            Comprehensive workflow results
        """
        workflow_config = workflow_config or {}
        
        operation_id = await self._create_operation("end_to_end_workflow", {
            'repository_count': len(repositories),
            'workflow_config': workflow_config
        })
        
        try:
            logger.info(f"Starting end-to-end batch workflow for {len(repositories)} repositories")
            
            # Phase 1: Pre-processing and optimization
            logger.info("Phase 1: Pre-processing and optimization")
            
            # Analyze cross-repository opportunities
            cross_repo_opportunities = await self._analyze_cross_repo_opportunities(repositories)
            
            # Optimize cache for the workflow
            cache_optimization = await self.cache_coordinator.optimize_cache_for_scan_pattern(
                repositories, workflow_config.get('scan_pattern', 'security_scan')
            )
            
            # Optimize repository processing order
            optimized_repos = await self.optimize_repository_processing_order(
                repositories, cross_repo_opportunities
            )
            
            # Phase 2: Strategy selection and adaptation
            logger.info("Phase 2: Strategy selection and adaptation")
            
            # Select optimal strategy based on current conditions
            optimal_strategy = await self._select_optimal_strategy_comprehensive(
                repositories, cross_repo_opportunities, cache_optimization
            )
            
            # Phase 3: Batch processing execution
            logger.info("Phase 3: Batch processing execution")
            
            # Execute batch processing with full integration
            processing_results = await self._execute_integrated_batch_processing(
                optimized_repos, optimal_strategy, cross_repo_opportunities, workflow_config
            )
            
            # Phase 4: Post-processing and analysis
            logger.info("Phase 4: Post-processing and analysis")
            
            # Analyze results and update strategies
            workflow_metrics = await self._analyze_workflow_results(processing_results)
            
            # Update global strategy based on workflow performance
            if self.strategy_adaptation_enabled:
                await self._adapt_strategy_from_workflow_results(workflow_metrics)
            
            # Compile comprehensive results
            comprehensive_results = {
                'processing_results': processing_results,
                'workflow_metrics': workflow_metrics,
                'cache_optimization': cache_optimization,
                'cross_repo_opportunities': len(cross_repo_opportunities),
                'strategy_used': optimal_strategy.value,
                'repositories_processed': len(repositories),
                'operation_id': operation_id
            }
            
            await self._complete_operation(operation_id, success=True)
            
            logger.info(f"Completed end-to-end batch workflow: {len(processing_results)} repositories processed")
            return comprehensive_results
            
        except Exception as e:
            await self._complete_operation(operation_id, success=False, error=str(e))
            logger.error(f"End-to-end batch workflow failed: {e}")
            raise BatchProcessingError(f"Workflow execution failed: {e}") from e
    
    async def _select_optimal_strategy_comprehensive(
        self,
        repositories: List[Repository],
        cross_repo_opportunities: List[CrossRepoBatch],
        cache_optimization: Dict[str, Any]
    ) -> BatchStrategy:
        """Select optimal strategy based on comprehensive analysis.
        
        Args:
            repositories: Repositories to be processed
            cross_repo_opportunities: Available cross-repo batching opportunities
            cache_optimization: Cache optimization results
            
        Returns:
            Optimal batching strategy
        """
        # Get base strategy recommendation
        base_strategy = await self._select_optimal_strategy(repositories)
        
        # Adjust based on cross-repo opportunities
        if cross_repo_opportunities and len(cross_repo_opportunities) > 0:
            avg_savings = sum(opp.estimated_savings for opp in cross_repo_opportunities) / len(cross_repo_opportunities)
            if avg_savings > 0.3:  # High savings potential
                if base_strategy == BatchStrategy.CONSERVATIVE:
                    base_strategy = BatchStrategy.ADAPTIVE
                elif base_strategy == BatchStrategy.ADAPTIVE:
                    base_strategy = BatchStrategy.AGGRESSIVE
        
        # Adjust based on cache optimization
        cache_hit_rate = cache_optimization.get('cache_state', {}).get('batch_hit_rate_percent', 0)
        if cache_hit_rate > 70:  # High cache hit rate
            # Can be more aggressive with good cache performance
            if base_strategy == BatchStrategy.CONSERVATIVE:
                base_strategy = BatchStrategy.ADAPTIVE
        elif cache_hit_rate < 30:  # Low cache hit rate
            # Be more conservative with poor cache performance
            if base_strategy == BatchStrategy.AGGRESSIVE:
                base_strategy = BatchStrategy.ADAPTIVE
        
        # Consider repository count and characteristics
        if len(repositories) > 20:
            # Large number of repositories - prefer parallel processing
            if base_strategy == BatchStrategy.SEQUENTIAL:
                base_strategy = BatchStrategy.PARALLEL
        
        logger.debug(f"Selected comprehensive strategy {base_strategy} for {len(repositories)} repositories")
        return base_strategy
    
    async def _execute_integrated_batch_processing(
        self,
        repositories: List[Repository],
        strategy: BatchStrategy,
        cross_repo_opportunities: List[CrossRepoBatch],
        workflow_config: Dict[str, Any]
    ) -> Dict[str, List[IOCMatch]]:
        """Execute integrated batch processing with all components coordinated.
        
        Args:
            repositories: Repositories to process
            strategy: Batching strategy to use
            cross_repo_opportunities: Cross-repo batching opportunities
            workflow_config: Workflow configuration
            
        Returns:
            Processing results
        """
        # Coordinate all components for optimal processing
        
        # Step 1: Configure parallel processor based on strategy
        await self._configure_parallel_processor_for_strategy(strategy)
        
        # Step 2: Pre-warm cache for anticipated requests
        await self._pre_warm_cache_for_repositories(repositories, strategy)
        
        # Step 3: Execute processing with full coordination
        if cross_repo_opportunities and self.config.enable_cross_repo_batching:
            results = await self._process_cross_repo_batches_integrated(
                cross_repo_opportunities, strategy, workflow_config
            )
        else:
            results = await self._process_repositories_integrated(
                repositories, strategy, workflow_config
            )
        
        return results
    
    async def _configure_parallel_processor_for_strategy(self, strategy: BatchStrategy) -> None:
        """Configure parallel processor based on selected strategy.
        
        Args:
            strategy: Batching strategy to configure for
        """
        # Adjust concurrency based on strategy
        if strategy == BatchStrategy.AGGRESSIVE:
            target_concurrency = self.config.max_concurrent_requests
        elif strategy == BatchStrategy.CONSERVATIVE:
            target_concurrency = max(1, self.config.max_concurrent_requests // 3)
        else:  # ADAPTIVE, PARALLEL, SEQUENTIAL
            target_concurrency = self.config.max_concurrent_requests // 2
        
        # Update parallel processor configuration
        self.parallel_processor.adjust_concurrency(
            rate_limit_remaining=5000,  # Assume good rate limit status
            rate_limit_limit=5000,
            reset_time=0
        )
        
        logger.debug(f"Configured parallel processor for strategy {strategy} with concurrency {target_concurrency}")
    
    async def _pre_warm_cache_for_repositories(
        self,
        repositories: List[Repository],
        strategy: BatchStrategy
    ) -> None:
        """Pre-warm cache for anticipated repository requests.
        
        Args:
            repositories: Repositories that will be processed
            strategy: Processing strategy being used
        """
        # Determine cache warming intensity based on strategy
        if strategy == BatchStrategy.AGGRESSIVE:
            # Aggressive warming for aggressive strategy
            await self.cache_coordinator.warm_cache_for_batch_operation(
                repositories, predicted_files=None  # Warm all common files
            )
        elif strategy in [BatchStrategy.ADAPTIVE, BatchStrategy.PARALLEL]:
            # Moderate warming for balanced strategies
            priority_files = ['package.json', 'requirements.txt', 'go.mod', 'Cargo.toml']
            await self.cache_coordinator.warm_cache_for_batch_operation(
                repositories, predicted_files=priority_files
            )
        # Conservative strategy uses minimal warming (handled by default cache behavior)
        
        logger.debug(f"Pre-warmed cache for {len(repositories)} repositories with strategy {strategy}")
    
    async def _process_repositories_integrated(
        self,
        repositories: List[Repository],
        strategy: BatchStrategy,
        workflow_config: Dict[str, Any]
    ) -> Dict[str, List[IOCMatch]]:
        """Process repositories with full component integration.
        
        Args:
            repositories: Repositories to process
            strategy: Processing strategy
            workflow_config: Workflow configuration
            
        Returns:
            Processing results
        """
        # Use the existing sequential processing but with enhanced coordination
        file_patterns = workflow_config.get('file_patterns')
        return await self._process_repositories_sequentially(repositories, strategy, file_patterns)
    
    async def _process_cross_repo_batches_integrated(
        self,
        cross_repo_opportunities: List[CrossRepoBatch],
        strategy: BatchStrategy,
        workflow_config: Dict[str, Any]
    ) -> Dict[str, List[IOCMatch]]:
        """Process cross-repo batches with full integration.
        
        Args:
            cross_repo_opportunities: Cross-repo batching opportunities
            strategy: Processing strategy
            workflow_config: Workflow configuration
            
        Returns:
            Processing results
        """
        # Enhanced cross-repo processing with full coordination
        results = {}
        
        for opportunity in cross_repo_opportunities:
            logger.debug(f"Processing cross-repo batch with {len(opportunity.repositories)} repositories")
            
            # Process repositories in this cross-repo batch
            batch_results = await self._process_repositories_integrated(
                opportunity.repositories, strategy, workflow_config
            )
            
            # Merge results
            results.update(batch_results)
        
        return results
    
    async def _analyze_workflow_results(
        self,
        processing_results: Dict[str, List[IOCMatch]]
    ) -> Dict[str, Any]:
        """Analyze workflow results and generate comprehensive metrics.
        
        Args:
            processing_results: Results from batch processing
            
        Returns:
            Comprehensive workflow metrics
        """
        # Get metrics from all components
        batch_metrics = self.get_batch_metrics()
        coordination_stats = self.get_coordination_statistics()
        
        # Calculate workflow-specific metrics
        total_repositories = len(processing_results)
        total_matches = sum(len(matches) for matches in processing_results.values())
        repositories_with_matches = sum(1 for matches in processing_results.values() if matches)
        
        workflow_metrics = {
            'batch_metrics': batch_metrics.__dict__,
            'coordination_stats': coordination_stats,
            'total_repositories': total_repositories,
            'total_ioc_matches': total_matches,
            'repositories_with_matches': repositories_with_matches,
            'match_rate': repositories_with_matches / total_repositories if total_repositories > 0 else 0.0,
            'average_matches_per_repo': total_matches / total_repositories if total_repositories > 0 else 0.0
        }
        
        return workflow_metrics
    
    async def _adapt_strategy_from_workflow_results(
        self,
        workflow_metrics: Dict[str, Any]
    ) -> None:
        """Adapt global strategy based on comprehensive workflow results.
        
        Args:
            workflow_metrics: Comprehensive workflow metrics
        """
        batch_metrics = workflow_metrics.get('batch_metrics', {})
        coordination_stats = workflow_metrics.get('coordination_stats', {})
        
        success_rate = batch_metrics.get('success_rate', 0.0)
        parallel_efficiency = batch_metrics.get('parallel_efficiency', 0.0)
        cache_hit_rate = coordination_stats.get('cache_coordination', {}).get('cache_efficiency', {}).get('hit_rate', 0.0)
        
        # Comprehensive strategy adaptation
        if success_rate > 95 and parallel_efficiency > 0.8 and cache_hit_rate > 70:
            # Excellent performance across all metrics
            if self.current_strategy in [BatchStrategy.CONSERVATIVE, BatchStrategy.ADAPTIVE]:
                self.current_strategy = BatchStrategy.AGGRESSIVE
                logger.info("Adapted to AGGRESSIVE strategy due to excellent performance")
        elif success_rate < 80 or parallel_efficiency < 0.5:
            # Poor performance - be more conservative
            if self.current_strategy == BatchStrategy.AGGRESSIVE:
                self.current_strategy = BatchStrategy.ADAPTIVE
                logger.info("Adapted to ADAPTIVE strategy due to performance issues")
            elif self.current_strategy == BatchStrategy.ADAPTIVE:
                self.current_strategy = BatchStrategy.CONSERVATIVE
                logger.info("Adapted to CONSERVATIVE strategy due to poor performance")
        elif success_rate > 90 and self.current_strategy == BatchStrategy.CONSERVATIVE:
            # Good performance - can be more aggressive
            self.current_strategy = BatchStrategy.ADAPTIVE
            logger.info("Adapted to ADAPTIVE strategy due to good performance")
    
    async def _analyze_cross_repo_opportunities(
        self, 
        repositories: List[Repository]
    ) -> List[CrossRepoBatch]:
        """Analyze repositories for cross-repo batching opportunities.
        
        Args:
            repositories: List of repositories to analyze
            
        Returns:
            List of cross-repository batching opportunities
        """
        if not self.config.enable_cross_repo_batching or len(repositories) < 2:
            return []
        
        try:
            # For now, we'll use a simplified approach
            # In a full implementation, we would analyze actual file structures
            repo_files = {}
            for repo in repositories:
                # Simulate common files analysis
                repo_files[repo.full_name] = [
                    'package.json', 'requirements.txt', 'go.mod', 'Cargo.toml'
                ]
            
            opportunities = self.strategy_manager.identify_cross_repo_opportunities(
                repositories, repo_files
            )
            
            logger.debug(f"Identified {len(opportunities)} cross-repo batching opportunities")
            return opportunities
            
        except Exception as e:
            logger.warning(f"Error analyzing cross-repo opportunities: {e}")
            return []
    
    async def _prioritize_repositories(self, repositories: List[Repository]) -> List[Repository]:
        """Prioritize repositories based on importance and processing characteristics.
        
        Args:
            repositories: List of repositories to prioritize
            
        Returns:
            Prioritized list of repositories
        """
        # Calculate priority scores for each repository
        repo_priorities = []
        
        for repo in repositories:
            priority_score = await self._calculate_repository_priority(repo)
            repo_priorities.append((repo, priority_score))
        
        # Sort by priority score (highest first)
        repo_priorities.sort(key=lambda x: x[1], reverse=True)
        
        prioritized = [repo for repo, _ in repo_priorities]
        
        logger.debug(f"Prioritized {len(repositories)} repositories")
        return prioritized
    
    async def _calculate_repository_priority(self, repository: Repository) -> float:
        """Calculate priority score for a repository.
        
        Args:
            repository: Repository to calculate priority for
            
        Returns:
            Priority score (higher = more important)
        """
        priority_score = 0.0
        
        # Base priority factors
        repo_name = repository.full_name.lower()
        
        # 1. Repository name patterns (higher priority for certain patterns)
        high_priority_patterns = [
            'api', 'service', 'core', 'main', 'backend', 'frontend',
            'auth', 'security', 'payment', 'billing', 'user'
        ]
        for pattern in high_priority_patterns:
            if pattern in repo_name:
                priority_score += 2.0
                break
        
        # 2. Repository freshness (more recently updated = higher priority)
        if repository.updated_at:
            from datetime import datetime, timezone
            # Ensure both datetimes are timezone-aware
            now = datetime.now(timezone.utc)
            updated_at = repository.updated_at
            if updated_at.tzinfo is None:
                updated_at = updated_at.replace(tzinfo=timezone.utc)
            days_since_update = (now - updated_at).days
            if days_since_update < 7:
                priority_score += 3.0  # Very recent
            elif days_since_update < 30:
                priority_score += 2.0  # Recent
            elif days_since_update < 90:
                priority_score += 1.0  # Somewhat recent
        
        # 3. Repository status (non-archived = higher priority)
        if not repository.archived:
            priority_score += 1.0
        
        # 4. Organization vs personal repos (org repos often more important)
        if '/' in repository.full_name and not repository.full_name.startswith('users/'):
            priority_score += 1.0
        
        # 5. Repository name length (shorter names often more important)
        name_length_factor = max(0, 2.0 - (len(repository.name) / 20.0))
        priority_score += name_length_factor
        
        return priority_score
    
    async def optimize_repository_processing_order(
        self,
        repositories: List[Repository],
        cross_repo_opportunities: List[CrossRepoBatch]
    ) -> List[Repository]:
        """Optimize the processing order of repositories for maximum efficiency.
        
        Args:
            repositories: List of repositories to order
            cross_repo_opportunities: Cross-repository batching opportunities
            
        Returns:
            Optimally ordered list of repositories
        """
        if not repositories:
            return []
        
        # Start with prioritized repositories
        prioritized_repos = await self._prioritize_repositories(repositories)
        
        # If no cross-repo opportunities, return prioritized order
        if not cross_repo_opportunities:
            return prioritized_repos
        
        # Optimize order based on cross-repo batching opportunities
        optimized_order = []
        processed_repos = set()
        
        # Process cross-repo batches first (highest savings first)
        for opportunity in sorted(cross_repo_opportunities, key=lambda x: x.estimated_savings, reverse=True):
            batch_repos = [r for r in opportunity.repositories if r.full_name not in processed_repos]
            if batch_repos:
                # Add repos from this batch in priority order
                batch_repos_prioritized = [r for r in prioritized_repos if r in batch_repos]
                optimized_order.extend(batch_repos_prioritized)
                processed_repos.update(r.full_name for r in batch_repos_prioritized)
        
        # Add remaining repositories in priority order
        remaining_repos = [r for r in prioritized_repos if r.full_name not in processed_repos]
        optimized_order.extend(remaining_repos)
        
        logger.debug(f"Optimized processing order for {len(repositories)} repositories")
        return optimized_order
    
    async def _select_optimal_strategy(self, repositories: List[Repository]) -> BatchStrategy:
        """Select optimal batching strategy based on current conditions.
        
        Args:
            repositories: Repositories to be processed
            
        Returns:
            Optimal batching strategy
        """
        # Get recent performance metrics
        recent_metrics = self.parallel_processor.get_metrics()
        
        # Use strategy manager to adapt based on performance
        if recent_metrics.total_requests > 0:
            optimal_strategy = self.strategy_manager.adapt_strategy(recent_metrics)
        else:
            optimal_strategy = self.current_strategy
        
        # Consider repository count and characteristics
        if len(repositories) > 10:
            # Large number of repositories - prefer parallel processing
            if optimal_strategy == BatchStrategy.SEQUENTIAL:
                optimal_strategy = BatchStrategy.PARALLEL
        elif len(repositories) < 3:
            # Small number of repositories - sequential might be fine
            if optimal_strategy == BatchStrategy.AGGRESSIVE:
                optimal_strategy = BatchStrategy.ADAPTIVE
        
        logger.debug(f"Selected strategy {optimal_strategy} for {len(repositories)} repositories")
        return optimal_strategy
    
    async def _process_cross_repo_batches(
        self,
        opportunities: List[CrossRepoBatch],
        strategy: BatchStrategy,
        file_patterns: Optional[List[str]]
    ) -> Dict[str, List[IOCMatch]]:
        """Process repositories using cross-repo batching opportunities.
        
        Args:
            opportunities: Cross-repo batching opportunities
            strategy: Batching strategy to use
            file_patterns: Optional file patterns to focus on
            
        Returns:
            Dictionary mapping repository names to IOC matches
        """
        results = {}
        total_repos = sum(len(opportunity.repositories) for opportunity in opportunities)
        
        # Start progress monitoring for cross-repo batching
        self.progress_monitor.start_monitoring(total_repos, "cross_repo_batch_scan")
        completed_count = 0
        
        for batch_idx, opportunity in enumerate(opportunities):
            logger.info(f"Processing cross-repo batch {batch_idx + 1}/{len(opportunities)} "
                       f"with {len(opportunity.repositories)} repositories")
            
            # Process each repository in the cross-repo batch using the real implementation
            for repo in opportunity.repositories:
                try:
                    logger.debug(f"Processing repository {repo.full_name} in cross-repo batch")
                    repo_results = await self._process_single_repository_batch(
                        repo, strategy, file_patterns
                    )
                    results[repo.full_name] = repo_results
                    completed_count += 1
                    
                    # Update progress every 3 repositories
                    if completed_count % 3 == 0 or completed_count == total_repos:
                        success_count = sum(1 for matches in results.values() if matches is not None)
                        failure_count = completed_count - success_count
                        
                        snapshot = self.progress_monitor.update_progress(
                            completed=completed_count,
                            success_count=success_count,
                            failure_count=failure_count,
                            current_batch_size=len(opportunity.repositories)
                        )
                        
                        if snapshot:
                            eta = self.progress_monitor.calculate_eta()
                            if eta:
                                logger.info(f"Cross-repo progress: {completed_count}/{total_repos} repositories "
                                          f"({snapshot.completion_percentage:.1f}%) - "
                                          f"ETA: {eta.estimated_time_remaining_str}")
                        
                except Exception as e:
                    logger.error(f"Failed to process repository {repo.full_name} in cross-repo batch: {e}")
                    results[repo.full_name] = []
                    completed_count += 1
        
        # Finish progress monitoring for cross-repo batching
        final_stats = self.progress_monitor.finish_monitoring()
        logger.debug(f"Cross-repo batch progress monitoring stats: {final_stats}")
        
        return results
    
    async def _process_repositories_sequentially(
        self,
        repositories: List[Repository],
        strategy: BatchStrategy,
        file_patterns: Optional[List[str]]
    ) -> Dict[str, List[IOCMatch]]:
        """Process repositories sequentially with the given strategy.
        
        Args:
            repositories: Repositories to process
            strategy: Batching strategy to use
            file_patterns: Optional file patterns to focus on
            
        Returns:
            Dictionary mapping repository names to IOC matches
        """
        results = {}
        
        # Determine concurrency based on strategy and batch size
        if strategy == BatchStrategy.CONSERVATIVE:
            max_concurrent = 1
        elif len(repositories) > 100:
            # Very large batches: minimal concurrency to avoid rate limits
            max_concurrent = 2
            logger.info(f"Large batch ({len(repositories)} repos) - using minimal concurrency: {max_concurrent}")
        elif len(repositories) > 50:
            # Large batches: conservative concurrency
            max_concurrent = 3
            logger.info(f"Medium batch ({len(repositories)} repos) - using conservative concurrency: {max_concurrent}")
        elif strategy == BatchStrategy.AGGRESSIVE:
            max_concurrent = min(8, self.config.max_concurrent_repos)
        else:
            # Default adaptive strategy
            max_concurrent = min(5, self.config.max_concurrent_repos)
        
        # Process repositories with controlled concurrency
        semaphore = asyncio.Semaphore(max_concurrent)
        completed_counter = {"count": 0}  # Mutable counter for async function
        
        async def process_single_repo(repo: Repository) -> Tuple[str, List[IOCMatch]]:
            async with semaphore:
                try:
                    logger.debug(f"Processing repository {repo.full_name}")
                    # Process repository with batch optimization
                    repo_results = await self._process_single_repository_batch(
                        repo, strategy, file_patterns
                    )
                    
                    # Update progress counter
                    completed_counter["count"] += 1
                    current_count = completed_counter["count"]
                    
                    if len(repo_results) > 0:
                        logger.info(f"🚨 IOC matches found in {repo.full_name}: {len(repo_results)} threats")
                    
                    # Log progress every 10 repositories or at key milestones
                    if current_count % 10 == 0 or current_count in [1, 5, len(repositories)]:
                        percentage = (current_count / len(repositories)) * 100
                        logger.info(f"📊 Progress: {current_count}/{len(repositories)} repositories ({percentage:.1f}%)")
                    
                    logger.debug(f"Completed repository {repo.full_name}, found {len(repo_results)} matches")
                    return repo.full_name, repo_results
                except Exception as e:
                    completed_counter["count"] += 1
                    logger.error(f"Failed to process repository {repo.full_name}: {e}")
                    return repo.full_name, []
        
        # Start progress monitoring
        self.progress_monitor.start_monitoring(len(repositories), "repository_scan")
        
        # Execute repository processing
        tasks = [process_single_repo(repo) for repo in repositories]
        
        logger.info(f"🚀 Starting scan of {len(repositories)} repositories (concurrency: {max_concurrent})")
        
        # Process repositories with progress tracking
        successful_repos = 0
        failed_repos = 0
        
        # Use asyncio.as_completed for real-time progress updates
        for i, task in enumerate(asyncio.as_completed(tasks)):
            try:
                result = await task
                successful_repos += 1
                repo_name, matches = result
                results[repo_name] = matches
                
                # Update progress monitoring
                completed = successful_repos + failed_repos
                self.progress_monitor.update_progress(
                    completed=completed,
                    success_count=successful_repos,
                    failure_count=failed_repos,
                    current_batch_size=1  # Processing one repo at a time
                )
                
            except Exception as e:
                failed_repos += 1
                completed = successful_repos + failed_repos
                logger.error(f"Repository processing failed: {e}")
                
                # Update progress monitoring for failed repository
                self.progress_monitor.update_progress(
                    completed=completed,
                    success_count=successful_repos,
                    failure_count=failed_repos,
                    current_batch_size=1
                )
        
        # Count repositories with files and matches
        repos_with_files = sum(1 for matches in results.values() if matches)
        total_matches = sum(len(matches) for matches in results.values())
        
        # Finish progress monitoring
        final_stats = self.progress_monitor.finish_monitoring()
        
        logger.info(f"Batch completed: {successful_repos} successful, {failed_repos} failed")
        logger.info(f"File discovery: {repos_with_files}/{len(repositories)} repositories had relevant files, {total_matches} total matches")
        logger.debug(f"Progress monitoring stats: {final_stats}")
        
        return results
    
    async def _process_repositories_chunked(
        self,
        repositories: List[Repository],
        strategy: Optional[BatchStrategy] = None,
        file_patterns: Optional[List[str]] = None,
        chunk_size: int = 500
    ) -> Dict[str, List[IOCMatch]]:
        """Process large repository lists in smaller chunks to avoid memory/performance issues.
        
        Args:
            repositories: Large list of repositories to process
            strategy: Batching strategy to use
            file_patterns: Optional file patterns to focus on
            chunk_size: Size of each chunk (default: 500)
            
        Returns:
            Dictionary mapping repository names to IOC matches
        """
        logger.info(f"Processing {len(repositories)} repositories in chunks of {chunk_size}")
        
        all_results = {}
        total_chunks = (len(repositories) + chunk_size - 1) // chunk_size
        
        # Process repositories in chunks
        for chunk_idx in range(0, len(repositories), chunk_size):
            chunk_end = min(chunk_idx + chunk_size, len(repositories))
            chunk = repositories[chunk_idx:chunk_end]
            chunk_num = (chunk_idx // chunk_size) + 1
            
            logger.info(f"📦 Processing chunk {chunk_num}/{total_chunks}: repositories {chunk_idx+1}-{chunk_end}")
            
            try:
                # Process this chunk using the standard sequential method
                # Skip the expensive cross-repo analysis for chunks
                chunk_results = await self._process_repositories_sequentially(
                    chunk, strategy or BatchStrategy.CONSERVATIVE, file_patterns
                )
                
                # Merge results
                all_results.update(chunk_results)
                
                logger.info(f"✅ Chunk {chunk_num}/{total_chunks} completed: {len(chunk_results)} repositories processed")
                
                # Small delay between chunks to prevent overwhelming the system
                if chunk_num < total_chunks:
                    await asyncio.sleep(0.1)
                    
            except Exception as e:
                logger.error(f"❌ Chunk {chunk_num}/{total_chunks} failed: {e}")
                # Continue with next chunk instead of failing completely
                continue
        
        logger.info(f"🎯 Chunked processing completed: {len(all_results)} total repositories processed")
        return all_results
    
    def _is_team_first_org_scan(self) -> bool:
        """Check if this is a team-first organization scan that should preserve team grouping."""
        if hasattr(self, 'scanner') and self.scanner and hasattr(self.scanner, 'config'):
            return getattr(self.scanner.config, 'team_first_org', False)
        return False
    
    async def _process_single_repository_batch(
        self,
        repository: Repository,
        strategy: BatchStrategy,
        file_patterns: Optional[List[str]]
    ) -> List[IOCMatch]:
        """Process a single repository using batch optimization.
        
        Args:
            repository: Repository to process
            strategy: Batching strategy to use
            file_patterns: Optional file patterns to focus on
            
        Returns:
            List of IOC matches found in the repository
        """
        logger.debug(f"Processing repository {repository.full_name} with strategy {strategy}")
        
        try:
            # Step 1: Discover files to scan in the repository
            target_files = await self._discover_repository_files(repository, file_patterns)
            
            logger.debug(f"Found {len(target_files)} target files in {repository.full_name}")
            
            if not target_files:
                # Log this as info for debugging team scans
                if len(target_files) == 0:
                    logger.info(f"No target files found in repository {repository.full_name}")
                return []
            
            # Step 2: Process files using batch processing with rate limit handling
            priority_files = self._get_priority_files(target_files)
            batch_file_results = await self.process_files_batch(repository, target_files, priority_files)
            
            # Step 3: Analyze file contents for IOC matches
            files_processed = len(batch_file_results.get('files', {}))
            logger.debug(f"Starting IOC analysis for {repository.full_name} with {files_processed} files")
            ioc_matches = await self._analyze_files_for_iocs(repository, batch_file_results)
            
            logger.debug(f"Found {len(ioc_matches)} IOC matches in repository {repository.full_name}")
            
            # Store file count for statistics (temporary solution)
            if not hasattr(self, '_files_processed_count'):
                self._files_processed_count = {}
            self._files_processed_count[repository.full_name] = files_processed
            
            return ioc_matches
            
        except Exception as e:
            logger.error(f"Error processing repository {repository.full_name}: {e}")
            return []
    
    async def _discover_repository_files(
        self,
        repository: Repository,
        file_patterns: Optional[List[str]]
    ) -> List[str]:
        """Discover files to scan in a repository using GitHub Tree API with graceful rate limit handling.
        
        Args:
            repository: Repository to discover files in
            file_patterns: Optional file patterns to filter by
            
        Returns:
            List of file paths to scan
        """
        try:
            # Use the full file patterns for searching
            if file_patterns:
                search_patterns = file_patterns
            else:
                # Get the full patterns from the scanner if available
                if hasattr(self, 'scanner') and self.scanner:
                    search_patterns = self.scanner._get_scan_patterns()
                else:
                    # Default patterns for package manager files
                    search_patterns = [
                        'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb',
                        'requirements.txt', 'Pipfile.lock', 'poetry.lock', 'pyproject.toml',
                        'Gemfile.lock', 'composer.lock', 'go.mod', 'go.sum', 'Cargo.lock'
                    ]
            
            logger.debug(f"Using tree API to search for {len(search_patterns)} file patterns in {repository.full_name}")
            
            # Use GitHub Tree API to get all files in the repository efficiently
            try:
                tree_response = await self._make_rate_limited_request(
                    lambda: self.github_client.get_tree_async(repository),
                    repository.full_name,
                    "tree discovery"
                )
                
                if not tree_response or not tree_response.data:
                    logger.debug(f"No tree data returned for {repository.full_name}, falling back to individual file checks")
                    return await self._discover_repository_files_fallback(repository, file_patterns)
                
                logger.debug(f"Tree API returned {len(tree_response.data) if isinstance(tree_response.data, list) else 'unknown'} entries for {repository.full_name}")
                
                # Filter tree entries for matching filenames
                found_files = []
                tree_data = tree_response.data
                
                # The tree API returns a list of tree entries or an object with a tree attribute
                tree_entries = []
                if hasattr(tree_data, 'tree'):
                    tree_entries = tree_data.tree
                elif isinstance(tree_data, list):
                    tree_entries = tree_data
                else:
                    logger.warning(f"Unexpected tree data type: {type(tree_data)}")
                    return []
                
                logger.debug(f"Processing {len(tree_entries)} tree entries for {len(search_patterns)} target patterns")
                logger.debug(f"First few search patterns: {search_patterns[:5]}")
                
                # Debug: Show first few tree entries
                if tree_entries:
                    sample_entries = []
                    for entry in tree_entries[:5]:
                        if hasattr(entry, 'path'):
                            sample_entries.append(entry.path)
                        elif isinstance(entry, dict) and 'path' in entry:
                            sample_entries.append(entry['path'])
                    logger.debug(f"Sample tree entries: {sample_entries}")
                
                for entry in tree_entries:
                    # Handle FileInfo objects (which is what we're getting)
                    if hasattr(entry, 'path'):
                        entry_path = entry.path
                        # Check if the file path matches any of our search patterns
                        filename = entry_path.split('/')[-1]
                        for pattern in search_patterns:
                            if self._matches_file_pattern(entry_path, filename, pattern):
                                found_files.append(entry_path)
                                break  # Don't add the same file multiple times
                    elif isinstance(entry, dict):
                        # Handle dictionary format (fallback)
                        if entry.get('type') == 'blob' and 'path' in entry:
                            entry_path = entry['path']
                            filename = entry_path.split('/')[-1]
                            # Check if the file path matches any of our search patterns
                            for pattern in search_patterns:
                                if self._matches_file_pattern(entry_path, filename, pattern):
                                    found_files.append(entry_path)
                                    break
                    else:
                        logger.debug(f"Unexpected entry format: {type(entry)}")
                
                logger.debug(f"Found {len(found_files)} files using tree API: {found_files[:3]}{'...' if len(found_files) > 3 else ''}")
                return found_files
                
            except RateLimitError as e:
                # Handle rate limit gracefully
                await self._handle_rate_limit_error(e, repository.full_name, "tree discovery")
                # Fall back to the old method if rate limit persists
                return await self._discover_repository_files_fallback(repository, file_patterns)
            except Exception as e:
                # Log technical details for debugging but show user-friendly message
                if self.error_formatter.should_suppress_error(e):
                    logger.debug(f"Tree API error for {repository.full_name}: {self.error_formatter.format_technical_details(e)}")
                else:
                    logger.warning(f"Tree API failed for {repository.full_name}: {e}")
                # Fall back to the old method if tree API fails
                return await self._discover_repository_files_fallback(repository, file_patterns)
            
        except Exception as e:
            # Log technical details for debugging but show user-friendly message
            if self.error_formatter.should_suppress_error(e):
                logger.debug(f"File discovery error for {repository.full_name}: {self.error_formatter.format_technical_details(e)}")
            else:
                logger.warning(f"Failed to discover files in {repository.full_name}: {e}")
            return []
    
    def _matches_file_pattern(self, full_path: str, filename: str, pattern: str) -> bool:
        """Check if a file matches a pattern, supporting both filename and path patterns."""
        import fnmatch
        
        # If pattern contains a slash, it's a path pattern
        if "/" in pattern:
            # For path patterns, check if the full path ends with the pattern
            # or if the pattern matches the full path
            if pattern.startswith("*/") or pattern.startswith("**/"):
                # Wildcard path pattern like */yarn.lock or **/yarn.lock
                return fnmatch.fnmatch(full_path, pattern)
            elif full_path.endswith("/" + pattern) or full_path == pattern:
                # Exact path match like src/yarn.lock
                return True
            else:
                # Check if pattern matches any part of the path
                # For example, pattern "src/yarn.lock" should match "some/path/src/yarn.lock"
                return fnmatch.fnmatch(full_path, "*/" + pattern) or fnmatch.fnmatch(full_path, pattern)
        else:
            # For filename-only patterns, just match the filename
            return filename == pattern or fnmatch.fnmatch(filename, pattern)
    
    async def _discover_repository_files_fallback(
        self,
        repository: Repository,
        file_patterns: Optional[List[str]]
    ) -> List[str]:
        """Fallback method for file discovery using individual file checks with rate limit handling.
        
        Args:
            repository: Repository to discover files in
            file_patterns: Optional file patterns to filter by
            
        Returns:
            List of file paths to scan
        """
        try:
            # Use the original approach as fallback
            if file_patterns:
                search_patterns = file_patterns
            else:
                # Default patterns for package manager files (including common subdirectories)
                base_patterns = [
                    'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb',
                    'requirements.txt', 'Pipfile.lock', 'poetry.lock', 'pyproject.toml',
                    'Gemfile.lock', 'composer.lock', 'go.mod', 'go.sum', 'Cargo.lock'
                ]
                
                # Common subdirectories to check
                common_subdirs = ['', 'frontend/', 'backend/', 'client/', 'server/', 'web/', 'api/', 'app/', 'src/', 'cdk/']
                
                search_patterns = []
                for subdir in common_subdirs:
                    for pattern in base_patterns:
                        search_patterns.append(subdir + pattern)
            
            # Check which files actually exist by trying to fetch them
            found_files = []
            logger.debug(f"Fallback - checking {len(search_patterns)} patterns with rate limit handling")
            
            # Limit the number of patterns to avoid too many API calls
            limited_patterns = search_patterns[:50]  # Limit to first 50 patterns
            
            for pattern in limited_patterns:
                try:
                    response = await self._make_rate_limited_request(
                        lambda: self.github_client.get_file_content_async(repository, pattern),
                        repository.full_name,
                        f"fallback file check ({pattern})"
                    )
                    if response and response.data:
                        found_files.append(pattern)
                        logger.debug(f"Fallback found {pattern}")
                except RateLimitError as e:
                    # Rate limit already handled by _make_rate_limited_request
                    logger.debug(f"Rate limit during fallback check for {pattern}")
                    continue
                except Exception as e:
                    # Log technical details for debugging but don't show to user
                    if self.error_formatter.should_suppress_error(e):
                        logger.debug(f"Fallback file check error for {pattern}: {self.error_formatter.format_technical_details(e)}")
                    else:
                        logger.debug(f"Fallback file check failed for {pattern}: {e}")
                    continue
            
            logger.debug(f"Fallback discovery completed for {repository.full_name}: {len(found_files)} files found")
            return found_files
            
        except Exception as e:
            # Log technical details for debugging but show user-friendly message
            if self.error_formatter.should_suppress_error(e):
                logger.debug(f"Fallback file discovery error for {repository.full_name}: {self.error_formatter.format_technical_details(e)}")
            else:
                logger.warning(f"Fallback file discovery failed for {repository.full_name}: {e}")
            return []
    
    def _get_priority_files(self, file_paths: List[str]) -> List[str]:
        """Get priority files from a list of file paths.
        
        Args:
            file_paths: List of file paths to analyze
            
        Returns:
            List of high-priority file paths
        """
        priority_patterns = [
            'package.json', 'requirements.txt', 'go.mod', 'Cargo.toml',
            'pyproject.toml', 'Gemfile', 'composer.json'
        ]
        
        priority_files = []
        for file_path in file_paths:
            filename = file_path.split('/')[-1].lower()
            if any(pattern in filename for pattern in priority_patterns):
                priority_files.append(file_path)
        
        return priority_files
    
    async def _make_rate_limited_request(self, request_func, repo_name: str, operation: str):
        """Make a request with rate limit handling and progress tracking.
        
        Args:
            request_func: Function that makes the actual request
            repo_name: Repository name for logging
            operation: Description of the operation for logging
            
        Returns:
            Response from the request function
        """
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # Check if we're currently rate limited
                if self.rate_limit_manager.is_rate_limited():
                    wait_time = self.rate_limit_manager.get_wait_time()
                    if self.rate_limit_manager.should_show_message():
                        user_message = self.error_formatter.format_waiting_message(wait_time)
                        logger.info(f"⏳ {user_message}")
                    
                    # Update progress tracking to account for rate limit delay
                    await self._update_progress_for_rate_limit_delay(wait_time, operation)
                    
                    # Wait for rate limit to reset
                    await asyncio.sleep(wait_time)
                    self.rate_limit_manager.clear_expired_limits()
                
                # Make the request
                return await request_func()
                
            except RateLimitError as e:
                retry_count += 1
                await self._handle_rate_limit_error(e, repo_name, operation)
                
                if retry_count >= max_retries:
                    logger.warning(f"Max retries exceeded for {operation} on {repo_name}")
                    raise
                    
            except Exception as e:
                # For non-rate-limit errors, don't retry
                raise
        
        return None
    
    async def _handle_rate_limit_error(self, error: RateLimitError, repo_name: str, operation: str):
        """Handle a rate limit error with user-friendly messaging and progress tracking.
        
        Args:
            error: The rate limit error that occurred
            repo_name: Repository name for context
            operation: Operation that was being performed
        """
        # Extract reset time from error if available
        reset_time = self.error_formatter.extract_reset_time_from_exception(error)
        if not reset_time:
            # Default to 60 seconds if no reset time available
            from datetime import datetime, timedelta
            reset_time = datetime.now() + timedelta(seconds=60)
        
        # Update rate limit manager
        is_secondary = 'secondary' in str(error).lower() or 'abuse' in str(error).lower()
        self.rate_limit_manager.handle_rate_limit(reset_time, is_secondary)
        
        # Show user-friendly message if appropriate
        if self.rate_limit_manager.should_show_message():
            user_message = self.error_formatter.format_rate_limit_message(reset_time, repo_name)
            logger.info(f"🚦 {user_message}")
        
        # Log technical details for debugging
        technical_details = self.error_formatter.format_technical_details(error)
        logger.debug(f"Rate limit details for {operation} on {repo_name}: {technical_details}")
        
        # Update progress tracking
        wait_time = self.rate_limit_manager.get_wait_time()
        await self._update_progress_for_rate_limit_delay(wait_time, operation)
    
    async def _update_progress_for_rate_limit_delay(self, wait_time: int, operation: str):
        """Update progress tracking to account for rate limit delays.
        
        Args:
            wait_time: Number of seconds to wait
            operation: Operation being delayed
        """
        # Update the progress monitor's ETA calculation to account for the delay
        if hasattr(self.progress_monitor, 'add_delay'):
            self.progress_monitor.add_delay(wait_time, f"Rate limit delay for {operation}")
        
        # Log progress update with rate limit context
        logger.debug(f"Progress tracking: Adding {wait_time}s delay for rate limit during {operation}")
    
    def get_coordination_statistics(self) -> Dict[str, Any]:
        """Get comprehensive coordination statistics including rate limit info.
        
        Returns:
            Dictionary with coordination statistics
        """
        base_stats = self.cache_coordinator.get_coordination_statistics()
        
        # Add rate limit statistics
        rate_limit_stats = self.rate_limit_manager.get_status_summary()
        
        # Combine statistics
        comprehensive_stats = {
            **base_stats,
            'rate_limit_status': rate_limit_stats,
            'active_operations': len(self.active_operations),
            'total_operations': self.operation_counter
        }
        
        return comprehensive_stats
    
    async def _analyze_files_for_iocs(
        self,
        repository: Repository,
        file_results: Dict[str, Any]
    ) -> List[IOCMatch]:
        """Analyze file contents for IOC matches.
        
        Args:
            repository: Repository being analyzed
            file_results: Results from file batch processing
            
        Returns:
            List of IOC matches found
        """
        from .ioc_loader import IOCLoader
        from .parsers.factory import get_parser, parse_file_safely
        # Import parsers module to ensure all parsers are registered
        from . import parsers
        from .models import IOCMatch, FileContent
        
        ioc_matches = []
        
        try:
            # Load IOC definitions (cached for performance)
            if not hasattr(self, '_cached_ioc_definitions'):
                # Get the issues directory from the scanner if available
                # None means use built-in IOC definitions from the package
                issues_dir = None
                if hasattr(self, 'scanner') and self.scanner and hasattr(self.scanner, 'config'):
                    issues_dir = self.scanner.config.issues_dir  # None uses built-in IOCs
                
                ioc_loader = IOCLoader(issues_dir)
                self._cached_ioc_definitions = ioc_loader.load_iocs()
                logger.debug(f"Cached IOC definitions from {issues_dir}")
            
            ioc_definitions = self._cached_ioc_definitions
            
            # Process each file
            files = file_results.get('files', {})
            for file_path, file_data in files.items():
                if 'error' in file_data:
                    logger.warning(f"Skipping file {file_path} due to error: {file_data['error']}")
                    continue
                
                if 'content' not in file_data:
                    logger.debug(f"No content available for {file_path}")
                    continue
                
                try:
                    # Handle both string content and FileContent objects
                    content_data = file_data['content']
                    if isinstance(content_data, FileContent):
                        # Already a FileContent object
                        file_content = content_data
                        actual_content = content_data.content
                    else:
                        # String content, create FileContent object
                        file_content = FileContent(
                            content=content_data,
                            sha=file_data.get('sha', 'unknown'),
                            size=len(content_data)
                        )
                        actual_content = content_data
                    
                    # Parse packages from file content
                    packages = parse_file_safely(file_path, actual_content)
                    
                    if not packages:
                        logger.debug(f"No packages found in {file_path}")
                        continue
                    
                    logger.debug(f"Found {len(packages)} packages in {file_path}")
                    
                    # Check packages against IOC definitions
                    for package in packages:
                        package_name = package.name
                        version = package.version
                        logger.debug(f"Checking package {package_name}@{version}")
                        for ioc_file, ioc_definition in ioc_definitions.items():
                            if package_name in ioc_definition.packages:
                                ioc_versions = ioc_definition.packages[package_name]
                                logger.debug(f"Found IOC package {package_name}, checking version {version} against {ioc_versions}")
                                
                                # Check if this version matches IOC criteria
                                if ioc_versions is None or version in ioc_versions:
                                    ioc_match = IOCMatch(
                                        repo=repository.full_name,
                                        file_path=file_path,
                                        package_name=package_name,
                                        version=version,
                                        ioc_source=ioc_file
                                    )
                                    ioc_matches.append(ioc_match)
                                    logger.info(f"IOC match found: {package_name}@{version} in {repository.full_name}/{file_path}")
                    
                except Exception as e:
                    logger.warning(f"Failed to analyze file {file_path}: {e}")
                    continue
            
            logger.debug(f"Found {len(ioc_matches)} IOC matches in {repository.full_name}")
            return ioc_matches
            
        except Exception as e:
            logger.error(f"Failed to analyze files for IOCs in {repository.full_name}: {e}")
            return []
    
    async def _create_prioritized_batch_requests(
        self,
        repo: Repository,
        file_paths: List[str],
        priority_files: Optional[List[str]]
    ) -> List[BatchRequest]:
        """Create prioritized batch requests for file processing.
        
        Args:
            repo: Repository containing the files
            file_paths: List of file paths to process
            priority_files: Optional list of high-priority files
            
        Returns:
            List of prioritized batch requests
        """
        # Prioritize files using strategy manager
        prioritized_files = self.strategy_manager.prioritize_files(file_paths)
        
        # Create batch requests
        batch_requests = []
        for prioritized_file in prioritized_files:
            # Boost priority for explicitly requested priority files
            priority = prioritized_file.priority
            if priority_files and prioritized_file.path in priority_files:
                priority += 5  # Boost priority
            
            request = BatchRequest(
                repo=repo,
                file_path=prioritized_file.path,
                priority=priority,
                estimated_size=prioritized_file.estimated_size
            )
            batch_requests.append(request)
        
        logger.debug(f"Created {len(batch_requests)} prioritized batch requests")
        return batch_requests
    
    async def _process_uncached_requests(self, requests: List[BatchRequest]) -> List[BatchResult]:
        """Process requests that were not served from cache.
        
        Args:
            requests: List of uncached batch requests
            
        Returns:
            List of batch results from API processing
        """
        if not requests:
            return []
        
        # Determine optimal batch size
        file_sizes = {req.file_path: req.estimated_size for req in requests}
        file_paths = [req.file_path for req in requests]
        
        # Get current rate limit info (simplified)
        rate_limit_remaining = 5000  # Default assumption
        
        optimal_batch_size = self.strategy_manager.calculate_optimal_batch_size(
            file_paths, file_sizes, rate_limit_remaining
        )
        
        # Process in optimal-sized batches
        results = []
        total = len(requests)
        for i in range(0, len(requests), optimal_batch_size):
            batch = requests[i:i + optimal_batch_size]
            batch_results = await self.parallel_processor.process_batch_parallel(batch)
            results.extend(batch_results)
            completed = min(i + optimal_batch_size, total)
            self._report_progress(completed, total, len(batch), None)
        
        return results
    
    async def _format_file_batch_results(self, results: List[BatchResult]) -> Dict[str, Any]:
        """Format batch results for return to caller.
        
        Args:
            results: List of batch results to format
            
        Returns:
            Flat dictionary mapping file paths to their content (successful files only).
            Files that failed are excluded from the result.
        """
        formatted = {}
        
        for result in results:
            if result.success and result.content:
                formatted[result.request.file_path] = result.content
        
        return formatted
    
    async def _adapt_strategy_from_results(self, results: Dict[str, Any]) -> None:
        """Adapt batching strategy based on processing results.
        
        Args:
            results: Processing results to analyze
        """
        try:
            # Analyze results and update strategy if needed
            # This is a simplified implementation
            current_metrics = self.get_batch_metrics()
            
            if current_metrics.success_rate < 80:
                # Poor success rate - switch to more conservative strategy
                if self.current_strategy == BatchStrategy.AGGRESSIVE:
                    self.current_strategy = BatchStrategy.ADAPTIVE
                    logger.info("Adapted strategy to ADAPTIVE due to low success rate")
            elif current_metrics.success_rate > 95 and current_metrics.parallel_efficiency > 0.8:
                # Excellent performance - can be more aggressive
                if self.current_strategy == BatchStrategy.CONSERVATIVE:
                    self.current_strategy = BatchStrategy.ADAPTIVE
                    logger.info("Adapted strategy to ADAPTIVE due to good performance")
            
        except Exception as e:
            logger.warning(f"Error adapting strategy from results: {e}")
    
    async def _create_operation(self, operation_type: str, metadata: Dict[str, Any]) -> str:
        """Create a new batch operation with tracking.
        
        Args:
            operation_type: Type of operation
            metadata: Operation metadata
            
        Returns:
            Operation ID
        """
        async with self._coordination_lock:
            self.operation_counter += 1
            operation_id = f"{operation_type}_{self.operation_counter}_{int(time.time())}"
            
            self.active_operations[operation_id] = {
                'type': operation_type,
                'start_time': datetime.now(),
                'metadata': metadata,
                'status': 'active'
            }
            
            logger.debug(f"Created operation {operation_id} of type {operation_type}")
            return operation_id
    
    async def _complete_operation(
        self, 
        operation_id: str, 
        success: bool, 
        error: Optional[str] = None
    ) -> None:
        """Complete a batch operation and update tracking.
        
        Args:
            operation_id: Operation ID to complete
            success: Whether the operation was successful
            error: Optional error message if failed
        """
        async with self._coordination_lock:
            if operation_id in self.active_operations:
                operation = self.active_operations[operation_id]
                operation['status'] = 'completed' if success else 'failed'
                operation['end_time'] = datetime.now()
                operation['duration'] = (operation['end_time'] - operation['start_time']).total_seconds()
                
                if error:
                    operation['error'] = error
                
                # Move to history
                self.operation_history.append(operation)
                del self.active_operations[operation_id]
                
                # Keep only recent history
                if len(self.operation_history) > 100:
                    self.operation_history = self.operation_history[-50:]
                
                logger.debug(f"Completed operation {operation_id}: {'success' if success else 'failed'}")
    
    async def _wait_for_active_operations(self, timeout: float = 30.0) -> None:
        """Wait for all active operations to complete.
        
        Args:
            timeout: Maximum time to wait in seconds
        """
        start_time = time.time()
        
        while self.active_operations and (time.time() - start_time) < timeout:
            await asyncio.sleep(0.1)
        
        if self.active_operations:
            logger.warning(f"Timeout waiting for {len(self.active_operations)} operations to complete")
    
    def _calculate_average_batch_size(self) -> float:
        """Calculate average batch size from operation history.
        
        Returns:
            Average batch size
        """
        if not self.operation_history:
            return 0.0
        
        total_items = 0
        total_operations = 0
        
        for operation in self.operation_history[-10:]:  # Last 10 operations
            if operation['type'] == 'files_batch':
                total_items += operation['metadata'].get('file_count', 0)
                total_operations += 1
            elif operation['type'] == 'repositories_batch':
                total_items += operation['metadata'].get('repository_count', 0)
                total_operations += 1
        
        return total_items / total_operations if total_operations > 0 else 0.0
    
    def get_coordination_statistics(self) -> Dict[str, Any]:
        """Get comprehensive coordination statistics.
        
        Returns:
            Dictionary containing coordination statistics
        """
        return {
            'coordinator': {
                'active_operations': len(self.active_operations),
                'completed_operations': len(self.operation_history),
                'current_strategy': self.current_strategy.value,
                'strategy_adaptation_enabled': self.strategy_adaptation_enabled,
                'average_batch_size': self._calculate_average_batch_size()
            },
            'cache_coordination': self.cache_coordinator.get_coordination_statistics(),
            'parallel_processing': {
                'current_concurrency': self.parallel_processor.get_current_concurrency(),
                'metrics': self.parallel_processor.get_metrics().__dict__
            }
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
    
    def get_total_files_processed(self) -> int:
        """Get the total number of files processed in the last batch operation."""
        if hasattr(self, '_last_batch_files_processed'):
            return self._last_batch_files_processed
        elif hasattr(self, '_files_processed_count'):
            return sum(self._files_processed_count.values())
        return 0