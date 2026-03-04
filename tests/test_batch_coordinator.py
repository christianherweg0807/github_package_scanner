"""Tests for the BatchCoordinator class."""

import asyncio
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from src.github_ioc_scanner.async_github_client import AsyncGitHubClient
from src.github_ioc_scanner.batch_cache_coordinator import BatchCacheCoordinator
from src.github_ioc_scanner.batch_coordinator import BatchCoordinator
from src.github_ioc_scanner.batch_models import (
    BatchConfig, BatchMetrics, BatchRequest, BatchResult, BatchStrategy,
    CrossRepoBatch, PrioritizedFile
)
from src.github_ioc_scanner.batch_strategy_manager import BatchStrategyManager
from src.github_ioc_scanner.cache_manager import CacheManager
from src.github_ioc_scanner.exceptions import BatchProcessingError, ConfigurationError
from src.github_ioc_scanner.models import Repository, FileContent
from src.github_ioc_scanner.parallel_batch_processor import ParallelBatchProcessor


@pytest.fixture
def mock_github_client():
    """Create a mock async GitHub client."""
    client = AsyncMock(spec=AsyncGitHubClient)
    return client


@pytest.fixture
def mock_cache_manager():
    """Create a mock cache manager."""
    cache_manager = MagicMock(spec=CacheManager)
    return cache_manager


@pytest.fixture
def batch_config():
    """Create a test batch configuration."""
    return BatchConfig(
        max_concurrent_requests=5,
        max_concurrent_repos=2,
        default_batch_size=10,
        max_batch_size=20,
        min_batch_size=1,
        enable_cross_repo_batching=True,
        enable_file_prioritization=True
    )


@pytest.fixture
def sample_repositories():
    """Create sample repositories for testing."""
    from datetime import datetime
    return [
        Repository(name="repo1", full_name="org/repo1", archived=False, default_branch="main", updated_at=datetime.now()),
        Repository(name="repo2", full_name="org/repo2", archived=False, default_branch="main", updated_at=datetime.now()),
        Repository(name="repo3", full_name="org/repo3", archived=False, default_branch="main", updated_at=datetime.now())
    ]


@pytest.fixture
def sample_file_paths():
    """Create sample file paths for testing."""
    return [
        "package.json",
        "requirements.txt",
        "src/main.py",
        "README.md",
        "go.mod"
    ]


@pytest.fixture
def batch_coordinator(mock_github_client, mock_cache_manager, batch_config):
    """Create a batch coordinator for testing."""
    coordinator = BatchCoordinator(
        github_client=mock_github_client,
        cache_manager=mock_cache_manager,
        config=batch_config
    )
    
    # Mock the sub-components to avoid actual initialization
    coordinator.cache_coordinator = AsyncMock(spec=BatchCacheCoordinator)
    coordinator.strategy_manager = MagicMock(spec=BatchStrategyManager)
    coordinator.parallel_processor = MagicMock(spec=ParallelBatchProcessor)
    
    # Setup default mock behaviors
    coordinator.cache_coordinator.start = AsyncMock()
    coordinator.cache_coordinator.stop = AsyncMock()
    coordinator.cache_coordinator.coordinate_batch_operation = AsyncMock(return_value=([], []))
    coordinator.cache_coordinator.finalize_batch_operation = AsyncMock()
    coordinator.cache_coordinator.get_coordination_statistics = MagicMock(return_value={
        'batch_cache': {'batch_hits': 0, 'batch_misses': 0},
        'cache_warming': {},
        'cache_efficiency': {}
    })
    
    coordinator.strategy_manager.identify_cross_repo_opportunities = MagicMock(return_value=[])
    coordinator.strategy_manager.prioritize_files = MagicMock(return_value=[])
    coordinator.strategy_manager.calculate_optimal_batch_size = MagicMock(return_value=10)
    coordinator.strategy_manager.adapt_strategy = MagicMock(return_value=BatchStrategy.ADAPTIVE)
    
    coordinator.parallel_processor.get_metrics = MagicMock(return_value=BatchMetrics())
    coordinator.parallel_processor.get_current_concurrency = MagicMock(return_value=5)
    coordinator.parallel_processor.process_batch_parallel = AsyncMock(return_value=[])
    
    return coordinator


class TestBatchCoordinatorInitialization:
    """Test BatchCoordinator initialization."""
    
    def test_init_with_valid_config(self, mock_github_client, mock_cache_manager, batch_config):
        """Test initialization with valid configuration."""
        coordinator = BatchCoordinator(
            github_client=mock_github_client,
            cache_manager=mock_cache_manager,
            config=batch_config
        )
        
        assert coordinator.github_client == mock_github_client
        assert coordinator.cache_manager == mock_cache_manager
        assert coordinator.config == batch_config
        assert coordinator.current_strategy == batch_config.default_strategy
        assert coordinator.strategy_adaptation_enabled is True
        assert len(coordinator.active_operations) == 0
        assert coordinator.operation_counter == 0
    
    def test_init_with_default_config(self, mock_github_client, mock_cache_manager):
        """Test initialization with default configuration."""
        coordinator = BatchCoordinator(
            github_client=mock_github_client,
            cache_manager=mock_cache_manager
        )
        
        assert coordinator.config is not None
        assert isinstance(coordinator.config, BatchConfig)
        assert coordinator.config.default_batch_size == 25  # Updated to match current default
    
    def test_init_with_invalid_config(self, mock_github_client, mock_cache_manager):
        """Test initialization with invalid configuration."""
        invalid_config = BatchConfig(
            max_concurrent_requests=0,  # Invalid
            min_batch_size=-1  # Invalid
        )
        
        with pytest.raises(ConfigurationError):
            BatchCoordinator(
                github_client=mock_github_client,
                cache_manager=mock_cache_manager,
                config=invalid_config
            )


class TestBatchCoordinatorLifecycle:
    """Test BatchCoordinator lifecycle management."""
    
    @pytest.mark.asyncio
    async def test_start_success(self, batch_coordinator):
        """Test successful coordinator startup."""
        await batch_coordinator.start()
        
        batch_coordinator.cache_coordinator.start.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_start_failure(self, batch_coordinator):
        """Test coordinator startup failure."""
        batch_coordinator.cache_coordinator.start.side_effect = Exception("Startup failed")
        
        with pytest.raises(BatchProcessingError):
            await batch_coordinator.start()
    
    @pytest.mark.asyncio
    async def test_stop_success(self, batch_coordinator):
        """Test successful coordinator shutdown."""
        await batch_coordinator.stop()
        
        batch_coordinator.cache_coordinator.stop.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_stop_with_active_operations(self, batch_coordinator):
        """Test coordinator shutdown with active operations."""
        # Add a mock active operation
        batch_coordinator.active_operations["test_op"] = {
            'type': 'test',
            'start_time': datetime.now(),
            'status': 'active'
        }
        
        # Mock the wait method to immediately clear operations
        async def mock_wait():
            batch_coordinator.active_operations.clear()
        
        batch_coordinator._wait_for_active_operations = AsyncMock(side_effect=mock_wait)
        
        await batch_coordinator.stop()
        
        batch_coordinator._wait_for_active_operations.assert_called_once()
        batch_coordinator.cache_coordinator.stop.assert_called_once()


class TestRepositoryBatchProcessing:
    """Test repository batch processing functionality."""
    
    @pytest.mark.asyncio
    async def test_process_repositories_batch_empty(self, batch_coordinator):
        """Test processing empty repository list."""
        result = await batch_coordinator.process_repositories_batch([])
        
        assert result == {}
    
    @pytest.mark.asyncio
    async def test_process_repositories_batch_basic(self, batch_coordinator, sample_repositories):
        """Test basic repository batch processing."""
        # Mock the internal methods
        batch_coordinator._analyze_cross_repo_opportunities = AsyncMock(return_value=[])
        batch_coordinator.optimize_repository_processing_order = AsyncMock(return_value=sample_repositories)
        batch_coordinator._select_optimal_strategy = AsyncMock(return_value=BatchStrategy.ADAPTIVE)
        batch_coordinator._process_repositories_sequentially = AsyncMock(return_value={
            'org/repo1': [],
            'org/repo2': [],
            'org/repo3': []
        })
        batch_coordinator._adapt_strategy_from_results = AsyncMock()
        batch_coordinator._create_operation = AsyncMock(return_value="test_op_1")
        batch_coordinator._complete_operation = AsyncMock()
        
        result = await batch_coordinator.process_repositories_batch(sample_repositories)
        
        assert len(result) == 3
        assert 'org/repo1' in result
        assert 'org/repo2' in result
        assert 'org/repo3' in result
        
        batch_coordinator._create_operation.assert_called_once()
        batch_coordinator._complete_operation.assert_called_once_with("test_op_1", success=True)
    
    @pytest.mark.asyncio
    async def test_process_repositories_batch_with_cross_repo(self, batch_coordinator, sample_repositories):
        """Test repository batch processing with cross-repo opportunities.
        
        Note: Cross-repo batching is currently disabled in the implementation
        (if False and cross_repo_opportunities), so this test verifies the
        sequential processing path is used instead.
        """
        cross_repo_opportunity = CrossRepoBatch(
            repositories=sample_repositories[:2],
            common_files=['package.json', 'requirements.txt'],
            estimated_savings=0.3
        )
        
        # Mock the internal methods
        batch_coordinator._analyze_cross_repo_opportunities = AsyncMock(return_value=[cross_repo_opportunity])
        batch_coordinator.optimize_repository_processing_order = AsyncMock(return_value=sample_repositories)
        batch_coordinator._select_optimal_strategy = AsyncMock(return_value=BatchStrategy.ADAPTIVE)
        # Since cross-repo batching is disabled, sequential processing is used
        batch_coordinator._process_repositories_sequentially = AsyncMock(return_value={
            'org/repo1': [],
            'org/repo2': [],
            'org/repo3': []
        })
        batch_coordinator._adapt_strategy_from_results = AsyncMock()
        batch_coordinator._create_operation = AsyncMock(return_value="test_op_1")
        batch_coordinator._complete_operation = AsyncMock()
        
        result = await batch_coordinator.process_repositories_batch(sample_repositories)
        
        # All 3 repositories should be processed sequentially
        assert len(result) == 3
        batch_coordinator._process_repositories_sequentially.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_repositories_batch_failure(self, batch_coordinator, sample_repositories):
        """Test repository batch processing failure handling."""
        batch_coordinator._analyze_cross_repo_opportunities = AsyncMock(side_effect=Exception("Analysis failed"))
        batch_coordinator._create_operation = AsyncMock(return_value="test_op_1")
        batch_coordinator._complete_operation = AsyncMock()
        
        with pytest.raises(BatchProcessingError):
            await batch_coordinator.process_repositories_batch(sample_repositories)
        
        batch_coordinator._complete_operation.assert_called_once_with(
            "test_op_1", success=False, error="Analysis failed"
        )
    
    @pytest.mark.asyncio
    async def test_process_organization_repositories_batch(self, batch_coordinator):
        """Test processing organization repositories with batch optimization."""
        # Mock organization repository discovery
        batch_coordinator._discover_organization_repositories = AsyncMock(return_value=[
            Repository(name="repo1", full_name="org/repo1", archived=False, default_branch="main", updated_at=datetime.now()),
            Repository(name="repo2", full_name="org/repo2", archived=False, default_branch="main", updated_at=datetime.now())
        ])
        
        # Mock cache optimization
        batch_coordinator.cache_coordinator.optimize_cache_for_scan_pattern = AsyncMock(return_value={})
        
        # Mock repository batch processing
        batch_coordinator.process_repositories_batch = AsyncMock(return_value={
            'org/repo1': [],
            'org/repo2': []
        })
        
        batch_coordinator._create_operation = AsyncMock(return_value="test_op_1")
        batch_coordinator._complete_operation = AsyncMock()
        
        result = await batch_coordinator.process_organization_repositories_batch("test-org")
        
        assert len(result) == 2
        assert 'org/repo1' in result
        assert 'org/repo2' in result
        
        batch_coordinator._discover_organization_repositories.assert_called_once_with("test-org", None, None)
        batch_coordinator.cache_coordinator.optimize_cache_for_scan_pattern.assert_called_once()
        batch_coordinator.process_repositories_batch.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_calculate_repository_priority(self, batch_coordinator, sample_repositories):
        """Test repository priority calculation."""
        repo = sample_repositories[0]
        
        priority = await batch_coordinator._calculate_repository_priority(repo)
        
        assert isinstance(priority, float)
        assert priority >= 0.0
    
    @pytest.mark.asyncio
    async def test_optimize_repository_processing_order(self, batch_coordinator, sample_repositories):
        """Test repository processing order optimization."""
        cross_repo_opportunities = [
            CrossRepoBatch(
                repositories=sample_repositories[:2],
                common_files=['package.json'],
                estimated_savings=0.4
            )
        ]
        
        # Mock prioritization
        batch_coordinator._prioritize_repositories = AsyncMock(return_value=sample_repositories)
        
        optimized_order = await batch_coordinator.optimize_repository_processing_order(
            sample_repositories, cross_repo_opportunities
        )
        
        assert len(optimized_order) == len(sample_repositories)
        assert all(repo in optimized_order for repo in sample_repositories)
    
    @pytest.mark.asyncio
    async def test_process_single_repository_batch(self, batch_coordinator, sample_repositories):
        """Test processing a single repository with batch optimization."""
        repo = sample_repositories[0]
        
        # Mock internal methods
        batch_coordinator._discover_repository_files = AsyncMock(return_value=['package.json', 'requirements.txt'])
        batch_coordinator.process_files_batch = AsyncMock(return_value={'files': {}, 'metadata': {}})
        batch_coordinator._analyze_files_for_iocs = AsyncMock(return_value=[])
        batch_coordinator._get_priority_files = MagicMock(return_value=['package.json'])
        
        result = await batch_coordinator._process_single_repository_batch(
            repo, BatchStrategy.ADAPTIVE, None
        )
        
        assert isinstance(result, list)
        batch_coordinator._discover_repository_files.assert_called_once()
        batch_coordinator.process_files_batch.assert_called_once()
        batch_coordinator._analyze_files_for_iocs.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_discover_repository_files(self, batch_coordinator, sample_repositories):
        """Test repository file discovery."""
        from src.github_ioc_scanner.models import APIResponse, FileInfo
        
        repo = sample_repositories[0]
        
        # Mock tree response with file entries
        mock_tree_data = [
            FileInfo(path="package.json", sha="abc123", size=1024),
            FileInfo(path="requirements.txt", sha="def456", size=512),
            FileInfo(path="src/main.py", sha="ghi789", size=2048),
        ]
        
        batch_coordinator.github_client.get_tree_async = AsyncMock(
            return_value=APIResponse(data=mock_tree_data)
        )
        
        files = await batch_coordinator._discover_repository_files(repo, None)
        
        assert isinstance(files, list)
        assert len(files) > 0
        assert 'package.json' in files
        assert 'requirements.txt' in files
    
    @pytest.mark.asyncio
    async def test_discover_repository_files_with_patterns(self, batch_coordinator, sample_repositories):
        """Test repository file discovery with patterns."""
        from src.github_ioc_scanner.models import APIResponse, FileInfo
        
        repo = sample_repositories[0]
        patterns = ['package.json', 'requirements.txt']
        
        # Mock tree response with file entries
        mock_tree_data = [
            FileInfo(path="package.json", sha="abc123", size=1024),
            FileInfo(path="requirements.txt", sha="def456", size=512),
            FileInfo(path="src/main.py", sha="ghi789", size=2048),
        ]
        
        batch_coordinator.github_client.get_tree_async = AsyncMock(
            return_value=APIResponse(data=mock_tree_data)
        )
        
        files = await batch_coordinator._discover_repository_files(repo, patterns)
        
        assert isinstance(files, list)
        # Files should match the patterns
        assert 'package.json' in files or 'requirements.txt' in files
    
    def test_get_priority_files(self, batch_coordinator):
        """Test priority file identification."""
        file_paths = ['package.json', 'src/main.py', 'requirements.txt', 'README.md', 'go.mod']
        
        priority_files = batch_coordinator._get_priority_files(file_paths)
        
        assert 'package.json' in priority_files
        assert 'requirements.txt' in priority_files
        assert 'go.mod' in priority_files
        assert 'src/main.py' not in priority_files
        assert 'README.md' not in priority_files


class TestFileBatchProcessing:
    """Test file batch processing functionality."""
    
    @pytest.mark.asyncio
    async def test_process_files_batch_empty(self, batch_coordinator, sample_repositories):
        """Test processing empty file list."""
        result = await batch_coordinator.process_files_batch(sample_repositories[0], [])
        
        assert result == {}
    
    @pytest.mark.asyncio
    async def test_process_files_batch_basic(self, batch_coordinator, sample_repositories, sample_file_paths):
        """Test basic file batch processing."""
        repo = sample_repositories[0]
        
        # Mock prioritized files
        prioritized_files = [
            PrioritizedFile(path=path, priority=5, file_type="unknown", estimated_size=1000)
            for path in sample_file_paths
        ]
        batch_coordinator.strategy_manager.prioritize_files.return_value = prioritized_files
        
        # Mock batch requests
        batch_requests = [
            BatchRequest(repo=repo, file_path=path, priority=5, estimated_size=1000)
            for path in sample_file_paths
        ]
        
        # Mock cache coordination
        cached_results = [
            BatchResult(
                request=batch_requests[0],
                content=FileContent(content="cached content", sha="abc123", size=100),
                from_cache=True
            )
        ]
        uncached_requests = batch_requests[1:]
        
        batch_coordinator.cache_coordinator.coordinate_batch_operation.return_value = (
            cached_results, uncached_requests
        )
        
        # Mock API processing
        api_results = [
            BatchResult(
                request=req,
                content=FileContent(content="api content", sha="def456", size=200),
                from_cache=False
            )
            for req in uncached_requests
        ]
        
        batch_coordinator._create_prioritized_batch_requests = AsyncMock(return_value=batch_requests)
        batch_coordinator._process_uncached_requests = AsyncMock(return_value=api_results)
        batch_coordinator._format_file_batch_results = AsyncMock(return_value={
            'files': {path: {'content': 'content'} for path in sample_file_paths},
            'metadata': {'total_files': len(sample_file_paths)}
        })
        batch_coordinator._create_operation = AsyncMock(return_value="test_op_1")
        batch_coordinator._complete_operation = AsyncMock()
        
        result = await batch_coordinator.process_files_batch(repo, sample_file_paths)
        
        assert 'files' in result
        assert 'metadata' in result
        assert result['metadata']['total_files'] == len(sample_file_paths)
        
        batch_coordinator._create_operation.assert_called_once()
        batch_coordinator._complete_operation.assert_called_once_with("test_op_1", success=True)
    
    @pytest.mark.asyncio
    async def test_process_files_batch_with_priority(self, batch_coordinator, sample_repositories, sample_file_paths):
        """Test file batch processing with priority files."""
        repo = sample_repositories[0]
        priority_files = ["package.json", "requirements.txt"]
        
        # Mock the internal methods
        batch_coordinator._create_prioritized_batch_requests = AsyncMock(return_value=[])
        batch_coordinator._process_uncached_requests = AsyncMock(return_value=[])
        batch_coordinator._format_file_batch_results = AsyncMock(return_value={'files': {}, 'metadata': {}})
        batch_coordinator._create_operation = AsyncMock(return_value="test_op_1")
        batch_coordinator._complete_operation = AsyncMock()
        
        await batch_coordinator.process_files_batch(repo, sample_file_paths, priority_files)
        
        # Verify priority files were passed to the request creation
        call_args = batch_coordinator._create_prioritized_batch_requests.call_args
        assert call_args[0][2] == priority_files  # Third argument should be priority_files
    
    @pytest.mark.asyncio
    async def test_process_files_batch_failure(self, batch_coordinator, sample_repositories, sample_file_paths):
        """Test file batch processing failure handling."""
        repo = sample_repositories[0]
        
        batch_coordinator._create_prioritized_batch_requests = AsyncMock(
            side_effect=Exception("Request creation failed")
        )
        batch_coordinator._create_operation = AsyncMock(return_value="test_op_1")
        batch_coordinator._complete_operation = AsyncMock()
        
        with pytest.raises(BatchProcessingError):
            await batch_coordinator.process_files_batch(repo, sample_file_paths)
        
        batch_coordinator._complete_operation.assert_called_once_with(
            "test_op_1", success=False, error="Request creation failed"
        )


class TestBatchMetrics:
    """Test batch metrics functionality."""
    
    @pytest.mark.asyncio
    async def test_get_batch_metrics(self, batch_coordinator):
        """Test getting comprehensive batch metrics."""
        # Mock component metrics
        parallel_metrics = BatchMetrics(
            total_requests=100,
            successful_requests=95,
            failed_requests=5,
            total_processing_time=10.5,
            parallel_efficiency=0.85
        )
        batch_coordinator.parallel_processor.get_metrics.return_value = parallel_metrics
        
        coordination_stats = {
            'batch_cache': {
                'batch_cache_hits': 50,
                'batch_cache_misses': 45
            }
        }
        batch_coordinator.cache_coordinator.get_coordination_statistics.return_value = coordination_stats
        
        # Mock average batch size calculation
        batch_coordinator._calculate_average_batch_size = MagicMock(return_value=12.5)
        
        metrics = batch_coordinator.get_batch_metrics()
        
        assert isinstance(metrics, BatchMetrics)
        assert metrics.total_requests >= 100
        assert metrics.successful_requests >= 95
        assert metrics.cache_hits == 50
        assert metrics.cache_misses == 45
        assert metrics.parallel_efficiency == 0.85


class TestStrategyAdaptation:
    """Test strategy adaptation functionality."""
    
    @pytest.mark.asyncio
    async def test_select_optimal_strategy_large_repos(self, batch_coordinator, sample_repositories):
        """Test strategy selection for large number of repositories."""
        # Create a large list of repositories
        large_repo_list = sample_repositories * 5  # 15 repositories
        
        # Mock recent metrics with good performance
        good_metrics = BatchMetrics(total_requests=100, successful_requests=95, parallel_efficiency=0.8)
        batch_coordinator.parallel_processor.get_metrics.return_value = good_metrics
        batch_coordinator.strategy_manager.adapt_strategy.return_value = BatchStrategy.SEQUENTIAL
        
        strategy = await batch_coordinator._select_optimal_strategy(large_repo_list)
        
        # Should upgrade to parallel for large number of repos
        assert strategy == BatchStrategy.PARALLEL
    
    @pytest.mark.asyncio
    async def test_select_optimal_strategy_small_repos(self, batch_coordinator, sample_repositories):
        """Test strategy selection for small number of repositories."""
        small_repo_list = sample_repositories[:2]  # 2 repositories
        
        # Mock recent metrics
        metrics = BatchMetrics(total_requests=50, successful_requests=48)
        batch_coordinator.parallel_processor.get_metrics.return_value = metrics
        batch_coordinator.strategy_manager.adapt_strategy.return_value = BatchStrategy.AGGRESSIVE
        
        strategy = await batch_coordinator._select_optimal_strategy(small_repo_list)
        
        # Should downgrade to adaptive for small number of repos
        assert strategy == BatchStrategy.ADAPTIVE
    
    @pytest.mark.asyncio
    async def test_adapt_strategy_from_results_poor_performance(self, batch_coordinator):
        """Test strategy adaptation for poor performance."""
        batch_coordinator.current_strategy = BatchStrategy.AGGRESSIVE
        
        # Mock poor performance metrics
        poor_metrics = BatchMetrics(
            total_requests=100,
            successful_requests=70,  # 70% success rate
            parallel_efficiency=0.5
        )
        batch_coordinator.get_batch_metrics = MagicMock(return_value=poor_metrics)
        
        await batch_coordinator._adapt_strategy_from_results({})
        
        # Should adapt to more conservative strategy
        assert batch_coordinator.current_strategy == BatchStrategy.ADAPTIVE
    
    @pytest.mark.asyncio
    async def test_adapt_strategy_from_results_good_performance(self, batch_coordinator):
        """Test strategy adaptation for good performance."""
        batch_coordinator.current_strategy = BatchStrategy.CONSERVATIVE
        
        # Mock excellent performance metrics
        excellent_metrics = BatchMetrics(
            total_requests=100,
            successful_requests=98,  # 98% success rate
            parallel_efficiency=0.9
        )
        batch_coordinator.get_batch_metrics = MagicMock(return_value=excellent_metrics)
        
        await batch_coordinator._adapt_strategy_from_results({})
        
        # Should adapt to more aggressive strategy
        assert batch_coordinator.current_strategy == BatchStrategy.ADAPTIVE


class TestOperationTracking:
    """Test operation tracking functionality."""
    
    @pytest.mark.asyncio
    async def test_create_operation(self, batch_coordinator):
        """Test operation creation and tracking."""
        metadata = {'test_key': 'test_value'}
        
        operation_id = await batch_coordinator._create_operation("test_type", metadata)
        
        assert operation_id.startswith("test_type_")
        assert operation_id in batch_coordinator.active_operations
        
        operation = batch_coordinator.active_operations[operation_id]
        assert operation['type'] == "test_type"
        assert operation['metadata'] == metadata
        assert operation['status'] == 'active'
    
    @pytest.mark.asyncio
    async def test_complete_operation_success(self, batch_coordinator):
        """Test successful operation completion."""
        # Create an operation first
        operation_id = await batch_coordinator._create_operation("test_type", {})
        
        await batch_coordinator._complete_operation(operation_id, success=True)
        
        assert operation_id not in batch_coordinator.active_operations
        assert len(batch_coordinator.operation_history) == 1
        
        completed_op = batch_coordinator.operation_history[0]
        assert completed_op['status'] == 'completed'
        assert 'duration' in completed_op
    
    @pytest.mark.asyncio
    async def test_complete_operation_failure(self, batch_coordinator):
        """Test failed operation completion."""
        # Create an operation first
        operation_id = await batch_coordinator._create_operation("test_type", {})
        
        await batch_coordinator._complete_operation(operation_id, success=False, error="Test error")
        
        assert operation_id not in batch_coordinator.active_operations
        assert len(batch_coordinator.operation_history) == 1
        
        completed_op = batch_coordinator.operation_history[0]
        assert completed_op['status'] == 'failed'
        assert completed_op['error'] == "Test error"
    
    def test_calculate_average_batch_size(self, batch_coordinator):
        """Test average batch size calculation."""
        # Add some operation history
        batch_coordinator.operation_history = [
            {
                'type': 'files_batch',
                'metadata': {'file_count': 10}
            },
            {
                'type': 'files_batch',
                'metadata': {'file_count': 20}
            },
            {
                'type': 'repositories_batch',
                'metadata': {'repository_count': 5}
            }
        ]
        
        avg_size = batch_coordinator._calculate_average_batch_size()
        
        # (10 + 20 + 5) / 3 = 11.67
        assert abs(avg_size - 11.67) < 0.01


class TestCoordinationStatistics:
    """Test coordination statistics functionality."""
    
    def test_get_coordination_statistics(self, batch_coordinator):
        """Test getting comprehensive coordination statistics."""
        # Mock sub-component statistics
        cache_stats = {'cache_coordination': {'test': 'data'}}
        batch_coordinator.cache_coordinator.get_coordination_statistics.return_value = cache_stats
        
        stats = batch_coordinator.get_coordination_statistics()
        
        assert 'coordinator' in stats
        assert 'cache_coordination' in stats
        assert 'parallel_processing' in stats
        
        coordinator_stats = stats['coordinator']
        assert 'active_operations' in coordinator_stats
        assert 'completed_operations' in coordinator_stats
        assert 'current_strategy' in coordinator_stats
        assert 'strategy_adaptation_enabled' in coordinator_stats


class TestAsyncContextManager:
    """Test async context manager functionality."""
    
    @pytest.mark.asyncio
    async def test_async_context_manager(self, batch_coordinator):
        """Test using BatchCoordinator as async context manager."""
        async with batch_coordinator as coordinator:
            assert coordinator == batch_coordinator
            batch_coordinator.cache_coordinator.start.assert_called_once()
        
        batch_coordinator.cache_coordinator.stop.assert_called_once()


class TestUnifiedSystemIntegration:
    """Test unified system integration functionality."""
    
    @pytest.mark.asyncio
    async def test_execute_end_to_end_batch_workflow(self, batch_coordinator, sample_repositories):
        """Test complete end-to-end batch workflow execution."""
        workflow_config = {
            'scan_pattern': 'security_scan',
            'file_patterns': ['package.json', 'requirements.txt']
        }
        
        # Mock all the internal workflow methods
        batch_coordinator._analyze_cross_repo_opportunities = AsyncMock(return_value=[])
        batch_coordinator.cache_coordinator.optimize_cache_for_scan_pattern = AsyncMock(return_value={
            'cache_state': {'batch_hit_rate_percent': 50}
        })
        batch_coordinator.optimize_repository_processing_order = AsyncMock(return_value=sample_repositories)
        batch_coordinator._select_optimal_strategy_comprehensive = AsyncMock(return_value=BatchStrategy.ADAPTIVE)
        batch_coordinator._execute_integrated_batch_processing = AsyncMock(return_value={
            'org/repo1': [],
            'org/repo2': [],
            'org/repo3': []
        })
        batch_coordinator._analyze_workflow_results = AsyncMock(return_value={
            'total_repositories': 3,
            'total_ioc_matches': 0,
            'batch_metrics': {}
        })
        batch_coordinator._adapt_strategy_from_workflow_results = AsyncMock()
        batch_coordinator._create_operation = AsyncMock(return_value="workflow_op_1")
        batch_coordinator._complete_operation = AsyncMock()
        
        result = await batch_coordinator.execute_end_to_end_batch_workflow(
            sample_repositories, workflow_config
        )
        
        assert 'processing_results' in result
        assert 'workflow_metrics' in result
        assert 'cache_optimization' in result
        assert 'strategy_used' in result
        assert result['repositories_processed'] == 3
        
        batch_coordinator._create_operation.assert_called_once()
        batch_coordinator._complete_operation.assert_called_once_with("workflow_op_1", success=True)
    
    @pytest.mark.asyncio
    async def test_select_optimal_strategy_comprehensive(self, batch_coordinator, sample_repositories):
        """Test comprehensive strategy selection."""
        cross_repo_opportunities = [
            CrossRepoBatch(
                repositories=sample_repositories[:2],
                common_files=['package.json'],
                estimated_savings=0.4
            )
        ]
        cache_optimization = {
            'cache_state': {'batch_hit_rate_percent': 80}
        }
        
        # Mock base strategy selection
        batch_coordinator._select_optimal_strategy = AsyncMock(return_value=BatchStrategy.CONSERVATIVE)
        
        strategy = await batch_coordinator._select_optimal_strategy_comprehensive(
            sample_repositories, cross_repo_opportunities, cache_optimization
        )
        
        # Should upgrade from conservative due to good cross-repo opportunities and cache hit rate
        assert strategy in [BatchStrategy.ADAPTIVE, BatchStrategy.AGGRESSIVE]
    
    @pytest.mark.asyncio
    async def test_execute_integrated_batch_processing(self, batch_coordinator, sample_repositories):
        """Test integrated batch processing execution."""
        cross_repo_opportunities = []
        workflow_config = {'file_patterns': ['package.json']}
        
        # Mock component configuration methods
        batch_coordinator._configure_parallel_processor_for_strategy = AsyncMock()
        batch_coordinator._pre_warm_cache_for_repositories = AsyncMock()
        batch_coordinator._process_repositories_integrated = AsyncMock(return_value={
            'org/repo1': [],
            'org/repo2': [],
            'org/repo3': []
        })
        
        result = await batch_coordinator._execute_integrated_batch_processing(
            sample_repositories, BatchStrategy.ADAPTIVE, cross_repo_opportunities, workflow_config
        )
        
        assert len(result) == 3
        batch_coordinator._configure_parallel_processor_for_strategy.assert_called_once()
        batch_coordinator._pre_warm_cache_for_repositories.assert_called_once()
        batch_coordinator._process_repositories_integrated.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_configure_parallel_processor_for_strategy(self, batch_coordinator):
        """Test parallel processor configuration for different strategies."""
        # Mock the adjust_concurrency method
        batch_coordinator.parallel_processor.adjust_concurrency = MagicMock()
        
        # Test aggressive strategy
        await batch_coordinator._configure_parallel_processor_for_strategy(BatchStrategy.AGGRESSIVE)
        batch_coordinator.parallel_processor.adjust_concurrency.assert_called()
        
        # Test conservative strategy
        await batch_coordinator._configure_parallel_processor_for_strategy(BatchStrategy.CONSERVATIVE)
        assert batch_coordinator.parallel_processor.adjust_concurrency.call_count == 2
    
    @pytest.mark.asyncio
    async def test_pre_warm_cache_for_repositories(self, batch_coordinator, sample_repositories):
        """Test cache pre-warming for different strategies."""
        # Mock cache warming
        batch_coordinator.cache_coordinator.warm_cache_for_batch_operation = AsyncMock(return_value=10)
        
        # Test aggressive strategy (should warm all files)
        await batch_coordinator._pre_warm_cache_for_repositories(
            sample_repositories, BatchStrategy.AGGRESSIVE
        )
        
        # Verify warming was called
        batch_coordinator.cache_coordinator.warm_cache_for_batch_operation.assert_called_once()
        call_args = batch_coordinator.cache_coordinator.warm_cache_for_batch_operation.call_args
        assert call_args[0][0] == sample_repositories  # First arg should be repositories
        assert call_args[1]['predicted_files'] is None  # Should warm all files for aggressive
        
        # Reset mock
        batch_coordinator.cache_coordinator.warm_cache_for_batch_operation.reset_mock()
        
        # Test adaptive strategy (should warm priority files)
        await batch_coordinator._pre_warm_cache_for_repositories(
            sample_repositories, BatchStrategy.ADAPTIVE
        )
        
        batch_coordinator.cache_coordinator.warm_cache_for_batch_operation.assert_called_once()
        call_args = batch_coordinator.cache_coordinator.warm_cache_for_batch_operation.call_args
        assert call_args[1]['predicted_files'] is not None  # Should have specific files for adaptive
    
    @pytest.mark.asyncio
    async def test_analyze_workflow_results(self, batch_coordinator):
        """Test workflow results analysis."""
        processing_results = {
            'org/repo1': [],  # No matches
            'org/repo2': [MagicMock()],  # One match
            'org/repo3': [MagicMock(), MagicMock()]  # Two matches
        }
        
        # Mock component metrics
        batch_coordinator.get_batch_metrics = MagicMock(return_value=BatchMetrics(
            total_requests=100,
            successful_requests=95
        ))
        batch_coordinator.get_coordination_statistics = MagicMock(return_value={
            'coordinator': {'active_operations': 0}
        })
        
        metrics = await batch_coordinator._analyze_workflow_results(processing_results)
        
        assert metrics['total_repositories'] == 3
        assert metrics['total_ioc_matches'] == 3
        assert metrics['repositories_with_matches'] == 2
        assert metrics['match_rate'] == 2/3
        assert metrics['average_matches_per_repo'] == 1.0
    
    @pytest.mark.asyncio
    async def test_adapt_strategy_from_workflow_results_excellent_performance(self, batch_coordinator):
        """Test strategy adaptation for excellent performance."""
        batch_coordinator.current_strategy = BatchStrategy.CONSERVATIVE
        
        workflow_metrics = {
            'batch_metrics': {
                'success_rate': 98.0,
                'parallel_efficiency': 0.9
            },
            'coordination_stats': {
                'cache_coordination': {
                    'cache_efficiency': {'hit_rate': 80.0}
                }
            }
        }
        
        await batch_coordinator._adapt_strategy_from_workflow_results(workflow_metrics)
        
        # Should upgrade to aggressive due to excellent performance
        assert batch_coordinator.current_strategy == BatchStrategy.AGGRESSIVE
    
    @pytest.mark.asyncio
    async def test_adapt_strategy_from_workflow_results_poor_performance(self, batch_coordinator):
        """Test strategy adaptation for poor performance."""
        batch_coordinator.current_strategy = BatchStrategy.AGGRESSIVE
        
        workflow_metrics = {
            'batch_metrics': {
                'success_rate': 70.0,
                'parallel_efficiency': 0.3
            },
            'coordination_stats': {
                'cache_coordination': {
                    'cache_efficiency': {'hit_rate': 30.0}
                }
            }
        }
        
        await batch_coordinator._adapt_strategy_from_workflow_results(workflow_metrics)
        
        # Should downgrade to adaptive due to poor performance
        assert batch_coordinator.current_strategy == BatchStrategy.ADAPTIVE


class TestInternalMethods:
    """Test internal helper methods."""
    
    @pytest.mark.asyncio
    async def test_prioritize_repositories(self, batch_coordinator, sample_repositories):
        """Test repository prioritization."""
        prioritized = await batch_coordinator._prioritize_repositories(sample_repositories)
        
        assert len(prioritized) == len(sample_repositories)
        assert all(repo in prioritized for repo in sample_repositories)
    
    @pytest.mark.asyncio
    async def test_analyze_cross_repo_opportunities_disabled(self, batch_coordinator, sample_repositories):
        """Test cross-repo analysis when disabled."""
        batch_coordinator.config.enable_cross_repo_batching = False
        
        opportunities = await batch_coordinator._analyze_cross_repo_opportunities(sample_repositories)
        
        assert opportunities == []
    
    @pytest.mark.asyncio
    async def test_analyze_cross_repo_opportunities_insufficient_repos(self, batch_coordinator):
        """Test cross-repo analysis with insufficient repositories."""
        single_repo = [Repository(name="repo1", full_name="org/repo1", archived=False, default_branch="main", updated_at=datetime.now())]
        
        opportunities = await batch_coordinator._analyze_cross_repo_opportunities(single_repo)
        
        assert opportunities == []
    
    @pytest.mark.asyncio
    async def test_format_file_batch_results(self, batch_coordinator, sample_repositories):
        """Test formatting of file batch results."""
        repo = sample_repositories[0]
        
        # Create test results
        results = [
            BatchResult(
                request=BatchRequest(repo=repo, file_path="success.txt"),
                content=FileContent(content="test content", sha="abc123", size=100),
                from_cache=True,
                processing_time=0.1
            ),
            BatchResult(
                request=BatchRequest(repo=repo, file_path="error.txt"),
                error=Exception("Test error"),
                processing_time=0.2
            )
        ]
        
        formatted = await batch_coordinator._format_file_batch_results(results)
        
        assert 'success.txt' in formatted
        assert 'error.txt' not in formatted
        assert isinstance(formatted['success.txt'], FileContent)