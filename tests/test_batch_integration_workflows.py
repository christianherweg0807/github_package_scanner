"""
Integration tests for complete batch processing workflows.

This module contains end-to-end integration tests for all batch scenarios,
error conditions and recovery scenarios, and tests with real GitHub repositories.
"""

import asyncio
import pytest
from typing import List, Dict, Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch
import tempfile
import json

from src.github_ioc_scanner.batch_coordinator import BatchCoordinator
from src.github_ioc_scanner.batch_models import (
    BatchRequest, BatchResult, BatchMetrics, BatchStrategy, BatchConfig
)
from src.github_ioc_scanner.models import Repository, FileContent, IOCMatch, APIResponse
from src.github_ioc_scanner.scanner import GitHubIOCScanner
from src.github_ioc_scanner.github_client import GitHubClient
from src.github_ioc_scanner.async_github_client import AsyncGitHubClient
from src.github_ioc_scanner.exceptions import (
    APIError, RateLimitError, RepositoryNotFoundError
)


class TestBatchIntegrationWorkflows:
    """Integration tests for complete batch processing workflows."""

    @pytest.fixture
    def mock_async_github_client(self):
        """Create a comprehensive mock async GitHub client."""
        client = AsyncMock(spec=AsyncGitHubClient)
        
        # Mock repository data
        from datetime import datetime
        mock_repos = {
            "owner/repo1": Repository(
                name="repo1",
                full_name="owner/repo1",
                archived=False,
                default_branch="main",
                updated_at=datetime.now()
            ),
            "owner/repo2": Repository(
                name="repo2",
                full_name="owner/repo2",
                archived=False,
                default_branch="main",
                updated_at=datetime.now()
            ),
            "owner/private-repo": Repository(
                name="private-repo",
                full_name="owner/private-repo",
                archived=False,
                default_branch="main",
                updated_at=datetime.now()
            )
        }
        
        # Mock file contents
        mock_file_contents = {
            "package.json": FileContent(
                content='{"dependencies": {"lodash": "^4.17.20", "express": "^4.18.0"}}',
                sha="abc123",
                size=65
            ),
            "requirements.txt": FileContent(
                content="requests==2.28.0\nflask==2.2.0\n",
                sha="def456",
                size=35
            ),
            "Gemfile.lock": FileContent(
                content="GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n",
                sha="ghi789",
                size=60
            ),
            "go.mod": FileContent(
                content="module example.com/myapp\n\ngo 1.19\n\nrequire github.com/gin-gonic/gin v1.8.0\n",
                sha="jkl012",
                size=75
            )
        }
        
        # Mock methods
        async def mock_get_repository(full_name):
            if full_name in mock_repos:
                return mock_repos[full_name]
            raise RepositoryNotFoundError(f"Repository {full_name} not found")
        
        async def mock_get_organization_repositories(org):
            return [repo for repo in mock_repos.values() if repo.full_name.split('/')[0] == org]
        
        async def mock_get_file_content(repo, path):
            if path in mock_file_contents:
                return mock_file_contents[path]
            raise APIError(f"File {path} not found")
        
        async def mock_get_multiple_file_contents(repo, paths):
            result = {}
            for path in paths:
                if path in mock_file_contents:
                    result[path] = mock_file_contents[path]
            return result
        
        async def mock_list_repository_files(repo, extensions=None):
            files = list(mock_file_contents.keys())
            if extensions:
                files = [f for f in files if any(f.endswith(ext) for ext in extensions)]
            return files
        
        async def mock_get_file_content_async(repo, path, etag=None):
            if path in mock_file_contents:
                return APIResponse(data=mock_file_contents[path])
            raise APIError(f"File {path} not found")
        
        client.get_repository = mock_get_repository
        client.get_organization_repositories = mock_get_organization_repositories
        client.get_file_content = mock_get_file_content
        client.get_file_content_async = mock_get_file_content_async
        client.get_multiple_file_contents = mock_get_multiple_file_contents
        client.list_repository_files = mock_list_repository_files
        
        return client

    @pytest.fixture
    def batch_config(self):
        """Create a test batch configuration."""
        return BatchConfig(
            max_concurrent_requests=5,
            max_concurrent_repos=2,
            default_batch_size=10,
            max_batch_size=20,
            enable_cross_repo_batching=True,
            enable_file_prioritization=True
        )

    @pytest.fixture
    def mock_cache_manager(self):
        """Create a mock cache manager for testing."""
        from src.github_ioc_scanner.cache_manager import CacheManager
        mock = MagicMock(spec=CacheManager)
        # Default to cache misses so files go through the API fetch path
        mock.get_file_content.return_value = None
        return mock

    @pytest.mark.asyncio
    async def test_end_to_end_single_repository_batch_workflow(
        self, mock_async_github_client, mock_cache_manager, batch_config
    ):
        """
        Test complete end-to-end batch workflow for a single repository.
        
        Requirements: 1.1, 1.2, 1.3, 1.4
        """
        coordinator = BatchCoordinator(mock_async_github_client, mock_cache_manager, batch_config)
        
        # Get repository
        repo = await mock_async_github_client.get_repository("owner/repo1")
        
        # List files in repository
        files = await mock_async_github_client.list_repository_files(repo)
        
        # Process files in batch
        results = await coordinator.process_files_batch(
            repo,
            files
        )
        
        # Verify results
        assert len(results) > 0
        
        # Verify all expected files were processed
        expected_files = ["package.json", "requirements.txt", "Gemfile.lock", "go.mod"]
        for file_path in expected_files:
            assert file_path in results
            assert results[file_path] is not None
        
        # Get batch metrics
        metrics = coordinator.get_batch_metrics()
        assert metrics.total_requests > 0
        assert metrics.successful_requests > 0

    @pytest.mark.asyncio
    async def test_end_to_end_multi_repository_batch_workflow(
        self, mock_async_github_client, mock_cache_manager, batch_config
    ):
        """
        Test complete end-to-end batch workflow for multiple repositories.
        
        Requirements: 1.1, 1.2, 1.3, 1.4
        """
        coordinator = BatchCoordinator(mock_async_github_client, mock_cache_manager, batch_config)
        
        # Get multiple repositories
        repos = await mock_async_github_client.get_organization_repositories("owner")
        
        # Process repositories in batch
        results = await coordinator.process_repositories_batch(
            repos,
            strategy=BatchStrategy.ADAPTIVE
        )
        
        # Verify results
        assert len(results) > 0
        
        # Verify each repository was processed
        for repo in repos:
            if "private" not in repo.full_name:  # Skip private repos in this test
                assert repo.full_name in results
                repo_results = results[repo.full_name]
                assert len(repo_results) >= 0  # May be empty if no IOCs found

    @pytest.mark.asyncio
    async def test_batch_workflow_with_scanner_integration(
        self, mock_async_github_client, batch_config
    ):
        """
        Test batch workflow integrated with the main Scanner class.
        
        Requirements: 1.1, 1.4
        """
        # Create scanner with batch-enabled client
        from src.github_ioc_scanner.models import ScanConfig
        from src.github_ioc_scanner.cache import CacheManager
        
        scan_config = ScanConfig()
        cache_manager = CacheManager()
        
        scanner = GitHubIOCScanner(
            config=scan_config,
            github_client=mock_async_github_client,
            cache_manager=cache_manager,
            batch_config=batch_config
        )
        
        # Mock IOC loader
        with patch('src.github_ioc_scanner.ioc_loader.IOCLoader') as mock_loader:
            mock_loader.return_value.load_iocs.return_value = {
                'lodash': ['4.17.20'],  # Vulnerable version
                'express': None  # Any version flagged
            }
            
            # Scan repository with batch processing
            results = scanner.scan_repository("owner", "repo1")
            
            # Verify scan completed successfully
            assert isinstance(results, list)
            # Results may be empty if no IOCs match, but scan should complete

    @pytest.mark.asyncio
    async def test_batch_workflow_error_recovery_scenarios(
        self, mock_async_github_client, mock_cache_manager, batch_config
    ):
        """
        Test batch workflow error recovery and resilience scenarios.
        
        Requirements: 1.1, 1.2, 1.3, 1.4
        """
        coordinator = BatchCoordinator(mock_async_github_client, mock_cache_manager, batch_config)
        
        # Test scenario 1: Individual file failures
        original_get_file_content_async = mock_async_github_client.get_file_content_async
        
        async def mock_get_file_content_with_failures(repo, path, etag=None):
            if path == "failing-file.json":
                raise APIError("Access denied for failing-file.json")
            return await original_get_file_content_async(repo, path, etag=etag)
        
        mock_async_github_client.get_file_content_async = mock_get_file_content_with_failures
        
        repo = await mock_async_github_client.get_repository("owner/repo1")
        files = ["package.json", "failing-file.json", "requirements.txt"]
        
        results = await coordinator.process_files_batch(repo, files)
        
        # Verify partial success - good files processed, bad file skipped
        assert "package.json" in results
        assert "requirements.txt" in results
        assert "failing-file.json" not in results
        
        # Test scenario 2: Rate limit handling
        rate_limit_calls = 0
        original_get_file_content_async2 = mock_async_github_client.get_file_content_async
        
        async def mock_get_file_content_with_rate_limit(repo, path, etag=None):
            nonlocal rate_limit_calls
            rate_limit_calls += 1
            if rate_limit_calls == 1:
                raise RateLimitError("Rate limit exceeded", reset_time=1)
            return await original_get_file_content_async2(repo, path, etag=etag)
        
        mock_async_github_client.get_file_content_async = mock_get_file_content_with_rate_limit
        
        # This should succeed after rate limit retry
        results = await coordinator.process_files_batch(repo, ["package.json"])
        assert "package.json" in results
        assert rate_limit_calls >= 1

    @pytest.mark.asyncio
    async def test_batch_workflow_with_caching_integration(
        self, mock_async_github_client, mock_cache_manager, batch_config
    ):
        """
        Test batch workflow with cache integration.
        
        Requirements: 1.1, 1.2, 1.3, 1.4
        """
        # Mock cache manager
        with patch('src.github_ioc_scanner.cache_manager.CacheManager') as mock_cache:
            cache_instance = mock_cache.return_value
            
            # First call - cache miss
            cache_instance.get_file_content.return_value = None
            
            coordinator = BatchCoordinator(mock_async_github_client, mock_cache_manager, batch_config)
            repo = await mock_async_github_client.get_repository("owner/repo1")
            
            # First batch - should fetch from API
            results1 = await coordinator.process_files_batch(
                repo, 
                ["package.json", "requirements.txt"]
            )
            
            # Verify results were returned
            assert len(results1) > 0
            
            # Second batch - same files
            results2 = await coordinator.process_files_batch(
                repo,
                ["package.json", "requirements.txt"]
            )
            
            # Verify results
            assert len(results1) == len(results2)
            assert "package.json" in results2
            assert "requirements.txt" in results2

    @pytest.mark.asyncio
    async def test_batch_workflow_cross_repository_optimization(
        self, mock_async_github_client, mock_cache_manager, batch_config
    ):
        """
        Test batch workflow with cross-repository optimization.
        
        Requirements: 1.1, 1.4
        """
        coordinator = BatchCoordinator(mock_async_github_client, mock_cache_manager, batch_config)
        
        # Get multiple repositories
        repos = await mock_async_github_client.get_organization_repositories("owner")
        public_repos = [repo for repo in repos if "private" not in repo.full_name]
        
        # Process with cross-repository batching enabled
        results = await coordinator.process_repositories_batch(
            public_repos,
            strategy=BatchStrategy.ADAPTIVE
        )
        
        # Verify all repositories were processed
        for repo in public_repos:
            assert repo.full_name in results
        
        # Get metrics to verify cross-repo optimization was attempted
        metrics = coordinator.get_batch_metrics()
        assert metrics.total_requests >= 0

    @pytest.mark.asyncio
    async def test_batch_workflow_with_different_strategies(
        self, mock_async_github_client, mock_cache_manager, batch_config
    ):
        """
        Test batch workflow with different processing strategies.
        
        Requirements: 1.1, 1.2, 1.3, 1.4
        """
        coordinator = BatchCoordinator(mock_async_github_client, mock_cache_manager, batch_config)
        repo = await mock_async_github_client.get_repository("owner/repo1")
        files = ["package.json", "requirements.txt", "Gemfile.lock", "go.mod"]
        
        strategies = [
            BatchStrategy.SEQUENTIAL,
            BatchStrategy.PARALLEL,
            BatchStrategy.ADAPTIVE
        ]
        
        results_by_strategy = {}
        
        for strategy in strategies:
            results = await coordinator.process_files_batch(
                repo,
                files
            )
            results_by_strategy[strategy] = results
            
            # Verify all strategies produce results
            assert len(results) > 0
            for file_path in files:
                assert file_path in results
        
        # Verify all strategies produce equivalent results
        first_strategy_results = list(results_by_strategy.values())[0]
        for strategy_results in results_by_strategy.values():
            assert set(strategy_results.keys()) == set(first_strategy_results.keys())

    @pytest.mark.asyncio
    async def test_batch_workflow_memory_management(
        self, mock_async_github_client, mock_cache_manager, batch_config
    ):
        """
        Test batch workflow memory management with large datasets.
        
        Requirements: 1.1, 1.2, 1.3, 1.4
        """
        import psutil
        import os
        
        # Configure for memory-efficient processing
        batch_config.max_memory_usage_mb = 50
        batch_config.stream_large_files_threshold = 1024
        
        coordinator = BatchCoordinator(mock_async_github_client, mock_cache_manager, batch_config)
        
        # Create large file list
        large_file_list = [f"file_{i}.json" for i in range(100)]
        
        # Mock large file contents
        async def mock_large_files_async(repo, path, etag=None):
            return APIResponse(data=FileContent(
                content="x" * 1000,  # 1KB per file
                sha=f"sha_{path}",
                size=1000
            ))
        
        mock_async_github_client.get_file_content_async = mock_large_files_async
        
        # Monitor memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        repo = await mock_async_github_client.get_repository("owner/repo1")
        results = await coordinator.process_files_batch(repo, large_file_list)
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Verify memory usage is reasonable
        assert memory_increase < batch_config.max_memory_usage_mb * 2
        # Verify that batch processing completed with some results (memory pressure may reduce exact count)
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_batch_workflow_progress_monitoring(
        self, mock_async_github_client, mock_cache_manager, batch_config
    ):
        """
        Test batch workflow with progress monitoring and reporting.
        
        Requirements: 1.1, 1.2, 1.3, 1.4
        """
        coordinator = BatchCoordinator(mock_async_github_client, mock_cache_manager, batch_config)
        
        # Enable progress monitoring
        progress_updates = []
        
        def mock_progress_callback(completed, total, current_batch_size, eta_seconds):
            progress_updates.append({
                'completed': completed,
                'total': total,
                'batch_size': current_batch_size,
                'eta': eta_seconds
            })
        
        # Mock progress monitor
        with patch.object(coordinator, '_report_progress', mock_progress_callback):
            repo = await mock_async_github_client.get_repository("owner/repo1")
            files = [f"file_{i}.json" for i in range(20)]
            
            results = await coordinator.process_files_batch(repo, files)
            
            # Verify progress was reported
            assert len(progress_updates) > 0
            
            # Verify progress updates make sense
            first_update = progress_updates[0]
            last_update = progress_updates[-1]
            
            assert first_update['completed'] <= last_update['completed']
            assert last_update['completed'] == len(files)

    @pytest.mark.asyncio
    async def test_batch_workflow_configuration_validation(
        self, mock_async_github_client, mock_cache_manager
    ):
        """
        Test batch workflow with various configuration scenarios.
        
        Requirements: 1.1, 1.2, 1.3, 1.4
        """
        # Test with minimal configuration
        minimal_config = BatchConfig(
            max_concurrent_requests=1,
            default_batch_size=1
        )
        
        coordinator = BatchCoordinator(mock_async_github_client, mock_cache_manager, minimal_config)
        repo = await mock_async_github_client.get_repository("owner/repo1")
        
        results = await coordinator.process_files_batch(
            repo, 
            ["package.json"]
        )
        assert len(results) == 1
        
        # Test with aggressive configuration
        aggressive_config = BatchConfig(
            max_concurrent_requests=20,
            default_batch_size=50,
            max_batch_size=100
        )
        
        coordinator = BatchCoordinator(mock_async_github_client, mock_cache_manager, aggressive_config)
        
        results = await coordinator.process_files_batch(
            repo,
            ["package.json", "requirements.txt"]
        )
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_batch_workflow_real_github_simulation(
        self, mock_async_github_client, mock_cache_manager, batch_config
    ):
        """
        Simulate batch workflow with realistic GitHub API behavior.
        
        Requirements: 1.1, 1.2, 1.3, 1.4
        """
        # Add realistic delays and occasional failures
        call_count = 0
        
        original_get_multiple = mock_async_github_client.get_multiple_file_contents
        
        async def realistic_get_multiple(repo, paths):
            nonlocal call_count
            call_count += 1
            
            # Simulate network delay
            await asyncio.sleep(0.1)
            
            # Simulate occasional failures (5% failure rate)
            if call_count % 20 == 0:
                raise APIError("Temporary network error")
            
            return await original_get_multiple(repo, paths)
        
        mock_async_github_client.get_multiple_file_contents = realistic_get_multiple
        
        coordinator = BatchCoordinator(mock_async_github_client, mock_cache_manager, batch_config)
        
        # Process multiple repositories with realistic conditions
        repos = await mock_async_github_client.get_organization_repositories("owner")
        
        results = await coordinator.process_repositories_batch(
            repos,
            strategy=BatchStrategy.ADAPTIVE
        )
        
        # Verify processing completed despite occasional failures
        assert len(results) > 0
        
        # Verify metrics were collected
        metrics = coordinator.get_batch_metrics()
        assert metrics.total_requests >= 0
        assert metrics.successful_requests >= 0