# Changelog

All notable changes to this project will be documented in this file.

## [1.7.0] - 2025-11-28

### 🚀 Performance Improvements

#### Parallel Workflow & Secrets Scanning
- **Parallel Processing**: Workflow and secrets scanning now runs in parallel using `ThreadPoolExecutor`
- **5-10x Faster**: Scanning 16 repos with 5 workers is ~3x faster, 100 repos with 10 workers is ~5-8x faster
- **Smart Worker Allocation**: Automatically adjusts worker count based on repository count
- **Progress Tracking**: Real-time progress display during parallel scanning

#### Incremental Repository Caching
- **Smart Incremental Fetch**: Only fetches repositories pushed since last cache update
- **Massive API Savings**: For 1000 repos with 5 new ones → only 1 API call instead of 10+
- **Always Current**: New/updated repositories are automatically detected
- **Sorted by PUSHED_AT**: GraphQL query now sorts by push date for efficient incremental fetching

### 🔧 New CLI Options

#### Cache Management
- **`--refresh-repos`**: Force refresh of repository list from GitHub (ignore cache)
- Repository list caching is now enabled by default for faster subsequent scans

#### IOC Management
- **`--update-iocs`**: Auto-update Shai-Hulud IOC definitions from Wiz Research
  - Downloads latest CSV from `wiz-sec-public/wiz-research-iocs`
  - Compares with existing IOCs and shows changes
  - Updates `shai_hulud_2.py` with new packages and versions
  - Shows summary of new, updated, and removed packages

### 🐛 Bug Fixes

#### Team-First Organization Scanning
- **Fixed**: Workflow and secrets scanning was missing in batch processing path for team scans
- **Fixed**: Missing newline before "Scanning workflows & secrets" message
- **Added**: Progress indicator now shows "(parallel)" to indicate parallel processing mode

#### Maven IOC Support
- **Fixed**: Maven IOC packages (`MAVEN_IOC_PACKAGES`) were not being loaded
- **Added**: 24 Maven-specific IOC packages for Shai-Hulud v2 campaign
- **Includes**: Typosquatting of popular Java libraries (Spring, Jackson, Commons, etc.)

### 📊 Updated Metrics
- **Total IOC Database**: 2,857+ packages (2,833 npm + 24 Maven)
- **Parallel Scanning**: Up to 10 concurrent workers for large batches
- **Cache Efficiency**: Incremental fetching reduces API calls by 90%+ for repeat scans

### 🔧 Technical Improvements

#### New Methods
- `_scan_workflows_and_secrets_parallel()`: Parallel scanning with ThreadPoolExecutor
- Enhanced `get_organization_repos_graphql()`: Supports incremental fetching with `cached_repos` and `cache_cutoff` parameters
- Updated `get_repository_metadata()`: Now returns cache timestamp for incremental updates

#### Cache Enhancements
- Repository metadata cache now stores timestamp for incremental fetching
- Cache returns 3-tuple: `(repositories, etag, cache_timestamp)`

---

## [1.6.0] - 2025-11-27

### 🚀 Major New Features

#### Maven/Java Support
- **Maven Parser**: Full support for scanning `pom.xml` files
- **Dependency Extraction**: Extracts groupId, artifactId, and version from dependencies
- **Property Resolution**: Basic support for Maven property references (`${project.version}`, etc.)
- **Dependency Management**: Scans both `<dependencies>` and `<dependencyManagement>` sections
- **Maven IOCs**: New `MAVEN_IOC_PACKAGES` dictionary for Java-specific threats

#### GitHub Actions Workflow Security Scanning
- **Dangerous Trigger Detection**: Identifies `pull_request_target` with unsafe checkout configurations
- **Privilege Escalation Detection**: Flags `workflow_run` triggers that could enable privilege escalation
- **Malicious Runner Detection**: Detects known malicious self-hosted runners (e.g., SHA1HULUD)
- **Shai Hulud 2 Patterns**: Detection of attack-specific workflow files (`discussion.yaml`, `formatter_123456789.yml`)
- **Severity Levels**: Findings categorized as critical, high, medium, or low
- **CLI Flags**: `--scan-workflows` / `--no-scan-workflows` to control workflow scanning

#### Secrets Detection
- **AWS Credentials**: Detection of access keys (AKIA...) and secret keys
- **GitHub Tokens**: Detection of personal access tokens (ghp_), OAuth tokens (gho_), app tokens (ghs_)
- **API Keys**: Generic API key pattern detection
- **Private Keys**: RSA, EC, and OpenSSH private key detection
- **Slack Tokens**: Detection of Slack bot and user tokens
- **Shai Hulud 2 Artifacts**: Detection of exfiltration files (cloud.json, environment.json, truffleSecrets.json)
- **Secret Masking**: All detected secrets are automatically masked in output (first 4 chars + ***)
- **CLI Flags**: `--scan-secrets` / `--no-scan-secrets` to control secrets scanning

### 🧹 Code Cleanup

#### Project Analysis and Cleanup
- **CodeAnalyzer Utility**: New tool for analyzing project structure and identifying unused code
- **Import Graph Analysis**: Automated detection of orphaned modules
- **Documentation Audit**: Identification of outdated documentation files
- **Cleanup Report**: Generated `docs/PROJECT_CLEANUP_REPORT.md` with findings

#### Removed Components
- Removed unused modules identified during analysis
- Archived outdated documentation
- Updated imports and fixed broken references
- Verified all tests pass after cleanup

### 📚 Documentation

#### New Documentation
- **[Maven Support](docs/MAVEN_SUPPORT.md)**: Complete guide to Maven/Java scanning
- **[Workflow Scanning](docs/WORKFLOW_SCANNING.md)**: GitHub Actions security scanning guide
- **[Secrets Detection](docs/SECRETS_DETECTION.md)**: Credential detection documentation

#### Updated Documentation
- **README.md**: Added Maven to supported package managers, new security features sections
- **Feature list**: Updated with workflow scanning and secrets detection capabilities

### 🔧 Technical Improvements

#### New Modules
- `src/github_ioc_scanner/parsers/maven.py`: Maven POM parser
- `src/github_ioc_scanner/workflow_scanner.py`: GitHub Actions workflow analyzer
- `src/github_ioc_scanner/secrets_scanner.py`: Secrets and credential detector
- `src/github_ioc_scanner/code_analyzer.py`: Project analysis utility

#### New Data Models
- `WorkflowFinding`: Represents security findings in GitHub Actions workflows
- `SecretFinding`: Represents detected secrets with masked values
- `MavenDependency`: Represents Maven dependency information

#### Test Coverage
- `tests/test_maven_parser.py`: Maven parser unit tests
- `tests/test_workflow_scanner.py`: Workflow scanner unit tests
- `tests/test_secrets_scanner.py`: Secrets scanner unit tests
- Test fixtures in `tests/fixtures/maven/`, `tests/fixtures/workflows/`, `tests/fixtures/secrets/`

### 📊 Updated Metrics
- **Total IOC Database**: 2,932+ packages
- **Supported Languages**: 7 (added Java/Maven)
- **Security Scan Types**: 4 (packages, workflows, secrets, SBOM)

## [1.5.4] - 2025-11-26

### 🚨 Critical Security Update - Extended Shai Hulud 2.0 IOC Database

#### 📦 Expanded Package Coverage
- **795 Compromised Packages**: Updated from official Wiz Security IOC list (+256 packages)
- **1,089 Package-Version Combinations**: Complete version-specific detection
- **Official Source**: Direct integration of Wiz Security's authoritative CSV data

#### 🎯 Newly Added Organizations & Packages
- **BrowserBase**: 8 packages (AI browser automation platform)
- **Additional Zapier packages**: Extended coverage
- **Additional AsyncAPI packages**: More comprehensive detection
- **Additional Postman packages**: Enhanced binary and MCP coverage
- **Additional PostHog packages**: Expanded plugin and integration coverage
- **Additional ENS Domains packages**: More thorough blockchain tooling coverage
- **Additional Voiceflow packages**: Complete conversational AI platform coverage
- **Hundreds of additional packages**: Development tools, React Native libraries, testing frameworks

#### 📊 Updated Metrics
- **Total IOC Database**: 2,932 packages (previously 2,676)
- **Shai Hulud 2.0**: 795 packages (previously 539)
- **Detection Accuracy**: Version-specific matching from official Wiz CSV

#### 📚 Source Attribution
- **Primary Source**: https://github.com/wiz-sec-public/wiz-research-iocs
- **CSV Data**: shai-hulud-2-packages.csv (official Wiz Security IOC list)
- **Research**: Wiz.io blog, Socket.dev analysis

## [1.5.3] - 2025-11-24

### 🐛 Bug Fix

#### Fixed Issues Directory Resolution
- **Default Value Fixed**: Changed `issues_dir` default from `"issues"` to `None` in `ScanConfig`
- **Built-in IOCs Now Default**: When no custom issues directory is specified, the scanner now correctly uses built-in IOC definitions from the installed package
- **Error Prevention**: Eliminates "IOC definitions directory not found: issues" error when running without custom IOC files
- **Backward Compatible**: Custom issues directories still work as expected when explicitly specified

#### Technical Details
- Modified `models.py`: `issues_dir: Optional[str] = None` (was `"issues"`)
- IOCLoader logic unchanged: When `issues_dir=None`, automatically uses package's built-in issues directory
- Affects all CLI operations that don't specify `--issues-dir` parameter

## [1.5.2] - 2025-11-24

### 🚨 Critical Security Update - Shai Hulud 2.0 Complete IOC Database

#### 📦 Comprehensive Package Coverage
- **533 Compromised npm Packages**: Complete and verified IOC database from Socket.dev research
- **All Major Ecosystems Covered**: Every compromised package from the November 2025 campaign
- **Version-Specific Detection**: Precise version numbers for all affected packages

#### 🎯 Enhanced Organizational Coverage
- **Zapier**: 16 packages (platform automation, SDK, and integration tools)
- **AsyncAPI**: 41 packages (API specification, code generation, templates)
- **Postman**: 17 packages (API development, testing, binary distributions)
- **PostHog**: 52 packages (analytics, plugins, integrations)
- **ENS Domains**: 46 packages (Ethereum Name Service infrastructure)
- **Voiceflow**: 56 packages (conversational AI platform)
- **Accord Project**: 7 packages (smart contract templates)
- **300+ Additional Packages**: Development tools, React Native libraries, testing frameworks

#### 🔬 Detailed Attack Intelligence
- **Payload Files**: setup_bun.js (10MB obfuscated script), bun_environment.js
- **Attack Vector**: Preinstall script execution with silent output suppression
- **Multi-Cloud Targeting**: AWS, Azure, GCP credential harvesting
- **GitHub Actions Exploitation**: Workflow injection for persistence
- **Docker Breakout**: Privileged container escape attempts

#### 🌐 Network & File IOCs
- **Exfiltration Domain**: webhook.site
- **Artifact Files**: cloud.json, contents.json, environment.json, truffleSecrets.json
- **Malicious Workflows**: discussion.yaml, formatter_123456789.yml
- **Self-Hosted Runner**: SHA1HULUD identifier

#### 📊 Impact Metrics
- **25,000+ Affected Repositories**: Across ~350 unique GitHub users
- **Attack Window**: November 21-24, 2025 (confirmed)
- **Continuous Discovery**: New repositories being created every 30 minutes during peak

#### 📚 Source Attribution
- **Primary Source**: Socket.dev comprehensive analysis
- **Additional Sources**: Wiz.io, GitHub wiz-sec-public IOCs
- **Research Links**: Complete documentation in shai_hulud_2.py

## [1.5.1] - 2025-11-24

### 🚨 Critical Security Update - Shai Hulud 2.0 Worm Attack

#### 🛡️ New IOC Database - Shai Hulud 2.0
- **533+ Compromised Packages**: Complete coverage of the November 2025 Shai Hulud 2.0 campaign
- **Major Ecosystem Impact**: Added detection for compromised packages from:
  - **Zapier** (16 packages): Platform automation and integration tools
  - **AsyncAPI** (36 packages): API specification and code generation tools
  - **Postman** (16 packages): API development and testing ecosystem
  - **PostHog** (47 packages): Product analytics and feature management
  - **ENS Domains** (46 packages): Ethereum Name Service infrastructure
  - **Voiceflow** (56 packages): Conversational AI development platform
  - **300+ Additional Packages**: Wide range of development tools and libraries

#### 🔍 Enhanced Attack Intelligence
- **Preinstall Script Execution**: New attack vector using preinstall lifecycle scripts
- **Multi-Cloud Targeting**: AWS, Azure, and GCP credential theft capabilities
- **Docker Privilege Escalation**: Container breakout attempts detected
- **GitHub Actions Injection**: Malicious workflow injection for persistence
- **New Payload Files**: `setup_bun.js` and `bun_environment.js` detection

#### 📊 Attack Indicators
- **GitHub IOCs**: Detection for malicious workflows, self-hosted runners (SHA1HULUD)
- **File Artifacts**: cloud.json, contents.json, environment.json, truffleSecrets.json
- **Network IOCs**: webhook.site exfiltration domain detection
- **MITRE ATT&CK Mapping**: Complete TTP documentation

#### 📚 Documentation Updates
- **Source Attribution**: Wiz.io, Socket.dev, and GitHub wiz-sec-public IOCs
- **Attack Timeline**: November 21-24, 2025 compromise window documented
- **Impact Scope**: 25,000+ affected repositories across ~350 users

## [1.5.0] - 2025-09-26

### 🚨 Critical Security Update - Shai Hulud Worm Attack

#### 🛡️ IOC Database Expansion
- **Shai Hulud Worm Attack Coverage**: Added 500+ compromised npm packages from the Shai Hulud worm attack
- **Worm Payload Detection**: Enhanced detection for first-of-its-kind worm payloads in npm packages
- **Mobile Development Packages**: Added detection for compromised Capacitor and Cordova packages
- **Framework Package Coverage**: Enhanced coverage for Ember, React, and Angular ecosystem packages
- **Security Tooling Impersonation**: Added detection for malicious packages impersonating CrowdStrike tools

#### 🔧 Repository Maintenance
- **Documentation Organization**: Moved all summary documents to `docs/` directory
- **Test Code Cleanup**: Removed temporary and development test files
- **Clean Repository Structure**: Organized project for better maintainability

#### 📊 Attack Intelligence
- **Supply Chain Worm**: First documented worm payload in npm supply chain attacks
- **Cross-Platform Targeting**: Attack affects web, mobile, and development tooling ecosystems
- **Version-Specific IOCs**: Precise version targeting for accurate threat detection

## [1.4.0] - 2025-09-19

### 🎉 Major Release - Production Ready

#### 🐛 Critical Bug Fixes
- **Fixed form-data Cache Issue**: Resolved critical issue where form-data was incorrectly flagged as threat due to old installed package IOCs
- **Token Refresh Problem**: Fixed GitHub App token expiration after 1 hour causing scan failures
- **Resume Functionality**: Complete integration between CLI and scanner with state management
- **Empty Repository Handling**: Graceful 409 error handling for repositories with no commits
- **Network Timeout Issues**: Added retry logic with exponential backoff for temporary network issues

#### 🚀 Enhanced Features
- **Complete Error Handling Solution**: Comprehensive error handling with automatic recovery
- **Advanced Rate Limiting**: Proactive and adaptive rate limiting strategies
- **Network Resilience**: Robust network error handling with intelligent retry mechanisms
- **Memory Management**: Optimized resource usage for large-scale scans
- **Progress Monitoring**: Real-time progress tracking with detailed metrics

#### 📚 Documentation Reorganization
- **Moved all feature documentation to `docs/` directory**
- **Created comprehensive `docs/INDEX.md` navigation guide**
- **Updated all documentation links and references**
- **Maintained clean root directory structure**

#### 🧹 Project Cleanup
- **Removed 68+ debug and test artifacts**
- **Eliminated all unused code and backup files**
- **Optimized project structure for production use**
- **Professional documentation organization**

#### 🔒 Security Enhancements
- **2,138+ IOC definitions** including latest npm supply chain attacks
- **Enhanced SBOM scanning** with multiple format support
- **Improved threat detection accuracy**

### 🛠️ Technical Improvements
- **Development Installation**: Package now installs in development mode using local files
- **Cache Optimization**: Improved caching strategies with proper IOC hash validation
- **Batch Processing**: Enhanced batch processing with comprehensive error handling
- **State Management**: Complete scan state persistence and resumption

---

## [1.2.0] - 2025-09-18

### 🎯 Major New Features
- **SBOM Support**: Added comprehensive Software Bill of Materials (SBOM) scanning capability
  - Support for GitHub Dependency Graph API SBOM export
  - SPDX JSON format parsing with nested API structure handling
  - CycloneDX JSON format support
  - Automatic detection and parsing of both in-repository and API-based SBOMs
  - Seamless integration with existing lockfile scanning
- **Enhanced Security Coverage**: Repositories are now scanned using both traditional lockfiles AND GitHub's dependency graph
- **Improved IOC Detection**: Doubled security coverage by scanning multiple dependency sources per repository

### 🔧 Technical Improvements
- **API SBOM Parser**: Enhanced SBOM parser to handle GitHub's nested `{"sbom": {...}}` API response format
- **Dual-Source Scanning**: Intelligent combination of lockfile and SBOM data for comprehensive coverage
- **Performance Optimized**: SBOM scanning integrated with existing caching and rate limiting systems

### 📊 Statistics
- Successfully tested with 1000+ package SBOMs
- Verified IOC detection across both lockfile and SBOM sources
- Maintains existing performance characteristics while adding comprehensive SBOM support

## [1.1.6] - 2025-09-18

### 🚀 Major Performance Improvements
- **Tree-First Mode**: Use Tree API by default for large team scans to avoid Code Search rate limits entirely
- **No-Wait Rate Limiting**: Only wait when REST API is completely exhausted, not for low limits
- **Optimized Large Team Scanning**: Dramatically faster scanning for teams with 50+ repositories
- **Intelligent API Selection**: Automatically choose the most efficient API for the scan type

## [1.1.5] - 2025-09-18

### 🚀 Performance Improvements
- **Smart Code Search Fallback**: Automatically fallback to Tree API when Code Search rate limits are hit
- **Rate Limit Intelligence**: Track Code Search rate limit status to avoid unnecessary API calls
- **Improved Large Team Scanning**: Better handling of teams with many repositories (100+ repos)
- **Smart Rate Limiter**: New intelligent rate limiting system optimized for large scans

## [1.1.4] - 2025-09-18

### 🔧 Fixes
- **Repository Links**: Fixed broken GitHub repository URLs in pyproject.toml and documentation
- **Documentation Updates**: Updated repository references from placeholder to actual GitHub repository
- **Copyright Year**: Updated copyright year to 2025 in LICENSE file
- **Current Status**: Updated "Current as of" date to January 2025 in README

## [1.1.3] - 2025-09-18

### 🔒 Security Improvements
- **Archived Repository Filtering**: Archived repositories are now consistently excluded from all scan types
- **Team Scan Enhancement**: Fixed archived repository filtering for team-based scans
- **Clear Communication**: Added informative logging about excluded archived repositories
- **Configuration Option**: Added `--include-archived` flag to optionally include archived repositories

## [1.1.0] - 2025-09-18

### 🚀 Major New Features

#### SBOM (Software Bill of Materials) Support
- **Native SBOM Scanning**: Full support for SPDX and CycloneDX formats (JSON/XML)
- **Multiple SBOM Formats**: SPDX, CycloneDX, and generic SBOM files
- **Intelligent File Detection**: Automatic recognition of SBOM files by pattern and content
- **Three Scanning Modes**: 
  - Default: Lockfiles + SBOM files
  - SBOM-only: `--sbom-only` flag
  - Lockfiles-only: `--disable-sbom` flag
- **SBOM-specific Caching**: Optimized caching strategies for SBOM content and parsed packages
- **Package URL (PURL) Support**: Automatic package type detection from PURLs

#### Enhanced Rate Limiting
- **Proactive Rate Limiting**: Intelligent slowdown before hitting API limits
- **Adaptive Learning**: Learns from rate limit patterns and adjusts delays automatically
- **Code Search API Optimization**: Separate handling for Code Search API (30 req/min) limits
- **Conservative Batch Configuration**: Optimized defaults for large organizations
- **Real-time Monitoring**: Enhanced logging with rate limit status indicators

### 🛠️ Improvements

#### Performance & Reliability
- **Reduced Default Concurrency**: More conservative settings for better rate limit handling
- **Improved Error Handling**: Better recovery from rate limit and network issues
- **Enhanced Logging**: More informative rate limit status messages with emojis
- **Batch Processing Optimizations**: Better handling of large repository scans

#### CLI Enhancements
- **New SBOM Options**: `--enable-sbom`, `--disable-sbom`, `--sbom-only`
- **Better Progress Reporting**: More accurate ETA calculations with rate limiting
- **Enhanced Help Text**: Updated documentation for new features

### 📁 Supported SBOM Files

#### File Patterns
- `sbom.json`, `bom.json`, `cyclonedx.json`, `spdx.json`
- `sbom.xml`, `bom.xml`, `cyclonedx.xml`, `spdx.xml`
- `software-bill-of-materials.json`, `software-bill-of-materials.xml`
- `.sbom`, `.spdx`, `SBOM.json`, `BOM.json`

#### SBOM Formats
- **SPDX 2.3**: Industry standard SBOM format (JSON/XML)
- **CycloneDX 1.4**: OWASP SBOM standard (JSON/XML)
- **Generic**: Custom SBOM formats with automatic detection

### 🔧 Technical Changes

#### New Modules
- `src/github_ioc_scanner/parsers/sbom.py`: SBOM parser implementation
- `src/github_ioc_scanner/improved_rate_limiting.py`: Enhanced rate limiting logic

#### Updated Modules
- `src/github_ioc_scanner/scanner.py`: SBOM integration and scanning modes
- `src/github_ioc_scanner/cli.py`: New CLI options and SBOM support
- `src/github_ioc_scanner/github_client.py`: Improved rate limiting integration
- `src/github_ioc_scanner/batch_models.py`: Conservative batch configuration
- `src/github_ioc_scanner/models.py`: Extended ScanConfig for SBOM options

#### New Examples
- `examples/sbom_scanning_example.py`: Comprehensive SBOM feature demonstration
- `examples/rate_limit_optimization_example.py`: Rate limiting optimization guide

### 🧪 Testing

#### New Test Coverage
- **29 SBOM Tests**: Complete test suite for SBOM parsing and integration
- **16 SBOM Parser Tests**: All formats, edge cases, and error handling
- **13 Scanner Integration Tests**: End-to-end SBOM functionality
- **Rate Limiting Tests**: Proactive and adaptive rate limiting validation

### 📚 Documentation

#### Updated Documentation
- **README.md**: SBOM feature documentation and usage examples
- **[docs/SBOM_FEATURE_SUMMARY.md](docs/SBOM_FEATURE_SUMMARY.md)**: Comprehensive SBOM implementation guide
- **[docs/RATE_LIMIT_IMPROVEMENTS.md](docs/RATE_LIMIT_IMPROVEMENTS.md)**: Rate limiting optimization documentation

### 🔒 Security Enhancements

#### Supply Chain Security
- **Comprehensive SBOM Analysis**: Scan standardized software bills of materials
- **Enhanced Dependency Visibility**: Better coverage of project dependencies
- **Compliance Support**: SPDX and CycloneDX standard compliance
- **IOC Integration**: Same IOC definitions work for both lockfiles and SBOM files

### ⚡ Performance Improvements

#### Rate Limiting Optimizations
- **90% Fewer Rate Limit Warnings**: Proactive prevention of API exhaustion
- **Predictable Scan Times**: More stable ETA calculations
- **Adaptive Delays**: Smart delay adjustments based on API response patterns
- **Conservative Defaults**: Optimized for large organization scanning

### 🎯 Usage Examples

#### SBOM Scanning
```bash
# Default: Scan both lockfiles and SBOM files
github-ioc-scan --org myorg

# Scan only SBOM files
github-ioc-scan --org myorg --sbom-only

# Disable SBOM scanning
github-ioc-scan --org myorg --disable-sbom
```

#### Rate Limit Optimization
```bash
# Conservative settings for large organizations
github-ioc-scan --org large-org --max-concurrent 2 --batch-size 5

# Balanced settings for medium organizations  
github-ioc-scan --org medium-org --max-concurrent 5 --batch-size 10

# Fast mode for quick assessment
github-ioc-scan --org any-org --fast --sbom-only
```

### 🐛 Bug Fixes
- Fixed import errors in test suite
- Improved error handling for malformed SBOM files
- Better handling of XML namespace parsing
- Fixed recursive scanning issues in combined mode

### 🔄 Breaking Changes
- None - All changes are backward compatible

### 📦 Dependencies
- No new dependencies added
- All existing dependencies maintained

---

## [1.0.10] - 2025-09-18

### Previous Release
- Core IOC scanning functionality
- Multi-language package manager support
- Batch processing capabilities
- Comprehensive caching system
- Professional CLI interface

---

**Full Changelog**: https://github.com/your-org/github-ioc-scanner/compare/v1.0.10...v1.1.0
