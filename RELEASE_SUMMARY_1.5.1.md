# Release 1.5.1 - Shai Hulud 2.0 Detection

**Release Date:** November 24, 2025
**Release Type:** Critical Security Update  
**Threat Level:** CRITICAL

## 🚨 Overview

This release adds comprehensive detection for the **Shai Hulud 2.0** supply chain attack that compromised 533+ npm packages between November 21-24, 2025. This sophisticated campaign affected major development ecosystems including Zapier, AsyncAPI, Postman, PostHog, ENS Domains, and Voiceflow.

## 🎯 Critical Changes

### New IOC Database: `shai_hulud_2.py`

Comprehensive coverage of 533 compromised packages organized by ecosystem:

- **Zapier Ecosystem** (16 packages)
  - Platform automation and integration tools
  - Versions: 18.0.2 - 18.0.4 affected

- **AsyncAPI Tools** (36 packages)
  - API specification and code generation
  - Multiple template and parser packages

- **Postman Tools** (16 packages)
  - API development and testing ecosystem
  - Binary packages for Linux, macOS, Windows

- **PostHog Analytics** (47 packages)
  - Product analytics and feature management
  - Multiple plugins and integrations

- **ENS Domains** (46 packages)
  - Ethereum Name Service infrastructure
  - Smart contract and resolver packages

- **Voiceflow Platform** (56 packages)
  - Conversational AI development
  - Extensive SDK and tooling packages

- **Additional Packages** (300+ packages)
  - Development tools and libraries
  - React Native, Node.js, and CLI tools

## 🔍 Attack Characteristics

### Key Differences from Shai Hulud 1.0

1. **Execution Method**: Uses `preinstall` scripts instead of postinstall
2. **New Payloads**: 
   - `setup_bun.js` - Stealthy loader for Bun runtime
   - `bun_environment.js` - 10MB obfuscated malicious script
3. **Expanded Targeting**: Multi-cloud and container environments
4. **Persistence**: GitHub Actions workflow injection

### Attack Capabilities

- **Multi-Cloud Credential Theft**: AWS, Azure, GCP
- **Docker Privilege Escalation**: Container breakout attempts
- **GitHub Secret Exfiltration**: Via workflow injection
- **Self-Hosted Runner Backdoor**: Named "SHA1HULUD"
- **Network Exfiltration**: Via webhook.site

## 📊 Indicators of Compromise

### GitHub Indicators
- Malicious workflows: `discussion.yaml`, `formatter_123456789.yml`
- Self-hosted runner: `SHA1HULUD`
- Repository descriptions containing "Shai-Hulud"

### File Artifacts
- `cloud.json` - Cloud credential dumps
- `contents.json` - Repository content exfiltration
- `environment.json` - Environment variable capture
- `truffleSecrets.json` - Secret scanning results
- `setup_bun.js` - Payload loader
- `bun_environment.js` - Main malicious payload

### Network Indicators
- Outbound connections to `webhook.site`
- Unauthorized GitHub repository creation

## 🛡️ Detection Capabilities

The scanner now detects:
- All 533 compromised package versions
- Malicious GitHub workflow files
- Self-hosted runner configurations
- Exfiltration artifacts
- Network indicators

## 📚 Sources

This release incorporates threat intelligence from:
- **Wiz Research**: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
- **Socket Security**: https://socket.dev/blog/shai-hulud-strikes-again-v2
- **Wiz IOCs**: https://github.com/wiz-sec-public/wiz-research-iocs

## 🔧 Installation

```bash
pip install --upgrade github-ioc-scanner
```

## 📖 Usage

Scan for Shai Hulud 2.0 IOCs:

```bash
github-ioc-scan --repo owner/repo --token YOUR_TOKEN
```

The scanner will automatically check against all known IOCs including the new Shai Hulud 2.0 indicators.

## ⚠️ Recommended Actions

If you find any of these packages in your environment:

1. **Immediate Actions**:
   - Remove compromised packages immediately
   - Delete `node_modules` folder
   - Clear npm cache: `npm cache clean --force`

2. **Credential Rotation**:
   - Rotate all npm tokens
   - Rotate GitHub Personal Access Tokens
   - Rotate SSH keys
   - Rotate cloud provider credentials (AWS, Azure, GCP)
   - Enforce MFA on all accounts

3. **GitHub Audit**:
   - Search for repositories with "Shai-Hulud" in description
   - Review for unauthorized workflows
   - Check for self-hosted runners named "SHA1HULUD"
   - Audit recent npm publishes

4. **Security Hardening**:
   - Restrict/disable lifecycle scripts in CI/CD
   - Limit outbound network access from build systems
   - Use short-lived, scoped automation tokens
   - Review and update dependency pinning

## 🎓 MITRE ATT&CK Mapping

- **TA0001** - Initial Access: npm package versions
- **TA0002** - Execution: preinstall script in package.json
- **TA0003** - Persistence: GitHub Actions workflow injection
- **TA0007** - Discovery: Cloud metadata endpoint access
- **TA0009** - Collection: Encoded secret files
- **TA0010** - Exfiltration: webhook.site and GitHub repos

## 📈 Impact Assessment

- **Affected Repositories**: 25,000+
- **Affected Users**: ~350
- **Compromised Packages**: 533+
- **Attack Duration**: November 21-24, 2025
- **Detection Window**: Ongoing

## 🔐 Security Notice

This is a **CRITICAL** security release. All users should update immediately and scan their repositories for these IOCs. The attack is sophisticated and targets multiple cloud platforms and development tools.

## 📞 Support

- GitHub Issues: https://github.com/christianherweg0807/github_package_scanner/issues
- Documentation: https://github.com/christianherweg0807/github_package_scanner/tree/main/docs

---

**Stay vigilant and keep your dependencies secure!**
