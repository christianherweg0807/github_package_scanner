"""
Shai-Hulud-like supply chain worm - Februar 2026

This file contains IOC definitions of 19 malicious packages

Source: https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning
Attack Type: Supply chain attack via typosquatting and AI toolchain poisoning
Attack Date: Februar 20, 2026
Threat Level: CRITICAL
"""

IOC_PACKAGES = {
    "claud-code": {"0.2.1"},
    "cloude-code": {"0.2.1"},
    "cloude": {"0.3.0"},
    "crypto-locale": {"1.0.0"},
    "crypto-reader-info": {"1.0.0"},
    "detect-cache": {"1.0.0"},
    "format-defaults": {"1.0.0"},
    "hardhta": {"1.0.0"},
    "locale-loader-pro": {"1.0.0"},
    "naniod": {"1.0.0"},
    "node-native-bridge": {"1.0.0"},
    "opencraw": {"2026.2.17"},
    "parse-compat": {"1.0.0"},
    "rimarf": {"1.0.0"},
    "scan-store": {"1.0.0"},
    "secp256": {"1.0.0"},
    "suport-color": {"1.0.1"},
    "veim": {"2.46.2"},
    "yarsg": {"18.0.1"},

    # -------------------
    # Sleeper Packages
    # -------------------
    "ethres": None,
    "iru-caches": None,
    "iruchache": None,
    "uudi": None,
}
