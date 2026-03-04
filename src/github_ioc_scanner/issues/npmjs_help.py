"""
Phishing campaign npmjs help - September 2025

This file contains IOC definitions for 19 packages that got compromised
after a phishing campaign via the domain `npmjs.help`.

Source: https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised
Source: https://socket.dev/blog/npm-author-qix-compromised-in-major-supply-chain-attack
Source: https://www.ox.security/blog/npm-packages-compromised/
Attack Type: Supply chain attack with malware payload
Attack Date: September 8, 2025
Threat Level: CRITICAL
"""

IOC_PACKAGES = {
    "ansi-regex": {"6.2.1"},
    "ansi-styles": {"6.2.2"},
    "backslash": {"0.2.1"},
    "chalk": {"5.6.1"},
    "chalk-template": {"1.1.1"},
    "color-convert": {"3.1.1"},
    "color-name": {"2.0.1"},
    "color-string": {"2.1.1"},
    "debug": {"4.4.2"},
    "error-ex": {"1.3.3"},
    "has-ansi": {"6.0.1"},
    "is-arrayish": {"0.3.3"},
    "proto-tinker-wc": {"1.8.7"},
    "simple-swizzle": {"0.2.3"},
    "slice-ansi": {"7.1.1"},
    "strip-ansi": {"7.1.1"},
    "supports-color": {"10.2.1"},
    "supports-hyperlinks": {"4.1.1"},
    "wrap-ansi": {"9.0.1"},
}
