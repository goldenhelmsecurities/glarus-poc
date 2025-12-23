# Glarus - macOS dirhelper Local Privilege Escalation

**Vendor:** Apple Inc.  
**Product:** macOS  
**Affected Versions:** 26.0 (patched in 26.1)  
**Severity:** Local Privilege Escalation  
**Researcher:** Golden Helm Securities  

## Executive Summary

Glarus is a local privilege escalation exploit chain targeting macOS's `dirhelper` system daemon. By combining a string truncation vulnerability with a TOCTOU (Time-of-Check to Time-of-Use) race condition, an unprivileged local user can gain ownership of arbitrary root-owned files, enabling complete system compromise.

## Vulnerability Overview

| Component | Description |
|-----------|-------------|
| **Bug #1** | Unchecked `strlcat()` return value allows path truncation |
| **Bug #2** | TOCTOU race between `mkdir()` and `lchown()` operations |
| **Service** | `/usr/libexec/dirhelper` (runs as root) |
| **Impact** | User → Root privilege escalation |

## Repository Contents

```
glarus_poc_final/
├── README.md                      # This file
├── QUICKSTART.md                  # 5-minute reproduction guide
├── src/
│   ├── dirhelper_client.c         # MIG client (macOS 26+ compatible)
│   ├── race_swap.c                # TOCTOU race condition exploit
│   └── entitlements.plist         # Sandbox entitlements
├── scripts/
│   ├── build.sh                   # Build all components
│   ├── setup.sh                   # Setup hardlink structure
│   ├── exploit.sh                 # Main exploit orchestrator
│   └── cleanup.sh                 # Restore system state
└── docs/
    └── TECHNICAL_ANALYSIS.md      # Detailed vulnerability analysis
```

## Quick Start

```bash
# 1. Build all components
./scripts/build.sh

# 2. Run the exploit (targets /etc/newsyslog.conf by default)
./scripts/exploit.sh

# 3. Or specify a custom target
./scripts/exploit.sh /etc/hosts
```

See `QUICKSTART.md` for detailed reproduction steps.

## System Requirements

- macOS 14.0 or later (tested on 26.0)
- Xcode Command Line Tools (`xcode-select --install`)
- Local user account (no special privileges required)
- Target file must be on same filesystem as ~/Library

## Technical Note: Bundle ID

The exploit uses a fixed bundle ID (`com.glarus.poc`) for the target container. This is separate from DirhelperClient.app's own container (`com.example.dirhelper-client`).

To use a different bundle ID:
```bash
GLARUS_BUNDLE_ID=com.custom.bundle ./scripts/exploit.sh /etc/hosts
```

## Attack Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Phase 1       │     │   Phase 2       │     │   Phase 3       │
│   Setup         │ ──▶ │   Race          │ ──▶ │   Escalate      │
│                 │     │                 │     │                 │
│ • Create Fake/  │     │ • Trigger       │     │ • Modify owned  │
│   directory     │     │   dirhelper     │     │   file          │
│ • Hardlink to   │     │ • Win mkdir→    │     │ • Execute       │
│   target file   │     │   lchown race   │     │   privileged    │
│                 │     │ • Swap Data↔    │     │   action        │
│                 │     │   Fake (rename) │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

**Note:** The swap uses `rename()` instead of `symlink()` because Apple's
sandbox infrastructure blocks creating symlinks named "Data" in container
directories.

## Exploitation Targets

### Confirmed Exploitable (No TCC Protection)

| File | Impact |
|------|--------|
| `/etc/newsyslog.conf` | Log rotation → arbitrary file overwrite |
| `/etc/hosts` | DNS hijacking |
| `/etc/resolv.conf` | DNS resolver manipulation |
| `/etc/ntp.conf` | NTP configuration |
| `/etc/asl.conf` | System logging configuration |

### TCC Protected (Requires User Consent)

| File | Protection |
|------|------------|
| `/etc/pam.d/sudo` | "Administer Computer" TCC prompt |
| `/etc/pam.d/su` | "Administer Computer" TCC prompt |
| `/etc/sudoers` | "Administer Computer" TCC prompt |

### SIP Protected (Requires SIP Disabled)

| File | Notes |
|------|-------|
| `/System/*` | System Integrity Protection |
| `/usr/*` | System Integrity Protection |

## Post-Exploitation Examples

### After owning /etc/newsyslog.conf:
```bash
# Add entry to overwrite any file with log rotation
echo "/var/log/exploit.log 644 7 * * J /etc/crontab" >> /etc/newsyslog.conf
```

### After owning /etc/hosts:
```bash
# DNS hijacking
echo "192.168.1.100 legitimate-bank.com" >> /etc/hosts
```

### After owning /etc/pam.d/sudo (if TCC approved):
```bash
# Bypass sudo authentication
echo "auth sufficient pam_permit.so" | cat - /etc/pam.d/sudo > /tmp/sudo_new
cp /tmp/sudo_new /etc/pam.d/sudo
sudo -s  # No password required
```


## Timeline

| Date | Event |
|------|-------|
| 2025-08-08 | Initial dirhelper vulnerability reported to Apple |
| 2025-09-09 | Apple requests additional information |
| 2025-10-13 | Glarus TOCTOU patch released |
| 2025-10-16 | Glarus exploit technique submitted |
| 2025-12-22 | Public disclosure |

## References

- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [Apple MIG Documentation](https://developer.apple.com/documentation/kernel/mach)
- [strlcat(3) Manual](https://man.openbsd.org/strlcat.3)

## Disclaimer

This proof-of-concept is provided for authorized security research and Apple Bug Bounty submissions only. Use responsibly.

## Credits

Vulnerability Research and Exploit Development: **Golden Helm Securities**
