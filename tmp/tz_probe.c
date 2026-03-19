/*
 * tz_probe.c - Probe storsec and egista TZ app commands
 * Focus on finding RPMB write or device state modification capabilities
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <errno.h>

struct QSEECom_handle {
    unsigned char *ion_sbuffer;
    unsigned char *ion_alloc_handle;
};

typedef int (*start_app_fn)(struct QSEECom_handle **handle,
    const char *path, const char *name, uint32_t sb_size);
typedef int (*shutdown_app_fn)(struct QSEECom_handle **handle);
typedef int (*send_cmd_fn)(struct QSEECom_handle *handle,
    void *send_buf, uint32_t sbuf_len,
    void *recv_buf, uint32_t rbuf_len);
typedef int (*send_mod_cmd_fn)(struct QSEECom_handle *handle,
    void *send_buf, uint32_t sbuf_len,
    void *recv_buf, uint32_t rbuf_len,
    void *ifd_data);

static start_app_fn    qsc_start;
static shutdown_app_fn qsc_shutdown;
static send_cmd_fn     qsc_send;
static send_mod_cmd_fn qsc_send_mod;

static void hexdump(const void *buf, int len) {
    const uint8_t *p = buf;
    for (int i = 0; i < len && i < 128; i++) {
        if (i % 16 == 0) printf("  %04x: ", i);
        printf("%02x ", p[i]);
        if (i % 16 == 15 || i == len - 1) printf("\n");
    }
}

static int has_nonzero(const void *buf, int len) {
    const uint8_t *p = buf;
    for (int i = 0; i < len; i++)
        if (p[i]) return 1;
    return 0;
}

static void probe_app(const char *path, const char *name, uint32_t sbsize) {
    struct QSEECom_handle *handle = NULL;
    
    printf("\n====== Probing %s (sbuf=%u) ======\n", name, sbsize);
    
    int ret = qsc_start(&handle, path, name, sbsize);
    if (ret != 0 || !handle) {
        printf("[-] Failed to connect: ret=%d errno=%d\n", ret, errno);
        return;
    }
    printf("[+] Connected to %s\n\n", name);
    
    /* Phase 1: Probe small range of cmd_ids with various buffer sizes */
    uint32_t cmd_sizes[] = {8, 16, 32, 64, 128, 256, 512, 1024};
    
    for (int si = 0; si < sizeof(cmd_sizes)/sizeof(cmd_sizes[0]); si++) {
        uint32_t sz = cmd_sizes[si];
        if (sz > sbsize / 2) break;
        
        printf("[*] Testing with buffer size %u...\n", sz);
        
        for (uint32_t cmd = 0; cmd <= 20; cmd++) {
            uint8_t sbuf[1024] = {0};
            uint8_t rbuf[1024] = {0};
            
            /* Set command ID as first uint32 */
            memcpy(sbuf, &cmd, 4);
            
            ret = qsc_send(handle, sbuf, sz, rbuf, sz);
            
            /* Only report interesting results (not the generic -2 error) */
            int32_t status;
            memcpy(&status, rbuf + 4, 4);
            
            if (ret == 0 && status != (int32_t)0xfffffffe && has_nonzero(rbuf, sz)) {
                printf("[+] cmd=%u sz=%u: ret=%d status_field=%d (0x%08x)\n",
                       cmd, sz, ret, status, (uint32_t)status);
                hexdump(rbuf, sz < 64 ? sz : 64);
            }
        }
    }
    
    /* Phase 2: For storsec, try cmd_id=1 with various parameter combinations */
    if (strcmp(name, "storsec") == 0) {
        printf("\n[*] Storsec cmd_id=1 deep probe...\n");
        for (uint32_t p1 = 0; p1 <= 10; p1++) {
            for (uint32_t p2 = 0; p2 <= 2; p2++) {
                uint8_t sbuf[256] = {0};
                uint8_t rbuf[256] = {0};
                uint32_t cmd = 1;
                memcpy(sbuf, &cmd, 4);
                memcpy(sbuf + 4, &p1, 4);
                memcpy(sbuf + 8, &p2, 4);
                
                ret = qsc_send(handle, sbuf, 256, rbuf, 256);
                int32_t res;
                memcpy(&res, rbuf + 4, 4);
                
                if (res != (int32_t)0xfffffffe) {
                    printf("  cmd=1 p1=%u p2=%u: result=%d\n", p1, p2, res);
                    if (has_nonzero(rbuf + 8, 32))
                        hexdump(rbuf, 48);
                }
            }
        }
    }
    
    /* Phase 3: For egista, try OnePlus/OPPO specific commands */
    if (strcmp(name, "egista") == 0) {
        printf("\n[*] Egista OnePlus-specific probing...\n");
        
        /* Try large cmd_id ranges that OnePlus might use */
        uint32_t test_cmds[] = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            0x100, 0x101, 0x102, 0x103, 0x104, 0x105,
            0x200, 0x201, 0x202, 0x203,
            0x300, 0x301, 0x302,
            0x1000, 0x1001, 0x1002, 0x1003,
            0x2000, 0x2001, 0x2002,
            0x10000, 0x10001,
            0x100000, 0x100001,
            /* OnePlus engineer mode commands */
            0x4F50, /* "OP" */
            0x4F50454E, /* "OPEN" */
            100, 200, 300, 400, 500,
        };
        
        for (int i = 0; i < sizeof(test_cmds)/sizeof(test_cmds[0]); i++) {
            uint8_t sbuf[512] = {0};
            uint8_t rbuf[512] = {0};
            uint32_t cmd = test_cmds[i];
            memcpy(sbuf, &cmd, 4);
            
            ret = qsc_send(handle, sbuf, 512, rbuf, 512);
            
            /* Report anything that's not a generic error */
            int32_t res;
            memcpy(&res, rbuf + 4, 4);
            uint32_t w0;
            memcpy(&w0, rbuf, 4);
            
            if (ret == 0 && (w0 != 0 || res != (int32_t)0xfffffffe)) {
                printf("[+] cmd=0x%x: w0=0x%08x result=%d (0x%08x)\n",
                       cmd, w0, res, (uint32_t)res);
                if (has_nonzero(rbuf + 8, 56))
                    hexdump(rbuf, 64);
            }
        }
        
        /* Try with "unlock" related strings in the buffer */
        printf("\n[*] Trying string-based commands...\n");
        const char *strings[] = {
            "unlock", "oem_unlock", "device_unlock",
            "get_state", "set_state", "devinfo",
            "getvar", "setvar"
        };
        for (int s = 0; s < sizeof(strings)/sizeof(strings[0]); s++) {
            uint8_t sbuf[512] = {0};
            uint8_t rbuf[512] = {0};
            /* cmd_id = 0 with string payload */
            strncpy((char *)sbuf + 4, strings[s], 500);
            
            ret = qsc_send(handle, sbuf, 512, rbuf, 512);
            if (ret == 0 && has_nonzero(rbuf, 64)) {
                int32_t res;
                memcpy(&res, rbuf + 4, 4);
                if (res != (int32_t)0xfffffffe) {
                    printf("[+] String '%s': ", strings[s]);
                    hexdump(rbuf, 32);
                }
            }
        }
    }
    
    qsc_shutdown(&handle);
    printf("[*] %s shutdown\n", name);
}

int main() {
    void *lib = dlopen("/vendor/lib64/libQSEEComAPI.so", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }
    
    qsc_start    = dlsym(lib, "QSEECom_start_app");
    qsc_shutdown = dlsym(lib, "QSEECom_shutdown_app");
    qsc_send     = dlsym(lib, "QSEECom_send_cmd");
    qsc_send_mod = dlsym(lib, "QSEECom_send_modified_cmd");
    
    if (!qsc_start || !qsc_shutdown || !qsc_send) {
        fprintf(stderr, "Failed to resolve functions\n");
        return 1;
    }
    
    printf("=== TZ App Probing Tool ===\n");
    
    /* Probe storsec */
    probe_app("/vendor/firmware_mnt/image", "storsec", 4096);
    
    /* Probe egista (already loaded at boot) */
    probe_app("/vendor/firmware_mnt/image", "egista", 4096);
    
    /* Also try soter64 */
    probe_app("/vendor/firmware_mnt/image", "soter64", 4096);
    
    return 0;
}
