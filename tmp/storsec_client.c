/*
 * storsec_client.c - Qualcomm StorSec TZ app client
 *
 * Probes the storsec TZ app command interface to find
 * RPMB read/write capabilities.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>

/* QSEECom types */
struct QSEECom_handle {
    unsigned char *ion_sbuffer;
    unsigned char *ion_alloc_handle; /* placeholder */
};

typedef int (*QSEECom_start_app_fn)(struct QSEECom_handle **handle,
    const char *path, const char *name, uint32_t sb_size);
typedef int (*QSEECom_shutdown_app_fn)(struct QSEECom_handle **handle);
typedef int (*QSEECom_send_cmd_fn)(struct QSEECom_handle *handle,
    void *send_buf, uint32_t sbuf_len,
    void *recv_buf, uint32_t rbuf_len);

static QSEECom_start_app_fn    qsc_start;
static QSEECom_shutdown_app_fn qsc_shutdown;
static QSEECom_send_cmd_fn     qsc_send;

/* Generic storsec command header */
struct storsec_cmd_req {
    uint32_t cmd_id;
    uint32_t data[63]; /* up to 252 bytes of command data */
};

struct storsec_cmd_rsp {
    uint32_t status;
    uint32_t data[63];
};

/* RPMB-related command structures */
struct storsec_rpmb_info_req {
    uint32_t cmd_id;
};

struct storsec_rpmb_info_rsp {
    uint32_t status;
    uint32_t max_blocks;
    uint32_t write_counter;
    uint32_t key_provisioned;
    uint32_t extra[60];
};

struct storsec_rpmb_rw_req {
    uint32_t cmd_id;
    uint32_t block_addr;
    uint32_t block_count;
    uint32_t direction; /* 0=read, 1=write */
    uint8_t  data[256]; /* block data for write */
};

struct storsec_rpmb_rw_rsp {
    uint32_t status;
    uint8_t  data[256]; /* block data for read */
};

static void hexdump(const void *buf, int len) {
    const uint8_t *p = buf;
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("  %04x: ", i);
        printf("%02x ", p[i]);
        if (i % 16 == 15 || i == len - 1) printf("\n");
    }
}

static int probe_cmd(struct QSEECom_handle *handle, uint32_t cmd_id,
                     const void *extra_data, uint32_t extra_len) {
    uint8_t sbuf[256] = {0};
    uint8_t rbuf[256] = {0};

    /* Set command ID */
    memcpy(sbuf, &cmd_id, 4);
    if (extra_data && extra_len > 0 && extra_len <= 252) {
        memcpy(sbuf + 4, extra_data, extra_len);
    }

    int ret = qsc_send(handle, sbuf, sizeof(sbuf), rbuf, sizeof(rbuf));

    uint32_t status = 0;
    memcpy(&status, rbuf, 4);

    if (ret == 0 || (ret < 0 && errno != 22)) {
        printf("[+] cmd_id=%u: ret=%d errno=%d status=0x%08x\n",
               cmd_id, ret, errno, status);
        /* Show first 32 bytes of response */
        int has_data = 0;
        for (int i = 0; i < 32; i++) {
            if (rbuf[i]) { has_data = 1; break; }
        }
        if (has_data) {
            printf("    Response:\n");
            hexdump(rbuf, 64);
        }
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    void *lib = dlopen("/vendor/lib64/libQSEEComAPI.so", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    qsc_start = dlsym(lib, "QSEECom_start_app");
    qsc_shutdown = dlsym(lib, "QSEECom_shutdown_app");
    qsc_send = dlsym(lib, "QSEECom_send_cmd");

    if (!qsc_start || !qsc_shutdown || !qsc_send) {
        fprintf(stderr, "Failed to resolve QSEECom functions\n");
        return 1;
    }

    printf("=== StorSec TZ App Client ===\n\n");

    /* Try different shared buffer sizes */
    struct QSEECom_handle *handle = NULL;
    int sbuf_sizes[] = {4096, 8192, 16384, 32768, 65536, 1024};
    int connected = 0;

    for (int i = 0; i < sizeof(sbuf_sizes)/sizeof(sbuf_sizes[0]); i++) {
        handle = NULL;
        int ret = qsc_start(&handle, "/vendor/firmware_mnt/image",
                           "storsec", sbuf_sizes[i]);
        if (ret == 0 && handle) {
            printf("[+] Connected to storsec (sbuf_size=%d)\n", sbuf_sizes[i]);
            connected = 1;
            break;
        }
        printf("[-] start_app with sbuf=%d: ret=%d errno=%d\n",
               sbuf_sizes[i], ret, errno);
    }

    if (!connected) {
        fprintf(stderr, "[-] Could not connect to storsec with any buffer size\n");
        return 1;
    }

    printf("\n[*] Probing command IDs 0-31...\n");
    int found = 0;
    for (uint32_t cmd = 0; cmd <= 31; cmd++) {
        if (probe_cmd(handle, cmd, NULL, 0)) {
            found++;
        }
    }

    if (found == 0) {
        printf("\n[*] No commands responded to basic probe.\n");
        printf("[*] Trying with different command formats...\n\n");

        /* Try with sub-command structure */
        for (uint32_t cmd = 0; cmd <= 31; cmd++) {
            uint32_t extra[4] = {0, 0, 0, 0};
            /* Try with sub-cmd = 1 */
            extra[0] = 1;
            if (probe_cmd(handle, cmd, extra, 16)) {
                found++;
            }
        }
    }

    if (found == 0) {
        printf("\n[*] Trying large command ID range (100-200, 256-300, 0x1000-0x1010)...\n");
        uint32_t ranges[] = {100, 200, 256, 300, 0x1000, 0x1010, 0x10000, 0x10010};
        for (int r = 0; r < sizeof(ranges)/sizeof(ranges[0]); r += 2) {
            for (uint32_t cmd = ranges[r]; cmd <= ranges[r+1]; cmd++) {
                if (probe_cmd(handle, cmd, NULL, 0)) {
                    found++;
                }
            }
        }
    }

    printf("\n[*] Total responding commands: %d\n", found);

    /* Try RPMB-specific commands */
    printf("\n[*] Trying RPMB-specific probes...\n");

    /* Qualcomm RPMB get_info pattern */
    struct {
        uint32_t cmd_id;
        uint32_t subcmd;
    } rpmb_info = {0x10, 0};
    probe_cmd(handle, rpmb_info.cmd_id, &rpmb_info.subcmd, 4);

    /* StorSec RPMB read block 0 */
    struct {
        uint32_t block_addr;
        uint32_t block_count;
    } rpmb_read = {0, 1};
    for (uint32_t cmd = 1; cmd <= 16; cmd++) {
        uint8_t buf[16] = {0};
        memcpy(buf, &rpmb_read, 8);
        if (probe_cmd(handle, cmd, buf, 8)) {
            printf("    ^ Possible RPMB read with cmd_id=%d\n", cmd);
        }
    }

    printf("\n[*] Shutting down storsec\n");
    qsc_shutdown(&handle);

    return 0;
}
