/*
 * storsec_rpmb.c - Deep exploration of storsec TZ app RPMB interface
 *
 * Uses both QSEECom_send_cmd and QSEECom_send_modified_cmd
 * to probe storsec's RPMB operations.
 *
 * Key insight from tz_probe:
 *   cmd=0: status=-24 (0xFFE8) → possibly "not initialized" or "no data"
 *   cmd=1, p2=0: status=-25 (0xFFE7) → "invalid param"
 *   cmd=1, p2=1: status=0 → SUCCESS! returns 0x100 (256) at offset 0x10
 *   cmd=1, p2=2: status=0 → SUCCESS! returns 0x100 (256) at offset 0x10
 *   cmd>=2: status=-15 (0xFFF1) → "not supported" (from egista, not storsec)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/* QSEECom types - more complete definition */
struct QSEECom_handle {
    unsigned char *ion_sbuffer;
};

struct QSEECom_ion_fd_info {
    int32_t fd;
    uint32_t cmd_buf_offset;
};

struct qseecom_send_modfd_cmd_req {
    struct QSEECom_ion_fd_info ifd_data[4];
};

typedef int (*QSEECom_start_app_fn)(struct QSEECom_handle **h,
    const char *path, const char *name, uint32_t sb_size);
typedef int (*QSEECom_shutdown_app_fn)(struct QSEECom_handle **h);
typedef int (*QSEECom_send_cmd_fn)(struct QSEECom_handle *h,
    void *send_buf, uint32_t sbuf_len,
    void *recv_buf, uint32_t rbuf_len);
typedef int (*QSEECom_send_modified_cmd_fn)(struct QSEECom_handle *h,
    void *send_buf, uint32_t sbuf_len,
    void *recv_buf, uint32_t rbuf_len,
    struct qseecom_send_modfd_cmd_req *ifd);
typedef int (*QSEECom_set_bandwidth_fn)(struct QSEECom_handle *h, int high);

static QSEECom_start_app_fn    qsc_start;
static QSEECom_shutdown_app_fn qsc_shutdown;
static QSEECom_send_cmd_fn     qsc_send;
static QSEECom_send_modified_cmd_fn qsc_send_mod;
static QSEECom_set_bandwidth_fn     qsc_set_bw;

static void hexdump(const char *label, const void *buf, int len) {
    const uint8_t *p = buf;
    printf("%s (%d bytes):\n", label, len);
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("  %04x: ", i);
        printf("%02x ", p[i]);
        if (i % 16 == 15 || i == len - 1) {
            if (i % 16 != 15) {
                for (int j = i % 16 + 1; j < 16; j++) printf("   ");
            }
            printf(" |");
            int start = i - (i % 16);
            for (int j = start; j <= i; j++) {
                printf("%c", (p[j] >= 0x20 && p[j] < 0x7f) ? p[j] : '.');
            }
            printf("|\n");
        }
    }
}

static int has_nonzero(const void *buf, int len) {
    const uint8_t *p = buf;
    for (int i = 0; i < len; i++) if (p[i]) return 1;
    return 0;
}

/*
 * Qualcomm storsec typically uses SFS (Secure File System) protocol.
 * The command structure for modern Qualcomm SFS over RPMB is:
 *
 * Request:
 *   [0x00] uint32_t cmd_id
 *   [0x04] uint32_t ... (varies per command)
 *
 * For RPMB partition operations:
 *   cmd=0: GET_PROVISION_STATUS / INIT
 *   cmd=1: READ_PARTITION_INFO (sub_id = partition index)
 *   cmd=2: READ_DATA
 *   cmd=3: WRITE_DATA
 *   cmd=4: ERASE_DATA
 *
 * Some implementations use a different layout:
 *   cmd=0x100/0x200: SFS operations
 *   cmd=0x300: RPMB raw operations
 *
 * Or the OnePlus/OEM variant:
 *   cmd=0: Query status
 *   cmd=1: Read with {partition_type, sub_id}
 *   cmd=2: Write with {partition_type, sub_id, data}
 */

int main(int argc, char *argv[]) {
    void *lib = dlopen("/vendor/lib64/libQSEEComAPI.so", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    qsc_start    = dlsym(lib, "QSEECom_start_app");
    qsc_shutdown = dlsym(lib, "QSEECom_shutdown_app");
    qsc_send     = dlsym(lib, "QSEECom_send_cmd");
    qsc_send_mod = dlsym(lib, "QSEECom_send_modified_cmd");
    qsc_set_bw   = dlsym(lib, "QSEECom_set_bandwidth");

    if (!qsc_start || !qsc_shutdown || !qsc_send) {
        fprintf(stderr, "Missing QSEECom functions\n");
        return 1;
    }
    printf("QSEECom_send_modified_cmd: %s\n", qsc_send_mod ? "available" : "NOT FOUND");
    printf("QSEECom_set_bandwidth: %s\n", qsc_set_bw ? "available" : "NOT FOUND");

    /* Use large shared buffer to enable data transfers */
    struct QSEECom_handle *h = NULL;
    uint32_t sbuf_size = 65536;  /* 64KB shared buffer */
    int ret = qsc_start(&h, "/vendor/firmware_mnt/image", "storsec", sbuf_size);
    if (ret != 0 || !h) {
        fprintf(stderr, "[-] start_app failed: ret=%d errno=%d\n", ret, errno);
        return 1;
    }
    printf("[+] Connected to storsec (sbuf=%u)\n\n", sbuf_size);

    /* Set high bandwidth for RPMB operations */
    if (qsc_set_bw) {
        ret = qsc_set_bw(h, 1);
        printf("[*] set_bandwidth(high): ret=%d\n", ret);
    }

    /* ======================================================
     * PHASE 1: Systematic cmd probe with storsec
     * The ion_sbuffer is divided: first half = request, second half = response
     * ====================================================== */
    printf("\n====== PHASE 1: Systematic command probe ======\n");

    for (uint32_t cmd = 0; cmd <= 20; cmd++) {
        uint8_t *req = h->ion_sbuffer;
        uint8_t *rsp = h->ion_sbuffer + sbuf_size / 2;
        memset(req, 0, sbuf_size / 2);
        memset(rsp, 0, sbuf_size / 2);

        *(uint32_t *)req = cmd;

        ret = qsc_send(h, req, sbuf_size / 2, rsp, sbuf_size / 2);
        int32_t status = *(int32_t *)(rsp + 4);

        if (ret == 0 && has_nonzero(rsp, 64)) {
            printf("[+] cmd=%u: ret=%d status=%d (0x%08x)\n", cmd, ret, status, (uint32_t)status);
            hexdump("  rsp", rsp, 64);
        } else if (ret != 0) {
            printf("[-] cmd=%u: ret=%d errno=%d\n", cmd, ret, errno);
        }
    }

    /* ======================================================
     * PHASE 2: Deep probe of cmd=1 (known working with p2=1)
     * Try all parameter combinations to understand the protocol
     * ====================================================== */
    printf("\n====== PHASE 2: Deep probe cmd=1 ======\n");

    /* From tz_probe: cmd=1, p2=1 returns success
     * Request at offset 4 is "something" and offset 8 is p2
     * Let me try different interpretations */

    /* Format A: {cmd, param1, param2} */
    printf("\n--- Format A: {cmd_id=1, p1, p2} as uint32 LE ---\n");
    for (uint32_t p1 = 0; p1 <= 3; p1++) {
        for (uint32_t p2 = 0; p2 <= 10; p2++) {
            uint8_t *req = h->ion_sbuffer;
            uint8_t *rsp = h->ion_sbuffer + sbuf_size / 2;
            memset(req, 0, 512);
            memset(rsp, 0, 512);

            ((uint32_t *)req)[0] = 1;  /* cmd */
            ((uint32_t *)req)[1] = p1;
            ((uint32_t *)req)[2] = p2;

            ret = qsc_send(h, req, 512, rsp, 512);
            int32_t st = *(int32_t *)(rsp + 4);

            if (st == 0) {
                printf("[+] p1=%u p2=%u: SUCCESS! ", p1, p2);
                printf("rsp[8-15]: %08x %08x\n",
                    ((uint32_t *)rsp)[2], ((uint32_t *)rsp)[3]);
                if (has_nonzero(rsp + 16, 48))
                    hexdump("  full rsp", rsp, 64);
            } else if (st != -15) { /* skip "not supported" from egista */
                printf("[-] p1=%u p2=%u: status=%d\n", p1, p2, st);
            }
        }
    }

    /* ======================================================
     * PHASE 3: Try to READ actual RPMB data through cmd=1
     * If p2 is a partition index, test with block offset
     * ====================================================== */
    printf("\n====== PHASE 3: Try reading RPMB data ======\n");

    /* Try cmd=1 with larger parameter space */
    printf("--- Trying cmd=1 with offset/length params ---\n");
    for (uint32_t part = 1; part <= 3; part++) {
        for (uint32_t off = 0; off <= 2; off++) {
            for (uint32_t len = 1; len <= 2; len++) {
                uint8_t *req = h->ion_sbuffer;
                uint8_t *rsp = h->ion_sbuffer + sbuf_size / 2;
                memset(req, 0, 1024);
                memset(rsp, 0, 4096);

                ((uint32_t *)req)[0] = 1;      /* cmd */
                ((uint32_t *)req)[1] = part;    /* partition */
                ((uint32_t *)req)[2] = off;     /* offset */
                ((uint32_t *)req)[3] = len;     /* length */
                ((uint32_t *)req)[4] = 256;     /* buffer size */

                ret = qsc_send(h, req, 1024, rsp, 4096);
                int32_t st = *(int32_t *)(rsp + 4);

                if (st == 0 && has_nonzero(rsp + 16, 256)) {
                    printf("[+] part=%u off=%u len=%u: data returned!\n", part, off, len);
                    hexdump("  rsp", rsp, 128);
                }
            }
        }
    }

    /* ======================================================
     * PHASE 4: Try cmd=2 (potential WRITE command)
     * ====================================================== */
    printf("\n====== PHASE 4: Probe cmd=2 (possible write) ======\n");

    /* First just probe if cmd=2 is accepted */
    for (uint32_t p1 = 0; p1 <= 3; p1++) {
        for (uint32_t p2 = 0; p2 <= 5; p2++) {
            uint8_t *req = h->ion_sbuffer;
            uint8_t *rsp = h->ion_sbuffer + sbuf_size / 2;
            memset(req, 0, 512);
            memset(rsp, 0, 512);

            ((uint32_t *)req)[0] = 2;  /* cmd=2 (write?) */
            ((uint32_t *)req)[1] = p1;
            ((uint32_t *)req)[2] = p2;

            ret = qsc_send(h, req, 512, rsp, 512);
            int32_t st = *(int32_t *)(rsp + 4);

            if (st != -15) {  /* Not "unsupported" */
                printf("[!] cmd=2 p1=%u p2=%u: ret=%d status=%d\n", p1, p2, ret, st);
                if (has_nonzero(rsp, 32))
                    hexdump("  rsp", rsp, 32);
            }
        }
    }

    /* Try larger cmd IDs specific to Qualcomm SFS */
    printf("\n--- Trying SFS-style command IDs ---\n");
    uint32_t sfs_cmds[] = {
        0x10, 0x11, 0x12, 0x13, /* SFS operations */
        0x20, 0x21, 0x22, 0x23, /* RPMB partition ops */
        0x30, 0x31, 0x32, 0x33, /* raw RPMB */
        0x100, 0x101, 0x102, 0x103, /* extended SFS */
        0x200, 0x201, 0x202, 0x203, /* extended RPMB */
        0x300, 0x301, 0x302, 0x303, /* raw RPMB frame */
        0x1000, 0x1001, 0x1002,     /* GP TEE storage */
    };
    for (int i = 0; i < sizeof(sfs_cmds)/sizeof(sfs_cmds[0]); i++) {
        uint8_t *req = h->ion_sbuffer;
        uint8_t *rsp = h->ion_sbuffer + sbuf_size / 2;
        memset(req, 0, 512);
        memset(rsp, 0, 512);

        ((uint32_t *)req)[0] = sfs_cmds[i];
        ((uint32_t *)req)[1] = 1;  /* try with param=1 */

        ret = qsc_send(h, req, 512, rsp, 512);
        int32_t st = *(int32_t *)(rsp + 4);

        if (ret == 0 && st != -15 && st != 0 && has_nonzero(rsp, 16)) {
            printf("[!] cmd=0x%x: status=%d (0x%08x)\n", sfs_cmds[i], st, (uint32_t)st);
            hexdump("  rsp", rsp, 32);
        } else if (st == 0) {
            printf("[+] cmd=0x%x: SUCCESS!\n", sfs_cmds[i]);
            hexdump("  rsp", rsp, 64);
        }
    }

    /* ======================================================
     * PHASE 5: Try send_modified_cmd with ION fd info
     * This is needed for large data transfers
     * ====================================================== */
    if (qsc_send_mod) {
        printf("\n====== PHASE 5: QSEECom_send_modified_cmd ======\n");

        struct qseecom_send_modfd_cmd_req ifd = {0};
        /* No extra ION fds - just test the API path */
        ifd.ifd_data[0].fd = -1;
        ifd.ifd_data[1].fd = -1;
        ifd.ifd_data[2].fd = -1;
        ifd.ifd_data[3].fd = -1;

        uint8_t *req = h->ion_sbuffer;
        uint8_t *rsp = h->ion_sbuffer + sbuf_size / 2;

        /* Try cmd=1 (known working) via modified path */
        memset(req, 0, 4096);
        memset(rsp, 0, 4096);
        ((uint32_t *)req)[0] = 1;  /* cmd=1 */
        ((uint32_t *)req)[1] = 0;  /* p1 */
        ((uint32_t *)req)[2] = 1;  /* p2=1 (known success) */

        ret = qsc_send_mod(h, req, 4096, rsp, 4096, &ifd);
        printf("[*] send_modified_cmd(cmd=1,p2=1): ret=%d\n", ret);
        if (ret == 0) {
            int32_t st = *(int32_t *)(rsp + 4);
            printf("    status=%d\n", st);
            if (has_nonzero(rsp, 128))
                hexdump("  rsp", rsp, 128);
        }

        /* Try cmd=2 via modified path */
        memset(req, 0, 4096);
        memset(rsp, 0, 4096);
        ((uint32_t *)req)[0] = 2;  /* cmd=2 */
        ((uint32_t *)req)[1] = 0;
        ((uint32_t *)req)[2] = 1;  /* p2=1 */

        ret = qsc_send_mod(h, req, 4096, rsp, 4096, &ifd);
        printf("[*] send_modified_cmd(cmd=2,p2=1): ret=%d\n", ret);
        if (ret == 0) {
            int32_t st = *(int32_t *)(rsp + 4);
            printf("    status=%d\n", st);
            if (has_nonzero(rsp, 64))
                hexdump("  rsp", rsp, 64);
        }

        /* Try cmd=1 with larger response expecting actual data */
        memset(req, 0, 4096);
        memset(rsp, 0, sbuf_size / 2);
        ((uint32_t *)req)[0] = 1;
        ((uint32_t *)req)[1] = 0;   /* partition 0 */
        ((uint32_t *)req)[2] = 1;   /* sub-cmd 1 */
        ((uint32_t *)req)[3] = 0;   /* block 0 */
        ((uint32_t *)req)[4] = 1;   /* 1 block */
        ((uint32_t *)req)[5] = 256; /* buffer offset for data */

        ret = qsc_send_mod(h, req, 4096, rsp, sbuf_size / 2, &ifd);
        printf("[*] send_modified_cmd(cmd=1,read,block=0): ret=%d\n", ret);
        if (ret == 0) {
            int32_t st = *(int32_t *)(rsp + 4);
            printf("    status=%d\n", st);
            /* Check if data appeared anywhere in the large response */
            for (int off = 0; off < 4096; off += 256) {
                if (has_nonzero(rsp + off, 256)) {
                    printf("    Data found at response offset %d:\n", off);
                    hexdump("    block", rsp + off,
                        (off + 256 <= 4096) ? 256 : 4096 - off);
                }
            }
        }
    }

    /* ======================================================
     * PHASE 6: Direct QSEECOM ioctl approach
     * Use raw ioctl to /dev/qseecom for maximum control
     * ====================================================== */
    printf("\n====== PHASE 6: Direct /dev/qseecom ioctl ======\n");

    int qsee_fd = open("/dev/qseecom", O_RDWR);
    if (qsee_fd < 0) {
        printf("[-] Cannot open /dev/qseecom: %s\n", strerror(errno));
    } else {
        printf("[+] Opened /dev/qseecom fd=%d\n", qsee_fd);

        /* QSEECOM_IOCTL_GET_QSEOS_VERSION = _IOWR('r', 2, ...) */
        uint32_t qseos_ver = 0;
        ret = ioctl(qsee_fd, 0xC004E602, &qseos_ver);
        printf("[*] QSEOS version ioctl: ret=%d ver=0x%08x\n", ret, qseos_ver);

        /* Try to check registered listeners */
        close(qsee_fd);
    }

    /* Clean up */
    if (qsc_set_bw) qsc_set_bw(h, 0);
    qsc_shutdown(&h);
    printf("\n[*] Done.\n");
    return 0;
}
