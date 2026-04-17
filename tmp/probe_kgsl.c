/*
 * Probe KGSL ioctls to find correct struct sizes for this kernel.
 * The ioctl cmd encodes struct size; if mismatch, kernel returns EINVAL
 * with "Malformed ioctl code" message.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09

/* Try different sizes for a given ioctl nr + direction */
static void probe_ioctl_sizes(int fd, int nr, const char *name) {
    printf("\n=== Probing %s (nr=0x%02x) ===\n", name, nr);

    char buf[512];
    memset(buf, 0, sizeof(buf));

    /* Try sizes from 4 to 256 in steps of 4 */
    for (int sz = 4; sz <= 256; sz += 4) {
        /* Try _IOWR direction (most common for kgsl) */
        unsigned int cmd = (3u << 30) | ((unsigned int)sz << 16) | (KGSL_IOC_TYPE << 8) | nr;
        memset(buf, 0, sizeof(buf));
        int ret = ioctl(fd, cmd, buf);
        int e = errno;

        /* EINVAL with our data = handler reached, size matched!
         * ENOTTY = ioctl not found (size mismatch in dispatch)
         * EINVAL from dispatch = "Malformed ioctl code" = size mismatch */
        if (ret == 0) {
            printf("  [!!!] size=%3d (0x%02x) cmd=0x%08x -> SUCCESS! Data:\n", sz, sz, cmd);
            for (int i = 0; i < sz && i < 64; i += 4)
                printf("    +%02d: 0x%08x\n", i, *(uint32_t*)(buf+i));
            return;
        }

        /* We need to distinguish "size mismatch" EINVAL from "handler validation" EINVAL.
         * Try with flags that should be invalid to detect handler-level EINVAL. */
        if (e != EINVAL) {
            /* Some other error */
            if (e == ENOTTY) continue; /* ioctl not found */
            printf("  [?]  size=%3d -> errno=%d (%s)\n", sz, e, strerror(e));
        }
    }

    /* Also try _IOW (write-only) direction */
    for (int sz = 4; sz <= 256; sz += 4) {
        unsigned int cmd = (1u << 30) | ((unsigned int)sz << 16) | (KGSL_IOC_TYPE << 8) | nr;
        memset(buf, 0, sizeof(buf));
        int ret = ioctl(fd, cmd, buf);
        int e = errno;
        if (ret == 0) {
            printf("  [!!!] IOW size=%3d (0x%02x) cmd=0x%08x -> SUCCESS!\n", sz, sz, cmd);
            return;
        }
        if (e != EINVAL && e != ENOTTY)
            printf("  [?]  IOW size=%3d -> errno=%d (%s)\n", sz, e, strerror(e));
    }

    printf("  [X] No successful size found for nr=0x%02x\n", nr);
}

/* More targeted probe: try to distinguish "dispatcher EINVAL" from "handler EINVAL" */
static void probe_ioctl_detailed(int fd, int nr, const char *name) {
    printf("\n=== Detailed probe for %s (nr=0x%02x) ===\n", name, nr);

    char buf[512];

    /* For each candidate size, try two different payloads:
     * - All-zero (most likely to pass handler validation)
     * - All-0xFF (most likely to fail handler validation)
     * If both give EINVAL, it's likely the dispatcher rejecting the size.
     * If zero succeeds but 0xFF fails, we found the correct size! */
    for (int sz = 4; sz <= 120; sz += 4) {
        unsigned int cmd = (3u << 30) | ((unsigned int)sz << 16) | (KGSL_IOC_TYPE << 8) | nr;

        /* Test 1: all zeros */
        memset(buf, 0, sizeof(buf));
        int ret0 = ioctl(fd, cmd, buf);
        int e0 = errno;

        /* Test 2: valid-looking flags (0x44 = IB_LIST|PER_CONTEXT_TS) */
        memset(buf, 0, sizeof(buf));
        *(uint32_t*)buf = 0x44;
        int ret1 = ioctl(fd, cmd, buf);
        int e1 = errno;

        /* Test 3: nonsense flags */
        memset(buf, 0xFF, sizeof(buf));
        int ret2 = ioctl(fd, cmd, buf);
        int e2 = errno;

        if (ret0 == 0 || ret1 == 0) {
            printf("  >>> size=%3d (0x%02x) WORKS! ret0=%d(%s) ret1=%d(%s)\n",
                   sz, sz, ret0, ret0?strerror(e0):"ok", ret1, ret1?strerror(e1):"ok");
            if (ret0 == 0) {
                printf("      Result (zeros):");
                for (int i = 0; i < sz && i < 32; i += 4)
                    printf(" %08x", *(uint32_t*)(buf+i));
                printf("\n");
            }
            if (ret1 == 0) {
                memset(buf, 0, sizeof(buf));
                *(uint32_t*)buf = 0x44;
                ioctl(fd, cmd, buf);
                printf("      Result (0x44): ");
                for (int i = 0; i < sz && i < 32; i += 4)
                    printf(" %08x", *(uint32_t*)(buf+i));
                printf("\n");
            }
            return;
        }

        /* If errors differ, the handler was reached (size correct) */
        if (e0 != e1 || e0 != e2) {
            printf("  [!] size=%3d errors differ: e0=%d(%s) e1=%d(%s) e2=%d(%s) -> handler reached!\n",
                   sz, e0, strerror(e0), e1, strerror(e1), e2, strerror(e2));
        }

        /* For debugging, show interesting sizes */
        if (sz == 8 || sz == 12 || sz == 16 || sz == 24 || sz == 32) {
            printf("  [.]  size=%3d: e0=%d(%s) e1=%d(%s) e2=%d(%s)\n",
                   sz, e0, strerror(e0), e1, strerror(e1), e2, strerror(e2));
        }
    }
}

/* Also probe GPU_COMMAND and related ioctls */
static void probe_gpu_command(int fd) {
    printf("\n=== Probing GPU_COMMAND (nr=0x34) sizes ===\n");
    for (int sz = 4; sz <= 128; sz += 4) {
        unsigned int cmd = (3u << 30) | ((unsigned int)sz << 16) | (KGSL_IOC_TYPE << 8) | 0x34;
        char buf[256];
        memset(buf, 0, sizeof(buf));
        int ret = ioctl(fd, cmd, buf);
        if (ret == 0) {
            printf("  [!!!] GPU_COMMAND size=%d WORKS\n", sz);
            return;
        }
        if (sz == 64 || sz == 72 || sz == 80 || sz == 88 || sz == 96) {
            printf("  [.]  size=%3d: errno=%d (%s)\n", sz, errno, strerror(errno));
        }
    }
}

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
        perror("open /dev/kgsl-3d0");
        return 1;
    }
    printf("[+] Opened /dev/kgsl-3d0 (fd=%d)\n", fd);

    /* First, verify GETPROPERTY works (we know this succeeds) */
    printf("\n--- Verifying GETPROPERTY (should work with size=0x18=24) ---\n");
    {
        unsigned int cmd = (3u << 30) | (24u << 16) | (KGSL_IOC_TYPE << 8) | 0x02;
        printf("Expected GETPROPERTY cmd: 0x%08x\n", cmd);
        uint32_t ver[4] = {0};
        struct {
            unsigned int type;
            unsigned int pad;
            void *value;
            unsigned int sizebytes;
            unsigned int pad2;
        } prop = { .type = 8, .value = ver, .sizebytes = sizeof(ver) };
        int ret = ioctl(fd, cmd, &prop);
        printf("GETPROPERTY version: ret=%d errno=%d ver=%u.%u/%u.%u\n",
               ret, errno, ver[0], ver[1], ver[2], ver[3]);
    }

    /* Probe DRAWCTXT_CREATE */
    probe_ioctl_detailed(fd, 0x13, "DRAWCTXT_CREATE");

    /* Probe DRAWCTXT_DESTROY */
    probe_ioctl_detailed(fd, 0x14, "DRAWCTXT_DESTROY");

    /* Probe GPUMEM_ALLOC_ID */
    probe_ioctl_detailed(fd, 0x2f, "GPUMEM_ALLOC_ID");

    /* Probe GPU_COMMAND */
    probe_gpu_command(fd);

    /* Probe GPUOBJ_ALLOC (0x45) and GPUOBJ_FREE (0x46) */
    probe_ioctl_detailed(fd, 0x45, "GPUOBJ_ALLOC");
    probe_ioctl_detailed(fd, 0x46, "GPUOBJ_FREE");

    /* Check dmesg for "Malformed ioctl code" */
    printf("\n--- Checking dmesg for KGSL messages ---\n");
    fflush(stdout);
    system("dmesg | grep -i 'kgsl\\|malformed\\|ioctl' | tail -20 2>/dev/null");

    close(fd);
    return 0;
}
