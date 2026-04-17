/*
 * Focused probe for DRAWCTXT_CREATE - try real flag values with different sizes
 * and also scan different ioctl NRs in case the numbering changed.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09

#define MY_IOWR(type, nr, size) \
    (0xC0000000UL | (((unsigned long)(size) & 0x3FFF) << 16) | ((type & 0xFF) << 8) | (nr & 0xFF))
#define MY_IOW(type, nr, size) \
    (0x40000000UL | (((unsigned long)(size) & 0x3FFF) << 16) | ((type & 0xFF) << 8) | (nr & 0xFF))

int main() {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    /* Flag combinations to try */
    unsigned int flags[] = {
        0x00000044, /* SUBMIT_IB_LIST | PER_CONTEXT_TS */
        0x00000004, /* SUBMIT_IB_LIST */
        0x00000054, /* SUBMIT_IB_LIST | PER_CONTEXT_TS | PREAMBLE */
        0x00000046,
        0x00100044,
        0x00000001,
        0x00000002,
        0x00000010,
        0x00000020,
        0x00000040,
        0x00000080,
        0x00000000,
        0xFFFFFFFF,
    };
    int nflags = sizeof(flags)/sizeof(flags[0]);

    printf("=== DRAWCTXT_CREATE probe ===\n");
    printf("Trying ioctl NR=0x13, various sizes & flags\n\n");

    for (int sz = 4; sz <= 64; sz += 4) {
        for (int fi = 0; fi < nflags; fi++) {
            char buf[256];
            memset(buf, 0, sizeof(buf));
            /* Place flags at offset 0 */
            memcpy(buf, &flags[fi], 4);

            unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x13, sz);
            int ret = ioctl(fd, cmd, buf);
            int err = errno;

            if (ret == 0) {
                unsigned int ctx_id;
                memcpy(&ctx_id, buf + 4, 4);
                printf("  NR=0x13 sz=%d flags=0x%08x: SUCCESS! ctx_id=%u\n", sz, flags[fi], ctx_id);
                /* destroy it */
                unsigned long dcmd = MY_IOW(KGSL_IOC_TYPE, 0x14, 4);
                ioctl(fd, dcmd, &ctx_id);
            } else if (err != EINVAL) {
                printf("  NR=0x13 sz=%d flags=0x%08x: err=%d (%s)\n", sz, flags[fi], err, strerror(err));
            }
        }
    }

    /* Maybe DRAWCTXT_CREATE is at a different NR in this kernel */
    printf("\n=== Scanning all NRs (0x00-0x60) with sz=8, flags=0x44 ===\n");
    for (int nr = 0; nr <= 0x60; nr++) {
        for (int sz = 8; sz <= 16; sz += 4) {
            char buf[256];
            memset(buf, 0, sizeof(buf));
            unsigned int f = 0x00000044;
            memcpy(buf, &f, 4);

            unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, nr, sz);
            int ret = ioctl(fd, cmd, buf);
            int err = errno;

            if (ret == 0) {
                printf("  NR=0x%02x sz=%d: SUCCESS\n", nr, sz);
                printf("    data: ");
                for (int j = 0; j < sz; j++) printf("%02x ", (unsigned char)buf[j]);
                printf("\n");
            } else if (err != EINVAL) {
                printf("  NR=0x%02x sz=%d: err=%d (%s)\n", nr, sz, err, strerror(err));
            }
        }
    }

    /* Try GPUMEM_ALLOC_ID specifically - also verify it works */
    printf("\n=== GPUMEM_ALLOC_ID (NR=0x2f) ===\n");
    for (int sz = 24; sz <= 48; sz += 4) {
        char buf[256];
        memset(buf, 0, sizeof(buf));
        /* struct: id(4), flags(4), size(8), mmapsize(8), gpuaddr(8) = 32 */
        uint64_t alloc_size = 4096;
        unsigned int alloc_flags = (3 << 26); /* WRITEBACK */
        memcpy(buf + 4, &alloc_flags, 4);
        memcpy(buf + 8, &alloc_size, 8);

        unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x2f, sz);
        int ret = ioctl(fd, cmd, buf);
        int err = errno;

        if (ret == 0) {
            printf("  sz=%d: SUCCESS\n", sz);
            printf("    data: ");
            for (int j = 0; j < sz; j++) printf("%02x ", (unsigned char)buf[j]);
            printf("\n");
        } else if (err != EINVAL) {
            printf("  sz=%d: err=%d (%s)\n", sz, err, strerror(err));
        }
    }

    /* Test reading /proc/self/maps for any kgsl mappings */
    printf("\n=== Checking /proc/self/maps for KGSL ===\n");
    FILE *f = fopen("/proc/self/maps", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "kgsl"))
                printf("  %s", line);
        }
        fclose(f);
    }

    /* Check dmesg for recent kgsl messages */
    printf("\n=== Recent dmesg KGSL messages ===\n");
    system("dmesg | grep -i kgsl | tail -20");

    close(fd);
    return 0;
}
