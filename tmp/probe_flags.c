/*
 * Find which flag bits are required for DRAWCTXT_CREATE
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

static int test_create(int fd, unsigned int flags) {
    unsigned char buf[16];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &flags, 4);
    unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x13, 8);
    int ret = ioctl(fd, cmd, buf);
    if (ret == 0) {
        unsigned int ctx_id;
        memcpy(&ctx_id, buf + 4, 4);
        /* destroy it */
        unsigned long dcmd = MY_IOW(KGSL_IOC_TYPE, 0x14, 4);
        ioctl(fd, dcmd, &ctx_id);
        return ctx_id;
    }
    return -errno;
}

int main() {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    printf("=== Bit-by-bit flag probe ===\n");

    /* Test each single bit */
    printf("\nSingle bits:\n");
    for (int bit = 0; bit < 32; bit++) {
        unsigned int flags = 1U << bit;
        int result = test_create(fd, flags);
        if (result >= 0)
            printf("  bit %2d (0x%08x): SUCCESS ctx=%d\n", bit, flags, result);
        /* Not printing failures to reduce noise */
    }

    /* Test 0xFFFFFFFF with each bit cleared */
    printf("\n0xFFFFFFFF with each bit cleared:\n");
    for (int bit = 0; bit < 32; bit++) {
        unsigned int flags = 0xFFFFFFFF & ~(1U << bit);
        int result = test_create(fd, flags);
        if (result < 0)
            printf("  bit %2d cleared (0x%08x): FAILS err=%d\n", bit, flags, -result);
    }

    /* Try priority bits (13-15) */
    printf("\nPriority combinations (bits 13-15):\n");
    for (int prio = 0; prio <= 7; prio++) {
        unsigned int flags = 0x44 | (prio << 13); /* IB_LIST | PER_CTX_TS | priority */
        int result = test_create(fd, flags);
        printf("  prio=%d flags=0x%08x: %s (ret=%d)\n", prio, flags,
               result >= 0 ? "SUCCESS" : "FAIL", result);
    }

    /* Try preempt style (bits 25-27) */
    printf("\nPreempt style (bits 25-27) + prio=2:\n");
    for (int ps = 0; ps <= 7; ps++) {
        unsigned int flags = 0x44 | (2 << 13) | (ps << 25);
        int result = test_create(fd, flags);
        printf("  preempt=%d flags=0x%08x: %s (ret=%d)\n", ps, flags,
               result >= 0 ? "SUCCESS" : "FAIL", result);
    }

    /* Minimal working flags */
    printf("\nMinimal flags search:\n");
    unsigned int base = 0xFFFFFFFF;
    /* Clear bits one at a time, keep what's needed */
    for (int bit = 31; bit >= 0; bit--) {
        unsigned int test = base & ~(1U << bit);
        int result = test_create(fd, test);
        if (result >= 0) {
            base = test; /* this bit wasn't needed */
        } else {
            printf("  bit %2d (0x%08x) required\n", bit, 1U << bit);
        }
    }
    printf("  Minimal flags = 0x%08x\n", base);
    int result = test_create(fd, base);
    printf("  Verify minimal: %s (ret=%d)\n", result >= 0 ? "SUCCESS" : "FAIL", result);

    /* Also try GPUMEM_ALLOC_ID and GPU_COMMAND with working context */
    printf("\n=== Testing with working context (flags=0xFFFFFFFF) ===\n");
    {
        unsigned char buf[16];
        memset(buf, 0xFF, sizeof(buf));
        unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x13, 8);
        if (ioctl(fd, cmd, buf) == 0) {
            unsigned int ctx_id;
            unsigned int ret_flags;
            memcpy(&ret_flags, buf, 4);
            memcpy(&ctx_id, buf + 4, 4);
            printf("  Context created: ctx_id=%u returned_flags=0x%08x\n", ctx_id, ret_flags);

            /* Try GPUMEM_ALLOC_ID */
            unsigned char alloc_buf[48];
            memset(alloc_buf, 0, sizeof(alloc_buf));
            unsigned int alloc_flags = (3 << 26); /* WRITEBACK */
            uint64_t sz = 4096;
            memcpy(alloc_buf + 4, &alloc_flags, 4);
            memcpy(alloc_buf + 8, &sz, 8);

            cmd = MY_IOWR(KGSL_IOC_TYPE, 0x2f, 32);
            if (ioctl(fd, cmd, alloc_buf) == 0) {
                printf("  GPUMEM_ALLOC_ID: SUCCESS\n");
                printf("    data: ");
                for (int j = 0; j < 32; j++) printf("%02x ", alloc_buf[j]);
                printf("\n");
            } else {
                printf("  GPUMEM_ALLOC_ID: err=%d (%s)\n", errno, strerror(errno));
            }

            /* Try GPU_COMMAND */
            printf("  GPU_COMMAND sz=64: ");
            unsigned char cmd_buf[128];
            memset(cmd_buf, 0, sizeof(cmd_buf));
            /* context_id is at some offset; need to figure out struct layout */
            cmd = MY_IOWR(KGSL_IOC_TYPE, 0x34, 64);
            if (ioctl(fd, cmd, cmd_buf) == 0) {
                printf("SUCCESS\n");
            } else {
                printf("err=%d (%s)\n", errno, strerror(errno));
            }

            /* Destroy context */
            unsigned long dcmd = MY_IOW(KGSL_IOC_TYPE, 0x14, 4);
            ioctl(fd, dcmd, &ctx_id);
        }
    }

    close(fd);
    return 0;
}
