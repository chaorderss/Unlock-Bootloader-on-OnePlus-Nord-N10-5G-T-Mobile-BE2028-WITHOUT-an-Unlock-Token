/*
 * Probe GPU_COMMAND struct layout:
 * - Find working size
 * - Find context_id field offset by setting context_id and varying its position
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09
#define MY_IOWR(t,n,sz) (0xC0000000UL|(((unsigned long)(sz)&0x3FFF)<<16)|((t&0xFF)<<8)|(n&0xFF))
#define MY_IOW(t,n,sz)  (0x40000000UL|(((unsigned long)(sz)&0x3FFF)<<16)|((t&0xFF)<<8)|(n&0xFF))

static unsigned int create_ctx(int fd) {
    unsigned char buf[16];
    memset(buf, 0, 16);
    /* flags: NO_GMEM_ALLOC|PREAMBLE|SUBMIT_IB_LIST|PER_CONTEXT_TS = 0x56 */
    unsigned int flags = 0x00000056;
    memcpy(buf, &flags, 4);
    unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x13, 8);
    if (ioctl(fd, cmd, buf) == 0) {
        unsigned int id; memcpy(&id, buf+4, 4);
        return id;
    }
    return 0;
}

static void destroy_ctx(int fd, unsigned int id) {
    unsigned long cmd = MY_IOW(KGSL_IOC_TYPE, 0x14, 4);
    ioctl(fd, cmd, &id);
}

int main() {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    unsigned int ctx = create_ctx(fd);
    printf("Context: %u\n", ctx);

    /* Probe GPU_COMMAND sizes */
    printf("\n=== GPU_COMMAND (NR=0x34) size probe ===\n");
    for (int sz = 8; sz <= 128; sz += 8) {
        unsigned char buf[256];
        memset(buf, 0, sizeof(buf));
        /* Try putting ctx at common offsets */
        for (int ctx_off = 0; ctx_off + 4 <= sz; ctx_off += 4) {
            memset(buf, 0, sz);
            memcpy(buf + ctx_off, &ctx, 4);
            unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x34, sz);
            int ret = ioctl(fd, cmd, buf);
            int err = errno;
            if (ret == 0) {
                printf("  sz=%3d ctx_off=%2d: SUCCESS!\n", sz, ctx_off);
            } else if (err != EINVAL) {
                printf("  sz=%3d ctx_off=%2d: err=%d (%s)\n", sz, ctx_off, err, strerror(err));
            }
        }
    }

    /* The KGSL GPU_COMMAND struct from msm_kgsl.h (newer kernels):
     * struct kgsl_gpu_command {
     *   __u64 flags;        // 0  +8
     *   __u64 cmdlist;      // 8  +8
     *   __u32 cmdsize;      // 16 +4
     *   __u32 numcmds;      // 20 +4
     *   __u64 objlist;      // 24 +8
     *   __u32 objsize;      // 32 +4
     *   __u32 numobjs;      // 36 +4
     *   __u64 synclist;     // 40 +8
     *   __u32 syncsize;     // 48 +4
     *   __u32 numsyncs;     // 52 +4
     *   __u32 context_id;   // 56 +4
     *   __u32 timestamp;    // 60 +4
     * };  // total = 64 bytes
     */
    printf("\n=== GPU_COMMAND with context_id at offset 56 in 64-byte struct ===\n");
    {
        unsigned char buf[64];
        memset(buf, 0, sizeof(buf));
        memcpy(buf + 56, &ctx, 4);
        unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x34, 64);
        int ret = ioctl(fd, cmd, buf);
        printf("  ctx@56, sz=64: ret=%d err=%d (%s)\n", ret, errno, strerror(errno));
    }

    /* Alternative layout from some kernel revisions:
     * Older struct has cmdtype/cmdbatch, context_id at offset 40 in 48-byte struct */
    printf("\n=== Alternative: context_id at offset 40 in 48-byte struct ===\n");
    {
        unsigned char buf[48];
        memset(buf, 0, sizeof(buf));
        memcpy(buf + 40, &ctx, 4);
        unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x34, 48);
        int ret = ioctl(fd, cmd, buf);
        printf("  ctx@40, sz=48: ret=%d err=%d (%s)\n", ret, errno, strerror(errno));
    }

    /* Newer: context_id might be at offset 32 in 40-byte struct */
    printf("\n=== Systematic: all offsets in working sizes ===\n");
    /* First find the right size */
    int found_sz = -1;
    int found_off = -1;
    for (int sz = 16; sz <= 96; sz += 8) {
        for (int ctx_off = 0; ctx_off + 4 <= sz; ctx_off += 4) {
            unsigned char buf[256];
            memset(buf, 0, sz);
            memcpy(buf + ctx_off, &ctx, 4);
            unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x34, sz);
            int ret = ioctl(fd, cmd, buf);
            int err = errno;
            if (err != EINVAL && ret != 0) {
                if (found_sz < 0) { found_sz = sz; found_off = ctx_off; }
                printf("  sz=%3d ctx_off=%2d: err=%d (%s)  <- NON-EINVAL\n",
                       sz, ctx_off, err, strerror(err));
            }
        }
    }

    if (found_sz > 0)
        printf("\nBest candidate: sz=%d ctx_off=%d\n", found_sz, found_off);
    else
        printf("\nNo non-EINVAL results found - need to check NR\n");

    /* Also probe NR=0x34 vs others for GPU_COMMAND */
    printf("\n=== Scanning all NRs for GPU submission (ctx=%u) ===\n", ctx);
    for (int nr = 0x30; nr <= 0x50; nr++) {
        for (int sz = 32; sz <= 80; sz += 8) {
            for (int ctx_off = sz-8; ctx_off < sz; ctx_off += 4) {
                unsigned char buf[256];
                memset(buf, 0, sz);
                memcpy(buf + ctx_off, &ctx, 4);
                unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, nr, sz);
                int ret = ioctl(fd, cmd, buf);
                int err = errno;
                if (err != EINVAL) {
                    printf("  NR=0x%02x sz=%3d ctx_off=%2d: ret=%d err=%d (%s)\n",
                           nr, sz, ctx_off, ret, err, strerror(err));
                }
            }
        }
    }

    destroy_ctx(fd, ctx);
    close(fd);
    return 0;
}
