/*
 * Determine exact GPU_COMMAND struct layout:
 * We know context_id is at offset 8. Now find the cmdlist/numcmds placement.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09
#define MY_IOWR(t,n,sz) (0xC0000000UL|(((unsigned long)(sz)&0x3FFF)<<16)|((t&0xFF)<<8)|(n&0xFF))
#define MY_IOW(t,n,sz)  (0x40000000UL|(((unsigned long)(sz)&0x3FFF)<<16)|((t&0xFF)<<8)|(n&0xFF))

static unsigned int create_ctx(int fd) {
    unsigned char buf[16];
    memset(buf, 0, 16);
    unsigned int flags = 0x00000056; /* NO_GMEM|PREAMBLE|SUBMIT_IB|PER_CTX_TS */
    memcpy(buf, &flags, 4);
    unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x13, 8);
    if (ioctl(fd, cmd, buf) == 0) {
        unsigned int id; memcpy(&id, buf+4, 4);
        return id;
    }
    printf("create_ctx failed: %s\n", strerror(errno));
    return 0;
}
static void destroy_ctx(int fd, unsigned int id) {
    unsigned long cmd = MY_IOW(KGSL_IOC_TYPE, 0x14, 4);
    ioctl(fd, cmd, &id);
}

/* Allocate GPU memory, return id */
static uint32_t alloc_gpu_mem(int fd, uint64_t *gpuaddr_out, uint64_t *mmapsize_out) {
    unsigned char buf[48];
    memset(buf, 0, sizeof(buf));
    /* flags at offset 0, id at offset 4 */
    unsigned int flags = (3 << 26); /* WRITEBACK */
    uint64_t sz = 4096;
    memcpy(buf + 0, &flags, 4);
    memcpy(buf + 8, &sz, 8);
    unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x2f, 32);
    if (ioctl(fd, cmd, buf) == 0) {
        uint32_t id; memcpy(&id, buf+4, 4);
        uint64_t mmapsz, gpuaddr;
        memcpy(&mmapsz, buf+16, 8);
        memcpy(&gpuaddr, buf+24, 8);
        if (gpuaddr_out) *gpuaddr_out = gpuaddr;
        if (mmapsize_out) *mmapsize_out = mmapsz;
        printf("[+] Alloc: id=%u gpuaddr=0x%lx mmapsize=%lu\n", id, (unsigned long)gpuaddr, (unsigned long)mmapsz);
        return id;
    }
    printf("alloc failed: %s\n", strerror(errno));
    return 0;
}

int main() {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    unsigned int ctx = create_ctx(fd);
    printf("Context: %u\n", ctx);

    uint64_t gpuaddr = 0, mmapsize = 0;
    uint32_t mem_id = alloc_gpu_mem(fd, &gpuaddr, &mmapsize);
    printf("mem_id=%u gpuaddr=0x%lx mmapsize=%lu\n", mem_id, (unsigned long)gpuaddr, (unsigned long)mmapsize);

    /* mmap the GPU memory */
    uint64_t mmap_sz = mmapsize ? mmapsize : 4096;
    void *gpu_mem = mmap(NULL, mmap_sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)mem_id * 4096);
    if (gpu_mem == MAP_FAILED) {
        printf("mmap id-based failed: %s, trying gpuaddr\n", strerror(errno));
        if (gpuaddr)
            gpu_mem = mmap(NULL, mmap_sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)gpuaddr);
    }
    if (gpu_mem == MAP_FAILED) {
        printf("mmap failed: %s\n", strerror(errno));
        gpu_mem = NULL;
    } else {
        printf("[+] GPU mem mapped at %p\n", gpu_mem);
        /* Write NOP IBs: Adreno type-7 NOP: 0x70000000 */
        uint32_t *cmds = (uint32_t *)gpu_mem;
        int n = (int)(mmap_sz / 4);
        for (int i = 0; i < n; i++) cmds[i] = 0x70000000;
        printf("[+] Wrote %d NOPs\n", n);
    }

    /*
     * The GPU_COMMAND struct layout based on probe (ctx_id @ offset 8):
     *
     * Hypothesis A (struct kgsl_cmdbatch_profiling_buf style):
     *   u32 context_id   @ 0
     *   u32 timestamp    @ 4
     *   u64 flags        @ 8
     *   ... cmds ...
     * But probe showed CTX at offset 8, not 0.
     *
     * Hypothesis B (common newer layout for this kernel):
     *   u64 flags        @ 0
     *   u32 context_id   @ 8
     *   u32 timestamp    @ 12
     *   u64 cmdlist      @ 16 (ptr to array of kgsl_command_object)
     *   u32 cmdsize      @ 24
     *   u32 numcmds      @ 28
     *   u64 objlist      @ 32
     *   u32 objsize      @ 36
     *   u32 numobjs      @ 40
     *   u64 synclist     @ 44 (or 48, depends on pad)
     *   ...etc
     *
     * Size = 16 bytes seems to work (context_id@8 with sz=16 returns SUCCESS)
     * Let's verify what errors we get with actual cmdlist set.
     */

    printf("\n=== Testing GPU_COMMAND layout with context_id@8 ===\n");

    /* Hypothesis B layout */
    struct {
        uint64_t flags;       /* 0 */
        uint32_t context_id; /* 8 */
        uint32_t timestamp;  /* 12 */
        /* minimal: just these 16 bytes */
    } cmd16;
    memset(&cmd16, 0, sizeof(cmd16));
    cmd16.context_id = ctx;
    cmd16.timestamp = 0;

    {
        unsigned long c = MY_IOWR(KGSL_IOC_TYPE, 0x34, 16);
        int r = ioctl(fd, c, &cmd16);
        printf("  16-byte, no cmds: ret=%d err=%d (%s)\n", r, errno, strerror(errno));
    }

    /* Try with a cmdlist pointer */
    if (gpu_mem) {
        /* kgsl_command_object: gpuaddr(8), size(8), flags(4), id(4) */
        struct {
            uint64_t gpuaddr;
            uint64_t size;
            uint32_t flags;
            uint32_t id;
        } cmdobj;
        memset(&cmdobj, 0, sizeof(cmdobj));
        cmdobj.gpuaddr = gpuaddr ? gpuaddr : (uint64_t)(uintptr_t)gpu_mem;
        cmdobj.size = 4096;
        cmdobj.flags = 1; /* KGSL_CMDLIST_IB */
        cmdobj.id = mem_id;

        /* Layout B: 64 bytes with cmdlist at offset 16 */
        struct {
            uint64_t flags;       /* 0 */
            uint32_t context_id; /* 8 */
            uint32_t timestamp;  /* 12 */
            uint64_t cmdlist;    /* 16 */
            uint32_t cmdsize;    /* 24 */
            uint32_t numcmds;    /* 28 */
            uint64_t objlist;    /* 32 */
            uint32_t objsize;    /* 36 */
            uint32_t numobjs;    /* 40 */
            uint64_t synclist;   /* 44 -- but need alignment! */
            uint32_t syncsize;   /* 52 */
            uint32_t numsyncs;   /* 56 */
            /* padding / extra: */
            uint32_t extra1;     /* 60 */
        } cmd64;
        memset(&cmd64, 0, sizeof(cmd64));
        cmd64.context_id = ctx;
        cmd64.cmdlist = (uint64_t)(uintptr_t)&cmdobj;
        cmd64.cmdsize = sizeof(cmdobj);
        cmd64.numcmds = 1;

        /* try sz=32 (up to numcmds) */
        for (int sz = 16; sz <= 64; sz += 8) {
            unsigned long c = MY_IOWR(KGSL_IOC_TYPE, 0x34, sz);
            int r = ioctl(fd, c, &cmd64);
            int err = errno;
            if (r == 0 || err != EINVAL)
                printf("  sz=%2d with cmdlist: ret=%d err=%d (%s)\n", sz, r, err, strerror(err));
        }

        /* Also try with objlist only (not cmdlist) */
        memset(&cmd64, 0, sizeof(cmd64));
        cmd64.context_id = ctx;
        cmd64.objlist = (uint64_t)(uintptr_t)&cmdobj;
        cmd64.objsize = sizeof(cmdobj);
        cmd64.numobjs = 1;
        for (int sz = 40; sz <= 64; sz += 8) {
            unsigned long c = MY_IOWR(KGSL_IOC_TYPE, 0x34, sz);
            int r = ioctl(fd, c, &cmd64);
            int err = errno;
            if (r == 0 || err != EINVAL)
                printf("  sz=%2d with objlist: ret=%d err=%d (%s)\n", sz, r, err, strerror(err));
        }
    }

    /* Free GPU mem */
    {
        unsigned char fbuf[16];
        memset(fbuf, 0, sizeof(fbuf));
        memcpy(fbuf + 4, &mem_id, 4);
        unsigned long c = MY_IOWR(KGSL_IOC_TYPE, 0x30, 8);
        ioctl(fd, c, fbuf);
    }

    destroy_ctx(fd, ctx);
    close(fd);
    return 0;
}
