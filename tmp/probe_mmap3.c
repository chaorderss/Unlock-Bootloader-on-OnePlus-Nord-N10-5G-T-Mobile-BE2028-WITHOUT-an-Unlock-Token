/*
 * Find the exact mmap size that works for KGSL GPUMEM_ALLOC_ID.
 * Uses the same struct layout as the exploit.
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

struct kgsl_gpumem_alloc_id {
    unsigned int flags;
    unsigned int id;
    uint64_t size;
    uint64_t mmapsize;
    uint64_t gpuaddr;
};
#define IOCTL_KGSL_GPUMEM_ALLOC_ID \
    _IOWR(KGSL_IOC_TYPE, 0x2f, struct kgsl_gpumem_alloc_id)

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};
#define IOCTL_KGSL_DRAWCTXT_CREATE \
    _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)

int main() {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    /* Create context (same as exploit) */
    struct kgsl_drawctxt_create ctx = {.flags = 0x56, .drawctxt_id = 0};
    int r = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx);
    printf("ctx: ret=%d id=%u err=%s\n", r, ctx.drawctxt_id,
           r < 0 ? strerror(errno) : "ok");

    /* Allocate (same as exploit) */
    struct kgsl_gpumem_alloc_id alloc = {
        .flags = (3U << 26),  /* WRITEBACK */
        .id = 0,
        .size = 4096,
        .mmapsize = 0,
        .gpuaddr = 0
    };
    r = ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &alloc);
    printf("alloc: ret=%d id=%u size=%lu mmapsize=%lu gpuaddr=0x%lx err=%s\n",
           r, alloc.id, (unsigned long)alloc.size,
           (unsigned long)alloc.mmapsize, (unsigned long)alloc.gpuaddr,
           r < 0 ? strerror(errno) : "ok");

    if (r < 0) {
        printf("Alloc failed, trying raw ioctl with different struct sizes\n");
        for (int sz = 24; sz <= 40; sz += 4) {
            unsigned char buf[48];
            memset(buf, 0, sizeof(buf));
            unsigned int f = (3U << 26);
            uint64_t s = 4096;
            memcpy(buf, &f, 4);
            memcpy(buf + 8, &s, 8);
            unsigned long cmd = _IOWR(KGSL_IOC_TYPE, 0x2f, 32);
            /* Override size in ioctl cmd */
            cmd = (cmd & ~(0x3FFFUL << 16)) | ((unsigned long)sz << 16);
            r = ioctl(fd, cmd, buf);
            if (r == 0) {
                printf("  sz=%d: SUCCESS: ", sz);
                for (int j = 0; j < sz; j++) printf("%02x ", buf[j]);
                printf("\n");
            }
        }
        /* Try reversed: id@0, flags@4 */
        printf("Trying id@0, flags@4 layout:\n");
        unsigned char buf[32];
        memset(buf, 0, 32);
        unsigned int f = (3U << 26);
        uint64_t s = 4096;
        memcpy(buf + 4, &f, 4); /* flags at offset 4 */
        memcpy(buf + 8, &s, 8);
        r = ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, buf);
        printf("  ret=%d err=%s\n", r, r < 0 ? strerror(errno) : "ok");
        if (r == 0) {
            printf("  data: ");
            for (int j = 0; j < 32; j++) printf("%02x ", buf[j]);
            printf("\n");
        }
        close(fd);
        return 1;
    }

    printf("\nTrying mmap with id=%u, offset=0x%lx\n", alloc.id,
           (unsigned long)alloc.id * 4096);

    /* Try every power-of-2 page-aligned size from 4KB to 1MB */
    unsigned long sizes[] = {
        4096, 8192, 12288, 16384, 20480, 24576, 28672, 32768,
        65536, 131072, 262144, 524288, 786432, 1048576,
        /* mmapsize value */
        alloc.mmapsize,
        /* size value */
        alloc.size
    };
    off_t offset = (off_t)alloc.id * 4096;

    for (int i = 0; i < 16; i++) {
        if (sizes[i] == 0) continue;
        void *m = mmap(NULL, sizes[i], PROT_READ|PROT_WRITE,
                       MAP_SHARED, fd, offset);
        if (m != MAP_FAILED) {
            printf("  mmap(sz=%7lu, off=0x%04lx): SUCCESS @ %p\n",
                   sizes[i], (unsigned long)offset, m);
            /* Quick write test */
            ((volatile uint32_t *)m)[0] = 0xDEADBEEF;
            uint32_t readback = ((volatile uint32_t *)m)[0];
            printf("    write/read test: wrote 0xDEADBEEF, read 0x%08X %s\n",
                   readback, readback == 0xDEADBEEF ? "OK" : "MISMATCH");
            munmap(m, sizes[i]);
        }
    }

    /* Also try mmap with offset=gpuaddr if non-zero */
    if (alloc.gpuaddr != 0) {
        printf("\nTrying offset=gpuaddr=0x%lx:\n", (unsigned long)alloc.gpuaddr);
        for (int i = 0; i < 14; i++) {
            void *m = mmap(NULL, sizes[i], PROT_READ|PROT_WRITE,
                           MAP_SHARED, fd, (off_t)alloc.gpuaddr);
            if (m != MAP_FAILED) {
                printf("  mmap(sz=%7lu, off=0x%lx): SUCCESS\n",
                       sizes[i], (unsigned long)alloc.gpuaddr);
                munmap(m, sizes[i]);
            }
        }
    }

    /* Try all offsets from 0 to id*2 pages, with mmapsize */
    printf("\nTrying offset sweep with mmapsize=%lu:\n", (unsigned long)alloc.mmapsize);
    for (unsigned int pg = 0; pg <= alloc.id * 2 + 2; pg++) {
        void *m = mmap(NULL, alloc.mmapsize ? alloc.mmapsize : 4096,
                       PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)pg * 4096);
        if (m != MAP_FAILED) {
            printf("  mmap(mmapsize, off=0x%04lx [pg=%u]): SUCCESS @ %p\n",
                   (unsigned long)pg * 4096, pg, m);
            munmap(m, alloc.mmapsize ? alloc.mmapsize : 4096);
        }
    }

    /* Print the ioctl number for verification */
    printf("\nioctl numbers:\n");
    printf("  GPUMEM_ALLOC_ID = 0x%lx\n", (unsigned long)IOCTL_KGSL_GPUMEM_ALLOC_ID);
    printf("  DRAWCTXT_CREATE = 0x%lx\n", (unsigned long)IOCTL_KGSL_DRAWCTXT_CREATE);
    printf("  sizeof(alloc_id) = %zu\n", sizeof(struct kgsl_gpumem_alloc_id));

    close(fd);
    return 0;
}
