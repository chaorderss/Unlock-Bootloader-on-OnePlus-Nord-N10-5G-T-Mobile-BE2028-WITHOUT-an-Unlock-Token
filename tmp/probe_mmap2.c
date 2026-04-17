/*
 * Probe correct mmap parameters for KGSL GPU memory.
 * Try both GPUMEM_ALLOC_ID and GPUOBJ_ALLOC, with various mmap sizes.
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

int main() {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    /* Create context first */
    unsigned char ctx_buf[8];
    memset(ctx_buf, 0, 8);
    unsigned int ctx_flags = 0x12; /* minimal */
    memcpy(ctx_buf, &ctx_flags, 4);
    ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x13, 8), ctx_buf);
    unsigned int ctx_id;
    memcpy(&ctx_id, ctx_buf + 4, 4);
    printf("ctx_id=%u\n", ctx_id);

    /* Test GPUMEM_ALLOC_ID with different allocation sizes */
    printf("\n=== GPUMEM_ALLOC_ID mmap tests ===\n");
    unsigned int alloc_sizes[] = {4096, 8192, 16384, 65536};
    for (int si = 0; si < 4; si++) {
        unsigned char buf[32];
        memset(buf, 0, 32);
        unsigned int flags = (3U << 26); /* WRITEBACK */
        uint64_t sz = alloc_sizes[si];
        memcpy(buf + 0, &flags, 4);
        memcpy(buf + 8, &sz, 8);

        int r = ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x2f, 32), buf);
        if (r < 0) { printf("alloc %u: FAIL %s\n", alloc_sizes[si], strerror(errno)); continue; }

        unsigned int id;
        uint64_t ret_sz, mmapsz, gpuaddr;
        memcpy(&id, buf + 4, 4);
        memcpy(&ret_sz, buf + 8, 8);
        memcpy(&mmapsz, buf + 16, 8);
        memcpy(&gpuaddr, buf + 24, 8);
        printf("alloc %u: id=%u size=%lu mmapsize=%lu gpuaddr=0x%lx\n",
               alloc_sizes[si], id, (unsigned long)ret_sz,
               (unsigned long)mmapsz, (unsigned long)gpuaddr);

        /* Try mmap with various sizes */
        off_t offset = (off_t)id * 4096;
        unsigned long try_sizes[] = {4096, ret_sz, mmapsz, alloc_sizes[si],
                                      4096*2, 4096*4, 4096*16, 4096*64, 4096*192};
        for (int ti = 0; ti < 9; ti++) {
            void *m = mmap(NULL, try_sizes[ti], PROT_READ|PROT_WRITE,
                           MAP_SHARED, fd, offset);
            if (m != MAP_FAILED) {
                printf("  mmap(sz=%lu, off=0x%lx): SUCCESS @ %p\n",
                       try_sizes[ti], (unsigned long)offset, m);
                /* Write test pattern */
                memset(m, 0xAA, 16);
                munmap(m, try_sizes[ti]);
            }
            /* else silently skip */
        }

        /* Also try mmap with offset=0 */
        for (int ti = 0; ti < 9; ti++) {
            void *m = mmap(NULL, try_sizes[ti], PROT_READ|PROT_WRITE,
                           MAP_SHARED, fd, 0);
            if (m != MAP_FAILED) {
                printf("  mmap(sz=%lu, off=0): SUCCESS @ %p\n",
                       try_sizes[ti], m);
                munmap(m, try_sizes[ti]);
            }
        }

        /* Free */
        unsigned char fb[8];
        memset(fb, 0, 8);
        memcpy(fb, &id, 4); /* try id@0 */
        ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x30, 8), fb);
    }

    /* Test GPUOBJ_ALLOC (NR=0x45) */
    printf("\n=== GPUOBJ_ALLOC mmap tests ===\n");
    for (int si = 0; si < 4; si++) {
        unsigned char buf[48];
        memset(buf, 0, 48);
        uint64_t sz = alloc_sizes[si];
        uint64_t flags = (3ULL << 26);
        memcpy(buf + 0, &sz, 8);
        memcpy(buf + 8, &flags, 8);

        int r = ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x45, 32), buf);
        if (r < 0) { printf("gpuobj_alloc %u: FAIL %s\n", alloc_sizes[si], strerror(errno)); continue; }

        uint64_t ret_sz, ret_flags, mmapsz, obj_id;
        memcpy(&ret_sz, buf + 0, 8);
        memcpy(&ret_flags, buf + 8, 8);
        memcpy(&mmapsz, buf + 16, 8);
        memcpy(&obj_id, buf + 24, 8);
        printf("gpuobj_alloc %u: id=%lu size=%lu mmapsize=%lu flags=0x%lx\n",
               alloc_sizes[si], (unsigned long)obj_id, (unsigned long)ret_sz,
               (unsigned long)mmapsz, (unsigned long)ret_flags);

        /* Try mmap with various sizes/offsets */
        for (int use_id = 0; use_id < 2; use_id++) {
            off_t offset = use_id ? (off_t)obj_id * 4096 : 0;
            unsigned long try_sizes[] = {4096, ret_sz, mmapsz, alloc_sizes[si],
                                          4096*192};
            for (int ti = 0; ti < 5; ti++) {
                if (try_sizes[ti] == 0) continue;
                void *m = mmap(NULL, try_sizes[ti], PROT_READ|PROT_WRITE,
                               MAP_SHARED, fd, offset);
                if (m != MAP_FAILED) {
                    printf("  mmap(sz=%lu, off=0x%lx): SUCCESS @ %p\n",
                           try_sizes[ti], (unsigned long)offset, m);
                    munmap(m, try_sizes[ti]);
                }
            }
        }

        /* Free via GPUOBJ_FREE */
        unsigned char fb[24];
        memset(fb, 0, 24);
        memcpy(fb + 8, &obj_id, 8);
        ioctl(fd, _IOW(KGSL_IOC_TYPE, 0x46, 24), fb);
    }

    /* Also try: mmap WITHOUT allocating first (kgsl shadow memory?) */
    printf("\n=== Direct mmap tests (no alloc) ===\n");
    for (off_t off = 0; off <= 0x10000; off += 0x1000) {
        for (int sz_i = 0; sz_i < 3; sz_i++) {
            unsigned long sz = (sz_i == 0) ? 4096 : (sz_i == 1) ? 786432 : 16384;
            void *m = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, off);
            if (m != MAP_FAILED) {
                printf("  mmap(sz=%lu, off=0x%lx): SUCCESS @ %p\n", sz, (long)off, m);
                munmap(m, sz);
            }
        }
    }

    /* Test with GET_INFO to see real gpuaddr */
    printf("\n=== GPUMEM_GET_INFO for existing allocs ===\n");
    {
        unsigned char buf[32];
        memset(buf, 0, 32);
        unsigned int flags = (3U << 26);
        uint64_t sz = 4096;
        memcpy(buf + 0, &flags, 4);
        memcpy(buf + 8, &sz, 8);
        int r = ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x2f, 32), buf);
        if (r == 0) {
            unsigned int id;
            memcpy(&id, buf + 4, 4);
            printf("Allocated id=%u for GET_INFO test\n", id);

            /* GET_INFO struct: gpuaddr(8), id(4), flags(4), size(8), mmapsize(8), useraddr(8) = 40 bytes */
            unsigned char gi[48];
            memset(gi, 0, 48);
            memcpy(gi + 8, &id, 4); /* id at offset 8 */
            r = ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x3c, 40), gi);
            printf("GET_INFO(id@8): ret=%d err=%s\n", r, strerror(errno));
            if (r == 0) {
                uint64_t ga; memcpy(&ga, gi, 8);
                unsigned int gi_id; memcpy(&gi_id, gi + 8, 4);
                unsigned int gi_f; memcpy(&gi_f, gi + 12, 4);
                uint64_t gi_sz; memcpy(&gi_sz, gi + 16, 8);
                uint64_t gi_mm; memcpy(&gi_mm, gi + 24, 8);
                uint64_t gi_ua; memcpy(&gi_ua, gi + 32, 8);
                printf("  gpuaddr=0x%lx id=%u flags=0x%x size=%lu mmapsize=%lu useraddr=0x%lx\n",
                       (unsigned long)ga, gi_id, gi_f, (unsigned long)gi_sz,
                       (unsigned long)gi_mm, (unsigned long)gi_ua);

                /* Now try mmap with the gpuaddr from GET_INFO as offset */
                if (ga != 0) {
                    void *m = mmap(NULL, gi_mm ? gi_mm : 4096, PROT_READ|PROT_WRITE,
                                   MAP_SHARED, fd, (off_t)ga);
                    if (m != MAP_FAILED) {
                        printf("  mmap(gpuaddr-offset=0x%lx): SUCCESS @ %p\n", (unsigned long)ga, m);
                        munmap(m, gi_mm ? gi_mm : 4096);
                    } else {
                        printf("  mmap(gpuaddr-offset=0x%lx): %s\n", (unsigned long)ga, strerror(errno));
                    }
                }
            }

            /* Also try id at offset 0 */
            memset(gi, 0, 48);
            memcpy(gi, &id, 4);
            r = ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x3c, 40), gi);
            printf("GET_INFO(id@0): ret=%d err=%s\n", r, strerror(errno));
            if (r == 0) {
                printf("  data: ");
                for (int j = 0; j < 40; j++) printf("%02x ", gi[j]);
                printf("\n");
            }
        }
    }

    /* Destroy context, close fd */
    unsigned int destroy_id = ctx_id;
    ioctl(fd, _IOW(KGSL_IOC_TYPE, 0x14, 4), &destroy_id);
    close(fd);
    return 0;
}
