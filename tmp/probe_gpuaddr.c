/*
 * Focused KGSL mmap probe: use GPUOBJ_ALLOC with full struct,
 * then GET_INFO for gpuaddr, then mmap with gpuaddr offset.
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

/* kgsl_gpuobj_alloc: size(8)+flags(8)+mmapsize(8)+id(4)+pad(4) = 32 */
struct kgsl_gpuobj_alloc {
    uint64_t size;
    uint64_t flags;
    uint64_t mmapsize;
    unsigned int id;
    unsigned int pad;
};

/* kgsl_gpumem_alloc_id: id(4)+flags(4)+size(8)+mmapsize(8)+gpuaddr(8) = 32 */
struct kgsl_gpumem_alloc_id_v2 {
    unsigned int id;       /* maybe id is at 0 */
    unsigned int flags;    /* flags at 4 */
    uint64_t size;
    uint64_t mmapsize;
    uint64_t gpuaddr;
};

int main() {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    /* Create context */
    unsigned char ctx_buf[8] = {0x56, 0, 0, 0, 0, 0, 0, 0};
    ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x13, 8), ctx_buf);
    unsigned int ctx_id = *(unsigned int *)(ctx_buf + 4);
    printf("ctx_id=%u\n", ctx_id);

    /* === Test 1: GPUOBJ_ALLOC with 32-byte struct === */
    printf("\n=== GPUOBJ_ALLOC (sz=32, full struct) ===\n");
    {
        unsigned char buf[32];
        memset(buf, 0, sizeof(buf));
        uint64_t sz = 4096;
        uint64_t flags = (3ULL << 26);
        memcpy(buf + 0, &sz, 8);
        memcpy(buf + 8, &flags, 8);

        int r = ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x45, 32), buf);
        printf("ret=%d err=%s\n", r, r < 0 ? strerror(errno) : "ok");
        printf("raw: ");
        for (int i = 0; i < 32; i++) printf("%02x ", buf[i]);
        printf("\n");

        if (r == 0) {
            uint64_t ret_sz, ret_fl, ret_mm;
            unsigned int ret_id, ret_pad;
            memcpy(&ret_sz, buf+0, 8);
            memcpy(&ret_fl, buf+8, 8);
            memcpy(&ret_mm, buf+16, 8);
            memcpy(&ret_id, buf+24, 4);
            memcpy(&ret_pad, buf+28, 4);
            printf("size=%lu flags=0x%lx mmapsize=%lu id=%u pad=0x%x\n",
                   (unsigned long)ret_sz, (unsigned long)ret_fl,
                   (unsigned long)ret_mm, ret_id, ret_pad);

            /* GET_INFO for this id */
            printf("\nGET_INFO for id=%u:\n", ret_id);
            for (int id_off = 0; id_off <= 16; id_off += 4) {
                unsigned char gi[48];
                memset(gi, 0, sizeof(gi));
                memcpy(gi + id_off, &ret_id, 4);
                int gr = ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x3c, 40), gi);
                if (gr == 0) {
                    printf("  id@%d → ", id_off);
                    for (int j = 0; j < 40; j++) printf("%02x ", gi[j]);
                    printf("\n");
                    /* Parse: gpuaddr(8) id(4) flags(4) size(8) mmapsize(8) useraddr(8) */
                    uint64_t ga; memcpy(&ga, gi, 8);
                    printf("  gpuaddr=0x%lx\n", (unsigned long)ga);
                    if (ga != 0) {
                        /* Try mmap with gpuaddr as offset */
                        void *m = mmap(NULL, ret_mm ? ret_mm : 4096,
                                       PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)ga);
                        if (m != MAP_FAILED) {
                            printf("  mmap(gpuaddr=0x%lx, sz=%lu): SUCCESS @ %p\n",
                                   (unsigned long)ga, ret_mm ? (unsigned long)ret_mm : 4096UL, m);
                            ((uint32_t*)m)[0] = 0xDEADBEEF;
                            printf("  write/read: 0x%08X\n", ((uint32_t*)m)[0]);
                            munmap(m, ret_mm ? ret_mm : 4096);
                        } else {
                            printf("  mmap(gpuaddr=0x%lx): %s\n", (unsigned long)ga, strerror(errno));
                        }
                        /* Also try with different sizes */
                        for (unsigned long tsz = 4096; tsz <= 1048576; tsz *= 2) {
                            void *m2 = mmap(NULL, tsz, PROT_READ|PROT_WRITE,
                                            MAP_SHARED, fd, (off_t)ga);
                            if (m2 != MAP_FAILED) {
                                printf("  mmap(gpuaddr, sz=%lu): SUCCESS\n", tsz);
                                munmap(m2, tsz);
                            }
                        }
                    }
                }
            }

            /* Also try mmap with id-based and various other offsets */
            printf("\nmmap sweep for gpuobj id=%u:\n", ret_id);
            unsigned long try_sizes[] = {4096, ret_sz, ret_mm, 786432};
            for (int si = 0; si < 4; si++) {
                if (try_sizes[si] == 0) continue;
                for (unsigned int pg = 0; pg < 16; pg++) {
                    void *m = mmap(NULL, try_sizes[si], PROT_READ|PROT_WRITE,
                                   MAP_SHARED, fd, (off_t)pg * 4096);
                    if (m != MAP_FAILED) {
                        printf("  mmap(sz=%lu, pg=%u): SUCCESS\n", try_sizes[si], pg);
                        munmap(m, try_sizes[si]);
                    }
                }
            }

            /* Free */
            unsigned char fb[24];
            memset(fb, 0, 24);
            uint64_t fid = ret_id;
            memcpy(fb + 8, &fid, 8);
            ioctl(fd, _IOW(KGSL_IOC_TYPE, 0x46, 24), fb);
        }
    }

    /* === Test 2: GPUMEM_ALLOC_ID with id@0 layout === */
    printf("\n=== GPUMEM_ALLOC_ID (id@0 layout) ===\n");
    {
        struct kgsl_gpumem_alloc_id_v2 alloc;
        memset(&alloc, 0, sizeof(alloc));
        alloc.flags = (3U << 26);
        alloc.size = 4096;

        int r = ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x2f, sizeof(alloc)), &alloc);
        printf("id@0: ret=%d err=%s id=%u flags=0x%x size=%lu mmapsize=%lu gpuaddr=0x%lx\n",
               r, r < 0 ? strerror(errno) : "ok",
               alloc.id, alloc.flags, (unsigned long)alloc.size,
               (unsigned long)alloc.mmapsize, (unsigned long)alloc.gpuaddr);

        if (r == 0 && alloc.gpuaddr != 0) {
            printf("GOT NONZERO GPUADDR! Trying mmap...\n");
            void *m = mmap(NULL, alloc.mmapsize ? alloc.mmapsize : alloc.size,
                           PROT_READ|PROT_WRITE, MAP_SHARED, fd,
                           (off_t)alloc.gpuaddr);
            if (m != MAP_FAILED) {
                printf("  mmap(gpuaddr-offset): SUCCESS @ %p\n", m);
                munmap(m, alloc.mmapsize ? alloc.mmapsize : alloc.size);
            }
        }
        /* Raw dump */
        printf("raw: ");
        unsigned char *p = (unsigned char *)&alloc;
        for (int i = 0; i < 32; i++) printf("%02x ", p[i]);
        printf("\n");
    }

    /* === Test 3: Use both field orderings for GPUMEM_ALLOC_ID === */
    printf("\n=== GPUMEM_ALLOC_ID: flags@0 vs id@0 ===\n");
    {
        /* A: flags@0, id@4 (current exploit layout) */
        unsigned char a[32];
        memset(a, 0, 32);
        unsigned int f = (3U << 26);
        uint64_t s = 4096;
        memcpy(a+0, &f, 4);
        memcpy(a+8, &s, 8);
        int r1 = ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x2f, 32), a);
        printf("flags@0: ret=%d ", r1);
        if (r1 == 0) {
            printf("raw: ");
            for (int i = 0; i < 32; i++) printf("%02x ", a[i]);
        } else {
            printf("err=%s", strerror(errno));
        }
        printf("\n");

        /* B: id@0, flags@4 */
        unsigned char b[32];
        memset(b, 0, 32);
        memcpy(b+4, &f, 4);
        memcpy(b+8, &s, 8);
        int r2 = ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x2f, 32), b);
        printf("id@0:    ret=%d ", r2);
        if (r2 == 0) {
            printf("raw: ");
            for (int i = 0; i < 32; i++) printf("%02x ", b[i]);
        } else {
            printf("err=%s", strerror(errno));
        }
        printf("\n");
    }

    /* Cleanup */
    unsigned int cid = *(unsigned int *)(ctx_buf + 4);
    ioctl(fd, _IOW(KGSL_IOC_TYPE, 0x14, 4), &cid);
    close(fd);
    return 0;
}
