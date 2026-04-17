/*
 * Raw byte dump of GPUMEM_ALLOC_ID response to verify struct layout.
 * Also try GPUOBJ_ALLOC raw dump.
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

    /* Create context */
    unsigned char ctx_buf[8];
    memset(ctx_buf, 0, 8);
    unsigned int ctx_flags = 0x56;
    memcpy(ctx_buf, &ctx_flags, 4);
    ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x13, 8), ctx_buf);
    printf("ctx_id=%u\n", *(unsigned int *)(ctx_buf + 4));

    /* GPUMEM_ALLOC_ID: fill with 0xAA first so we can see what kernel changed */
    printf("\n=== GPUMEM_ALLOC_ID raw dump ===\n");
    unsigned char raw[48];
    memset(raw, 0xAA, sizeof(raw));

    /* Set our inputs: */
    unsigned int flags = (3U << 26);
    uint64_t size_req = 4096;
    /* Layout A: flags@0, id@4, size@8 */
    memcpy(raw + 0, &flags, 4);
    memset(raw + 4, 0, 4);        /* id = 0 (output) */
    memcpy(raw + 8, &size_req, 8); /* size */
    memset(raw + 16, 0, 16);       /* mmapsize + gpuaddr = 0 (output) */

    printf("Before ioctl:\n");
    for (int i = 0; i < 32; i++) printf("%02x ", raw[i]);
    printf("\n");

    int r = ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x2f, 32), raw);
    printf("ret=%d err=%s\n", r, r < 0 ? strerror(errno) : "ok");

    printf("After ioctl:\n");
    for (int i = 0; i < 32; i++) printf("%02x ", raw[i]);
    printf("\n");

    /* Parse in all possible ways */
    printf("\nField interpretations:\n");
    printf("u32@0  = 0x%08x\n", *(unsigned int *)(raw + 0));
    printf("u32@4  = 0x%08x (=%u)\n", *(unsigned int *)(raw + 4), *(unsigned int *)(raw + 4));
    printf("u64@8  = 0x%016lx (=%lu)\n", *(uint64_t *)(raw + 8), *(uint64_t *)(raw + 8));
    printf("u64@16 = 0x%016lx (=%lu)\n", *(uint64_t *)(raw + 16), *(uint64_t *)(raw + 16));
    printf("u64@24 = 0x%016lx\n", *(uint64_t *)(raw + 24));
    printf("u32@8  = 0x%08x (=%u)\n", *(unsigned int *)(raw + 8), *(unsigned int *)(raw + 8));
    printf("u32@12 = 0x%08x (=%u)\n", *(unsigned int *)(raw + 12), *(unsigned int *)(raw + 12));

    if (r == 0) {
        /* Try mmap with every u32 value as potential id, and every u64 as potential size */
        printf("\nTrying mmap with different field interpretations:\n");
        for (int id_off = 0; id_off <= 24; id_off += 4) {
            unsigned int potential_id;
            memcpy(&potential_id, raw + id_off, 4);
            if (potential_id == 0 || potential_id > 1000) continue;

            for (int sz_off = 0; sz_off <= 24; sz_off += 8) {
                uint64_t potential_sz;
                memcpy(&potential_sz, raw + sz_off, 8);
                if (potential_sz == 0 || potential_sz > 16*1024*1024) continue;

                off_t offset = (off_t)potential_id * 4096;
                void *m = mmap(NULL, potential_sz, PROT_READ|PROT_WRITE,
                               MAP_SHARED, fd, offset);
                if (m != MAP_FAILED) {
                    printf("  id(u32@%d)=%u sz(u64@%d)=%lu off=0x%lx: SUCCESS @ %p\n",
                           id_off, potential_id, sz_off, (unsigned long)potential_sz,
                           (unsigned long)offset, m);
                    munmap(m, potential_sz);
                }
            }
        }
    }

    /* Free that allocation */
    unsigned int alloc_id = *(unsigned int *)(raw + 4);
    unsigned char fb[8];
    memset(fb, 0, 8);
    memcpy(fb, &alloc_id, 4);
    ioctl(fd, _IOWR(KGSL_IOC_TYPE, 0x30, 8), fb);

    /* Now try GPUOBJ_ALLOC raw dump */
    printf("\n=== GPUOBJ_ALLOC raw dump ===\n");
    memset(raw, 0xAA, sizeof(raw));
    uint64_t obj_size = 4096;
    uint64_t obj_flags = (3ULL << 26);
    memcpy(raw + 0, &obj_size, 8);
    memcpy(raw + 8, &obj_flags, 8);
    memset(raw + 16, 0, 16);

    printf("Before ioctl:\n");
    for (int i = 0; i < 48; i++) printf("%02x ", raw[i]);
    printf("\n");

    /* Try different struct sizes */
    for (int sz = 24; sz <= 48; sz += 8) {
        unsigned char raw2[48];
        memcpy(raw2, raw, sizeof(raw));
        unsigned long cmd = (_IOWR(KGSL_IOC_TYPE, 0x45, 32) & ~(0x3FFFUL << 16))
                            | ((unsigned long)sz << 16);
        r = ioctl(fd, cmd, raw2);
        if (r == 0) {
            printf("GPUOBJ_ALLOC sz=%d: ret=%d\n", sz, r);
            printf("  data: ");
            for (int j = 0; j < sz; j++) printf("%02x ", raw2[j]);
            printf("\n");
            printf("  u64@0=%lu u64@8=0x%lx u64@16=%lu u64@24=%lu u64@32=%lu\n",
                   *(uint64_t *)(raw2+0), *(uint64_t *)(raw2+8),
                   *(uint64_t *)(raw2+16), *(uint64_t *)(raw2+24),
                   sz >= 40 ? *(uint64_t *)(raw2+32) : 0);

            /* Try mmap with this allocation */
            for (int pg = 0; pg < 20; pg++) {
                for (int si = 0; si < 4; si++) {
                    unsigned long try_sz = (si == 0) ? 4096 :
                                            (si == 1) ? *(uint64_t *)(raw2+0) :
                                            (si == 2 && sz > 16) ? *(uint64_t *)(raw2+16) :
                                            786432;
                    if (try_sz == 0 || try_sz > 16*1024*1024) continue;
                    void *m = mmap(NULL, try_sz, PROT_READ|PROT_WRITE,
                                   MAP_SHARED, fd, (off_t)pg * 4096);
                    if (m != MAP_FAILED) {
                        printf("  mmap(sz=%lu, pg=%d): SUCCESS @ %p\n", try_sz, pg, m);
                        munmap(m, try_sz);
                    }
                }
            }

            /* Free */
            uint64_t free_id = *(uint64_t *)(raw2 + 24);
            if (free_id == 0 && sz > 32) free_id = *(uint64_t *)(raw2 + 32);
            unsigned char fb2[24];
            memset(fb2, 0, 24);
            memcpy(fb2 + 8, &free_id, 8);
            ioctl(fd, _IOW(KGSL_IOC_TYPE, 0x46, 24), fb2);
            break; /* Only need one success */
        }
    }

    /* Check /proc/self/maps for kgsl entries */
    printf("\n=== /proc/self/maps (kgsl) ===\n");
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "kgsl"))
            printf("  %s", line);
    }
    fclose(f);

    /* Cleanup */
    unsigned int cid = *(unsigned int *)(ctx_buf + 4);
    ioctl(fd, _IOW(KGSL_IOC_TYPE, 0x14, 4), &cid);
    close(fd);
    return 0;
}
