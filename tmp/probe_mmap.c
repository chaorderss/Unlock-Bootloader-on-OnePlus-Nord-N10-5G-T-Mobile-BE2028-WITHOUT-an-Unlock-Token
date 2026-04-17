/*
 * Fix mmap for KGSL GPU memory and test command submission with actual IB.
 * The mmap offset in KGSL is: gpuaddr >> PAGE_SHIFT (not id * PAGE_SIZE).
 * But gpuaddr=0 means the alloc struct is different.
 * Try GPUOBJ_ALLOC (NR=0x45) which returns a different layout.
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
    unsigned int flags = 0x56;
    memcpy(buf, &flags, 4);
    unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x13, 8);
    ioctl(fd, cmd, buf);
    unsigned int id; memcpy(&id, buf+4, 4);
    return id;
}

int main() {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    unsigned int ctx = create_ctx(fd);
    printf("ctx=%u\n", ctx);

    /* Try GPUOBJ_ALLOC (NR=0x45):
     * struct kgsl_gpuobj_alloc { u64 size, u64 flags, u64 mmapsize, u64 id }
     */
    printf("\n=== GPUOBJ_ALLOC (NR=0x45) ===\n");
    for (int sz = 16; sz <= 48; sz += 8) {
        unsigned char buf[64];
        memset(buf, 0xAA, sizeof(buf));
        uint64_t alloc_sz = 4096;
        uint64_t alloc_flags = (3ULL << 26);
        memcpy(buf, &alloc_sz, 8);
        memcpy(buf + 8, &alloc_flags, 8);
        memset(buf + 16, 0, sizeof(buf) - 16);

        unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x45, sz);
        int r = ioctl(fd, cmd, buf);
        if (r == 0 || errno != EINVAL) {
            printf("  sz=%d: ret=%d err=%d (%s)\n", sz, r, errno, strerror(errno));
            if (r == 0) {
                printf("  data: ");
                for (int j = 0; j < sz; j++) printf("%02x ", buf[j]);
                printf("\n");
            }
        }
    }

    /* Re-check GPUMEM_ALLOC_ID struct: maybe id is at offset 0, flags at 4 */
    printf("\n=== GPUMEM_ALLOC_ID (NR=0x2f) layout variants ===\n");
    /* variant A: flags@0, id@4, size@8, mmapsize@16, gpuaddr@24  (32 bytes) */
    {
        unsigned char buf[48];
        memset(buf, 0xAA, sizeof(buf));
        unsigned int flags_a = (3U << 26);
        uint64_t sz_a = 4096;
        memcpy(buf + 0, &flags_a, 4);
        memset(buf + 4, 0, 4); /* id=0 */
        memcpy(buf + 8, &sz_a, 8);
        memset(buf + 16, 0, 16);
        unsigned long cmd = MY_IOWR(KGSL_IOC_TYPE, 0x2f, 32);
        int r = ioctl(fd, cmd, buf);
        printf("  [A] flags@0 id@4: ret=%d err=%s\n", r, strerror(errno));
        if (r == 0) {
            printf("  data: ");
            for (int j = 0; j < 32; j++) printf("%02x ", buf[j]);
            printf("\n");
            unsigned int id_a; uint64_t mm, ga;
            memcpy(&id_a, buf+4, 4);
            memcpy(&mm, buf+16, 8);
            memcpy(&ga, buf+24, 8);
            printf("  id=%u mmapsize=%lu gpuaddr=0x%lx\n", id_a, (unsigned long)mm, (unsigned long)ga);

            /* Try various mmap offsets */
            printf("  mmap tests:\n");
            off_t offsets[] = { (off_t)id_a * 4096, 0, (off_t)ga,
                                (off_t)id_a << 12, (off_t)(id_a - 1) * 4096 };
            for (int oi = 0; oi < 5; oi++) {
                void *m = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, offsets[oi]);
                if (m != MAP_FAILED) {
                    printf("    offset=0x%lx: SUCCESS addr=%p\n", (unsigned long)offsets[oi], m);
                    munmap(m, 4096);
                } else {
                    printf("    offset=0x%lx: %s\n", (unsigned long)offsets[oi], strerror(errno));
                }
            }

            /* Submit a GPU command with the allocated (but unmapped) memory */
            struct {
                uint64_t flags;
                uint32_t context_id;
                uint32_t timestamp;
            } cmd16;
            memset(&cmd16, 0, sizeof(cmd16));
            cmd16.context_id = ctx;
            unsigned long gcmd = MY_IOWR(KGSL_IOC_TYPE, 0x34, 16);
            r = ioctl(fd, gcmd, &cmd16);
            printf("  GPU_COMMAND(16, no IB): ret=%d err=%s\n", r, strerror(errno));
            if (r == 0) printf("  timestamp=%u\n", cmd16.timestamp);

            /* Free alloc */
            unsigned char fb[8];
            memset(fb, 0, 8);
            memcpy(fb+4, &id_a, 4);
            unsigned long fc = MY_IOWR(KGSL_IOC_TYPE, 0x30, 8);
            ioctl(fd, fc, fb);
        }
    }

    /* Check /proc/self/maps for kgsl entries to understand mmap convention */
    printf("\n=== /proc/self/maps (kgsl) ===\n");
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "kgsl") || strstr(line, "/dev/"))
            printf("  %s", line);
    }
    fclose(f);

    /* Check if kgsl has a separate mmap device */
    printf("\n=== Checking for kgsl mmap device ===\n");
    int fd2 = open("/dev/kgsl-3d0", O_RDWR);
    /* Allocate and then look at /proc/self/maps */
    unsigned char alloc_buf[48];
    memset(alloc_buf, 0, sizeof(alloc_buf));
    unsigned int flags2 = (3U << 26);
    uint64_t sz2 = 4096;
    memcpy(alloc_buf, &flags2, 4);
    memcpy(alloc_buf + 8, &sz2, 8);
    unsigned long alloc_cmd = MY_IOWR(KGSL_IOC_TYPE, 0x2f, 32);
    int ar = ioctl(fd2, alloc_cmd, alloc_buf);
    printf("alloc2: ret=%d err=%s\n", ar, strerror(errno));
    if (ar == 0) {
        unsigned int id2; uint64_t ga2, mm2;
        memcpy(&id2, alloc_buf+4, 4);
        memcpy(&mm2, alloc_buf+16, 8);
        memcpy(&ga2, alloc_buf+24, 8);
        printf("id=%u mm=%lu ga=0x%lx\n", id2, (unsigned long)mm2, (unsigned long)ga2);

        /* Try every multiple of PAGE_SIZE from 0 to 4GB */
        /* KGSL kgsl_mmap() does: entry = kgsl_sharedmem_find(private, pgoff << PAGE_SHIFT)
         * So: mmap offset = gpuaddr (shifted), OR kgsl_sharedmem_find_id(pgoff) if gpuaddr lookup fails.
         * But gpuaddr=0... The driver likely assigns gpuaddr internally.
         * Let's try to get it from GPUMEM_GET_INFO */
        unsigned char ginfo[48];
        memset(ginfo, 0, sizeof(ginfo));
        memcpy(ginfo + 8, &id2, 4); /* id at offset 8 */
        unsigned long gc = MY_IOWR(KGSL_IOC_TYPE, 0x3c, 40);
        int gr = ioctl(fd2, gc, ginfo);
        printf("GET_INFO: ret=%d err=%s\n", gr, strerror(errno));
        if (gr == 0) {
            printf("GET_INFO data: ");
            for (int j = 0; j < 40; j++) printf("%02x ", ginfo[j]);
            printf("\n");
        }

        /* Try GET_INFO with different struct layouts */
        for (int id_off = 0; id_off < 32; id_off += 4) {
            memset(ginfo, 0, sizeof(ginfo));
            memcpy(ginfo + id_off, &id2, 4);
            gc = MY_IOWR(KGSL_IOC_TYPE, 0x3c, 40);
            gr = ioctl(fd2, gc, ginfo);
            if (gr == 0) {
                printf("GET_INFO id@%d: ", id_off);
                for (int j = 0; j < 40; j++) printf("%02x ", ginfo[j]);
                printf("\n");
            }
        }
    }

    close(fd2);

    unsigned long dcmd = MY_IOW(KGSL_IOC_TYPE, 0x14, 4);
    ioctl(fd, dcmd, &ctx);
    close(fd);
    return 0;
}
