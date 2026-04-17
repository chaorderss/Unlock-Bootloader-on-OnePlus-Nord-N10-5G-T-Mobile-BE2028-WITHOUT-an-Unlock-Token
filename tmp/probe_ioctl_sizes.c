/*
 * Probe KGSL ioctl struct sizes by trying different _IOWR encodings.
 * The KGSL dispatcher matches both ioctl NR and SIZE.
 * If size is wrong -> -ENOIOCTLCMD -> -EINVAL.
 * If size is right but flags are wrong -> different error or success.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09

/* Construct ioctl cmd manually */
#define MY_IOWR(type, nr, size) \
    (0xC0000000 | ((size & 0x3FFF) << 16) | ((type & 0xFF) << 8) | (nr & 0xFF))
#define MY_IOW(type, nr, size) \
    (0x40000000 | ((size & 0x3FFF) << 16) | ((type & 0xFF) << 8) | (nr & 0xFF))
#define MY_IOR(type, nr, size) \
    (0x80000000 | ((size & 0x3FFF) << 16) | ((type & 0xFF) << 8) | (nr & 0xFF))

/* ioctl NRs we need to probe */
struct ioctl_probe {
    const char *name;
    int nr;
    int dir; /* 0=IOWR, 1=IOW, 2=IOR */
};

static struct ioctl_probe ioctls[] = {
    { "DRAWCTXT_CREATE",    0x13, 0 },
    { "DRAWCTXT_DESTROY",   0x14, 1 },
    { "GPUMEM_ALLOC_ID",    0x2f, 0 },
    { "GPUMEM_FREE_ID",     0x30, 0 },
    { "GPU_COMMAND",        0x34, 0 },
    { "GPUOBJ_ALLOC",       0x45, 0 },
    { "GPUOBJ_FREE",        0x46, 1 },
    { "GPUMEM_GET_INFO",    0x3c, 0 },
    { "DEVICE_GETPROPERTY", 0x02, 0 },
    { "TIMESTAMP_EVENT",    0x33, 0 },
    { NULL, 0, 0 }
};

int main() {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    printf("Probing KGSL ioctl struct sizes...\n");
    printf("EINVAL = size mismatch (ioctl not found), other errors = ioctl found\n\n");

    for (int i = 0; ioctls[i].name; i++) {
        printf("=== %s (nr=0x%02x) ===\n", ioctls[i].name, ioctls[i].nr);

        for (int sz = 4; sz <= 128; sz += 4) {
            char buf[256];
            memset(buf, 0, sizeof(buf));

            unsigned long cmd;
            switch (ioctls[i].dir) {
                case 0: cmd = MY_IOWR(KGSL_IOC_TYPE, ioctls[i].nr, sz); break;
                case 1: cmd = MY_IOW(KGSL_IOC_TYPE, ioctls[i].nr, sz); break;
                case 2: cmd = MY_IOR(KGSL_IOC_TYPE, ioctls[i].nr, sz); break;
                default: cmd = MY_IOWR(KGSL_IOC_TYPE, ioctls[i].nr, sz); break;
            }

            int ret = ioctl(fd, cmd, buf);
            int err = errno;

            if (ret == 0) {
                printf("  size=%3d: SUCCESS (cmd=0x%08lx)\n", sz, cmd);
                /* dump first bytes */
                printf("           data: ");
                for (int j = 0; j < sz && j < 64; j++)
                    printf("%02x ", (unsigned char)buf[j]);
                printf("\n");
            } else if (err != EINVAL) {
                /* Not EINVAL means the ioctl was found but failed for other reasons */
                printf("  size=%3d: FOUND (cmd=0x%08lx) err=%d (%s)\n",
                       sz, cmd, err, strerror(err));
            }
            /* EINVAL = size mismatch, don't print to reduce noise */
        }

        /* Also try IOW/IOWR/IOR variants if not already tried */
        int other_dirs[] = {0, 1, 2};
        for (int d = 0; d < 3; d++) {
            if (other_dirs[d] == ioctls[i].dir) continue;
            for (int sz = 4; sz <= 128; sz += 4) {
                char buf[256];
                memset(buf, 0, sizeof(buf));

                unsigned long cmd;
                switch (other_dirs[d]) {
                    case 0: cmd = MY_IOWR(KGSL_IOC_TYPE, ioctls[i].nr, sz); break;
                    case 1: cmd = MY_IOW(KGSL_IOC_TYPE, ioctls[i].nr, sz); break;
                    case 2: cmd = MY_IOR(KGSL_IOC_TYPE, ioctls[i].nr, sz); break;
                    default: cmd = MY_IOWR(KGSL_IOC_TYPE, ioctls[i].nr, sz); break;
                }

                int ret = ioctl(fd, cmd, buf);
                int err = errno;

                if (ret == 0) {
                    printf("  [alt dir=%d] size=%3d: SUCCESS (cmd=0x%08lx)\n", other_dirs[d], sz, cmd);
                } else if (err != EINVAL) {
                    printf("  [alt dir=%d] size=%3d: FOUND (cmd=0x%08lx) err=%d (%s)\n",
                           other_dirs[d], sz, cmd, err, strerror(err));
                }
            }
        }
        printf("\n");
    }

    close(fd);
    return 0;
}
