/*
 * UFS RPMB Reader via SCSI Generic (SG_IO)
 * Target: OnePlus Nord N10 5G
 * RPMB WLUN: /dev/sg1 (LUN 0xC144)
 *
 * Read RPMB contents using SCSI SECURITY PROTOCOL commands.
 * RPMB reads do NOT require the authentication key (reads are
 * authenticated for integrity but don't need the write key).
 *
 * Compile:
 *   $NDK/aarch64-linux-android29-clang -static -O2 -o rpmb_read rpmb_read.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>

/* RPMB frame (512 bytes) */
struct rpmb_frame {
    uint8_t  stuff[196];
    uint8_t  key_mac[32];
    uint8_t  data[256];
    uint8_t  nonce[16];
    uint32_t write_counter;
    uint16_t address;
    uint16_t block_count;
    uint16_t result;
    uint16_t req_resp;
} __attribute__((packed));

/* RPMB request/response types */
#define RPMB_REQ_KEY_WRITE      0x0001
#define RPMB_REQ_COUNTER_READ   0x0002
#define RPMB_REQ_DATA_WRITE     0x0003
#define RPMB_REQ_DATA_READ      0x0004
#define RPMB_RESP_COUNTER_READ  0x0200
#define RPMB_RESP_DATA_READ     0x0400

/* Byte swap for big-endian RPMB fields */
static inline uint16_t be16(uint16_t v) {
    return (v >> 8) | (v << 8);
}
static inline uint32_t be32(uint32_t v) {
    return ((v >> 24) & 0xFF) | ((v >> 8) & 0xFF00) |
           ((v << 8) & 0xFF0000) | ((v << 24) & 0xFF000000);
}

static void hexdump(const char *label, const void *data, size_t len) {
    const uint8_t *p = data;
    printf("[*] %s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i += 16) {
        printf("    %04zx: ", i);
        for (size_t j = 0; j < 16 && (i+j) < len; j++)
            printf("%02x ", p[i+j]);
        for (size_t j = (len - i < 16) ? (len - i) : 16; j < 16; j++)
            printf("   ");
        printf(" |");
        for (size_t j = 0; j < 16 && (i+j) < len; j++)
            printf("%c", (p[i+j] >= 0x20 && p[i+j] < 0x7f) ? p[i+j] : '.');
        printf("|\n");
    }
}

/*
 * Send a SCSI command via SG_IO ioctl
 */
static int scsi_security_out(int fd, void *data, int data_len) {
    uint8_t cdb[12];
    uint8_t sense[32];
    struct sg_io_hdr io;

    /* SECURITY PROTOCOL OUT, opcode 0xB5 */
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = 0xB5;                     /* SECURITY PROTOCOL OUT */
    cdb[1] = 0xEC;                     /* Security Protocol: UFS */
    cdb[2] = 0x00;                     /* Security Protocol Specific (MSB) */
    cdb[3] = 0x01;                     /* Security Protocol Specific (LSB): RPMB region 0 */
    cdb[4] = 0x00;                     /* INC_512 = 0 */
    cdb[5] = 0x00;
    cdb[6] = (data_len >> 24) & 0xFF;  /* Transfer Length */
    cdb[7] = (data_len >> 16) & 0xFF;
    cdb[8] = (data_len >> 8) & 0xFF;
    cdb[9] = data_len & 0xFF;
    cdb[10] = 0x00;
    cdb[11] = 0x00;

    memset(&io, 0, sizeof(io));
    io.interface_id = 'S';
    io.cmd_len = 12;
    io.cmdp = cdb;
    io.dxfer_direction = SG_DXFER_TO_DEV;
    io.dxfer_len = data_len;
    io.dxferp = data;
    io.mx_sb_len = sizeof(sense);
    io.sbp = sense;
    io.timeout = 10000; /* 10 seconds */

    if (ioctl(fd, SG_IO, &io) < 0) {
        perror("SG_IO SECURITY PROTOCOL OUT");
        return -1;
    }

    if (io.status != 0 || io.host_status != 0 || io.driver_status != 0) {
        printf("[-] SECURITY PROTOCOL OUT error: status=%d host=%d driver=%d\n",
               io.status, io.host_status, io.driver_status);
        if (io.sb_len_wr > 0) {
            hexdump("Sense data", sense, io.sb_len_wr);
        }
        return -1;
    }

    return 0;
}

static int scsi_security_in(int fd, void *data, int data_len) {
    uint8_t cdb[12];
    uint8_t sense[32];
    struct sg_io_hdr io;

    /* SECURITY PROTOCOL IN, opcode 0xA2 */
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = 0xA2;                     /* SECURITY PROTOCOL IN */
    cdb[1] = 0xEC;                     /* Security Protocol: UFS */
    cdb[2] = 0x00;                     /* Security Protocol Specific (MSB) */
    cdb[3] = 0x01;                     /* Security Protocol Specific (LSB): RPMB region 0 */
    cdb[4] = 0x00;                     /* INC_512 = 0 */
    cdb[5] = 0x00;
    cdb[6] = (data_len >> 24) & 0xFF;  /* Transfer Length */
    cdb[7] = (data_len >> 16) & 0xFF;
    cdb[8] = (data_len >> 8) & 0xFF;
    cdb[9] = data_len & 0xFF;
    cdb[10] = 0x00;
    cdb[11] = 0x00;

    memset(&io, 0, sizeof(io));
    io.interface_id = 'S';
    io.cmd_len = 12;
    io.cmdp = cdb;
    io.dxfer_direction = SG_DXFER_FROM_DEV;
    io.dxfer_len = data_len;
    io.dxferp = data;
    io.mx_sb_len = sizeof(sense);
    io.sbp = sense;
    io.timeout = 10000;

    if (ioctl(fd, SG_IO, &io) < 0) {
        perror("SG_IO SECURITY PROTOCOL IN");
        return -1;
    }

    if (io.status != 0 || io.host_status != 0 || io.driver_status != 0) {
        printf("[-] SECURITY PROTOCOL IN error: status=%d host=%d driver=%d\n",
               io.status, io.host_status, io.driver_status);
        if (io.sb_len_wr > 0) {
            hexdump("Sense data", sense, io.sb_len_wr);
        }
        return -1;
    }

    return 0;
}

/*
 * Read RPMB write counter
 */
static int rpmb_read_counter(int fd, uint32_t *counter) {
    struct rpmb_frame req, resp;

    /* Prepare read counter request */
    memset(&req, 0, sizeof(req));
    req.req_resp = be16(RPMB_REQ_COUNTER_READ);

    /* Fill nonce with random data */
    for (int i = 0; i < 16; i++)
        req.nonce[i] = (uint8_t)(rand() & 0xFF);

    printf("[*] Sending RPMB read counter request...\n");

    /* Send request */
    if (scsi_security_out(fd, &req, sizeof(req)) < 0)
        return -1;

    /* Read response */
    memset(&resp, 0, sizeof(resp));
    if (scsi_security_in(fd, &resp, sizeof(resp)) < 0)
        return -1;

    uint16_t resp_type = be16(resp.req_resp);
    uint16_t result = be16(resp.result);
    *counter = be32(resp.write_counter);

    printf("[*] Response: type=0x%04x result=0x%04x counter=%u\n",
           resp_type, result, *counter);

    if (result != 0) {
        printf("[-] RPMB error: result=0x%x\n", result);
        return -1;
    }

    return 0;
}

/*
 * Read RPMB data block(s)
 * addr = half-sector address (256 bytes per half-sector)
 */
static int rpmb_read_data(int fd, uint16_t addr, uint8_t *out_data, size_t *out_len) {
    struct rpmb_frame req, resp;

    memset(&req, 0, sizeof(req));
    req.req_resp = be16(RPMB_REQ_DATA_READ);
    req.address = be16(addr);
    req.block_count = be16(1);

    /* Fill nonce */
    for (int i = 0; i < 16; i++)
        req.nonce[i] = (uint8_t)(rand() & 0xFF);

    /* Send read request */
    if (scsi_security_out(fd, &req, sizeof(req)) < 0)
        return -1;

    /* Read response */
    memset(&resp, 0, sizeof(resp));
    if (scsi_security_in(fd, &resp, sizeof(resp)) < 0)
        return -1;

    uint16_t resp_type = be16(resp.req_resp);
    uint16_t result = be16(resp.result);

    if (result != 0) {
        printf("[-] RPMB read addr=%u: result=0x%04x\n", addr, result);
        return -1;
    }

    /* Copy 256 bytes of data */
    memcpy(out_data, resp.data, 256);
    if (out_len) *out_len = 256;

    return 0;
}

int main(int argc, char **argv) {
    const char *dev = "/dev/sg1"; /* RPMB WLUN */
    int max_addr = 32; /* rpmb_rw_size = 0x20 = 32 half-sectors */

    if (argc >= 2) dev = argv[1];
    if (argc >= 3) max_addr = atoi(argv[2]);

    printf("============================================\n");
    printf("UFS RPMB Reader\n");
    printf("Device: %s\n", dev);
    printf("Max address: %d (= %d bytes)\n", max_addr, max_addr * 256);
    printf("============================================\n\n");

    int fd = open(dev, O_RDWR);
    if (fd < 0) {
        perror("open RPMB device");
        return 1;
    }

    /* Read write counter */
    uint32_t counter;
    if (rpmb_read_counter(fd, &counter) == 0) {
        printf("[+] RPMB write counter: %u\n\n", counter);
    } else {
        printf("[-] Failed to read RPMB counter, trying data read anyway...\n\n");
    }

    /* Read all RPMB data */
    printf("[*] Reading RPMB data (%d half-sectors = %d bytes)...\n",
           max_addr, max_addr * 256);

    uint8_t *rpmb_data = calloc(max_addr, 256);
    if (!rpmb_data) {
        perror("calloc");
        close(fd);
        return 1;
    }

    int blocks_read = 0;
    for (int addr = 0; addr < max_addr; addr++) {
        if (rpmb_read_data(fd, addr, rpmb_data + addr * 256, NULL) == 0) {
            blocks_read++;
        } else {
            printf("[-] Failed to read block %d, stopping\n", addr);
            break;
        }
    }

    printf("[+] Successfully read %d blocks (%d bytes)\n\n", blocks_read, blocks_read * 256);

    /* Dump the data */
    if (blocks_read > 0) {
        /* First, show summary of non-zero blocks */
        printf("[*] Non-zero blocks:\n");
        for (int addr = 0; addr < blocks_read; addr++) {
            int nonzero = 0;
            for (int i = 0; i < 256; i++) {
                if (rpmb_data[addr * 256 + i] != 0) { nonzero = 1; break; }
            }
            if (nonzero) {
                char label[64];
                snprintf(label, sizeof(label), "RPMB block %d (addr 0x%02x, offset 0x%04x)",
                         addr, addr, addr * 256);
                hexdump(label, rpmb_data + addr * 256, 256);
                printf("\n");
            }
        }

        /* Search for known patterns */
        printf("[*] Searching for known patterns...\n");
        /* ANDROID-BOOT! magic */
        for (int i = 0; i <= blocks_read * 256 - 13; i++) {
            if (memcmp(rpmb_data + i, "ANDROID-BOOT!", 13) == 0) {
                printf("[!] Found 'ANDROID-BOOT!' at offset 0x%x (block %d)\n",
                       i, i / 256);
                hexdump("DevInfo header", rpmb_data + i, 64);
            }
        }
        /* Search for is_unlocked patterns */
        for (int i = 0; i <= blocks_read * 256 - 4; i++) {
            /* Look for potential boolean fields near devinfo magic */
            if (rpmb_data[i] == 0x01 && i > 0 && rpmb_data[i-1] == 0x00) {
                /* Potential is_unlocked = 1 preceded by 0 */
            }
        }

        /* Write raw dump to file */
        const char *dumpfile = "/data/local/tmp/rpmb_dump.bin";
        FILE *f = fopen(dumpfile, "wb");
        if (f) {
            fwrite(rpmb_data, 1, blocks_read * 256, f);
            fclose(f);
            printf("[+] Raw RPMB dump saved to %s\n", dumpfile);
        }
    }

    free(rpmb_data);
    close(fd);
    return 0;
}
