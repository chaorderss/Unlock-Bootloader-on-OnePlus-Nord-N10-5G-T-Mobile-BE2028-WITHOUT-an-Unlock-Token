/*
 * QSEECOM UEFI Variable Client
 * Target: OnePlus Nord N10 5G (SM6350)
 *
 * Uses libQSEEComAPI.so to communicate with uefisecapp in TrustZone
 * to enumerate and modify UEFI variables (stored in RPMB).
 *
 * Compile:
 *   $NDK/aarch64-linux-android29-clang -O2 -o qsee_uefi qsee_uefi.c -ldl
 *
 * Run:
 *   LD_LIBRARY_PATH=/vendor/lib64 /data/local/tmp/qsee_uefi
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/* ---- QSEECom API types ---- */
struct QSEECom_handle {
    unsigned char *ion_sbuffer;
    uint32_t sbuf_len;
};

/* QSEECom API function pointers */
typedef int (*fn_start_app)(struct QSEECom_handle **handle,
                            const char *path, const char *name,
                            uint32_t size);
typedef int (*fn_shutdown_app)(struct QSEECom_handle **handle);
typedef int (*fn_send_cmd)(struct QSEECom_handle *handle,
                           void *send_buf, uint32_t sbuf_len,
                           void *rcv_buf, uint32_t rbuf_len);
typedef int (*fn_send_modified_cmd)(struct QSEECom_handle *handle,
                                    void *send_buf, uint32_t sbuf_len,
                                    void *rcv_buf, uint32_t rbuf_len,
                                    void *ifd_data);

static fn_start_app QSEECom_start_app;
static fn_shutdown_app QSEECom_shutdown_app;
static fn_send_cmd QSEECom_send_cmd;
static fn_send_modified_cmd QSEECom_send_modified_cmd;

/* ---- UEFI Variable TZ Command IDs ---- */
/* Multiple formats exist across Qualcomm platforms — try several */
#define UEFI_GET_VARIABLE           0x8000
#define UEFI_SET_VARIABLE           0x8001
#define UEFI_GET_NEXT_VARIABLE      0x8002
#define UEFI_QUERY_VARIABLE_INFO    0x8003

/* Alternative CMD IDs (used on some platforms) */
#define UEFI_GET_VARIABLE_ALT       1
#define UEFI_SET_VARIABLE_ALT       2
#define UEFI_GET_NEXT_VARIABLE_ALT  3

/* ---- EFI GUID ---- */
typedef struct {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t  data4[8];
} __attribute__((packed)) efi_guid_t;

/* Known GUIDs */
/* EFI_GLOBAL_VARIABLE_GUID */
static const efi_guid_t EFI_GLOBAL_GUID = {
    0x8BE4DF61, 0x93CA, 0x11D2,
    {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C}
};

/* Qualcomm vendor GUID (used for OEM lock state) */
static const efi_guid_t QC_VENDOR_GUID = {
    0x77FA9ABD, 0x0359, 0x4D32,
    {0xBD, 0x60, 0x28, 0xF4, 0xE7, 0x8F, 0x78, 0x4B}
};

/* OnePlus vendor GUID (guessed — may need adjustment) */
static const efi_guid_t OP_VENDOR_GUID = {
    0xC0DD69AC, 0x0000, 0x0000,
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};

/* ---- TZ Request/Response structures ---- */

/* Format 1: Offset-based (common on newer SoCs) */
struct tz_uefi_get_var_req {
    uint32_t cmd_id;
    uint32_t data_len;       /* total request length */
    uint32_t name_offset;    /* offset to name from start */
    uint32_t name_len;       /* name length in bytes (UTF-16) */
    efi_guid_t guid;
    uint32_t data_buf_len;   /* expected max data length */
} __attribute__((packed));

struct tz_uefi_get_var_resp {
    uint32_t cmd_id;
    uint32_t data_len;       /* actual data length */
    int32_t  status;         /* EFI_STATUS */
    uint32_t attributes;
    /* data follows */
} __attribute__((packed));

struct tz_uefi_get_next_req {
    uint32_t cmd_id;
    uint32_t data_len;
    efi_guid_t guid;
    uint32_t name_len;
    /* name follows (UTF-16) */
} __attribute__((packed));

struct tz_uefi_get_next_resp {
    uint32_t cmd_id;
    uint32_t data_len;
    int32_t  status;
    efi_guid_t guid;
    uint32_t name_len;
    /* name follows (UTF-16) */
} __attribute__((packed));

struct tz_uefi_set_var_req {
    uint32_t cmd_id;
    uint32_t data_len;
    uint32_t name_offset;
    uint32_t name_len;
    efi_guid_t guid;
    uint32_t attributes;
    uint32_t var_data_offset;
    uint32_t var_data_len;
} __attribute__((packed));

struct tz_uefi_set_var_resp {
    uint32_t cmd_id;
    uint32_t data_len;
    int32_t  status;
} __attribute__((packed));

/* ---- Helper functions ---- */

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

/* Convert ASCII to UTF-16LE */
static int to_utf16(const char *ascii, uint16_t *utf16, int max_chars) {
    int i;
    for (i = 0; ascii[i] && i < max_chars - 1; i++)
        utf16[i] = (uint16_t)ascii[i];
    utf16[i] = 0;
    return (i + 1) * 2; /* size in bytes including null */
}

/* Print UTF-16LE string */
static void print_utf16(const uint16_t *str, int len_bytes) {
    int n = len_bytes / 2;
    for (int i = 0; i < n && str[i]; i++)
        putchar((char)(str[i] & 0xFF));
}

static void print_guid(const efi_guid_t *g) {
    printf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           g->data1, g->data2, g->data3,
           g->data4[0], g->data4[1], g->data4[2], g->data4[3],
           g->data4[4], g->data4[5], g->data4[6], g->data4[7]);
}

/* Load QSEECom library */
static int load_qseecom(void) {
    /* Try multiple library paths */
    const char *libs[] = {
        "/vendor/lib64/libQSEEComAPI.so",
        "/system/lib64/libQSEEComAPI_system.so",
        "libQSEEComAPI.so",
        NULL
    };

    void *handle = NULL;
    for (int i = 0; libs[i]; i++) {
        handle = dlopen(libs[i], RTLD_NOW);
        if (handle) {
            printf("[+] Loaded %s\n", libs[i]);
            break;
        }
    }

    if (!handle) {
        printf("[-] Failed to load QSEECom library: %s\n", dlerror());
        return -1;
    }

    QSEECom_start_app = (fn_start_app)dlsym(handle, "QSEECom_start_app");
    QSEECom_shutdown_app = (fn_shutdown_app)dlsym(handle, "QSEECom_shutdown_app");
    QSEECom_send_cmd = (fn_send_cmd)dlsym(handle, "QSEECom_send_cmd");
    QSEECom_send_modified_cmd = (fn_send_modified_cmd)dlsym(handle, "QSEECom_send_modified_cmd");

    if (!QSEECom_start_app || !QSEECom_shutdown_app || !QSEECom_send_cmd) {
        printf("[-] Failed to resolve QSEECom functions: %s\n", dlerror());
        return -1;
    }

    printf("[+] QSEECom functions resolved:\n");
    printf("    start_app:    %p\n", QSEECom_start_app);
    printf("    shutdown_app: %p\n", QSEECom_shutdown_app);
    printf("    send_cmd:     %p\n", QSEECom_send_cmd);
    printf("    send_mod_cmd: %p\n", QSEECom_send_modified_cmd);

    return 0;
}

/* Try to connect to uefisecapp */
static struct QSEECom_handle *connect_uefisecapp(void) {
    struct QSEECom_handle *handle = NULL;
    int ret;

    /* Try different app names and paths */
    const char *paths[] = {
        "/vendor/firmware_mnt/image",
        "/firmware/image",
        "/vendor/firmware",
        "/system/etc/firmware",
        NULL
    };
    const char *names[] = {
        "uefisecapp",
        "uefi_sec_app",
        "tz_uefisec",
        "storsec",
        NULL
    };

    for (int p = 0; paths[p]; p++) {
        for (int n = 0; names[n]; n++) {
            printf("[*] Trying: path=%s name=%s\n", paths[p], names[n]);
            ret = QSEECom_start_app(&handle, paths[p], names[n], 4096);
            if (ret == 0 && handle) {
                printf("[+] Connected to TZ app: %s/%s\n", paths[p], names[n]);
                printf("    sbuffer=%p, sbuf_len=%u\n",
                       handle->ion_sbuffer, handle->sbuf_len);
                return handle;
            }
            printf("    Failed: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
        }
    }

    /* Also try loading from partition path (uefisecapp is on its own partition) */
    printf("[*] Trying partition-loaded uefisecapp...\n");
    ret = QSEECom_start_app(&handle, "", "uefisecapp", 4096);
    if (ret == 0 && handle) {
        printf("[+] Connected to partition-loaded uefisecapp\n");
        return handle;
    }
    printf("    Failed: ret=%d errno=%d\n", ret, errno);

    return NULL;
}

/* Enumerate UEFI variables using GetNextVariable */
static int enumerate_variables(struct QSEECom_handle *handle, uint32_t cmd_base) {
    uint8_t req_buf[4096];
    uint8_t resp_buf[4096];
    int ret;
    int count = 0;

    /* Start with empty name (first variable) */
    efi_guid_t cur_guid;
    uint16_t cur_name[256];
    memset(&cur_guid, 0, sizeof(cur_guid));
    memset(cur_name, 0, sizeof(cur_name));

    printf("\n[*] Enumerating UEFI variables (cmd_base=0x%x)...\n", cmd_base);

    for (int iter = 0; iter < 100; iter++) {
        memset(req_buf, 0, sizeof(req_buf));
        memset(resp_buf, 0, sizeof(resp_buf));

        struct tz_uefi_get_next_req *req = (struct tz_uefi_get_next_req *)req_buf;
        req->cmd_id = cmd_base + 2; /* GET_NEXT_VARIABLE */

        /* Copy current GUID */
        memcpy(&req->guid, &cur_guid, sizeof(efi_guid_t));

        /* Copy current name after the fixed header */
        int name_len = 0;
        while (cur_name[name_len]) name_len++;
        name_len = (name_len + 1) * 2; /* include null, in bytes */
        req->name_len = name_len;
        memcpy(req_buf + sizeof(*req), cur_name, name_len);
        req->data_len = sizeof(*req) + name_len;

        ret = QSEECom_send_cmd(handle, req_buf, sizeof(req_buf),
                               resp_buf, sizeof(resp_buf));
        if (ret != 0) {
            printf("[-] send_cmd failed: ret=%d errno=%d\n", ret, errno);
            break;
        }

        struct tz_uefi_get_next_resp *resp = (struct tz_uefi_get_next_resp *)resp_buf;

        if (resp->status != 0) {
            if (resp->status == 0x8000000000000005LL || /* EFI_NOT_FOUND (64-bit) */
                resp->status == (int32_t)0x80000005 ||  /* EFI_NOT_FOUND (32-bit) */
                resp->status == 0x14 ||                  /* Not found (legacy) */
                resp->status == 5) {                     /* Not found */
                printf("[*] End of variable list (status=0x%x)\n", resp->status);
                break;
            }
            printf("[-] GetNextVariable error: status=0x%x\n", resp->status);
            hexdump("Response", resp_buf, 64);
            break;
        }

        /* Extract next variable info */
        memcpy(&cur_guid, &resp->guid, sizeof(efi_guid_t));
        if (resp->name_len > 0 && resp->name_len <= sizeof(cur_name)) {
            memcpy(cur_name, resp_buf + sizeof(*resp), resp->name_len);
        }

        printf("  [%d] ", count);
        print_guid(&cur_guid);
        printf(" : ");
        print_utf16(cur_name, resp->name_len);
        printf(" (name_len=%u)\n", resp->name_len);

        count++;
    }

    printf("[*] Found %d variables\n", count);
    return count;
}

/* Get a specific UEFI variable */
static int get_variable(struct QSEECom_handle *handle, uint32_t cmd_base,
                        const char *name, const efi_guid_t *guid) {
    uint8_t req_buf[4096];
    uint8_t resp_buf[4096];
    int ret;

    memset(req_buf, 0, sizeof(req_buf));
    memset(resp_buf, 0, sizeof(resp_buf));

    struct tz_uefi_get_var_req *req = (struct tz_uefi_get_var_req *)req_buf;
    req->cmd_id = cmd_base; /* GET_VARIABLE */

    uint16_t name_utf16[256];
    int name_bytes = to_utf16(name, name_utf16, 256);

    req->name_offset = sizeof(*req);
    req->name_len = name_bytes;
    memcpy(&req->guid, guid, sizeof(efi_guid_t));
    req->data_buf_len = 1024;
    req->data_len = sizeof(*req) + name_bytes;

    memcpy(req_buf + sizeof(*req), name_utf16, name_bytes);

    printf("[*] GetVariable: '%s' GUID=", name);
    print_guid(guid);
    printf(" (cmd_id=0x%x)\n", req->cmd_id);

    ret = QSEECom_send_cmd(handle, req_buf, sizeof(req_buf),
                           resp_buf, sizeof(resp_buf));
    if (ret != 0) {
        printf("[-] send_cmd failed: ret=%d errno=%d\n", ret, errno);
        return -1;
    }

    struct tz_uefi_get_var_resp *resp = (struct tz_uefi_get_var_resp *)resp_buf;
    printf("    Response: cmd_id=0x%x data_len=%u status=0x%x attrs=0x%x\n",
           resp->cmd_id, resp->data_len, resp->status, resp->attributes);

    if (resp->status == 0 && resp->data_len > 0) {
        hexdump("Variable data", resp_buf + sizeof(*resp), resp->data_len);
    } else {
        hexdump("Full response", resp_buf, 64);
    }

    return resp->status;
}

/* ---- Direct QSEECOM ioctl approach (fallback) ---- */

#define QSEECOM_IOC_MAGIC  0x97

struct qseecom_load_img_req {
    uint32_t mdt_len;
    uint32_t img_len;
    int32_t  ifd_data_fd;
    char     img_name[64];
    uint32_t app_arch;
    uint32_t app_id;
};

struct qseecom_qseos_app_load_query {
    char     app_name[64];
    uint32_t app_id;
    uint32_t app_arch;
};

struct qseecom_set_sb_mem_param_req {
    int32_t ifd_data_fd;
    void   *virt_sb_base;
    uint32_t sb_len;
};

#define QSEECOM_IOCTL_APP_LOADED_QUERY \
    _IOWR(QSEECOM_IOC_MAGIC, 15, struct qseecom_qseos_app_load_query)

static int check_app_loaded(const char *name) {
    int fd = open("/dev/qseecom", O_RDWR);
    if (fd < 0) {
        printf("[-] Cannot open /dev/qseecom: %s\n", strerror(errno));
        return -1;
    }

    struct qseecom_qseos_app_load_query query;
    memset(&query, 0, sizeof(query));
    strncpy(query.app_name, name, 63);

    int ret = ioctl(fd, QSEECOM_IOCTL_APP_LOADED_QUERY, &query);
    printf("[*] App '%s' query: ret=%d app_id=%u app_arch=%u errno=%d\n",
           name, ret, query.app_id, query.app_arch, errno);

    close(fd);
    return ret == 0 ? (int)query.app_id : -1;
}

int main(int argc, char **argv) {
    printf("==============================================\n");
    printf("QSEECOM UEFI Variable Client\n");
    printf("==============================================\n\n");

    /* Step 1: Check which TZ apps are loaded */
    printf("[*] Checking loaded TZ apps...\n");
    const char *check_apps[] = {
        "uefisecapp", "uefi_sec_app", "storsec",
        "keymaster", "gatekeeper", "featenabler",
        "commonlib", "commonlib64", "cmnlib", "cmnlib64",
        NULL
    };
    for (int i = 0; check_apps[i]; i++) {
        check_app_loaded(check_apps[i]);
    }

    /* Step 2: Load QSEECom library */
    printf("\n[*] Loading QSEECom library...\n");
    if (load_qseecom() < 0) {
        printf("[-] Cannot load QSEECom library, trying direct ioctl...\n");
        return 1;
    }

    /* Step 3: Connect to uefisecapp */
    printf("\n[*] Connecting to uefisecapp...\n");
    struct QSEECom_handle *handle = connect_uefisecapp();
    if (!handle) {
        printf("[-] Could not connect to any UEFI TZ app\n");
        printf("[*] uefisecapp may need to be loaded from its partition\n");
        printf("[*] Trying direct SCSI RPMB write approach instead...\n");
        return 1;
    }

    /* Step 4: Try to enumerate variables with different command bases */
    uint32_t cmd_bases[] = { UEFI_GET_VARIABLE, UEFI_GET_VARIABLE_ALT, 0, 0x100, 0x200 };
    for (int i = 0; i < 5; i++) {
        printf("\n--- Trying cmd_base=0x%x ---\n", cmd_bases[i]);
        int n = enumerate_variables(handle, cmd_bases[i]);
        if (n > 0) break;
    }

    /* Step 5: Try to get specific known variables */
    printf("\n[*] Trying to read specific variables...\n");

    /* OemLock / DeviceState type variables */
    const char *var_names[] = {
        "OemLock", "DevLock", "DeviceState", "EnableOemUnlock",
        "UnlockToken", "CarrierLock", "IsUnlocked",
        "OEMUnlock", "BootState", "LockState",
        "BSPowerCycles", "MTC", /* known to exist */
        NULL
    };

    const efi_guid_t *guids[] = {
        &EFI_GLOBAL_GUID, &QC_VENDOR_GUID, &OP_VENDOR_GUID, NULL
    };

    for (int gi = 0; guids[gi]; gi++) {
        for (int vi = 0; var_names[vi]; vi++) {
            get_variable(handle, UEFI_GET_VARIABLE, var_names[vi], guids[gi]);
        }
    }

    /* Step 6: Cleanup */
    printf("\n[*] Shutting down TZ app...\n");
    QSEECom_shutdown_app(&handle);

    printf("[*] Done.\n");
    return 0;
}
