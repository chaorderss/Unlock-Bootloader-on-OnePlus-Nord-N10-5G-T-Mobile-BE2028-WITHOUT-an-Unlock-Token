/*
 * scm_fuzz.c - Qualcomm SCM / PIL Authentication Flow Fuzzer
 *
 * Kernel module that probes the TrustZone SCM interface to enumerate
 * available services and test PIL authentication behavior.
 *
 * Target: SDM765G (SM7250), kernel 4.19.81-perf+
 *
 * Phase 1: Enumerate all available SCM (svc, cmd) pairs
 * Phase 2: Probe PAS-supported peripheral IDs
 * Phase 3: PAS init_image fuzzing with crafted metadata
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("research");
MODULE_DESCRIPTION("SCM PIL Auth Fuzzer");

/* ---- SCM interface definitions (from qcom_scm.h) ---- */

#define MAX_SCM_ARGS   10
#define MAX_SCM_RETS   3

struct scm_desc {
    u32 arginfo;
    u64 args[MAX_SCM_ARGS];
    u64 ret[MAX_SCM_RETS];
};

/* Argument type encoding */
#define SCM_VAL   0x0
#define SCM_RO    0x1
#define SCM_RW    0x2
#define SCM_BUFVAL 0x3

/* arginfo helper: encodes arg count and types */
#define SCM_ARGS_1(a)     (1 | ((a) << 4))
#define SCM_ARGS_2(a,b)   (2 | ((a) << 4) | ((b) << 6))
#define SCM_ARGS_3(a,b,c) (3 | ((a) << 4) | ((b) << 6) | ((c) << 8))

/* SMC function ID construction */
#define QCOM_SCM_FNID(svc, cmd) (((svc) << 8) | (cmd))
#define SCM_SIP_FNID(svc, cmd)  (0x42000000UL | QCOM_SCM_FNID(svc, cmd))

/* Known SCM service IDs */
#define SCM_SVC_BOOT         0x01
#define SCM_SVC_PIL          0x02
#define SCM_SVC_IO           0x05
#define SCM_SVC_INFO         0x06
#define SCM_SVC_SSD          0x07
#define SCM_SVC_FUSE         0x08
#define SCM_SVC_PWR          0x09
#define SCM_SVC_CP           0x0c
#define SCM_SVC_DCVS         0x0d
#define SCM_SVC_ES           0x10
#define SCM_SVC_HDCP         0x11
#define SCM_SVC_MDTP         0x12
#define SCM_SVC_LMH          0x13
#define SCM_SVC_SMMU         0x15
#define SCM_SVC_QDSS         0x16

/* PIL PAS commands */
#define PAS_INIT_IMAGE        0x01
#define PAS_MEM_SETUP         0x02
#define PAS_AUTH_AND_RESET    0x05
#define PAS_SHUTDOWN          0x06
#define PAS_IS_SUPPORTED      0x07
#define PAS_MSS_RESET         0x0a

/* Known PAS peripheral IDs */
#define PAS_MODEM        0x04
#define PAS_ADSP         0x01
#define PAS_CDSP         0x12
#define PAS_WLAN         0x09
#define PAS_WLAN_CE      0x18
#define PAS_VENUS        0x09
#define PAS_GPU_ZAP      0x0d
#define PAS_IPA_FWS      0x1b
#define PAS_NPU          0x17
#define PAS_WCNSS        0x06

/* External kernel symbols (exported by qcom_scm) */
extern int scm_call2(u32 fn_id, struct scm_desc *desc);
extern int scm_call2_atomic(u32 fn_id, struct scm_desc *desc);
extern bool scm_is_call_available(u32 svc_id, u32 cmd_id);
extern bool qcom_scm_pas_supported(u32 peripheral);
extern int qcom_scm_pas_init_image(u32 peripheral, const void *metadata,
                                   size_t size);
extern int qcom_scm_pas_mem_setup(u32 peripheral, phys_addr_t addr,
                                  phys_addr_t size);
extern int qcom_scm_pas_auth_and_reset(u32 peripheral);
extern int qcom_scm_pas_shutdown(u32 peripheral);

/* ===================== RESULTS STORAGE ===================== */

#define MAX_LOG_SIZE    (128 * 1024)  /* 128KB log buffer */

static char *log_buf;
static int log_pos;
static struct mutex log_lock;

static void log_msg(const char *fmt, ...)
{
    va_list args;
    int len;

    mutex_lock(&log_lock);
    if (log_pos < MAX_LOG_SIZE - 256) {
        va_start(args, fmt);
        len = vsnprintf(log_buf + log_pos, MAX_LOG_SIZE - log_pos, fmt, args);
        va_end(args);
        if (len > 0)
            log_pos += len;
    }
    mutex_unlock(&log_lock);
}

/* ===================== PHASE 1: ENUMERATION ===================== */

static int phase;  /* current phase, writable from /proc */
static int running; /* guard against concurrent runs */

static void phase1_enumerate(void)
{
    u32 svc, cmd;
    int found = 0;

    log_msg("=== PHASE 1: SCM Call Enumeration ===\n");

    for (svc = 0; svc <= 0x20; svc++) {
        for (cmd = 0; cmd <= 0x20; cmd++) {
            if (scm_is_call_available(svc, cmd)) {
                log_msg("SCM_AVAIL svc=0x%02x cmd=0x%02x fn_id=0x%08lx\n",
                        svc, cmd, (unsigned long)SCM_SIP_FNID(svc, cmd));
                found++;
            }
        }
        /* Yield CPU between service scans */
        cond_resched();
    }

    log_msg("PHASE1_DONE: found %d available SCM calls\n\n", found);
}

/* ===================== PHASE 2: PAS PROBING ===================== */

static void phase2_pas_probe(void)
{
    u32 pid;
    int supported = 0;

    log_msg("=== PHASE 2: PAS Peripheral Support Probing ===\n");

    for (pid = 0; pid < 0x30; pid++) {
        bool sup = qcom_scm_pas_supported(pid);
        if (sup) {
            log_msg("PAS_SUPPORTED peripheral=0x%02x YES\n", pid);
            supported++;
        }
        cond_resched();
    }

    log_msg("PHASE2_DONE: %d peripherals supported\n\n", supported);
}

/* ===================== PHASE 3: PAS INIT_IMAGE FUZZING ===================== */

/* Minimal ELF header for Hexagon DSP */
static const u8 minimal_elf_hdr[] = {
    0x7f, 'E', 'L', 'F',   /* magic */
    0x01,                    /* 32-bit */
    0x01,                    /* little-endian */
    0x01,                    /* ELF version */
    0x00,                    /* OS/ABI */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* padding */
    0x02, 0x00,              /* ET_EXEC */
    0xa4, 0x00,              /* Hexagon */
    0x01, 0x00, 0x00, 0x00,  /* version */
    0x00, 0x00, 0x00, 0x00,  /* entry */
    0x34, 0x00, 0x00, 0x00,  /* phoff = 52 */
    0x00, 0x00, 0x00, 0x00,  /* shoff */
    0x00, 0x00, 0x00, 0x00,  /* flags */
    0x34, 0x00,              /* ehsize = 52 */
    0x20, 0x00,              /* phentsize = 32 */
    0x02, 0x00,              /* phnum = 2 */
    0x00, 0x00,              /* shentsize */
    0x00, 0x00,              /* shnum */
    0x00, 0x00               /* shstrndx */
};

static void phase3_pas_fuzz(void)
{
    int ret;
    u32 test_pids[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0xa6, /* 0xa6 = ICNSS WLAN from DT */
        0xff, 0xfe, 0xfd,
    };
    void *meta_buf;
    u8 *fuzz_buf;
    int i, j;
    int num_pids = ARRAY_SIZE(test_pids);

    log_msg("=== PHASE 3: PAS init_image Fuzzing ===\n");

    /* Test 3a: Zero-filled metadata for each peripheral */
    log_msg("--- Test 3a: zero metadata (52 bytes) ---\n");
    meta_buf = kzalloc(4096, GFP_KERNEL);
    if (!meta_buf) {
        log_msg("ERROR: kzalloc failed\n");
        return;
    }

    for (i = 0; i < num_pids; i++) {
        ret = qcom_scm_pas_init_image(test_pids[i], meta_buf, 52);
        log_msg("PAS_INIT pid=0x%02x zero_meta ret=%d\n",
                test_pids[i], ret);
        cond_resched();
        msleep(10);
    }

    /* Test 3b: Minimal ELF header as metadata */
    log_msg("--- Test 3b: minimal ELF header ---\n");
    memcpy(meta_buf, minimal_elf_hdr, sizeof(minimal_elf_hdr));
    for (i = 0; i < num_pids; i++) {
        ret = qcom_scm_pas_init_image(test_pids[i], meta_buf, sizeof(minimal_elf_hdr));
        log_msg("PAS_INIT pid=0x%02x elf_meta ret=%d\n",
                test_pids[i], ret);
        cond_resched();
        msleep(10);
    }

    /* Test 3c: Various metadata sizes (boundary testing) */
    log_msg("--- Test 3c: metadata size boundary ---\n");
    {
        size_t sizes[] = { 0, 1, 4, 16, 32, 48, 52, 64, 128, 256,
                           512, 1024, 2048, 4096 };
        memset(meta_buf, 0x41, 4096);
        for (j = 0; j < ARRAY_SIZE(sizes); j++) {
            /* Test with WLAN PAS ID 0x18 and ICNSS 0xa6 */
            if (sizes[j] == 0) {
                ret = qcom_scm_pas_init_image(0x18, meta_buf, 1);
            } else {
                ret = qcom_scm_pas_init_image(0x18, meta_buf, sizes[j]);
            }
            log_msg("PAS_INIT pid=0x18 size=%zu ret=%d\n", sizes[j], ret);

            ret = qcom_scm_pas_init_image(0xa6, meta_buf, sizes[j] ? sizes[j] : 1);
            log_msg("PAS_INIT pid=0xa6 size=%zu ret=%d\n", sizes[j], ret);
            cond_resched();
            msleep(10);
        }
    }

    /* Test 3d: Bit-flip fuzzing on ELF header */
    log_msg("--- Test 3d: bit-flip on ELF metadata ---\n");
    fuzz_buf = (u8 *)meta_buf;
    for (i = 0; i < (int)sizeof(minimal_elf_hdr) && i < 44; i++) {
        /* Restore clean header */
        memcpy(fuzz_buf, minimal_elf_hdr, sizeof(minimal_elf_hdr));
        /* Flip each byte */
        fuzz_buf[i] ^= 0xFF;
        ret = qcom_scm_pas_init_image(0x18, fuzz_buf, sizeof(minimal_elf_hdr));
        log_msg("PAS_INIT pid=0x18 bitflip[%d]=0x%02x ret=%d\n",
                i, fuzz_buf[i], ret);
        cond_resched();
    }

    kfree(meta_buf);
    log_msg("PHASE3_DONE\n\n");
}

/* ===================== PHASE 4: RAW SCM CALL PROBING ===================== */

static void phase4_raw_scm(void)
{
    struct scm_desc desc = {0};
    int ret;
    u32 svc, cmd;

    log_msg("=== PHASE 4: Raw SCM Call Probing ===\n");

    /* 4a: Try interesting boot/security SCM calls */
    log_msg("--- Test 4a: Boot/Security service probes ---\n");

    /* SVC_BOOT commands: check for debug/dev mode queries */
    for (cmd = 0; cmd <= 0x20; cmd++) {
        if (!scm_is_call_available(SCM_SVC_BOOT, cmd))
            continue;
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = 0; /* no args */
        ret = scm_call2(SCM_SIP_FNID(SCM_SVC_BOOT, cmd), &desc);
        log_msg("RAW svc=0x01 cmd=0x%02x ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                cmd, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
        cond_resched();
        msleep(5);
    }

    /* SVC_INFO commands: query TZ info */
    log_msg("--- Test 4b: Info service probes ---\n");
    for (cmd = 0; cmd <= 0x10; cmd++) {
        if (!scm_is_call_available(SCM_SVC_INFO, cmd))
            continue;
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = 0;
        ret = scm_call2(SCM_SIP_FNID(SCM_SVC_INFO, cmd), &desc);
        log_msg("RAW svc=0x06 cmd=0x%02x ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                cmd, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
        cond_resched();
        msleep(5);
    }

    /* SVC_FUSE commands: check fuse read/status */
    log_msg("--- Test 4c: Fuse service probes ---\n");
    for (cmd = 0; cmd <= 0x10; cmd++) {
        if (!scm_is_call_available(SCM_SVC_FUSE, cmd))
            continue;
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = 0;
        ret = scm_call2(SCM_SIP_FNID(SCM_SVC_FUSE, cmd), &desc);
        log_msg("RAW svc=0x08 cmd=0x%02x ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                cmd, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
        cond_resched();
        msleep(5);
    }

    /* 4d: PIL service - check for undocumented commands */
    log_msg("--- Test 4d: PIL undocumented commands ---\n");
    for (cmd = 0; cmd <= 0x20; cmd++) {
        if (!scm_is_call_available(SCM_SVC_PIL, cmd))
            continue;
        /* Skip known dangerous commands (init_image, auth_and_reset) */
        if (cmd == PAS_INIT_IMAGE || cmd == PAS_AUTH_AND_RESET ||
            cmd == PAS_MEM_SETUP)
            continue;
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = SCM_ARGS_1(SCM_VAL);
        desc.args[0] = 0; /* peripheral ID = 0 */
        ret = scm_call2(SCM_SIP_FNID(SCM_SVC_PIL, cmd), &desc);
        log_msg("RAW svc=0x02 cmd=0x%02x ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                cmd, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
        cond_resched();
        msleep(5);
    }

    /* 4e: Scan ALL available calls with no-arg probing */
    log_msg("--- Test 4e: Full available call probe (no args) ---\n");
    for (svc = 0; svc <= 0x20; svc++) {
        for (cmd = 0; cmd <= 0x20; cmd++) {
            if (!scm_is_call_available(svc, cmd))
                continue;
            /* Skip already tested and known dangerous */
            if (svc == SCM_SVC_BOOT || svc == SCM_SVC_INFO ||
                svc == SCM_SVC_FUSE || svc == SCM_SVC_PIL)
                continue;
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = 0;
            ret = scm_call2(SCM_SIP_FNID(svc, cmd), &desc);
            log_msg("RAW svc=0x%02x cmd=0x%02x ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                    svc, cmd, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
            cond_resched();
            msleep(5);
        }
    }

    log_msg("PHASE4_DONE\n\n");
}

/* ===================== PHASE 5: PAS AUTH BOUNDARY PROBING ===================== */

static void phase5_pas_auth_probe(void)
{
    int ret;
    u32 pid;

    log_msg("=== PHASE 5: PAS Auth & Shutdown Probing ===\n");

    /* Test: call pas_shutdown on various peripheral IDs
     * This is relatively safe - worst case TZ rejects or no-ops */
    log_msg("--- Test 5a: pas_shutdown responses ---\n");
    for (pid = 0; pid < 0x30; pid++) {
        ret = qcom_scm_pas_shutdown(pid);
        log_msg("PAS_SHUTDOWN pid=0x%02x ret=%d\n", pid, ret);
        cond_resched();
        msleep(10);
    }
    /* Also test ICNSS WLAN PAS ID */
    ret = qcom_scm_pas_shutdown(0xa6);
    log_msg("PAS_SHUTDOWN pid=0xa6 ret=%d\n", ret);

    /* Test: pas_mem_setup with addr=0, size=0 for each peripheral
     * This probes whether TZ validates memory ranges before other checks */
    log_msg("--- Test 5b: pas_mem_setup with zero addr/size ---\n");
    for (pid = 0; pid < 0x20; pid++) {
        ret = qcom_scm_pas_mem_setup(pid, 0, 0);
        log_msg("PAS_MEMSETUP pid=0x%02x addr=0 size=0 ret=%d\n", pid, ret);
        cond_resched();
        msleep(10);
    }

    log_msg("PHASE5_DONE\n\n");
}

/* ===================== PROC INTERFACE ===================== */

static struct proc_dir_entry *proc_entry;
static struct proc_dir_entry *proc_ctrl;

static int fuzz_log_show(struct seq_file *m, void *v)
{
    mutex_lock(&log_lock);
    seq_write(m, log_buf, log_pos);
    mutex_unlock(&log_lock);
    return 0;
}

static int fuzz_log_open(struct inode *inode, struct file *file)
{
    return single_open(file, fuzz_log_show, NULL);
}

static const struct file_operations fuzz_log_fops = {
    .owner   = THIS_MODULE,
    .open    = fuzz_log_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

static ssize_t fuzz_ctrl_write(struct file *file, const char __user *buf,
                               size_t count, loff_t *ppos)
{
    char *cmd;
    int len = min_t(size_t, count, 31);

    cmd = kmalloc(32, GFP_KERNEL);
    if (!cmd)
        return -ENOMEM;

    if (copy_from_user(cmd, buf, len)) {
        kfree(cmd);
        return -EFAULT;
    }
    cmd[len] = '\0';

    /* Strip trailing newline */
    if (len > 0 && cmd[len-1] == '\n')
        cmd[len-1] = '\0';

    if (running) {
        pr_err("scm_fuzz: already running\n");
        kfree(cmd);
        return -EBUSY;
    }

    if (strcmp(cmd, "phase1") == 0) {
        running = 1;
        /* Clear log */
        mutex_lock(&log_lock);
        log_pos = 0;
        mutex_unlock(&log_lock);
        phase1_enumerate();
        running = 0;
    } else if (strcmp(cmd, "phase2") == 0) {
        running = 1;
        mutex_lock(&log_lock);
        log_pos = 0;
        mutex_unlock(&log_lock);
        phase2_pas_probe();
        running = 0;
    } else if (strcmp(cmd, "phase3") == 0) {
        running = 1;
        mutex_lock(&log_lock);
        log_pos = 0;
        mutex_unlock(&log_lock);
        phase3_pas_fuzz();
        running = 0;
    } else if (strcmp(cmd, "phase4") == 0) {
        running = 1;
        mutex_lock(&log_lock);
        log_pos = 0;
        mutex_unlock(&log_lock);
        phase4_raw_scm();
        running = 0;
    } else if (strcmp(cmd, "phase5") == 0) {
        running = 1;
        mutex_lock(&log_lock);
        log_pos = 0;
        mutex_unlock(&log_lock);
        phase5_pas_auth_probe();
        running = 0;
    } else if (strcmp(cmd, "all") == 0) {
        running = 1;
        mutex_lock(&log_lock);
        log_pos = 0;
        mutex_unlock(&log_lock);
        phase1_enumerate();
        phase2_pas_probe();
        phase3_pas_fuzz();
        phase4_raw_scm();
        phase5_pas_auth_probe();
        running = 0;
    } else if (strcmp(cmd, "clear") == 0) {
        mutex_lock(&log_lock);
        log_pos = 0;
        mutex_unlock(&log_lock);
    } else {
        pr_err("scm_fuzz: unknown command '%s'\n", cmd);
        pr_err("scm_fuzz: use: phase1|phase2|phase3|phase4|phase5|all|clear\n");
        kfree(cmd);
        return -EINVAL;
    }

    kfree(cmd);
    return count;
}

static ssize_t fuzz_ctrl_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
    char status[128];
    int len;

    len = snprintf(status, sizeof(status),
                   "running=%d log_bytes=%d/%d\n"
                   "commands: phase1 phase2 phase3 phase4 phase5 all clear\n",
                   running, log_pos, MAX_LOG_SIZE);

    return simple_read_from_buffer(buf, count, ppos, status, len);
}

static const struct file_operations fuzz_ctrl_fops = {
    .owner = THIS_MODULE,
    .write = fuzz_ctrl_write,
    .read  = fuzz_ctrl_read,
};

/* ===================== MODULE INIT/EXIT ===================== */

static int __init scm_fuzz_init(void)
{
    log_buf = kmalloc(MAX_LOG_SIZE, GFP_KERNEL);
    if (!log_buf)
        return -ENOMEM;
    log_pos = 0;
    mutex_init(&log_lock);

    proc_entry = proc_create("scm_fuzz_log", 0444, NULL, &fuzz_log_fops);
    if (!proc_entry) {
        kfree(log_buf);
        return -ENOMEM;
    }

    proc_ctrl = proc_create("scm_fuzz_ctrl", 0666, NULL, &fuzz_ctrl_fops);
    if (!proc_ctrl) {
        proc_remove(proc_entry);
        kfree(log_buf);
        return -ENOMEM;
    }

    pr_info("scm_fuzz: loaded. Use /proc/scm_fuzz_ctrl to control.\n");
    pr_info("scm_fuzz: echo phaseN > /proc/scm_fuzz_ctrl\n");
    pr_info("scm_fuzz: cat /proc/scm_fuzz_log to read results\n");

    return 0;
}

static void __exit scm_fuzz_exit(void)
{
    proc_remove(proc_ctrl);
    proc_remove(proc_entry);
    kfree(log_buf);
    pr_info("scm_fuzz: unloaded\n");
}

module_init(scm_fuzz_init);
module_exit(scm_fuzz_exit);
