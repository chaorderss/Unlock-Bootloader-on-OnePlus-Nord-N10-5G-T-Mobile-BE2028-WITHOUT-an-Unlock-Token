/*
 * scm_fuzz2.c - SCM fuzzer v2 - runs on module load, results via dmesg
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("research");
MODULE_DESCRIPTION("SCM PIL Auth Fuzzer v2");

/* Phase to run: 1=enumerate, 2=pas_probe, 3=pas_init_fuzz, 4=raw_scm, 5=pas_auth */
static int run_phase = 1;
module_param(run_phase, int, 0);
MODULE_PARM_DESC(run_phase, "Phase to run (1-5, 0=all)");

/* ---- SCM interface ---- */
#define MAX_SCM_ARGS   10
#define MAX_SCM_RETS   3

struct scm_desc {
    u32 arginfo;
    u64 args[MAX_SCM_ARGS];
    u64 ret[MAX_SCM_RETS];
};

#define SCM_VAL   0x0
#define SCM_RO    0x1
#define SCM_RW    0x2
#define SCM_BUFVAL 0x3

#define SCM_ARGS_1(a)     (1 | ((a) << 4))
#define SCM_ARGS_2(a,b)   (2 | ((a) << 4) | ((b) << 6))
#define SCM_ARGS_3(a,b,c) (3 | ((a) << 4) | ((b) << 6) | ((c) << 8))

#define QCOM_SCM_FNID(svc, cmd) (((svc) << 8) | (cmd))
#define SCM_SIP_FNID(svc, cmd)  (0x42000000UL | QCOM_SCM_FNID(svc, cmd))

#define SCM_SVC_BOOT  0x01
#define SCM_SVC_PIL   0x02
#define SCM_SVC_IO    0x05
#define SCM_SVC_INFO  0x06
#define SCM_SVC_SSD   0x07
#define SCM_SVC_FUSE  0x08
#define SCM_SVC_PWR   0x09
#define SCM_SVC_CP    0x0c
#define SCM_SVC_DCVS  0x0d
#define SCM_SVC_ES    0x10
#define SCM_SVC_HDCP  0x11
#define SCM_SVC_MDTP  0x12
#define SCM_SVC_LMH   0x13
#define SCM_SVC_SMMU  0x15
#define SCM_SVC_QDSS  0x16

#define PAS_INIT_IMAGE     0x01
#define PAS_MEM_SETUP      0x02
#define PAS_AUTH_AND_RESET 0x05
#define PAS_SHUTDOWN       0x06
#define PAS_IS_SUPPORTED   0x07
#define PAS_MSS_RESET      0x0a

extern int scm_call2(u32 fn_id, struct scm_desc *desc);
extern int scm_call2_atomic(u32 fn_id, struct scm_desc *desc);
extern bool scm_is_call_available(u32 svc_id, u32 cmd_id);
extern bool qcom_scm_pas_supported(u32 peripheral);
extern int qcom_scm_pas_init_image(u32 peripheral, const void *metadata, size_t size);
extern int qcom_scm_pas_mem_setup(u32 peripheral, phys_addr_t addr, phys_addr_t size);
extern int qcom_scm_pas_auth_and_reset(u32 peripheral);
extern int qcom_scm_pas_shutdown(u32 peripheral);

/* ===================== PHASES ===================== */

static void phase1_enumerate(void)
{
    u32 svc, cmd;
    int found = 0;

    pr_info("scm_fuzz: === PHASE 1: SCM Call Enumeration ===\n");
    for (svc = 0; svc <= 0x20; svc++) {
        for (cmd = 0; cmd <= 0x20; cmd++) {
            if (scm_is_call_available(svc, cmd)) {
                pr_info("scm_fuzz: SCM_AVAIL svc=0x%02x cmd=0x%02x fn=0x%08lx\n",
                        svc, cmd, (unsigned long)SCM_SIP_FNID(svc, cmd));
                found++;
            }
        }
        cond_resched();
    }
    pr_info("scm_fuzz: PHASE1_DONE found=%d\n", found);
}

static void phase2_pas_probe(void)
{
    u32 pid;
    pr_info("scm_fuzz: === PHASE 2: PAS Peripheral Probing ===\n");
    for (pid = 0; pid < 0x30; pid++) {
        if (qcom_scm_pas_supported(pid))
            pr_info("scm_fuzz: PAS_SUPPORTED pid=0x%02x YES\n", pid);
        cond_resched();
    }
    /* Extra IDs */
    if (qcom_scm_pas_supported(0xa6))
        pr_info("scm_fuzz: PAS_SUPPORTED pid=0xa6 YES\n");
    pr_info("scm_fuzz: PHASE2_DONE\n");
}

static const u8 minimal_elf_hdr[] = {
    0x7f, 'E', 'L', 'F', 0x01, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0xa4, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x20, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

static void phase3_pas_fuzz(void)
{
    int ret;
    u32 test_pids[] = { 0x00, 0x01, 0x04, 0x06, 0x09, 0x0d,
                        0x12, 0x17, 0x18, 0x1b, 0xa6 };
    void *meta_buf;
    u8 *fuzz_buf;
    int i, j;

    pr_info("scm_fuzz: === PHASE 3: PAS init_image Fuzzing ===\n");

    meta_buf = kzalloc(4096, GFP_KERNEL);
    if (!meta_buf) {
        pr_err("scm_fuzz: kzalloc failed\n");
        return;
    }

    /* 3a: zero metadata */
    pr_info("scm_fuzz: --- 3a: zero metadata ---\n");
    for (i = 0; i < ARRAY_SIZE(test_pids); i++) {
        ret = qcom_scm_pas_init_image(test_pids[i], meta_buf, 52);
        pr_info("scm_fuzz: PAS_INIT pid=0x%02x zero ret=%d\n",
                test_pids[i], ret);
        cond_resched();
        msleep(10);
    }

    /* 3b: ELF header metadata */
    pr_info("scm_fuzz: --- 3b: ELF header ---\n");
    memcpy(meta_buf, minimal_elf_hdr, sizeof(minimal_elf_hdr));
    for (i = 0; i < ARRAY_SIZE(test_pids); i++) {
        ret = qcom_scm_pas_init_image(test_pids[i], meta_buf, sizeof(minimal_elf_hdr));
        pr_info("scm_fuzz: PAS_INIT pid=0x%02x elf ret=%d\n",
                test_pids[i], ret);
        cond_resched();
        msleep(10);
    }

    /* 3c: size boundary tests */
    pr_info("scm_fuzz: --- 3c: size boundary ---\n");
    {
        size_t sizes[] = { 1, 4, 16, 32, 48, 52, 64, 128, 256, 512, 1024, 2048, 4096 };
        memset(meta_buf, 0x41, 4096);
        for (j = 0; j < ARRAY_SIZE(sizes); j++) {
            ret = qcom_scm_pas_init_image(0x18, meta_buf, sizes[j]);
            pr_info("scm_fuzz: PAS_INIT pid=0x18 size=%zu ret=%d\n", sizes[j], ret);
            ret = qcom_scm_pas_init_image(0xa6, meta_buf, sizes[j]);
            pr_info("scm_fuzz: PAS_INIT pid=0xa6 size=%zu ret=%d\n", sizes[j], ret);
            cond_resched();
            msleep(10);
        }
    }

    /* 3d: bit-flip on ELF header */
    pr_info("scm_fuzz: --- 3d: bitflip ---\n");
    fuzz_buf = (u8 *)meta_buf;
    for (i = 0; i < (int)sizeof(minimal_elf_hdr) && i < 44; i++) {
        memcpy(fuzz_buf, minimal_elf_hdr, sizeof(minimal_elf_hdr));
        fuzz_buf[i] ^= 0xFF;
        ret = qcom_scm_pas_init_image(0x18, fuzz_buf, sizeof(minimal_elf_hdr));
        pr_info("scm_fuzz: PAS_INIT pid=0x18 flip[%d]=0x%02x ret=%d\n",
                i, fuzz_buf[i], ret);
        cond_resched();
    }

    kfree(meta_buf);
    pr_info("scm_fuzz: PHASE3_DONE\n");
}

static void phase4_raw_scm(void)
{
    struct scm_desc desc;
    int ret;
    u32 svc, cmd;

    pr_info("scm_fuzz: === PHASE 4: Raw SCM Call Probing ===\n");

    /* 4a: Boot service */
    pr_info("scm_fuzz: --- 4a: Boot service ---\n");
    for (cmd = 0; cmd <= 0x20; cmd++) {
        if (!scm_is_call_available(SCM_SVC_BOOT, cmd))
            continue;
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = 0;
        ret = scm_call2(SCM_SIP_FNID(SCM_SVC_BOOT, cmd), &desc);
        pr_info("scm_fuzz: RAW svc=0x01 cmd=0x%02x ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                cmd, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
        cond_resched();
        msleep(5);
    }

    /* 4b: Info service */
    pr_info("scm_fuzz: --- 4b: Info service ---\n");
    for (cmd = 0; cmd <= 0x10; cmd++) {
        if (!scm_is_call_available(SCM_SVC_INFO, cmd))
            continue;
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = 0;
        ret = scm_call2(SCM_SIP_FNID(SCM_SVC_INFO, cmd), &desc);
        pr_info("scm_fuzz: RAW svc=0x06 cmd=0x%02x ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                cmd, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
        cond_resched();
        msleep(5);
    }

    /* 4c: Fuse service */
    pr_info("scm_fuzz: --- 4c: Fuse service ---\n");
    for (cmd = 0; cmd <= 0x10; cmd++) {
        if (!scm_is_call_available(SCM_SVC_FUSE, cmd))
            continue;
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = 0;
        ret = scm_call2(SCM_SIP_FNID(SCM_SVC_FUSE, cmd), &desc);
        pr_info("scm_fuzz: RAW svc=0x08 cmd=0x%02x ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                cmd, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
        cond_resched();
        msleep(5);
    }

    /* 4d: PIL undocumented commands */
    pr_info("scm_fuzz: --- 4d: PIL undocumented ---\n");
    for (cmd = 0; cmd <= 0x20; cmd++) {
        if (!scm_is_call_available(SCM_SVC_PIL, cmd))
            continue;
        if (cmd == PAS_INIT_IMAGE || cmd == PAS_AUTH_AND_RESET || cmd == PAS_MEM_SETUP)
            continue;
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = SCM_ARGS_1(SCM_VAL);
        desc.args[0] = 0;
        ret = scm_call2(SCM_SIP_FNID(SCM_SVC_PIL, cmd), &desc);
        pr_info("scm_fuzz: RAW svc=0x02 cmd=0x%02x ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                cmd, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
        cond_resched();
        msleep(5);
    }

    /* 4e: All other services */
    pr_info("scm_fuzz: --- 4e: Other services ---\n");
    for (svc = 0; svc <= 0x20; svc++) {
        if (svc == SCM_SVC_BOOT || svc == SCM_SVC_INFO ||
            svc == SCM_SVC_FUSE || svc == SCM_SVC_PIL)
            continue;
        for (cmd = 0; cmd <= 0x20; cmd++) {
            if (!scm_is_call_available(svc, cmd))
                continue;
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = 0;
            ret = scm_call2(SCM_SIP_FNID(svc, cmd), &desc);
            pr_info("scm_fuzz: RAW svc=0x%02x cmd=0x%02x ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                    svc, cmd, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
            cond_resched();
            msleep(5);
        }
    }

    pr_info("scm_fuzz: PHASE4_DONE\n");
}

static void phase5_pas_auth_probe(void)
{
    int ret;
    u32 pid;

    pr_info("scm_fuzz: === PHASE 5: PAS Auth & Shutdown Probing ===\n");

    pr_info("scm_fuzz: --- 5a: pas_shutdown ---\n");
    for (pid = 0; pid < 0x30; pid++) {
        ret = qcom_scm_pas_shutdown(pid);
        pr_info("scm_fuzz: PAS_SHUTDOWN pid=0x%02x ret=%d\n", pid, ret);
        cond_resched();
        msleep(10);
    }
    ret = qcom_scm_pas_shutdown(0xa6);
    pr_info("scm_fuzz: PAS_SHUTDOWN pid=0xa6 ret=%d\n", ret);

    pr_info("scm_fuzz: --- 5b: pas_mem_setup zero ---\n");
    for (pid = 0; pid < 0x20; pid++) {
        ret = qcom_scm_pas_mem_setup(pid, 0, 0);
        pr_info("scm_fuzz: PAS_MEMSETUP pid=0x%02x addr=0 size=0 ret=%d\n", pid, ret);
        cond_resched();
        msleep(10);
    }

    pr_info("scm_fuzz: PHASE5_DONE\n");
}

/* ===================== MODULE INIT/EXIT ===================== */

static int __init scm_fuzz_init(void)
{
    pr_info("scm_fuzz: loaded, run_phase=%d\n", run_phase);

    switch (run_phase) {
    case 0:
        phase1_enumerate();
        phase2_pas_probe();
        phase3_pas_fuzz();
        phase4_raw_scm();
        phase5_pas_auth_probe();
        break;
    case 1:
        phase1_enumerate();
        break;
    case 2:
        phase2_pas_probe();
        break;
    case 3:
        phase3_pas_fuzz();
        break;
    case 4:
        phase4_raw_scm();
        break;
    case 5:
        phase5_pas_auth_probe();
        break;
    default:
        pr_err("scm_fuzz: invalid phase %d\n", run_phase);
        return -EINVAL;
    }

    return 0;
}

static void __exit scm_fuzz_exit(void)
{
    pr_info("scm_fuzz: unloaded\n");
}

module_init(scm_fuzz_init);
module_exit(scm_fuzz_exit);
