/*
 * scm_fuzz3.c - SCM fuzzer v3 - single operation per load, safe probing
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("research");
MODULE_DESCRIPTION("SCM PIL Auth Fuzzer v3 - single op");

static int op = 0;       /* operation type */
static int pid_val = -1;  /* peripheral ID */
static int svc_val = -1;  /* service ID */
static int cmd_val = -1;  /* command ID */
static int meta_type = 0; /* metadata type for pas_init */
static int meta_size = 52;/* metadata size */

module_param(op, int, 0);
module_param(pid_val, int, 0);
module_param(svc_val, int, 0);
module_param(cmd_val, int, 0);
module_param(meta_type, int, 0);
module_param(meta_size, int, 0);

MODULE_PARM_DESC(op, "0=pas_supported 1=pas_init 2=pas_shutdown 3=pas_memsetup 4=raw_scm 5=pas_auth_reset 6=info_query");
MODULE_PARM_DESC(pid_val, "PAS peripheral ID");
MODULE_PARM_DESC(svc_val, "SCM service ID (for op=4)");
MODULE_PARM_DESC(cmd_val, "SCM command ID (for op=4)");
MODULE_PARM_DESC(meta_type, "0=zero 1=elf 2=0x41fill 3=random-ish");
MODULE_PARM_DESC(meta_size, "metadata size in bytes");

/* SCM interface */
#define MAX_SCM_ARGS 10
#define MAX_SCM_RETS 3

struct scm_desc {
    u32 arginfo;
    u64 args[MAX_SCM_ARGS];
    u64 ret[MAX_SCM_RETS];
};

#define SCM_VAL   0x0
#define SCM_RO    0x1
#define SCM_ARGS_1(a)     (1 | ((a) << 4))
#define SCM_ARGS_2(a,b)   (2 | ((a) << 4) | ((b) << 6))
#define QCOM_SCM_FNID(svc, cmd) (((svc) << 8) | (cmd))
#define SCM_SIP_FNID(svc, cmd)  (0x42000000UL | QCOM_SCM_FNID(svc, cmd))

extern int scm_call2(u32 fn_id, struct scm_desc *desc);
extern bool scm_is_call_available(u32 svc_id, u32 cmd_id);
extern bool qcom_scm_pas_supported(u32 peripheral);
extern int qcom_scm_pas_init_image(u32 peripheral, const void *metadata, size_t size);
extern int qcom_scm_pas_mem_setup(u32 peripheral, phys_addr_t addr, phys_addr_t size);
extern int qcom_scm_pas_auth_and_reset(u32 peripheral);
extern int qcom_scm_pas_shutdown(u32 peripheral);

static const u8 minimal_elf_hdr[] = {
    0x7f, 'E', 'L', 'F', 0x01, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0xa4, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x20, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

static int __init scm_fuzz_init(void)
{
    int ret;
    void *meta_buf;
    struct scm_desc desc;

    pr_info("scm_fuzz3: op=%d pid=0x%x svc=0x%x cmd=0x%x meta_type=%d meta_size=%d\n",
            op, pid_val, svc_val, cmd_val, meta_type, meta_size);

    switch (op) {
    case 0: /* pas_supported */
        if (pid_val < 0) {
            pr_err("scm_fuzz3: need pid_val\n");
            return -EINVAL;
        }
        pr_info("scm_fuzz3: RESULT pas_supported(0x%x) = %d\n",
                pid_val, qcom_scm_pas_supported(pid_val));
        break;

    case 1: /* pas_init_image */
        if (pid_val < 0) {
            pr_err("scm_fuzz3: need pid_val\n");
            return -EINVAL;
        }
        if (meta_size < 1 || meta_size > 4096) meta_size = 52;
        meta_buf = kzalloc(meta_size, GFP_KERNEL);
        if (!meta_buf) return -ENOMEM;

        switch (meta_type) {
        case 0: /* zero-filled */
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
        ret = qcom_scm_pas_init_image(pid_val, meta_buf, meta_size);
        pr_info("scm_fuzz3: RESULT pas_init_image(0x%x, type=%d, size=%d) = %d\n",
                pid_val, meta_type, meta_size, ret);
        kfree(meta_buf);
        break;

    case 2: /* pas_shutdown */
        if (pid_val < 0) {
            pr_err("scm_fuzz3: need pid_val\n");
            return -EINVAL;
        }
        ret = qcom_scm_pas_shutdown(pid_val);
        pr_info("scm_fuzz3: RESULT pas_shutdown(0x%x) = %d\n", pid_val, ret);
        break;

    case 3: /* pas_mem_setup */
        if (pid_val < 0) {
            pr_err("scm_fuzz3: need pid_val\n");
            return -EINVAL;
        }
        ret = qcom_scm_pas_mem_setup(pid_val, 0, 0);
        pr_info("scm_fuzz3: RESULT pas_mem_setup(0x%x, 0, 0) = %d\n", pid_val, ret);
        break;

    case 4: /* raw scm_call2 */
        if (svc_val < 0 || cmd_val < 0) {
            pr_err("scm_fuzz3: need svc_val and cmd_val\n");
            return -EINVAL;
        }
        memset(&desc, 0, sizeof(desc));
        if (pid_val >= 0) {
            desc.arginfo = SCM_ARGS_1(SCM_VAL);
            desc.args[0] = pid_val;
        }
        ret = scm_call2(SCM_SIP_FNID(svc_val, cmd_val), &desc);
        pr_info("scm_fuzz3: RESULT scm_call2(svc=0x%x,cmd=0x%x,arg0=0x%x) ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                svc_val, cmd_val, pid_val >= 0 ? pid_val : 0, ret,
                desc.ret[0], desc.ret[1], desc.ret[2]);
        break;

    case 5: /* pas_auth_and_reset - DANGEROUS, use with caution */
        if (pid_val < 0) {
            pr_err("scm_fuzz3: need pid_val\n");
            return -EINVAL;
        }
        ret = qcom_scm_pas_auth_and_reset(pid_val);
        pr_info("scm_fuzz3: RESULT pas_auth_and_reset(0x%x) = %d\n", pid_val, ret);
        break;

    case 6: /* info queries - safer exploration */
        if (svc_val < 0 || cmd_val < 0) {
            pr_err("scm_fuzz3: need svc_val and cmd_val\n");
            return -EINVAL;
        }
        if (!scm_is_call_available(svc_val, cmd_val)) {
            pr_info("scm_fuzz3: RESULT call_not_available svc=0x%x cmd=0x%x\n",
                    svc_val, cmd_val);
            break;
        }
        memset(&desc, 0, sizeof(desc));
        desc.arginfo = 0;
        ret = scm_call2(SCM_SIP_FNID(svc_val, cmd_val), &desc);
        pr_info("scm_fuzz3: RESULT info_query(svc=0x%x,cmd=0x%x) ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                svc_val, cmd_val, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
        break;

    default:
        pr_err("scm_fuzz3: invalid op %d\n", op);
        return -EINVAL;
    }

    return 0;
}

static void __exit scm_fuzz_exit(void)
{
    pr_info("scm_fuzz3: unloaded\n");
}

module_init(scm_fuzz_init);
module_exit(scm_fuzz_exit);
