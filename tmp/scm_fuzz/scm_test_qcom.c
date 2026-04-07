/* scm_test_qcom.c - Test qcom_scm_pas API */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

extern int qcom_scm_pas_shutdown(u32 peripheral);
extern int qcom_scm_pas_init_image(u32 peripheral, const void *metadata, size_t size);

static int op = 0;
module_param(op, int, 0);

static int __init scm_test_qcom_init(void)
{
    int ret;
    pr_info("scm_test_qcom: start op=%d\n", op);

    if (op == 0) {
        pr_info("scm_test_qcom: calling qcom_scm_pas_shutdown(9)...\n");
        ret = qcom_scm_pas_shutdown(9);
        pr_info("scm_test_qcom: shutdown ret=%d\n", ret);
    } else if (op == 1) {
        void *buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
        if (!buf) return -ENOMEM;
        pr_info("scm_test_qcom: calling qcom_scm_pas_init_image(9, buf, 4096)...\n");
        ret = qcom_scm_pas_init_image(9, buf, PAGE_SIZE);
        pr_info("scm_test_qcom: init_image ret=%d\n", ret);
        kfree(buf);
    }

    return 0;
}

static void __exit scm_test_qcom_exit(void)
{
    pr_info("scm_test_qcom: unloaded\n");
}

module_init(scm_test_qcom_init);
module_exit(scm_test_qcom_exit);
