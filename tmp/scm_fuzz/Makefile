obj-m := scm_fuzz4.o scm_fuzz5.o scm_test_init.o scm_test_qcom.o scm_dump.o wlan_probe.o fuse_reader.o msa_hijack.o scm_pil_fuzz.o
KDIR ?= /lib/modules/$(shell uname -r)/build

# Cross-compile for aarch64 (Android/Ubuntu Touch kernel)
ARCH := arm64
CROSS_COMPILE := aarch64-linux-gnu-

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) clean
