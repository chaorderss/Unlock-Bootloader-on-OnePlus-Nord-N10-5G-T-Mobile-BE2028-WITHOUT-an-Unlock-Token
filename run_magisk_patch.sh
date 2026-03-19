#!/bin/bash
set -e
mkdir -p magisk_patch
cp magisk_extracted/assets/boot_patch.sh magisk_patch/
cp magisk_extracted/assets/util_functions.sh magisk_patch/
cp magisk_extracted/assets/stub.apk magisk_patch/
cp magisk_extracted/lib/x86_64/libmagiskboot.so magisk_patch/magiskboot
cp magisk_extracted/lib/x86_64/libmagiskinit.so magisk_patch/magiskinit
cp magisk_extracted/lib/x86_64/libmagisk.so magisk_patch/magisk
cp magisk_extracted/lib/x86_64/libinit-ld.so magisk_patch/init-ld
chmod +x magisk_patch/magiskboot magisk_patch/magiskinit magisk_patch/magisk magisk_patch/init-ld
cp edl_backup/boot_b.img magisk_patch/boot.img
cd magisk_patch
export KEEPVERITY=false
export KEEPFORCEENCRYPT=false
export PATCHVBMETAFLAG=false
export RECOVERYMODE=false
export LEGACYSAR=false
bash boot_patch.sh boot.img
echo "[DONE] Output:"
ls -lh new-boot.img
