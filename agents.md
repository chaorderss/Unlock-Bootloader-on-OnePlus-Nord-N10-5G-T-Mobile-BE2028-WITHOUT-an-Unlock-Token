修改abl行不能,因为xbl会校验
修改boot.img也不行,同样abl会校验
在项目路径下的tmp文件创建临时文件
总是先计划,再执行,最后测试

oneplus nord N10 5G OEM Unlock 处理流程（0x48810）
fastboot oem unlock
  ├─ TST W21, #0xFF
  │   └─ == 0 → 直接跳到 carrier check
  │   └─ != 0 → 检查 IsAllowUnlock [0x1C0010]
  │              ├─ != 0 → 跳到 carrier check
  │              └─ == 0 → BL 0x3A258 (ops override)
  │                         └─ 失败 → error
  ├─ BL 0x3BB48 (CARRIER CHECK)
  │   ├─ 型号不匹配 T-Mobile → return 0 (通过)
  │   └─ 型号匹配 → 检查 [0x1BF518]
  │       ├─ == 1 → return 0 (通过)
  │       └─ == 0 → "Please flash unlock token first"
  ├─ 通过 → 跳到 0x48944 (执行解锁)
  └─ 失败 → BL 0x1DA4 (security level = 2)
           ├─ == 3 → 直接 SetDeviceUnlocked
           └─ != 3 → C0DD69AC 协议 token 验证

关键攻击面 — 3个世界可写的高危设备
设备节点	权限	用途
/dev/kgsl-3d0	rw-rw-rw-	Adreno GPU 驱动
/dev/qseecom	rw-rw-rw-	TrustZone 安全环境接口
/dev/diag	rw-rw-rw-	Qualcomm 诊断接口

推荐漏洞 (按优先级)
1. ★★★ CVE-2021-1905 / CVE-2021-1906 (Adreno KGSL)
GPU 驱动 UAF / 不当内存处理
补丁日 2021-05/06，设备补丁 2021-02 → 确定易受攻击
/dev/kgsl-3d0 世界可写，无需特殊权限
无 CFI 保护 → 内核代码执行相对容易
2. ★★★ CVE-2021-1048 + CVE-2021-0920 (epoll + unix GC)
两个内核 UAF，补丁日 2021-11/12 → 确定易受攻击
实际在野利用过 (ITW)，有公开分析
epoll / AF_UNIX 从 shell 即可触发，无需任何特殊权限
内核 4.19.81 无 CFI，exploit 稳定性好
3. ★★ /dev/qseecom (TrustZone)
世界可写！可直接与 TrustZone 通信
如果能访问 keymaster applet → 可能操作 RPMB 中的 devinfo
历史上多个 QSEE CVE 允许任意 trustlet 执行

adb已经有root权限