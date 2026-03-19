# OnePlus Nord N10 5G T-Mobile 解锁 Bootloader 全过程

> 设备：OnePlus Nord N10 5G (BE2028, T-Mobile, model 20888)
> SoC 序列号：0x75655d5b
> 最终结果：`fastboot getvar unlocked` → **yes**，`ro.boot.verifiedbootstate` = **orange**

---

## 目录

1. [背景与前提条件](#1-背景与前提条件)
2. [整体思路](#2-整体思路)
3. [阶段一：获取 Root 权限与初步信息收集](#3-阶段一获取-root-权限与初步信息收集)
4. [阶段二：逆向 ABL 解锁逻辑](#4-阶段二逆向-abl-解锁逻辑)
5. [阶段三：理解 param 分区结构](#5-阶段三理解-param-分区结构)
6. [阶段四：找到 SID 0x13C 加密密钥](#6-阶段四找到-sid-0x13c-加密密钥)
7. [阶段五：找到关键常量（proc 魔数 + SWID 哈希）](#7-阶段五找到关键常量proc-魔数--swid-哈希)
8. [阶段六：第一次写入尝试（失败）](#8-阶段六第一次写入尝试失败)
9. [阶段七：排查失败原因——块格式错误](#9-阶段七排查失败原因块格式错误)
10. [阶段八：最终写入与解锁成功](#10-阶段八最终写入与解锁成功)
11. [关键数据一览](#11-关键数据一览)
12. [完整解锁脚本 write_swid3.py](#12-完整解锁脚本-write_swid3py)

---

## 1. 背景与前提条件

OnePlus Nord N10 5G 的 T-Mobile 版（BE2028，model ID 20888）在 `fastboot oem unlock` 时会报错：

```
FAILED (remote: 'Please flash unlock token first.')
```

这是因为 ABL（Android Bootloader）内置了运营商锁定逻辑：检测到机型为 T-Mobile 版时，要求先烧录解锁 token 才能解锁。Token 需要联系官方申请，已被 OnePlus/T-Mobile 封闭。

**前提条件：**

- 设备已开启 USB 调试
- `adb shell` 可 root（`ro.debuggable=1`，执行 `adb root` 即可）
- SELinux 处于 Permissive 模式
- macOS 开发机，安装了 `adb`、`fastboot`、`python3`、`pycryptodome`、`capstone`

---

## 2. 整体思路

```
fastboot oem unlock
  ├─ 检查 IsAllowUnlock
  ├─ BL CARRIER_CHECK
  │   ├─ 型号不是 T-Mobile → 直接通过
  │   └─ 型号是 T-Mobile  → 检查 RPMB 中的 SoftwareProjectID
  │       ├─ SWID != 20888 的 CM Hash → 通过（当成非 TMO 设备）
  │       └─ SWID == 20888 的 CM Hash → "Please flash unlock token first"
  └─ 通过 → 执行解锁
```

**突破点：** RPMB 中的 `SoftwareProjectID` 来自 `param` 分区的 SID 0x13C。
只要让 ABL 在下次启动时把 **model 20886（非 T-Mobile）** 的 CM 哈希写入 RPMB，之后的 `fastboot oem unlock` 就会跳过 carrier check。

ABL 内置了一个"备份到 RPMB"的触发机制：当它读取到 `sw_proj_id_proc == 0xDC9EF893` 时，会把 param 中的 `SoftwareProjectID` 备份到 RPMB 并清除 proc 标志。

所以完整攻击链是：

```
修改 param 分区 SID 0x13C
  → SWID = 0xB8BD9E39 (model 20886 的 CM hash)
  → proc = 0xDC9EF893 (触发 ABL "备份到 RPMB" 的魔数)
  → 重启
  → ABL 把 SWID 写入 RPMB
  → fastboot oem unlock → 通过
```

---

## 3. 阶段一：获取 Root 权限与初步信息收集

```bash
adb root
adb shell id        # uid=0(root)
adb shell getenforce  # Permissive

# 查看型号和补丁级别
adb shell getprop ro.product.model          # BE2028
adb shell getprop ro.build.version.security_patch  # 2021-02-01
adb shell getprop ro.product.name           # OnePlusNord N10 5G
```

备份关键分区：

```bash
adb shell dd if=/dev/block/sda6 2>/dev/null > edl_backup/param_original.bin  # param
adb shell dd if=/dev/block/sde8 2>/dev/null > /tmp/abl_a.bin                 # ABL
```

查看设备节点权限（发现三个高危世界可写设备）：

```
/dev/kgsl-3d0   rw-rw-rw-   Adreno GPU 驱动
/dev/qseecom    rw-rw-rw-   TrustZone 接口
/dev/diag       rw-rw-rw-   Qualcomm 诊断接口
```

---

## 4. 阶段二：逆向 ABL 解锁逻辑

### 4.1 提取 ABL 二进制

ABL（`abl_a` 分区）是压缩存储在 FV（Firmware Volume）容器中的 AARCH64 PE 文件。

```bash
# abl_a 分区 = 8MB raw
adb shell dd if=/dev/block/sde8 2>/dev/null > /tmp/abl_a.bin

# 用 parse_fv2.py 解析 FV 结构，找到 LZMA 压缩的 PE blob
python3 tmp/parse_fv2.py
# → 解压得到 /tmp/abl_dec.bin (1,872,072 bytes, AARCH64 PE)
```

ABL PE 结构：

| Section | RVA | Size |
|---------|-----|------|
| .text   | 0x1000 | 0x69000（同时包含代码和字符串） |
| .data   | 0x6A000 | 0x15E000 |
| .reloc  | 0x1C8000 | 0x1000 |

MZ header 在解压数据偏移 0xB8，imageBase = 0。

### 4.2 定位关键函数

安装 capstone 反汇编：

```bash
pip3 install capstone pycryptodome
```

用 `grep_search` 在二进制中找 ABL 日志字符串：

```
"sw_proj_id_proc:"       → RVA 0x4C0E6
"start backup spi"       → RVA 0x4C12E
"check and restore"      → RVA 0x4C163
"Software ID equals"     → RVA 0x4C17B
```

通过 ADRP+ADD 交叉引用（搜索 20 条指令窗口内的引用），定位到函数 `init_param_sw_prj_id`，核心代码在 RVA **0x35900–0x36000** 附近。

### 4.3 关键反汇编片段

**proc 魔数比较（RVA 0x35C88）：**

```asm
mov  w8, #0xf893
movk w8, #0xdc9e, lsl #16     ; w8 = 0xDC9EF893
cmp  w20, w8                   ; w20 = ReadParam(0x13C, 0x88) = proc
b.ne #0x35d24                  ; ≠ → "check and restore from RPMB"
                               ; = → "start backup spi to rpmb"
```

**ReadParam 调用（确认偏移映射）：**

```asm
; 读 sw_proj_id_proc
bl   #0x32AB0   ; ReadParam
; args: SID=0x13C, offset=0x88, &buf, size=4

; 读 SoftwareProjectID
bl   #0x32AB0   ; ReadParam
; args: SID=0x13C, offset=0x84, &buf, size=4
```

**控制流：**

```
proc == 0xDC9EF893
  → StoreToRPMB(SWID)          ← 我们想走这条路
  → 清除 proc 标志

proc != 0xDC9EF893
  → ReadFromRPMB(SWID)
  → 比较 param 中的 SWID 与 RPMB 中是否一致
  → 不一致则用 RPMB 覆盖 param ("Software ID equals!" 说明一致)
```

---

## 5. 阶段三：理解 param 分区结构

param 分区大小 1MB（0x100000），按 SID（Secure ID）编号，每个 SID 占 0x1000 字节，偏移 = `SID × 0x400`。

**SID 块格式（0x1000 字节）：**

```
block[0x000:0x004]  magic = 0xA0AD646A (uint32 LE)  ← 必须正确！
block[0x004]        hv    (hw_version)
block[0x005]        cv    (crypto_version)
block[0x010]        updatecounter
block[0x080:0x090]  outer_md5 = MD5(encrypted_data)  ← 必须在 0x80！
block[0x400:0xC00+0x400]  AES-CBC 加密数据（0xC00 字节）
```

**解密后的数据结构（0xC00 字节）：**

```
dec[0x000:0x010]   inner_md5 = MD5(itemdata)
dec[0x010:0x080]   全零填充（0x70 字节）
dec[0x080:0xC00]   itemdata（0xB80 字节）
```

**SID 0x13C itemdata 字段（ReadParam offset → itemdata 偏移映射）：**

| ReadParam offset | itemdata 偏移 | 字段名 | 本机原始值 |
|-----------------|--------------|--------|-----------|
| 0x80 | itemdata[0x00] | supported_flag | 1 |
| 0x84 | itemdata[0x04] | SoftwareProjectID (SWID) | 0x142F1BD7 |
| 0x88 | itemdata[0x08] | sw_proj_id_proc | 0xEFF7A27F |

---

## 6. 阶段四：找到 SID 0x13C 加密密钥

edl 工具（`oneplus_param.py`）的密钥派生逻辑：

```python
# cv == 1：静态密钥
STATIC_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')  # "000OnePlus818000"

# cv == 2：从 SoC 序列号派生
serial = 0x75655d5b  # 从 ABL 日志 / ADB 获取
seed = bytes.fromhex("a9264fbf8a" + "%08x" % serial + "6b4487ea")[:0x1A]
DERIVED_KEY = hashlib.sha256(seed).digest()[:16]
```

实测：ABL 在 RPMB 恢复之后，会用**静态密钥**重新加密 SID 0x13C（cv 从 2 变成 74）。因此我们写入时也必须使用**静态密钥**。

```python
# 验证解密是否成功
dec = AES.new(STATIC_KEY, AES.MODE_CBC, IV).decrypt(enc)
assert hashlib.md5(dec[-0xB80:]).digest() == dec[:16]  # inner MD5 check
```

---

## 7. 阶段五：找到关键常量（proc 魔数 + SWID 哈希）

### proc 魔数

从反汇编（RVA 0x35C88）直接读出：

```
proc_magic = 0xDC9EF893
```

### model 20886 的 CM 哈希

从 edl 工具源码（`oneplus.py` line 87）读出：

```python
"20886": dict(cm="b8bd9e39")
# SWID_20886 = 0xB8BD9E39
```

---

## 8. 阶段六：第一次写入尝试（失败）

`write_swid2.py` 有两个严重 bug，导致 ABL 拒绝读取 param 块并从 RPMB 恢复原始值：

### Bug 1：magic 缺失

```python
# ❌ 错误：完全没有写入 magic
block[0] = hv
block[1] = cv

# ✅ 正确
struct.pack_into('<I', block, 0, 0xA0AD646A)
block[4] = hv
block[5] = cv
```

ABL 的 `decryptsid` 函数第一步就检查 `if magic != 0xA0AD646A: return None`，magic 缺失直接导致整个解密返回 NULL。

### Bug 2：outer MD5 位置错误

```python
# ❌ 错误：MD5 放在 block[4:20]
outer_md5 = hashlib.md5(enc).digest()
block[4:20] = outer_md5

# ✅ 正确：MD5 在 block[0x80:0x90]
block[0x80:0x90] = hashlib.md5(enc).digest()
```

### 失败表现

ABL 日志中始终显示：

```
init_param_sw_prj_id[00000893] sw_proj_id_proc: 0
init_param_sw_prj_id[000008B1] Process: check and restore software ID from RPMB
init_param_sw_prj_id[000008C6] Software ID equals!
GetParamSoftwareProjectID 0
androidboot.swprojid=20888
```

虽然写入被 readback 验证通过，但 ABL 读取时因 magic 错误拒绝了整个块，从 RPMB 恢复了原始值。

---

## 9. 阶段七：排查失败原因——块格式错误

### 诊断过程

重启后用 `check_param2.py` 重新读取 param：

```
SID 0x13C: magic OK, outer MD5 MATCH, static key → Inner MD5 MATCH
  SWID = 0x142F1BD7  ← ABL 从 RPMB 恢复的原始值
  proc = 0xEFF7A27F  ← ABL 从 RPMB 恢复的原始值
  hv=0, cv=74        ← ABL 重新加密时用的参数
```

发现 ABL "恢复"后使用的是 cv=74、静态密钥，与我们用 derived key + cv=2 写入的完全不同。

### 交叉比对 edl 工具源码

查阅 `oneplus_param.py` 的 `decryptsid` 函数，逐行对比块格式，发现上述两处 bug。

---

## 10. 阶段八：最终写入与解锁成功

用修复后的 `write_swid3.py`：

```bash
python3 tmp/write_swid3.py
```

输出：

```
[*] Reading param partition from device...
    Size: 1048576 bytes OK

[*] SID 0x13C (primary): hv=0, cv=74, uc=250
    Current: supported=1, SWID=0x142F1BD7, proc=0xEFF7A27F
    New: SWID=0xB8BD9E39, proc=0xDC9EF893 [verified]

[*] SID 0x33C (backup): hv=0, cv=74, uc=250
    Current: supported=1, SWID=0x142F1BD7, proc=0xEFF7A27F
    New: SWID=0xB8BD9E39, proc=0xDC9EF893 [verified]

[*] Writing modified param to device...
    dd exit code: 0
[*] Verifying write by readback...
    SID 0x13C: SWID=0xB8BD9E39 (OK), proc=0xDC9EF893 (OK)
    SID 0x33C: SWID=0xB8BD9E39 (OK), proc=0xDC9EF893 (OK)

[+] Done! Ready to reboot.
```

重启到 bootloader：

```bash
adb reboot bootloader
sleep 15
fastboot oem unlock
# → OKAY [0.024s]
```

验证：

```bash
fastboot getvar unlocked
# unlocked: yes

# 重启进入系统后
adb shell getprop ro.boot.verifiedbootstate
# orange
adb shell getprop ro.boot.flash.locked
# 0
```

**Bootloader 解锁成功。**

---

## 11. 关键数据一览

| 名称 | 值 |
|-----|---|
| 设备型号 | BE2028，model ID 20888（T-Mobile） |
| SoC 序列号 | 0x75655d5b |
| 目标 model | 20886（非 T-Mobile） |
| 静态 AES 密钥 | `3030304F6E65506C7573383138303030`（"000OnePlus818000"） |
| AES IV | `562E17996D093D28DDB3BA695A2E6F58` |
| proc 魔数 | `0xDC9EF893`（触发"备份到 RPMB"的 ABL 内部常量） |
| model 20886 CM 哈希（SWID） | `0xB8BD9E39` |
| param 分区块设备 | `/dev/block/sda6` |
| ABL 分区块设备 | `/dev/block/sde8` |
| SID 0x13C 主分区偏移 | `0x13C × 0x400 = 0x4F000` |
| SID 0x33C 备份偏移 | `0x33C × 0x400 = 0xCF000` |

---

## 12. 完整解锁脚本 write_swid3.py

脚本位于 `tmp/write_swid3.py`，核心逻辑如下：

```python
MAGIC = 0xA0AD646A
IV    = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
STATIC_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')

SWID_20886 = 0xB8BD9E39   # model 20886 CM hash (非 T-Mobile)
PROC_MAGIC = 0xDC9EF893   # ABL "backup to RPMB" 触发魔数

def encrypt_sid(dec_data, hv, cv, updatecounter, key):
    block = bytearray(0x1000)

    # 1. 写入 magic + hv + cv
    struct.pack_into('<I', block, 0, MAGIC)   # ← 关键，之前漏掉了
    block[4] = hv
    block[5] = cv
    block[0x10] = (updatecounter + 1) & 0xFF

    # 2. 加密
    enc = AES.new(key, AES.MODE_CBC, IV).encrypt(bytes(dec_data))

    # 3. outer MD5 在 0x80（之前错误地放在 0x04）
    block[0x80:0x90] = hashlib.md5(enc).digest()  # ← 关键
    block[0x400:0x400 + 0xC00] = enc
    return bytes(block)

# 对 SID 0x13C 和 0x33C 都执行：
# 1. 解密（用静态密钥）
# 2. 修改 itemdata[0x04] = SWID_20886, itemdata[0x08] = PROC_MAGIC
# 3. 重算 inner MD5
# 4. 重新加密
# 5. 写回 /dev/block/sda6
```

**运行一次即可，之后直接 `fastboot oem unlock`。**

---

*文档生成日期：2026-03-20*
