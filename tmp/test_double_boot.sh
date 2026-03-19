#!/bin/bash
# 双重启动测试：验证 param 分区的 reset_devinfo 标志是否在第一次启动后被清除
#
# 理论：
# 第1次启动: init_defaults 运行（内存设默认值），但 set_param 清除 reset_devinfo 标志
# 第2次启动: reset_devinfo=0 → 不调用 init_defaults → 读取我们的 devinfo → unlocked=true
#
# 用法: 先通过 EDL 刷入解锁的 devinfo, 然后在 fastboot 下运行此脚本

set -e
echo "====================================================="
echo "双重启动测试 - 验证 param 分区标志清除"
echo "====================================================="
echo ""

# Step 1: 检查当前 fastboot 状态
echo "=== 步骤 1: 检查当前（第1次启动）状态 ==="
echo "运行 fastboot oem device-info..."
fastboot oem device-info 2>&1 || true
echo ""

echo "=== 步骤 2: 重启到 fastboot (第2次启动) ==="
echo "执行 fastboot reboot bootloader..."
fastboot reboot bootloader
echo "等待设备重新进入 fastboot..."
sleep 15

# Step 3: 再次检查
echo ""
echo "=== 步骤 3: 检查第2次启动状态 ==="
echo "运行 fastboot oem device-info..."
fastboot oem device-info 2>&1 || true
echo ""

echo "====================================================="
echo "结果分析:"
echo "  - 如果第2次启动显示 'Device unlocked: true' → 成功！"
echo "  - 如果仍然显示 'Device unlocked: false' → param 写入也失败了"
echo "====================================================="
