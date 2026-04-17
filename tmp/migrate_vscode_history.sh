#!/bin/bash
# migrate_vscode_history.sh
# 将本地 workspace storage (历史对话/memory) 迁移到 VS Code Remote SSH 新建的 workspace 文件夹
#
# 使用方法:
#   1. 用 VS Code Remote SSH 打开 c1 上的 /home/hj/pinganhuijia (哪怕只是停留1秒后关闭)
#   2. 运行本脚本: bash migrate_vscode_history.sh

set -e

STORAGE_ROOT="$HOME/Library/Application Support/Code/User/workspaceStorage"
OLD_HASH="0c34dc7011788c454cbc0939710315f7"
OLD_DIR="$STORAGE_ROOT/$OLD_HASH"

echo "=== VS Code Workspace History 迁移工具 ==="
echo ""

# 检查旧目录
if [ ! -d "$OLD_DIR" ]; then
    echo "ERROR: 找不到旧的工作区存储: $OLD_DIR"
    exit 1
fi

# 找到最新创建的 workspaceStorage 文件夹（排除旧的）
echo "正在寻找新的 Remote SSH workspace 文件夹..."
NEW_HASH=$(ls -1t "$STORAGE_ROOT" | grep -v "$OLD_HASH" | head -1)

if [ -z "$NEW_HASH" ]; then
    echo "ERROR: 没有找到新建的 workspace 文件夹"
    echo "请先用 VS Code Remote SSH 打开 c1 上的 /home/hj/pinganhuijia，然后再运行此脚本"
    exit 1
fi

NEW_DIR="$STORAGE_ROOT/$NEW_HASH"

# 验证是否是 Remote SSH workspace
WORKSPACE_JSON="$NEW_DIR/workspace.json"
if [ ! -f "$WORKSPACE_JSON" ]; then
    echo "ERROR: $NEW_DIR/workspace.json 不存在，可能不是正确的文件夹"
    exit 1
fi

echo "找到新文件夹: $NEW_HASH"
echo "workspace.json 内容:"
cat "$WORKSPACE_JSON"
echo ""

# 确认是否是正确的 remote SSH workspace
if ! grep -q "ssh-remote" "$WORKSPACE_JSON" && ! grep -q "c1" "$WORKSPACE_JSON"; then
    echo "WARNING: workspace.json 中没有 ssh-remote 或 c1 字样，请确认这是正确的文件夹"
    echo "内容: $(cat "$WORKSPACE_JSON")"
    read -p "是否继续? (y/N): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 1
fi

echo ""
echo "将从: $OLD_HASH"
echo "迁移到: $NEW_HASH"
echo ""
read -p "确认迁移? (y/N): " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "已取消"; exit 0; }

# 迁移 chatSessions (历史对话)
echo ""
echo "[1/4] 迁移 chatSessions (历史对话)..."
if [ -d "$OLD_DIR/chatSessions" ]; then
    mkdir -p "$NEW_DIR/chatSessions"
    cp -v "$OLD_DIR/chatSessions/"*.jsonl "$NEW_DIR/chatSessions/" 2>/dev/null || echo "  (无 .jsonl 文件)"
    echo "  chatSessions 迁移完成"
else
    echo "  chatSessions 不存在，跳过"
fi

# 迁移 chatEditingSessions
echo ""
echo "[2/4] 迁移 chatEditingSessions..."
if [ -d "$OLD_DIR/chatEditingSessions" ]; then
    mkdir -p "$NEW_DIR/chatEditingSessions"
    cp -rv "$OLD_DIR/chatEditingSessions/"* "$NEW_DIR/chatEditingSessions/" 2>/dev/null || echo "  (空目录)"
    echo "  chatEditingSessions 迁移完成"
else
    echo "  chatEditingSessions 不存在，跳过"
fi

# 迁移 GitHub Copilot memory (session memory + repo memory)
echo ""
echo "[3/4] 迁移 Copilot memory..."
if [ -d "$OLD_DIR/GitHub.copilot-chat" ]; then
    mkdir -p "$NEW_DIR/GitHub.copilot-chat"
    cp -rv "$OLD_DIR/GitHub.copilot-chat/"* "$NEW_DIR/GitHub.copilot-chat/" 2>/dev/null || echo "  (空目录)"
    echo "  Copilot memory 迁移完成"
else
    echo "  GitHub.copilot-chat 不存在，跳过"
fi

# 迁移 state.vscdb (编辑器状态、打开的文件、断点等)
echo ""
echo "[4/4] 迁移 state.vscdb (编辑器状态)..."
if [ -f "$OLD_DIR/state.vscdb" ]; then
    cp -v "$OLD_DIR/state.vscdb" "$NEW_DIR/state.vscdb"
    echo "  state.vscdb 迁移完成"
else
    echo "  state.vscdb 不存在，跳过"
fi

echo ""
echo "=== 迁移完成！ ==="
echo "重新打开 VS Code 并通过 Remote SSH 连接 c1，历史对话和 memory 应已恢复。"
echo ""
echo "注意: User memory (/memories/) 存储在 VS Code 全局配置中，无需迁移，所有 workspace 共享。"
