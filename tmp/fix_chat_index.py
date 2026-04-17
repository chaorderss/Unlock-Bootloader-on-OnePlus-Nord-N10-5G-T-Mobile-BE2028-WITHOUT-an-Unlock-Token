#!/usr/bin/env python3
# fix_chat_index.py
# 将旧工作区的 chat session 索引合并到新的 Remote SSH 工作区
# 运行前必须先完全退出 VS Code (Cmd+Q)

import sqlite3
import json
import shutil
import os
from datetime import datetime

STORAGE_ROOT = os.path.expanduser("~/Library/Application Support/Code/User/workspaceStorage")
OLD_HASH = "0c34dc7011788c454cbc0939710315f7"
NEW_HASH = "fdffe6a7b05923a843650ea4a8feac2c"

old_db = os.path.join(STORAGE_ROOT, OLD_HASH, "state.vscdb")
new_db = os.path.join(STORAGE_ROOT, NEW_HASH, "state.vscdb")

print(f"旧工作区: {OLD_HASH}")
print(f"新工作区: {NEW_HASH}")
print()

# 备份新的 state.vscdb
backup = new_db + f".bak_{datetime.now().strftime('%H%M%S')}"
shutil.copy2(new_db, backup)
print(f"已备份新 state.vscdb 到: {os.path.basename(backup)}")

# 读取旧工作区的 chat session 索引
conn_old = sqlite3.connect(old_db)
row = conn_old.execute("SELECT value FROM ItemTable WHERE key='chat.ChatSessionStore.index'").fetchone()
conn_old.close()

if not row:
    print("ERROR: 旧工作区没有 chat.ChatSessionStore.index")
    exit(1)

old_index = json.loads(row[0])
print(f"\n旧工作区中有 {len(old_index.get('entries', {}))} 个 sessions:")
for sid, entry in old_index.get("entries", {}).items():
    print(f"  [{sid[:8]}] {entry.get('title', '(no title)')[:60]}")

# 读取新工作区的 chat session 索引
conn_new = sqlite3.connect(new_db)
row2 = conn_new.execute("SELECT value FROM ItemTable WHERE key='chat.ChatSessionStore.index'").fetchone()
if row2:
    new_index = json.loads(row2[0])
else:
    new_index = {"version": 1, "entries": {}}

print(f"\n新工作区中有 {len(new_index.get('entries', {}))} 个 sessions (将被保留)")
for sid, entry in new_index.get("entries", {}).items():
    print(f"  [{sid[:8]}] {entry.get('title', '(no title)')[:60]}")

# 合并：旧的 entries 优先（旧的更重要，但不覆盖新工作区中同 ID 的）
merged_entries = {}
merged_entries.update(old_index.get("entries", {}))   # 先放旧的
merged_entries.update(new_index.get("entries", {}))   # 新的覆盖（保留新会话）

merged = {"version": 1, "entries": merged_entries}
merged_json = json.dumps(merged, ensure_ascii=False, separators=(',', ':'))

print(f"\n合并后共 {len(merged_entries)} 个 sessions")

# 写入新数据库
if row2:
    conn_new.execute("UPDATE ItemTable SET value=? WHERE key='chat.ChatSessionStore.index'", (merged_json,))
else:
    conn_new.execute("INSERT INTO ItemTable (key, value) VALUES ('chat.ChatSessionStore.index', ?)", (merged_json,))
conn_new.commit()
conn_new.close()

print("\n=== 合并完成！===")
print("现在可以重新打开 VS Code 并通过 Remote SSH 连接 c1。")
print("所有历史对话应该出现在 Copilot Chat 的历史记录中。")
