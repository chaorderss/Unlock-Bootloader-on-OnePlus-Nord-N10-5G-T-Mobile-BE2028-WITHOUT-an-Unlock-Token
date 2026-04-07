#!/usr/bin/env python3
"""Fix waydroid lxc.py for OnePlus Nord N10 5G"""
import os

lxc_py = '/usr/lib/waydroid/tools/helpers/lxc.py'
with open(lxc_py, 'r') as f:
    content = f.read()

# Fix 1: /dev/video* glob catches /dev/video directory (which is a dir, not a device)
# Add os.path.isdir check to skip directories
old_video = '    for n in glob.glob("/dev/video*"):\n        make_entry(n)'
new_video = '    for n in glob.glob("/dev/video*"):\n        if not os.path.isdir(n):\n            make_entry(n)'
assert old_video in content, "Fix 1: old_video pattern not found"
content = content.replace(old_video, new_video)

# Fix 2: /sys/class/leds/vibrator is a symlink - LXC refuses to bind mount symlinks
# Resolve the symlink to the real path before mounting
old_vibrator = '    make_entry("/sys/class/leds/vibrator",\n               options="bind,create=dir,optional 0 0")'
new_vibrator = '    vibrator_path = "/sys/class/leds/vibrator"\n    if os.path.islink(vibrator_path):\n        vibrator_path = os.path.realpath(vibrator_path)\n    make_entry(vibrator_path, "sys/class/leds/vibrator",\n               options="bind,create=dir,optional 0 0")'
assert old_vibrator in content, "Fix 2: old_vibrator pattern not found"
content = content.replace(old_vibrator, new_vibrator)

with open(lxc_py, 'w') as f:
    f.write(content)

# Remove cached bytecode
import glob
for pyc in glob.glob('/usr/lib/waydroid/tools/helpers/__pycache__/lxc*.pyc'):
    os.remove(pyc)
    print(f"Removed: {pyc}")

print("All patches applied successfully!")
