#!/usr/bin/env python3
"""Analyze hwcomposer binary to find set_maximized for patching"""
import struct, sys

with open("/Users/xmxx/pinganhuijia/tmp/hwc.so", "rb") as f:
    data = f.read()

# Find key strings
for s in [b"set_maximized\x00", b"set_fullscreen\x00", b"xdg_toplevel\x00"]:
    idx = data.find(s)
    print(f"{s!r} at offset: 0x{idx:x}" if idx >= 0 else f"{s!r} NOT FOUND")

# The Waydroid hwcomposer calls xdg_toplevel_set_maximized() which is an inline:
# wl_proxy_marshal_flags(proxy, XDG_TOPLEVEL_SET_MAXIMIZED, NULL, version, 0)
# XDG_TOPLEVEL_SET_MAXIMIZED = 9
# In AArch64, opcode 9 is loaded with: mov w1, #9 = 0x52800121
# or mov w2, #9 depending on calling convention
# wl_proxy_marshal_flags(proxy=x0, opcode=w1, interface=x2, version=w3, flags=w4, ...)

# Search for "mov w1, #9" (0x52800121) near references to xdg_toplevel
import struct as st

# AArch64: mov w1, #9 = 0x52800121
mov_w1_9 = bytes([0x21, 0x01, 0x80, 0x52])
# AArch64: mov w1, #11 = 0x52800161 (set_fullscreen)
mov_w1_11 = bytes([0x61, 0x01, 0x80, 0x52])

print(f"\nmov w1, #9 occurrences:")
idx = 0
while True:
    idx = data.find(mov_w1_9, idx)
    if idx < 0:
        break
    # Show surrounding instructions
    ctx = data[idx-16:idx+20]
    print(f"  0x{idx:x}: {ctx.hex()}")
    idx += 4

print(f"\nmov w1, #11 occurrences:")
idx = 0
while True:
    idx = data.find(mov_w1_11, idx)
    if idx < 0:
        break
    ctx = data[idx-16:idx+20]
    print(f"  0x{idx:x}: {ctx.hex()}")
    idx += 4

sys.exit(0)

def send(data):
    s.sendall(data)

def recv():
    try:
        return s.recv(4096)
    except socket.timeout:
        return b''

# get_registry + sync
send(struct.pack("<IHHI", 1, 1, 12, 2) + struct.pack("<IHHI", 1, 0, 12, 3))

data = recv()
print("globals: %d bytes" % len(data))

# Parse globals to find xdg_wm_base and wl_compositor IDs
offset = 0
xdg_wm_base_name = None
wl_compositor_name = None
wl_shm_name = None

while offset < len(data):
    obj_id = struct.unpack_from("<I", data, offset)[0]
    opcode = struct.unpack_from("<H", data, offset+4)[0]
    size = struct.unpack_from("<H", data, offset+6)[0]
    if obj_id == 2 and opcode == 0:  # wl_registry.global
        name = struct.unpack_from("<I", data, offset+8)[0]
        iface_len = struct.unpack_from("<I", data, offset+12)[0]
        iface = data[offset+16:offset+16+iface_len-1].decode()
        version = struct.unpack_from("<I", data, offset+16+((iface_len+3)&~3))[0]
        print(f"  global {name}: {iface} v{version}")
        if iface == "xdg_wm_base":
            xdg_wm_base_name = name
        if iface == "wl_compositor":
            wl_compositor_name = name
        if iface == "wl_shm":
            wl_shm_name = name
    offset += size

if xdg_wm_base_name is None:
    print("No xdg_wm_base found!")
    sys.exit(1)

# Bind xdg_wm_base (id=4)
iface = b"xdg_wm_base\x00"
iface_padded = iface + b"\x00" * ((4 - len(iface)%4)%4)
bind_msg = struct.pack("<IHHI", 2, 0, 8+4+4+len(iface_padded)+4, xdg_wm_base_name)
bind_msg += struct.pack("<I", len(iface)) + iface_padded + struct.pack("<II", 1, 4)
send(bind_msg)

# Bind wl_compositor (id=5)
iface2 = b"wl_compositor\x00"
iface2_padded = iface2 + b"\x00" * ((4 - len(iface2)%4)%4)
bind_msg2 = struct.pack("<IHHI", 2, 0, 8+4+4+len(iface2_padded)+4, wl_compositor_name)
bind_msg2 += struct.pack("<I", len(iface2)) + iface2_padded + struct.pack("<II", 4, 5)
send(bind_msg2)

# wl_compositor.create_surface -> id=6
send(struct.pack("<IHHI", 5, 0, 12, 6))

# xdg_wm_base.get_xdg_surface(id=7, surface=6)
send(struct.pack("<IHHII", 4, 1, 16, 7, 6))

# xdg_surface.get_toplevel(id=8)
send(struct.pack("<IHHI", 7, 0, 12, 8))

# xdg_toplevel.set_maximized() opcode=9
send(struct.pack("<IHH", 8, 9, 8))

# sync to flush
send(struct.pack("<IHHI", 1, 0, 12, 9))

data2 = recv()
print("after set_maximized: %d bytes response" % len(data2))
if data2:
    print("response hex:", data2[:64].hex())
else:
    print("NO response (connection might be broken)")

# Try another sync to see if alive
try:
    send(struct.pack("<IHHI", 1, 0, 12, 10))
    data3 = recv()
    print("still alive: %d bytes" % len(data3))
except:
    print("connection dead after set_maximized")

s.close()
