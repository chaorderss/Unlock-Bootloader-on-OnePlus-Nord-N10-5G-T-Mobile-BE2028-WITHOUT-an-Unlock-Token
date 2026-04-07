#!/usr/bin/env python3
"""Query Wayland registry globals from the compositor."""
import ctypes
import ctypes.util
import os
import sys

# Load libwayland-client
wl = ctypes.CDLL("libwayland-client.so.0")

# Type definitions
wl_display_p = ctypes.c_void_p
wl_registry_p = ctypes.c_void_p

# Callback types
GLOBAL_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, wl_registry_p,
                              ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32)
GLOBAL_REMOVE_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, wl_registry_p,
                                     ctypes.c_uint32)

class wl_registry_listener(ctypes.Structure):
    _fields_ = [
        ("global_", GLOBAL_CB),
        ("global_remove", GLOBAL_REMOVE_CB),
    ]

# Function signatures
wl.wl_display_connect.restype = wl_display_p
wl.wl_display_connect.argtypes = [ctypes.c_char_p]

wl.wl_display_disconnect.restype = None
wl.wl_display_disconnect.argtypes = [wl_display_p]

wl.wl_display_get_registry.restype = wl_registry_p
wl.wl_display_get_registry.argtypes = [wl_display_p]

wl.wl_display_roundtrip.restype = ctypes.c_int
wl.wl_display_roundtrip.argtypes = [wl_display_p]

wl.wl_registry_add_listener.restype = ctypes.c_int
wl.wl_registry_add_listener.argtypes = [wl_registry_p, ctypes.POINTER(wl_registry_listener), ctypes.c_void_p]

globals_list = []

@GLOBAL_CB
def on_global(data, registry, name, interface, version):
    iface = interface.decode('utf-8')
    globals_list.append((name, iface, version))

@GLOBAL_REMOVE_CB
def on_global_remove(data, registry, name):
    pass

display = wl.wl_display_connect(None)
if not display:
    print("Failed to connect to Wayland display")
    sys.exit(1)

registry = wl.wl_display_get_registry(display)
listener = wl_registry_listener(on_global, on_global_remove)
wl.wl_registry_add_listener(registry, ctypes.byref(listener), None)
wl.wl_display_roundtrip(display)

print(f"Found {len(globals_list)} globals:")
for name, iface, ver in sorted(globals_list, key=lambda x: x[1]):
    print(f"  {name:3d}: {iface} v{ver}")

# Check for key protocols
key_protocols = ['xdg_wm_base', 'zxdg_shell_v6', 'wl_shell', 'wl_compositor',
                 'wl_shm', 'wl_seat', 'wl_output', 'zwp_linux_dmabuf_v1',
                 'wp_viewporter', 'xdg_decoration_manager_v1']
print("\nKey protocol check:")
found = {g[1] for g in globals_list}
for p in key_protocols:
    status = "YES" if p in found else "NO"
    print(f"  {p}: {status}")

wl.wl_display_disconnect(display)
