#!/usr/bin/env python3
"""Test Wayland connection and globals using libwayland-client directly."""
import ctypes
import os
import sys

# Load libs
wl_client = ctypes.CDLL("libwayland-client.so.0")

# wl_display_connect / disconnect / roundtrip / get_error
wl_client.wl_display_connect.restype = ctypes.c_void_p
wl_client.wl_display_connect.argtypes = [ctypes.c_char_p]
wl_client.wl_display_disconnect.argtypes = [ctypes.c_void_p]
wl_client.wl_display_roundtrip.restype = ctypes.c_int
wl_client.wl_display_roundtrip.argtypes = [ctypes.c_void_p]
wl_client.wl_display_get_error.restype = ctypes.c_int
wl_client.wl_display_get_error.argtypes = [ctypes.c_void_p]

# wl_proxy_marshal_constructor
wl_client.wl_proxy_marshal_constructor.restype = ctypes.c_void_p

# wl_proxy_add_listener
wl_client.wl_proxy_add_listener.restype = ctypes.c_int
wl_client.wl_proxy_add_listener.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

# wl_display_interface, wl_registry_interface (external symbols)
wl_display_interface = ctypes.c_void_p.in_dll(wl_client, "wl_display_interface")
wl_registry_interface = ctypes.c_void_p.in_dll(wl_client, "wl_registry_interface")

display = wl_client.wl_display_connect(None)
if not display:
    print("FAIL: Could not connect to Wayland display")
    sys.exit(1)
print(f"Connected to display: {display:#x}")

err = wl_client.wl_display_get_error(display)
print(f"Display error after connect: {err}")

# Get registry: wl_display.get_registry (opcode 1)
# wl_proxy_marshal_constructor(display, 1, &wl_registry_interface, NULL)
registry = wl_client.wl_proxy_marshal_constructor(
    display, 1, ctypes.byref(wl_registry_interface), ctypes.c_void_p(0))
print(f"Registry: {registry:#x}" if registry else "FAIL: Could not get registry")

if not registry:
    wl_client.wl_display_disconnect(display)
    sys.exit(1)

# Set up listener for registry events
globals_list = []

GLOBAL_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p,
                              ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32)
GLOBAL_REMOVE_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32)

@GLOBAL_CB
def on_global(data, registry, name, interface, version):
    iface = interface.decode('utf-8') if interface else "??"
    globals_list.append((name, iface, version))
    print(f"  GLOBAL: {name} -> {iface} v{version}")

@GLOBAL_REMOVE_CB
def on_remove(data, registry, name):
    print(f"  GLOBAL_REMOVE: {name}")

# Create listener struct (2 function pointers)
LISTENER_TYPE = ctypes.CFUNCTYPE(None) * 2
listener = (ctypes.c_void_p * 2)(
    ctypes.cast(on_global, ctypes.c_void_p),
    ctypes.cast(on_remove, ctypes.c_void_p)
)

ret = wl_client.wl_proxy_add_listener(registry, ctypes.cast(listener, ctypes.c_void_p), None)
print(f"Add listener result: {ret}")

err = wl_client.wl_display_get_error(display)
print(f"Display error before roundtrip: {err}")

print("Calling wl_display_roundtrip...")
ret = wl_client.wl_display_roundtrip(display)
print(f"Roundtrip returned: {ret}")

err = wl_client.wl_display_get_error(display)
print(f"Display error after roundtrip: {err}")

print(f"\nTotal globals: {len(globals_list)}")

wl_client.wl_display_disconnect(display)
