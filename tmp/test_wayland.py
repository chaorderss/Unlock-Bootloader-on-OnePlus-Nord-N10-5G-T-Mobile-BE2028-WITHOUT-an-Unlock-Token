import socket, struct
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/wayland-syscomp")
s.settimeout(3)
msg = struct.pack("<IHHI", 1, 1, 12, 2) + struct.pack("<IHHI", 1, 0, 12, 3)
s.sendall(msg)
data = s.recv(4096)
print("received %d bytes - Wayland OK" % len(data))
s.close()
