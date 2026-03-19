with open('/Users/xmxx/pinganhuijia/global_abl_raw.img','rb') as f:
    data = f.read()
target = 8*1024*1024
if len(data) < target:
    data = data + bytes(target - len(data))
with open('/Users/xmxx/pinganhuijia/global_abl_padded.img','wb') as f:
    f.write(data)
print('Written {} bytes to global_abl_padded.img'.format(len(data)))
