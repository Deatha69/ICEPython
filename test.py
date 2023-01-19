from ice_cipher import IceKey

# Use 128 bits key
raw_key = b'\x18\x92\xd6\xad\x94/\xc5TU\xf9\x08M\x9ac\x93\xd9'
ice_key = IceKey(2)
ice_key.set(raw_key)

to_encrypt = bytearray(b'hello world')

# Pad bytes if needed
to_encrypt.extend(0 for _ in range(8 - len(to_encrypt) % 8))

# Original data: bytearray(b'hello world\x00\x00\x00\x00\x00')
print('Original data: {}'.format(to_encrypt))

encrypted = bytearray()
for i in range(0, len(to_encrypt), 8):
	encrypted.extend(ice_key.encrypt(to_encrypt[i:i + 8]))

# Encrypted: bytearray(b'\xfa\xc3{j\xd9\xfe\xcac\x07\x90\xab\xc4\xc8l\x18/')
print('Encrypted: {}'.format(encrypted))

decrypted = bytearray()
for i in range(0, len(encrypted), 8):
	decrypted.extend(ice_key.decrypt(encrypted[i:i + 8]))

# Decrypted: bytearray(b'hello world\x00\x00\x00\x00\x00')
print('Decrypted: {}'.format(decrypted))

