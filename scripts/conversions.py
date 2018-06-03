
# Endianness refers to the sequential order in which bytes are arranged
# - big endian: ordered from the big end, i.e. most significant bit first
# - little endian: ordered from the little end, i.e. least significant bit first

xbytes = b'\x00\x0f' # assume big endian
print("x is " + ("" if isinstance(xbytes, bytes) else "not ") + "bytes; as bytes:", xbytes)
print("x is " + ("" if isinstance(xbytes, int) else "not ") + "int; as int:", int.from_bytes(xbytes, 'big'))
print("x is " + ("" if isinstance(xbytes, str) else "not ") + "str; as hex string:", xbytes.hex())
print()

xint = 15
print("x is " + ("" if isinstance(xint, bytes) else "not ") + "bytes; as bytes:", xint.to_bytes(2, 'big'))
print("x is " + ("" if isinstance(xint, int) else "not ") + "int; as int:", xint)
# fixed length (4) with trailing 0s, and lower capitalization for letters (x)
print("x is " + ("" if isinstance(xint, str) else "not ") + "str; as 4 character hex string:", format(xint, '04x'))
# shortest possible string with 0x prefix
#print("x is " + ("" if isinstance(xint, str) else "not ") + "str; as hex string:", hex(xint))
print()

# it would be better to avoid strings as input... anyway

xstr = "000f" # must be even lenght for conversion to bytes to work
print("x is " + ("" if isinstance(xstr, bytes) else "not ") + "bytes; as bytes:", bytes.fromhex(xstr))
print("x is " + ("" if isinstance(xstr, int) else "not ") + "int; as int:", int(xstr, 16))
print("x is " + ("" if isinstance(xstr, str) else "not ") + "str; as hex string:", xstr)
print()

xstr = "00f" # alternatively, for bytes conversion, it is more robust to pivot on int, then bytes
print("x is " + ("" if isinstance(xstr, bytes) else "not ") + "bytes; as bytes:", int(xstr, 16).to_bytes(2, 'big'))
print("x is " + ("" if isinstance(xstr, int) else "not ") + "int; as int:", int(xstr, 16))
print("x is " + ("" if isinstance(xstr, str) else "not ") + "str; as hex string:", xstr)
print()

xstr = "0x000f" # alternatively, for bytes conversion, it is more rubust to pivot on int, then bytes
print("x is " + ("" if isinstance(xstr, bytes) else "not ") + "bytes; as bytes:", int(xstr, 16).to_bytes(2, 'big'))
print("x is " + ("" if isinstance(xstr, int) else "not ") + "int; as int:", int(xstr, 16))
print("x is " + ("" if isinstance(xstr, str) else "not ") + "str; as hex string:", xstr)
print()
