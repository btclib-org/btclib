
print("\nfrom hexstring to bytes, then back:")
xhexstr = "000f"
print("hexstring", xhexstr)
#import codecs; xbytes = codecs.decode(xhexstr, 'hex')
#xbytes = int(xhexstr, 16).to_bytes(2, 'big') # also handle "00f" and "0x000f", but you must know how many bytes
xbytes = bytes.fromhex(xhexstr)
print("bytes", xbytes)
assert xhexstr == xbytes.hex()
xhexstr = xbytes.hex()
print("hexstring", xhexstr)

print("\nfrom int to hex string, then back:")
xint = 15
print("int", xint)
xhexstr = format(xint, '04x')
print("hexstring", xhexstr, "(how many hexdigits, i.e. bytes, must be known in advance)")
assert xint == int(xhexstr, 16)
xint = int(xhexstr, 16)
print("int", xint)

print("\nfrom int to bytes, then back:")
xint = 15
print("int", xint)
xbytes = xint.to_bytes(2, 'big')
print("bytes", xbytes, "(how many bytes must be known in advance)")
assert xint == int.from_bytes(xbytes, 'big')
xint = int.from_bytes(xbytes, 'big')
print("int", xint)

t = 0
print(type(t == str))
