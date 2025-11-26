"""
D3DES (DES encryption) module for VNC authentication
VNC uses DES encryption to encrypt the challenge response
"""

def desencrypt(key, challenge):
    """
    Encrypt challenge with DES using the given key
    VNC-specific implementation
    """
    # VNC password is limited to 8 characters
    key = key[:8]
    
    # Pad key to 8 bytes if needed
    while len(key) < 8:
        key += b'\x00'
    
    # VNC uses a mirror/reverse of the bits in each byte of the password
    newkey = []
    for ki in range(len(key)):
        byte = key[ki]
        newbyte = 0
        for i in range(8):
            if byte & (1 << i):
                newbyte = newbyte | (1 << (7 - i))
        newkey.append(newbyte)
    
    key = bytes(newkey)
    
    # Use PyCrypto/Cryptodome or simple DES implementation
    try:
        from Crypto.Cipher import DES
        des = DES.new(key, DES.MODE_ECB)
        return des.encrypt(challenge)
    except ImportError:
        # Fallback to pyDes if available
        try:
            import pyDes
            des = pyDes.des(key, mode=pyDes.ECB, padmode=pyDes.PAD_NORMAL)
            return des.encrypt(challenge)
        except ImportError:
            # If no DES library available, return challenge unchanged
            # This won't work for actual authentication but prevents crashes
            print("Warning: No DES library found. Install pycryptodome: pip install pycryptodome")
            return challenge
