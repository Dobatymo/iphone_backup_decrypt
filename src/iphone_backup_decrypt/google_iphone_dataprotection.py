#####
# This code is derived from 'iphone-dataprotection':
# https://code.google.com/p/iphone-dataprotection/
#     iphone-dataprotection/python_scripts/keystore/keybag.py
#     iphone-dataprotection/python_scripts/crypto/aes.py
# Original License: https://opensource.org/licenses/BSD-3-Clause
#####

import logging
import struct
from binascii import hexlify
from itertools import tee

import Crypto.Cipher.AES

try:
    from fastpbkdf2 import pbkdf2_hmac  # Prefer a fast, C++ implementation;
except ImportError:
    from hashlib import pbkdf2_hmac  # but settle for a standard library one if necessary!

    try:
        import ssl
    except ImportError:
        logging.warning("Using slow python implementation of PBKDF2-HMAC")


__all__ = ["Keybag", "AESdecryptCBC_stream"]


_CLASSKEY_TAGS = [b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"]  # UUID
_KEYBAG_TYPES = ["System", "Backup", "Escrow", "OTA (icloud)"]
_KEY_TYPES = ["AES", "Curve25519"]
_PROTECTION_CLASSES = {
    1: "NSFileProtectionComplete",
    2: "NSFileProtectionCompleteUnlessOpen",
    3: "NSFileProtectionCompleteUntilFirstUserAuthentication",
    4: "NSFileProtectionNone",
    5: "NSFileProtectionRecovery?",
    6: "kSecAttrAccessibleWhenUnlocked",
    7: "kSecAttrAccessibleAfterFirstUnlock",
    8: "kSecAttrAccessibleAlways",
    9: "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    10: "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
    11: "kSecAttrAccessibleAlwaysThisDeviceOnly"
}
_WRAP_DEVICE = 1
_WRAP_PASSPHRASE = 2


class Keybag:
    def __init__(self, data):
        self.type = None
        self.uuid = None
        self.wrap = None
        self.deviceKey = None
        self.attrs = {}
        self.classKeys = {}
        self.KeyBagKeys = None  # DATASIGN blob
        self.parseBinaryBlob(data)

    def parseBinaryBlob(self, data):
        currentClassKey = None

        for tag, data in _loopTLVBlocks(data):
            if len(data) == 4:
                data = struct.unpack(">L", data)[0]
            if tag == b"TYPE":
                self.type = data
                if self.type > 3:
                    print("FAIL: keybag type > 3 : %d" % self.type)
            elif tag == b"UUID" and self.uuid is None:
                self.uuid = data
            elif tag == b"WRAP" and self.wrap is None:
                self.wrap = data
            elif tag == b"UUID":
                if currentClassKey:
                    self.classKeys[currentClassKey[b"CLAS"]] = currentClassKey
                currentClassKey = {b"UUID": data}
            elif tag in _CLASSKEY_TAGS:
                currentClassKey[tag] = data
            else:
                self.attrs[tag] = data
        if currentClassKey:
            self.classKeys[currentClassKey[b"CLAS"]] = currentClassKey

    def unlockWithPassphrase(self, passphrase):
        passphrase_round1 = pbkdf2_hmac('sha256', passphrase, self.attrs[b"DPSL"], self.attrs[b"DPIC"], 32)
        passphrase_key = pbkdf2_hmac('sha1', passphrase_round1, self.attrs[b"SALT"], self.attrs[b"ITER"], 32)
        for classkey in self.classKeys.values():
            if b"WPKY" not in classkey:
                continue
            if classkey[b"WRAP"] & _WRAP_PASSPHRASE:
                k = _AESUnwrap(passphrase_key, classkey[b"WPKY"])
                if not k:
                    return False
                classkey[b"KEY"] = k
        return True

    def unwrapKeyForClass(self, protection_class, persistent_key):
        ck = self.classKeys[protection_class][b"KEY"]
        if len(persistent_key) != 0x28:
            raise Exception("Invalid key length")
        return _AESUnwrap(ck, persistent_key)

    def printClassKeys(self):
        print("== Keybag")
        print("Keybag type: %s keybag (%d)" % (_KEYBAG_TYPES[self.type], self.type))
        print("Keybag version: %d" % self.attrs[b"VERS"])
        print("Keybag UUID: %s" % hexlify(self.uuid))
        print("-"*209)
        print("".join(["Class".ljust(53),
                       "WRAP".ljust(5),
                       "Type".ljust(11),
                       "Key".ljust(65),
                       "WPKY".ljust(65),
                       "Public key"]))
        print("-"*208)
        for k, ck in self.classKeys.items():
            if k == 6:
                print("")

            print("".join(
                [_PROTECTION_CLASSES.get(k).ljust(53),
                 str(ck.get(b"WRAP", "")).ljust(5),
                 _KEY_TYPES[ck.get(b"KTYP", 0)].ljust(11),
                 hexlify(ck.get(b"KEY", b"")).ljust(65).decode('utf-8'),
                 hexlify(ck.get(b"WPKY", b"")).ljust(65).decode('utf-8'),
                 ]))
        print()


def _loopTLVBlocks(blob):
    i = 0
    while i + 8 <= len(blob):
        tag = blob[i:i+4]
        length = struct.unpack(">L", blob[i+4:i+8])[0]
        data = blob[i+8:i+8+length]
        yield (tag, data)
        i += 8 + length


def _unpack64bit(s):
    return struct.unpack(">Q", s)[0]


def _pack64bit(s):
    return struct.pack(">Q", s)


def _AESUnwrap(kek, wrapped):
    C = []
    for i in range(len(wrapped)//8):
        C.append(_unpack64bit(wrapped[i * 8:i * 8 + 8]))
    n = len(C) - 1
    R = [0] * (n+1)
    A = C[0]

    for i in range(1, n+1):
        R[i] = C[i]

    for j in reversed(range(0, 6)):
        for i in reversed(range(1, n+1)):
            todec = _pack64bit(A ^ (n * j + i))
            todec += _pack64bit(R[i])
            B = Crypto.Cipher.AES.new(kek, Crypto.Cipher.AES.MODE_ECB).decrypt(todec)
            A = _unpack64bit(B[:8])
            R[i] = _unpack64bit(B[8:])

    if A != 0xa6a6a6a6a6a6a6a6:
        return None
    res = b"".join(map(_pack64bit, R[1:]))
    return res


# Crypto.Util.Padding.unpad
def removePadding(data, blocksize=16):
    n = int(data[-1])  # RFC 1423: last byte contains number of padding bytes.
    if n > blocksize or n > len(data):
        raise Exception('Invalid CBC padding')
    return data[:-n]


def file_iter(f_in, chunksize):
    while True:
        data = f_in.read(chunksize)
        if data:
            yield data
        else:
            break


def AESdecryptCBC_stream(f_in, f_out, key, iv=b"\x00" * 16, chunksize=1024*1024, padding=False):
    if chunksize % 16 != 0:
        raise ValueError("chunksize must be a multiple of 16")

    dec = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    a, b = tee(file_iter(f_in, chunksize))

    try:
        next(a)
    except StopIteration:
        return

    try:
        while True:
            next(a)
            f_out.write(dec.decrypt(next(b)))
    except StopIteration:
        pass

    last = next(b)
    if len(last) % 16 == 0:
        if padding:
            f_out.write(removePadding(dec.decrypt(last)))
        else:
            f_out.write(dec.decrypt(last))
    else:
        raise RuntimeError("filesize is not a multiple of 16")

    try:
        next(b)
        raise RuntimeError("data left in iterator")
    except StopIteration:
        pass
