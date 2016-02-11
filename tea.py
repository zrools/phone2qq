# -*- coding: utf-8 -*-

import struct, ctypes
from random import randint

__all__ = ['encrypt', 'decrypt']

def xor(a, b):
    a1,a2 = struct.unpack('!LL', a[0:8])
    b1,b2 = struct.unpack('!LL', b[0:8])
    r = struct.pack('!LL', a1 ^ b1, a2 ^ b2)
    return r

def encipher(v, k):
    n=16
    delta = 0x9e3779b9
    k = struct.unpack('!LLLL', k[0:16])
    y, z = map(ctypes.c_uint32, struct.unpack('!LL', v[0:8]))
    s = ctypes.c_uint32(0)
    for i in range(n):
        s.value += delta
        y.value += (z.value << 4) + k[0] ^ z.value+ s.value ^ (z.value >> 5) + k[1]
        z.value += (y.value << 4) + k[2] ^ y.value+ s.value ^ (y.value >> 5) + k[3]
    r = struct.pack('!LL', y.value, z.value)
    return r

def encrypt(v, k):
    vl = len(v)
    filln = (6 - vl) % 8
    v_arr = [
        bytes(bytearray([filln | 0xf8])),
        b'\xad' * (filln + 2),
        v,
        b'\0' * 7,
    ]
    v = b''.join(v_arr)
    tr = b'\0'*8
    to = b'\0'*8
    r = []
    o = b'\0' * 8
    for i in range(0, len(v), 8):
        o = xor(v[i:i+8], tr)
        tr = xor(encipher(o, k), to)
        to = o
        r.append(tr)
    r = b''.join(r)
    return r

def decrypt(v, k):
    l = len(v)
    prePlain = decipher(v, k)
    pos = ord(prePlain[0].to_bytes(1, 'big')) & 0x07 + 2
    r = prePlain
    preCrypt = v[0:8]
    for i in range(8, l, 8):
        x = xor(decipher(xor(v[i:i+8], prePlain), k), preCrypt)
        prePlain = xor(x, preCrypt)
        preCrypt = v[i:i+8]
        r += x
    if r[-7:] == b'\0'*7:
        return r[pos+1:-7]


def decipher(v, k):
    n = 16
    y, z = map(ctypes.c_uint32, struct.unpack('!LL', v[0:8]))
    a, b, c, d = map(ctypes.c_uint32, struct.unpack('!LLLL', k[0:16]))
    delta = 0x9E3779B9
    s = ctypes.c_uint32(delta << 4)
    for i in range(n):
        z.value -= ((y.value << 4) + c.value) ^ (y.value + s.value) ^ ((y.value >> 5) + d.value)
        y.value -= ((z.value << 4) + a.value) ^ (z.value + s.value) ^ ((z.value >> 5) + b.value)
        s.value -= delta
    return struct.pack('!LL', y.value, z.value)