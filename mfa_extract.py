#!/usr/bin/python3

# tested with
# mstflint -v
# mstflint, mstflint 4.6.0. Git SHA Hash: 375120d

import sys
import os
import subprocess
import struct
import zlib
import lzma
import re
import configparser

FLINT = "mstflint"

def read_buff(fn, n=-1):
    with open(fn, 'rb') as f:
        return f.read(n)

def lzma_decompress(buf):
    decomp = lzma.LZMADecompressor(memlimit=0x10000000)
    try:
        return decomp.decompress(buf)
    except lzma.LZMAError:
        pass
    return b''

def save_bin(fn, buff, bin_off, bin_len):
    decomp = lzma.LZMADecompressor(memlimit=0x10000000)
    with open(fn, 'wb') as f:
        try:
            f.write(decomp.decompress(buff)[bin_off:bin_off + bin_len])
        except lzma.LZMAError:
            pass
    return decomp.eof

def parse_mtoc(buff, compressed, offset, size):
    mtoc = {}
    if compressed:
        off = 0
        while off < len(buff):
            a, b, c = struct.unpack_from('>32sB1xH', buff, off)
            psid = a.decode('ascii').strip('\0')
            _, pn, _, desc = buff[off+40:off+180].decode('latin1').strip('\0').split('\0')[0:4]
            mtoc[psid] = { 'pn': pn, 'desc': desc, 'off': [struct.unpack_from('>IHH', buff, 36+off+c+40*i) for i in range(b)]}
            off += 36 + 40 * b + c
    return mtoc

def mfa_extract(mfaname, psid):
    SECTIONS = {}
    BUFFER = bytearray(read_buff(mfaname))
    if b'MFAR' != BUFFER[0:4]:
        return 1
    off = 16
    for i in range(3):
        a,b,c,d = struct.unpack_from('>B2xBI4s', BUFFER, off)
        off += 8
        SECTIONS[a] = {'offset': off, 'size': c, 'compressed': b and (d == b'\xFD7zX'), 'buff': memoryview(BUFFER[off:off+c]) }
        if SECTIONS[a]['compressed'] and i < 2:
            SECTIONS[a]['buff'] = lzma_decompress(SECTIONS[a]['buff'])
        off += c

    MTOC = parse_mtoc(**SECTIONS[1])
    if MTOC.get(psid):
        fn = "{}.bin".format(psid)
        for moff in MTOC[psid]['off']:
            off, size = struct.unpack_from('>ii', SECTIONS[2]['buff'], moff[0])
            if size > 0:
                break
        if save_bin(fn, SECTIONS[3]['buff'], off, size):
            print(subprocess.check_output([FLINT, '-i', fn, 'v']).decode('ascii'))
            print(subprocess.check_output([FLINT, '-i', fn, 'q']).decode('ascii'))
            return 0

    else:
        for i, psid in enumerate(sorted(MTOC.keys()), 1):
            print('{i:>3}. {psid:15s}{pn:33s}{desc}'.format(i=i, psid=psid, **MTOC[psid]))
        return 0
    return 1

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:\n\t{0} firmware.mfa <PSID>\t - to extract\n\t{0} firmware.mfa l|list\t - to list".format(*sys.argv))
        sys.exit(2)
    sys.exit(mfa_extract(*sys.argv[1:]))

