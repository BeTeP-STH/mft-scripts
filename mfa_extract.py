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

FLINT = 'mstflint'
XZ_MARKER = b'\xFD7zXZ'
MTOC_STRUCT = '32s8x150s38x'
META_STRUCT = '>II16x'
MTOC_REC_LEN = struct.calcsize(MTOC_STRUCT)
META_REC_LEN = struct.calcsize(META_STRUCT)

BUFFER = bytearray()
MTOC = []

def read_buff(fn, n=-1):
    with open(fn, 'rb') as f:
        return f.read(n)

def parse_mtoc(mtoc):
    global MTOC
    for r in struct.iter_unpack(MTOC_STRUCT, mtoc):
        d = [s for s in 'PSID\0{}{}'.format(*map(bytes.decode,r)).split('\0') if s]
        MTOC.append(dict(zip(d[::2], d[1::2])))

def parse_meta(meta, psid=''):
    global MTOC
    o, s = 0, 0
    for i, r in enumerate(struct.iter_unpack(META_STRUCT, meta)):
        MTOC[i].update({'OFFSET': r[0], 'SIZE': r[1]})
        if MTOC[i]['PSID'] == psid:
            o, s = r
    return o, s

def save_bin(fn, lzma_off, bin_off, bin_len):
    global BUFFER
    decomp = lzma.LZMADecompressor(memlimit=0x10000000)
    with open(fn, 'wb') as f:
        try:
            f.write(decomp.decompress(BUFFER[lzma_off:])[bin_off:bin_off + bin_len])
        except lzma.LZMAError:
            pass
    return decomp.eof

def mfa_extract(mfaname, psid):
    global BUFFER
    BUFFER = bytearray(read_buff(mfaname))
    mtoc_off = BUFFER.find(XZ_MARKER)
    meta_off = BUFFER.find(XZ_MARKER, mtoc_off + 1)
    data_off = BUFFER.find(XZ_MARKER, meta_off + 1)
    parse_mtoc(lzma.decompress(BUFFER[mtoc_off:]))
    if psid in [r['PSID'] for r in MTOC]:
        o, s = parse_meta(lzma.decompress(BUFFER[meta_off:]), psid)
        fn = "{}.bin".format(psid)
        if save_bin(fn, data_off, o, s):
            print(subprocess.check_output([FLINT, '-i', fn, 'v']).decode('ascii'))
            print(subprocess.check_output([FLINT, '-i', fn, 'q']).decode('ascii'))
            return 0
    else:
        for r in MTOC:
            print('{PSID} {PN: <32} {DESCRIPTION:96.96}'.format(**r))
        return 0
    return 1

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:\n\t{0} firmware.mfa <PSID>\t - to extract\n\t{0} firmware.mfa l|list\t - to list".format(*sys.argv))
        sys.exit(2)
    sys.exit(mfa_extract(*sys.argv[1:]))
