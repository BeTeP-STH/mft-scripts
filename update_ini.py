#!/usr/bin/python3

# tested with
# mstflint -v
# mstflint, mstflint 4.6.0. Git SHA Hash: 375120d

import sys
import os
import subprocess
import struct
import zlib
import re
import configparser

FLINT = 'mstflint'
RE_SECTIONS = re.compile("     /0x(.{8})-0x.{8} \(0x(.{6})\)/ \(([^)]+)\)[^-]+- (OK|wrong CRC)(?: \(exp:0x)?((?<=exp:0x)....)?.*$", re.M|re.A)
SECTION_FIELDS = 'start length name status crc'.split()
RE_EXPECTED_CRC = re.compile("wrong CRC \(exp:(0x.{4}), act:0x")
FLINT_STARTSWITH = "\n     FS2 failsafe image. Start address: 0x0."
FLINT_ENDSWITH_1 = "\n\n-I- FW image verification succeeded. Image is bootable.\n\n"
FLINT_ENDSWITH_2 = "\n\n-E- FW image verification failed: Bad CRC.. AN HCA DEVICE CAN NOT BOOT FROM THIS IMAGE.\n"
FLINT_FULLIMG_OK = "(Full Image) - OK"
FLINT_FW_CONF_OK = "(FW Configuration) - OK"
ERROR_MSG = '''
.bin is not supported FS2 image file
can't find the FW_CONF section
can't find the new CRC
can't find the new FW_CONF section CRC
FW_CONF integration failed
can't find the full image CRC
'''.splitlines()
TMPBIN = 'tmp.bin'
FLINT_SECTIONS = []
BUFFER = bytearray()

def read_buff(fn, n=-1):
    with open(fn, 'rb') as f:
        return f.read(n)

def save_buff(fn):
    global BUFFER
    with open(fn, 'wb') as f:
        f.write(BUFFER)

def save_crc(crc, off=0x22):
    global BUFFER
    if off < 0:
        off += len(BUFFER)
    struct.pack_into('>H', BUFFER, off, crc & 0xffff)
    save_buff(TMPBIN)

def i16(x):
    return int('0{}'.format(x), 16)

def aligned(buf, n=4, f=b'\0'):
    return buf + f * (n - len(buf) % n)

def find_crc(name, rc=1, idx=0):
    try:
        return [x['crc'] for x in  FLINT_SECTIONS if x['name'] == name][idx]
    except:
        print('{}\n\n{}'.format(text, ERROR_MSG[rc]))
        sys.exit(rc)

def find_offset(name, rc=1, idx=0):
    try:
        return [x['start'] for x in  FLINT_SECTIONS if x['name'] == name][idx]
    except:
        print('{}\n\n{}'.format(text, ERROR_MSG[rc]))
        sys.exit(rc)

def add_ini_section(fn):
    global BUFFER
    ini = read_buff(fn)
    cfg = configparser.ConfigParser()
    cfg.read_string(ini.decode('ascii'))
    zipped = aligned(zlib.compress(ini, 9))
    BUFFER.extend(struct.pack('>IIII', 9, len(zipped)//4, 0, 0xff000000) + zipped + b'\0\0\0\0')
    return cfg['ADAPTER']['PSID']

def flint_verify(fn, expected_ending='\n', rc=1):
    global FLINT_SECTIONS
    try:
        out = subprocess.check_output([FLINT, '-i', fn, 'v']).decode('ascii')
    except subprocess.CalledProcessError as e:
        out = e.stdout.decode('ascii')
    FLINT_SECTIONS = [dict(zip(SECTION_FIELDS, (i16(r[0]), i16(r[1]), r[2], r[3], i16(r[4])))) for r in RE_SECTIONS.findall(out)]
    if not out.startswith(FLINT_STARTSWITH):
        print('{}\n\n{}'.format(out, ERROR_MSG[1]))
        sys.exit(1)
    if not out.endswith(expected_ending):
        print('{}\n\n{}'.format(out, ERROR_MSG[rc]))
        sys.exit(rc)
    return out

def update_ini(binname, ininame):
    global BUFFER
    flint_verify(binname, FLINT_ENDSWITH_1, 1)
    BUFFER.extend(read_buff(binname, find_offset('FW Configuration', 2)))
    psid_ini = add_ini_section(ininame)
    save_crc(-1)
    flint_verify(TMPBIN, FLINT_ENDSWITH_2, 3)
    save_crc(find_crc('FW Configuration', 4), -2)
    flint_verify(TMPBIN, FLINT_ENDSWITH_1, 5)
    save_crc(find_crc('Full Image', 6))

    out = flint_verify(TMPBIN)
    if out.endswith(FLINT_ENDSWITH_1) and out.find(FLINT_FULLIMG_OK) > 0 and out.find(FLINT_FW_CONF_OK) > 0:
        save_buff(binname)
        psid_bin = BUFFER[0:find_offset('Image Info') + 76][-16:].decode('ascii').strip('\0')
        print(out)
        if psid_bin == psid_ini:
            print('PSID:\t{}'.format(psid_bin))
        else:
            print('\033[0;31m!!!PSID MISMATCH!!!\033[0m\n\t.bin PSID:\t{}\n\t.ini PSID:\t{}'.format(psid_bin, psid_ini))
        os.remove(TMPBIN)
        return 0
    return len(ERROR_MSG) + 2

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:\n\t{0} firmware.bin config.ini".format(*sys.argv))
        sys.exit(len(ERROR_MSG) + 1)
    sys.exit(update_ini(*sys.argv[1:]))

