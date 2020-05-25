#!/usr/bin/python3

import sys
import struct
import zlib
import configparser
import inspect
import subprocess

DEBUG = 0

def dbg(*a, **b):
    if DEBUG:
        print(inspect.stack()[1].function, *a, **b)

class FS2Image():
    ZLIB = b'\x78\xDA'
    GPH_STRUCT = '>IIII'
    GPH_SIZE = struct.calcsize(GPH_STRUCT)
    GPH_FIELDS = 'type size param next'.split()
    GPH_TYPES = 'UNKNOWN DDR CNF JMP EMT ROM GUID BOARD_ID USER_DATA FW_CONF IMG_INFO DDRZ HASH_FILE LAST'.split()
    IIT_STRUCT = '>B1xH'
    IIT_SIZE = struct.calcsize(IIT_STRUCT)
    IIT_FIELDS = 'tag size'.split()
    IIT_TAGS = """IiFormatRevision
FwVersion
FwBuildTime
DeviceType
PSID
VSD
SuppurtedPsids
ProductVer
VsdVendorId
IsGa
HwDevsId
MicVersion
MinFitVersion
HwAccessKey
PROFILES_LIST
SUPPORTED_PROFS
CONFIG_INFO
TLVS_FORMAT
TRACER_HASH
ConfigArea
PSInfo""".splitlines()
    FS2_CRC_OFF = 0x22
    LASTNEXT = 0xff000000
    FS2_BOOT_START = 0x38

    def __init__(self, fn=None):
        self.filename = fn
        self.buffer = bytearray()
        self.sections = []
        self.image_info = []
        if fn:
            self.readbin(fn)

    def readbin(self, fn):
        self.filename = fn
        self.buffer = bytearray(self.read(fn))
        self.sections = self.parse_sections()
        self.image_info = self.parse_imginfo()

    def read(self, fn, n=-1):
        with open(fn, 'rb') as f:
            return f.read(n)

    def save(self, fn=None, update_crc=False):
        if update_crc:
            self.crc16(update=True)
        if not fn:
            fn = self.filename
        with open(fn, 'wb') as f:
            f.write(self.buffer)

    def parse_sections(self):
        sections = []
        off = self.FS2_BOOT_START
        while 0 < off < len(self.buffer):
            gph = dict(zip(self.GPH_FIELDS, struct.unpack_from(self.GPH_STRUCT, self.buffer, off)))
            gph['offset'] = off
            gph['size'] = gph['size'] * 4 + self.GPH_SIZE
            gph['typename'] = 'BOOT2'
            if 0 < gph['type'] < len(self.GPH_TYPES):
                gph['typename'] = self.GPH_TYPES[gph['type']]
                gph['size'] += 4
            gph['crc_offset'] = off + gph['size'] - 4
            gph['crc'] = struct.unpack_from('>I', self.buffer, gph['crc_offset'])[0]
            sections.append(gph)
            off = gph['crc_offset'] + 4
            dbg('offset={offset:08X} size={size:08X} next={next:08X} crc={crc:04X} type={typename}'.format(**gph))
            if gph['next'] == self.LASTNEXT:
                break
        return sections

    def parse_imginfo(self):
        info = []
        ii = [s for s in self.sections if s['typename'] == 'IMG_INFO'][0]
        off = ii['offset'] + self.GPH_SIZE
        while off < ii['next']:
            iit = dict(zip(self.IIT_FIELDS, struct.unpack_from(self.IIT_STRUCT, self.buffer, off)))
            if iit['tag'] == 255:
                break
            iit['offset'] = off
            off += 4
            if iit['tag'] < len(self.IIT_TAGS):
                iit['tagname'] = self.IIT_TAGS[iit['tag']]
            iit['data'] = self.buffer[off:off+iit['size']]
            dbg('offset={offset:08x} size={size:08x} tag={tagname}'.format(**iit))
            info.append(iit)
            if  iit['tagname'] == 'PSID':
                self.psid_offset = off
                self.psid_size = iit['size']
                self.PSID = iit['data'].decode('ascii').strip()
            off += iit['size']
        dbg('PSID={PSID} offset={psid_offset:08x} size={psid_size:08x}'.format(**self.__dict__))
        return info

    def crc16(self, start=0, end=None, update=False):
        crc = 0xffff
        if start == 0:
            orig = struct.unpack_from('>H',self.buffer, self.FS2_CRC_OFF)
            struct.pack_into('>H',self.buffer, self.FS2_CRC_OFF, crc)

        for dw, in struct.iter_unpack('>I', self.buffer[start:end]):
            for i in range(32):
                if crc & 0x8000:
                    crc = (((crc << 1) | (dw >> 31)) ^ 0x100b) & 0xffff
                else:
                    crc = ((crc << 1) | (dw >> 31)) & 0xffff
                dw = (dw << 1) & 0xffffffff
        for i in range(16):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x100b) & 0xffff
            else:
                crc = (crc << 1) & 0xffff
        crc ^= 0xffff
        if start == 0:
            if update:
                struct.pack_into('>H',self.buffer, self.FS2_CRC_OFF, crc)
            else:
                struct.pack_into('>H',self.buffer, self.FS2_CRC_OFF, orig)
        return crc

    def set_psid(self, psid):
        ii = [s for s in self.sections if s['typename'] == 'IMG_INFO'][0]
        struct.pack_into('{}s'.format(self.psid_size),self.buffer, self.psid_offset, bytes('{:\0<{}}'.format(psid, self.psid_size), 'ascii'))
        struct.pack_into('>I',self.buffer, ii['crc_offset'], self.crc16(ii['offset'], ii['offset'] + ii['size'] - 4))
        self.image_info = self.parse_imginfo()

    def update_ini(self, fn):
        def aligned(buf, n=4, f=b'\0'):
            return buf + f * (n - len(buf) % n)
        ini = self.read(fn)
        cfg = configparser.ConfigParser()
        cfg.read_string(ini.decode('ascii'))
        dbg('{} - PSID from {}'.format(self.PSID, self.filename))
        dbg('{} - PSID from {}'.format(cfg['ADAPTER']['PSID'], fn))
        zipped = aligned(zlib.compress(ini, 9))
        off = [s for s in self.sections if s['typename'] == 'FW_CONF'][0]['offset']
        self.buffer = bytearray(self.buffer[0:off])
        self.buffer.extend(struct.pack('>IIII', 9, len(zipped)//4, 0, 0xff000000) + zipped)
        self.buffer.extend(struct.pack('>I', self.crc16(off)))
        self.set_psid(cfg['ADAPTER']['PSID'])

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:\n\t{0} firmware.bin config.ini".format(*sys.argv))
        sys.exit(1)
    fs = FS2Image(sys.argv[1])
    fs.update_ini(sys.argv[2])
    fs.save(sys.argv[1], update_crc=True)
    sys.exit(0)

