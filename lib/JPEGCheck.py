#! /usr/bin/env python
# coding=utf-8

import struct


def JPEGCheck(data):
    pos = 0
    ret = ''
    lens = len(data)
    while pos < lens:
        tok = struct.unpack('>H', data[pos:pos + 2])[0]
        pos += 2
        if tok == 0xFFD8:
            # SOI:Start of Image
            ret += '%08X:SOI\n' % (pos - 2)
            continue
        elif tok == 0xFFC0:
            ret += '%08X:SOF0\n' % (pos - 2)
            tok2 = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += tok2
        elif tok == 0xFFC1:
            ret += '%08X:SOF0(adobe)\n' % (pos - 2)
            tok2 = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += tok2
        elif tok == 0xFFC2:
            ret += '%08X:SOF0(???)\n' % (pos - 2)
            tok2 = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += tok2
        elif tok == 0xFFC4:
            # DHT
            ret += '%08X:DHT\n' % (pos - 2)
            tok2 = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += tok2
        elif tok >= 0xFFD0 and tok <= 0xFFD7:
            # SOS?
            ret += '%08X:SOS?\n' % (pos - 2)
            while pos < lens:
                tok2 = struct.unpack('B', data[pos])[0]
                pos += 1
                if tok2 != 0xFF:
                    continue
                else:
                    tok3 = struct.unpack('B', data[pos])[0]
                    if tok3 == 0:
                        pos += 1
                    else:
                        pos -= 1
                        break
        elif tok == 0xFFD9:
            ret += '%08X:EOI\n' % (pos - 2)
            break

        elif tok == 0xFFDA:
            ret += '%08X:SOS\n' % (pos - 2)
            while pos < lens:
                tok2 = struct.unpack('B', data[pos])[0]
                pos += 1
                if tok2 != 0xFF:
                    continue
                else:
                    tok3 = struct.unpack('B', data[pos])[0]
                    if tok3 == 0:
                        pos += 1
                    else:
                        pos -= 1
                        break
        elif tok == 0xFFDB:
            ret += '%08X:DQT\n' % (pos - 2)
            tok2 = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += tok2
        elif tok == 0xFFDD:
            ret += '%08X:DRI\n' % (pos - 2)
            tok2 = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += tok2
            continue
        elif tok >= 0xFFE0 and tok <= 0xFFED:
            ret += '%08X:APPx\n' % (pos - 2)
            tok2 = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += tok2
        elif tok == 0xFFEE:
            ret += '%08X:Adobex\n' % (pos - 2)
            tok2 = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += tok2
        elif tok == 0xFFFE:
            ret += '%08X:Adobex\n' % (pos - 2)
            tok2 = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += tok2
        elif tok == 0xFFFF:
            pos -= 1
        else:
            # error
            ret += '%08X:Unknown Marker' % (pos - 2) + ('%04X\n' % tok)
            break

    if pos <= lens and pos >= lens - 48:
        ret += 'Normal JPEG\n'
    else:
        null_flag = True
        for i in range(pos, lens):
            if ord(data[i:i + 1]) != 0:
                null_flag = False
        ret += '%08X-' % pos + '%08X:' % lens
        if null_flag:
            ret += 'Null\n'
        else:
            ret += 'Malicious JPEG\n'

    return ret
