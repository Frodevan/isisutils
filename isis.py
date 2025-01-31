#!/usr/bin/python3
# Program to list directory or extract files from an ImageDisk image
# of an Intel ISIS-II disk
#
# Copyright 2015, 2016 Eric Smith <spacewar@gmail.com>
# All rights reserved.

#    This program is free software: you can redistribute it and/or
#    modify it under the terms of version 3 of the GNU General Public
#    License as published by the Free Software Foundation.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see
#    <http://www.gnu.org/licenses/>.

import argparse
import fnmatch
import os
import zipfile

from imagedisk import ImageDisk


class LayoutFormat:

    def __init__(self, format):
        self.cylinders = 77
        self.sectors = 26
        self.bytes_per_linking_block = 128
        if 'intel' in format:
            self.type = 'intel'
            self.mode = 0x00
            self.heads = 1
            self.bytes_per_block = 128
            self.first_block = (0, 1)
            self.dir_link_block = (1, 1)
            self.dir_entry_len = 16
            self.filename_len = 6
            self.attribute_word = 10
            self.attribute_mask = 0xff
            self.byte_count_word = 11
            self.byte_count_mask = 0xff
            self.block_count_word = 12
            self.link_address_word = 14
            self.attribute_list = {'I': 0, 'S': 1, 'P': 2, 'A': 3, 'X': 6, 'F': 7}
        elif format == 'tandberg dsdd':
            self.type = 'tandberg dsdd'
            self.mode = 0x03
            self.heads = 2
            self.bytes_per_block = 256
            self.first_block = (0x80 + 1, 1)
            self.dir_link_block = (1, 4)
            self.dir_entry_len = 32
            self.filename_len = 8
            self.attribute_word = 14
            self.attribute_mask = 0xffff
            self.byte_count_word = 17
            self.byte_count_mask = 0xffff
            self.block_count_word = 19
            self.link_address_word = 30
            self.attribute_list = {} # Documentation missing, unknown bit-positions
        else:
            raise Exception('Unknown disk format')
        if format == 'intel dd':
            self.mode = 0x03  # ImageDisk doesn't (yet?) have a defined mode for
                              # Intel M2FM
            self.sectors = 52


class IsisFile:

    def __init__(self, dir_entry, dir_index, format):
        self.format = format
        self.file_index = dir_index
        if dir_entry is not None:
            self.basename = dir_entry[1:format.filename_len+1].decode('ascii').rstrip('\0')
            self.extension = dir_entry[format.filename_len+1:format.filename_len+4].decode('ascii').rstrip('\0')
            self.attributes = {}
            attribute_data = self._get_word(dir_entry, format.attribute_word, format.attribute_mask)
            for attribute, bit in format.attribute_list.items():
                self.attributes[attribute] = bool((attribute_data >> bit) & 1)

            self.whole_blocks_used = self._get_word(dir_entry, format.block_count_word) - 1
            self.bytes_in_last_block = self._get_word(dir_entry, format.byte_count_word, format.byte_count_mask)
            self.link_block_addr = (dir_entry[format.link_address_word+1], dir_entry[format.link_address_word])

    @staticmethod
    def _get_word(data, offset, mask = 0xffff):
        return (data[offset] + (data[offset+1] << 8)) & mask

    def get_link_addr(self):
        return self.link_block_addr

    def get_index(self):
        assert self.file_index != -1
        return self.file_index

    def get_data_blocks_used(self):
        return self.whole_blocks_used + 1


    def get_size(self):
        return self.whole_blocks_used * self.format.bytes_per_block + self.bytes_in_last_block

    def get_filename(self, force_lowercase = False):
        ret = self.basename
        if self.extension != '':
            ret += '.' + self.extension
        if force_lowercase:
            return ret.lower()
        return ret

    def get_attribute_byte(self):
        ret = 0
        for attribute, active in self.attributes.items():
            if active:
                ret = ret|(1 << self.format.attribute_list[attribute])
        return ret

    def get_attribute_str(self):
        return ''.join([attribute if active else '.' for attribute, active in self.attributes.items()])

    def get_directory_str(self, force_lowercase = False):
        return '%-12s %s %6d (%3d,%3d)' % (self.get_filename(force_lowercase), self.get_attribute_str(), self.get_size(), self.link_block_addr[0], self.link_block_addr[1])

    def get_directory_entry_struct(self):
        assert self.format.type == 'intel'
        entry = bytearray()
        entry += b'\0'
        entry += bytearray('{:{}}{:3}'.format(self.basename[:self.format.filename_len], self.format.filename_len, self.extension[:3]).replace(' ', '\0'), encoding = 'ascii')
        entry += bytearray(self.format.dir_entry_len - (self.format.filename_len + 4))
        entry[self.format.attribute_word] = self.get_attribute_byte()
        entry[self.format.byte_count_word] = self.bytes_in_last_block
        entry[self.format.block_count_word] = self.get_data_blocks_used()&0xff
        entry[self.format.block_count_word+1] = (self.get_data_blocks_used() >> 8)&0xff
        entry[self.format.link_address_word] = self.link_block_addr[1]
        entry[self.format.link_address_word+1] = self.link_block_addr[0]
        return entry


class NewIsisFile(IsisFile):

    def __init__(self, filename, size, link_block, format):
        super().__init__(None, -1, format)
        self.basename = filename.split('.')[0][:format.filename_len]
        if '.' in filename:
            self.extension = filename.split('.')[-1][:3]
        else:
            self.extension = ''
        self.attributes = {}
        self.whole_blocks_used = int(size/format.bytes_per_block)
        self.bytes_in_last_block = size - self.whole_blocks_used*format.bytes_per_block
        self.link_block_addr = link_block

    def set_file_index(self, index):
        self.file_index = index


class IsisFilesystem:

    def __init__(self, image, format):
        self.image = image
        self.format = format
        self.file_entries = []
        directory_data = self.get_data(self._get_directory_blocks())
        for i in range(len(directory_data)//format.dir_entry_len):
            dir_entry = directory_data[i*format.dir_entry_len:(i+1)*format.dir_entry_len]
            if dir_entry[0] == 0x7f:
                continue # unused entry
            elif dir_entry[0] == 0xff:
                continue # deleted entry
            elif dir_entry[0] == 0x00:
                self.file_entries.append(IsisFile(dir_entry, i, format))

    def _get_directory_blocks(self):
        if self.format.type == 'intel':
            return self._get_intel_dir(self.format.dir_link_block)
        elif self.format.type == 'tandberg dsdd':
            return self._get_tandberg_dsdd_dir(self.format.dir_link_block)
        raise Exception('Unknown disk format')

    def _get_intel_dir(self, link_addr):
        return self.get_data_blocks([link_addr])

    def _get_tandberg_dsdd_dir(self, link_addr):
        blocks = []
        for block in range(link_addr[1], link_addr[1]+2):
            link_block = get_sector(self.image, (link_addr[0], block))
            for i in range(0, self.format.bytes_per_block, 2):
                data_block_addr = (link_block[i+1], link_block[i])
                if data_block_addr == (0, 0):
                    return blocks
                else:
                    blocks.append(data_block_addr)
        return self.get_data(blocks)

    def get_files(self):
        return self.file_entries

    def unroll_link_chain(self, link_addr):
        link_blocks = []
        expected_prev_link_addr = (0, 0)
        while link_addr != (0, 0):
            link_blocks.append(link_addr)
            link_block = get_sector(self.image, link_addr)
            prev_link_addr = (link_block[1], link_block[0])
            next_link_addr = (link_block[3], link_block[2])
            assert prev_link_addr == expected_prev_link_addr
            expected_prev_link_addr = link_addr
            link_addr = next_link_addr
        return link_blocks

    def get_link_blocks(self, file_entry):
        return self.unroll_link_chain(file_entry.get_link_addr())

    def get_data_blocks(self, link_blocks):
        blocks = []
        for block in link_blocks:
            link_block = get_sector(self.image, block)
            for i in range(4, self.format.bytes_per_linking_block, 2):
                data_block_addr = (link_block[i+1], link_block[i])
                if data_block_addr == (0, 0):
                    break
                else:
                    blocks.append(data_block_addr)
        return blocks

    def get_data(self, data_blocks):
        data = bytearray()
        for block in data_blocks:
            data += get_sector(self.image, block)
        return data

    def get_file_data(self, file_entry):
        return self.get_data(self.get_data_blocks(self.get_link_blocks(file_entry)))

    def get_used_blocks(self):
        used_blocks = []
        if self.format.type == 'tandberg dsdd':
            # Blocks reserved by TOS-II, without assigning file-entries
            for sector in range(1, 27):
                used_blocks.append((0x80 + 1, sector))
            for sector in range(1, 7):
                used_blocks.append((2, sector))
        for file in self.file_entries:
            link_blocks = filesystem.get_link_blocks(file)
            used_blocks.extend(link_blocks)
            used_blocks.extend(self.get_data_blocks(link_blocks))
        used_blocks.sort(key=lambda x: (((x[0]&0x7f)<<1)|((x[0]&0x80)>>7), x[1]))
        return used_blocks

    def get_mapfile(self):
        return self.get_mapfile_bitmap(self.get_used_blocks())

    def get_mapfile_bitmap(self, blocks):
        if self.format.type == 'intel':
            map = [0 for _ in range(256)]
        elif self.format.type == 'tandberg dsdd':
            map = [0 for _ in range(512)]

        for block in blocks:
            if self.format.type == 'intel':
                block_nr = block[0]*26 + (block[1]-1)
            elif self.format.type == 'tandberg dsdd':
                block_nr = (block[0]&0x7f)*52 + ((block[0]&0x80)>>7)*26 + (block[1]-1) - 3*26
            bit_mask = 0x80>>block_nr%8
            byte_nr = int(block_nr/8)
            map[byte_nr] = map[byte_nr]|bit_mask
        return map

    def get_next_free_block(self, reserved = 0):
        used_blocks = self.get_used_blocks()
        cylinder = self.format.first_block[0]&0x7f
        head = (self.format.first_block[0]&0x80)>>7
        sector = self.format.first_block[1]
        while cylinder < self.format.cylinders:
            head = head%self.format.heads
            while head < self.format.heads:
                sector = (sector%(self.format.sectors+1))+1
                while sector <= self.format.sectors:
                    block_addr = ((cylinder&0x7f)|((head&0x01) << 7), sector)
                    if block_addr not in used_blocks:
                        if reserved == 0:
                            return block_addr
                        reserved -= 1
                    sector += 1
                head += 1
            cylinder += 1
        return None

    def add_new_file(self, filename, data):
        assert self.format.type == 'intel'
        link_blocks = [self.get_next_free_block()]
        data_blocks = []
        new_file = NewIsisFile(filename, len(data), link_blocks[0], self.format)
        for file in self.file_entries:
            assert new_file.get_filename(True) != file.get_filename(True)
        directory_blocks = self._get_directory_blocks()
        directory_data = self.get_data(directory_blocks)
        for i in range(len(directory_data)//self.format.dir_entry_len):
            dir_entry_ptr = i*self.format.dir_entry_len
            if directory_data[dir_entry_ptr] == 0x7f or directory_data[dir_entry_ptr] == 0xff:
                new_file.set_file_index(i)
                new_file_entry = new_file.get_directory_entry_struct()
                for j in range(self.format.dir_entry_len):
                    directory_data[dir_entry_ptr + j] = new_file_entry[j]
                reserved_block_count = 1
                for j in range(new_file.get_data_blocks_used()):
                    if j > 0 and j%((self.format.bytes_per_linking_block-4)/2) == 0:
                        link_blocks.append(self.get_next_free_block(reserved_block_count))
                        reserved_block_count += 1
                    data_blocks.append(self.get_next_free_block(reserved_block_count))
                    reserved_block_count += 1
                self._write_file_data(data, link_blocks, data_blocks)
                self._mark_in_mapfile(self.get_mapfile_bitmap(link_blocks + data_blocks))
                self._write_file_data(directory_data, [self.format.dir_link_block], directory_blocks)
                break
        self.file_entries.append(new_file)

    def _write_file_data(self, data, link_blocks, data_blocks):
        previous_link_addr = (0, 0)
        data_nr = 0
        for link_nr in range(len(link_blocks)):
            if link_nr+1 < len(link_blocks):
                next_link_addr = link_blocks[link_nr+1]
            else:
                next_link_addr = (0, 0)
            link_block_data = bytearray(self.format.bytes_per_block)
            link_block_data[0] = previous_link_addr[1]
            link_block_data[1] = previous_link_addr[0]
            link_block_data[2] = next_link_addr[1]
            link_block_data[3] = next_link_addr[0]
            for slot in range(0, self.format.bytes_per_linking_block-4, 2):
                link_block_data[4+slot] = data_blocks[data_nr][1]
                link_block_data[5+slot] = data_blocks[data_nr][0]
                write_sector(self.image, data_blocks[data_nr], data[data_nr*self.format.bytes_per_block:(data_nr+1)*self.format.bytes_per_block])
                data_nr += 1
                if data_nr == len(data_blocks):
                    break
            write_sector(self.image, link_blocks[link_nr], link_block_data)
            if link_nr+1 == len(link_blocks):
                return
            previous_link_addr = link_blocks[link_nr]

    def delete_file(self, filename):
        assert self.format.type == 'intel'
        file_entry = self.get_file_entry(filename)
        if file_entry is None:
            return False
        self.file_entries.remove(file_entry)
        link_blocks = self.get_link_blocks(file_entry)
        data_blocks = self.get_data_blocks(link_blocks)
        self._mark_in_mapfile(self.get_mapfile_bitmap(link_blocks + data_blocks), clear = True)
        directory_blocks = self._get_directory_blocks()
        directory_data = self.get_data(directory_blocks)
        directory_data[file_entry.get_index()*self.format.dir_entry_len] = 0xff
        self._write_file_data(directory_data, [self.format.dir_link_block], directory_blocks)
        return True

    def rebuild_mapfile(self):
        assert self.format.type == 'intel'
        file_entry = self.get_file_entry('ISIS.MAP')
        assert file_entry is not None
        link_blocks = self.get_link_blocks(file_entry)
        data_blocks = self.get_data_blocks(link_blocks)
        data = self.get_mapfile()
        self._write_file_data(data, link_blocks, data_blocks)

    def _mark_in_mapfile(self, bitmap, clear = False):
        file_entry = self.get_file_entry('ISIS.MAP')
        assert file_entry is not None
        link_blocks = self.get_link_blocks(file_entry)
        data_blocks = self.get_data_blocks(link_blocks)
        data = self.get_data(data_blocks)
        assert len(bitmap) == len(data)
        for i in range(len(bitmap)):
            if clear:
                data[i] = data[i]&~bitmap[i]
            else:
                data[i] = data[i]|bitmap[i]
        self._write_file_data(data, link_blocks, data_blocks)

    def get_file_entry(self, filename):
        for file in self.file_entries:
            if file.get_filename() == filename:
                return file
        return None


def hex_dump(b):
    for i in range(0, len(b), 16):
        print('%04x:' % i, end = '')
        for j in range(16):
            if i+j < len(b):
                print(' %02x' % b[i+j], end='')
            else:
                print('   ', end='')
        print()


format = None

def load_raw_image(f):
    global format
    imd = ImageDisk()
    raw_image = f.read()
    bytes_per_sector00 = 128
    mode00 = 0x00
    if len(raw_image) == 256256:
        # IBM 3740 single-density FM format
        format = LayoutFormat('intel')
    elif len(raw_image) == 512512:
        # Intel SBC 202 double-density M2FM format
        format = LayoutFormat('intel dd')
        mode00 = 0x03
    elif len(raw_image) == 1021696:
        # Tandberg TOS-II double-density MFM format
        format = LayoutFormat('tandberg dsdd')
    else:
        raise Exception("unrecognized raw image size")
    offset = 0
    for track in range(format.cylinders):
        for head in range(format.heads):
            for sector in range(format.sectors):
                if track == 0 and head == 0:
                    data = raw_image[offset:offset + bytes_per_sector00]
                    imd.write_sector(mode00, track, head, sector + 1, data)
                    offset += bytes_per_sector00
                else:
                    data = raw_image[offset:offset + format.bytes_per_block]
                    imd.write_sector(format.mode, track, head, sector + 1, data)
                    offset += format.bytes_per_block
    return imd;

def write_raw_image(f, imd):
    global format
    for track in range(format.cylinders):
        for head in range(format.heads):
            for sector in range(format.sectors):
                f.write(imd.read_sector(track, head, sector+1))

# Note that sector numbers are based at 1 rather than zero
def get_sector(imd, addr):
    if addr[0]&0x80:
        return imd.read_sector(addr[0]&0x7f, 1, addr[1])
    return imd.read_sector(addr[0], 0, addr[1])


def write_sector(imd, addr, data):
    while len(data) < format.bytes_per_block:
        data.append(0)
    if isinstance(data, list):
        data = bytearray(data)
    if addr[0]&0x80:
        return imd.write_sector(format.mode, addr[0]&0x7f, 1, addr[1], data, replace_ok = True)
    return imd.write_sector(format.mode, addr[0]&0x7f, 0, addr[1], data, replace_ok = True)


# system files
# locations of bootstrap blocks are assumed
# locations of link blocks of system files are assumed
#
#             Link   Data
# Filename    Block  Blocks        Contents
# ----------  -----  ------------  --------
# ISIS.T0     00,24  00,01..00,23  bootstrap
# ISIS.LAB    00,25  00,26         disk label
# ISIS.DIR    01,01  01,02..01,26  directory
# ISIS.MAP    02,01  02,02..02,03  allocation bit map
# ISIS.BIN    02,04


parser = argparse.ArgumentParser(description = 'List directory or extract files from Intel ISIS-II floppy disk image')

action_parser = parser.add_mutually_exclusive_group()
action_parser.add_argument('-v', '--dir', dest='dir', action='store_true', help = 'show directory')
action_parser.add_argument('-x', '--extract', dest='extract', action='store_true', help = 'extract files')
action_parser.add_argument('-a', '--add', dest='add', type = str, help = 'add file')
action_parser.add_argument('-e', '--delete', dest='delete', type = str, help = 'delete file')
action_parser.add_argument('-m', '--remap', dest='remap', action='store_true', help = 'regenerate ISIS.MAP')

dest_parser = parser.add_mutually_exclusive_group()
dest_parser.add_argument('-d', '--destdir', type = str, help = 'destination directory')
dest_parser.add_argument('-z', '--destzip', type=argparse.FileType('wb'), help = 'destination ZIP file')

parser.add_argument('-l', '--lower', action = 'store_true', help = 'convert filenames to lowercase')

parser.add_argument('-r', '--raw', action = 'store_true', help = 'use a raw binary file rather than an ImageDisk image')

parser.add_argument('--debug', action = 'store_true', help = argparse.SUPPRESS)
parser.add_argument('--mapdump', action = 'store_true', help = argparse.SUPPRESS)


parser.add_argument('image',   type = str, help = 'floppy image')

parser.add_argument('pattern', type = str, nargs = '?', help = 'filename pattern')


args = parser.parse_args()

if args.destdir is not None and not os.path.isdir(args.destdir):
    os.mkdir(args.destdir)

with open(args.image, 'rb') as img:
    if args.raw:
        imd = load_raw_image(img)
    else:
        imd = ImageDisk(img)
filesystem = IsisFilesystem(imd, format)

if args.extract and args.destzip is not None:
    destzip = zipfile.ZipFile(args.destzip, 'w', compression = zipfile.ZIP_DEFLATED)
else:
    destzip = None

if args.add is not None and os.path.exists(args.add):
    with open(args.add, 'rb') as f:
        data = bytearray(f.read())
        filesystem.add_new_file(args.add.replace('\\', '/').split('/')[-1], data)
        with open(args.image, 'wb') as img:
            if args.raw:
                 write_raw_image(img, imd)
            else:
                imd = ImageDisk(img)

if args.delete is not None:
    if filesystem.delete_file(args.delete):
        with open(args.image, 'wb') as img:
            if args.raw:
                 write_raw_image(img, imd)
            else:
                imd = ImageDisk(img)

if args.remap:
    filesystem.rebuild_mapfile()
    with open(args.image, 'wb') as img:
        if args.raw:
             write_raw_image(img, imd)
        else:
            imd = ImageDisk(img)

if args.mapdump:
    print('\nBlocks used on disk:')
    btrack = -1
    for block in filesystem.get_used_blocks():
        if btrack != block[0]:
            btrack = block[0]
            print('\nhead {} cyl {:02}:   '.format((btrack & 0x80) >> 7, btrack & 0x7f), end='')
        print('{} '.format(block[1]), end='')

    print('\n\nMapfile:\n\n    ', end='')
    mapbyte_count = 0
    for v in filesystem.get_mapfile():
        mapbyte_count += 1
        if mapbyte_count%16 == 0:
            print('{:02X} \n    '.format(v), end='')
        else:
            print('{:02X} '.format(v), end='')

if args.dir:
    print('filename     attr   length link block')
    print('------------ ------ ------ ----------')

for file in filesystem.get_files():
    filename = file.get_filename(args.lower)

    if args.pattern is not None:
        if not fnmatch.fnmatch(file.get_filename(), args.pattern):
            continue

    if args.dir:
        print(file.get_directory_str())
        if args.debug:
            link_blocks = filesystem.get_link_blocks(file)
            data_blocks = filesystem.get_data_blocks(link_blocks)
            print('\n    Linking blocks:')
            for block in link_blocks:
                print('        (%2d %2d) ' % (block[0], block[1]))
            print('\n    Data blocks:', end = '')
            i = 7
            for block in data_blocks:
                if i%8 == 7:
                    print('\n        ', end = '')
                print('(%3d %2d) ' % (block[0], block[1]), end='')
                i += 1
        print('\n\n--------------------------------------------------------------------------------\n')
        continue

    if args.extract:
        file_data = filesystem.get_file_data(file)
        #print('file length, dir: %d  based on link blocks: %d' % (file_length, len(file_data)))
        assert len(file_data) >= file.get_size()
        file_data = file_data[:file.get_size()]

        if destzip is not None:
            destzip.writestr(filename, file_data)
        else:
            if args.destdir is not None:
                path = os.path.join(args.destdir, filename)
            else:
                path = filename
            with open(path, 'wb') as f:
                f.write(file_data)

if destzip is not None:
    destzip.close()

