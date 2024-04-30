#!/usr/bin/env python3
# coding=utf-8
#----------------------------------------------------------------------------
# Copyright @ Huawei Technologies Co., Ltd. 2022-2023. All rights reserved.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# Calculate the elfhash values of TAs by segment and combine the values.
#----------------------------------------------------------------------------

"""
calculate the elfhash values of TA
"""

from __future__ import print_function
import os
import sys
import hashlib
import struct
import logging
import re
from base64 import urlsafe_b64encode


def whitelist_check(intput_str):
    """ check str """
    if not re.match(r"^[A-Za-z0-9\/\-_.]+$", intput_str):
        return 1
    return 0


def elf_header_verify_check(elf_header):
    """ check is elf file """
    elfinfo_mag0_index        = 0
    elfinfo_mag1_index        = 1
    elfinfo_mag2_index        = 2
    elfinfo_mag3_index        = 3
    elfinfo_mag0              = '\x7f'
    elfinfo_mag1              = 'E'
    elfinfo_mag2              = 'L'
    elfinfo_mag3              = 'F'

    if (elf_header.e_ident[elfinfo_mag0_index] != ord(elfinfo_mag0)) or \
       (elf_header.e_ident[elfinfo_mag1_index] != ord(elfinfo_mag1)) or \
       (elf_header.e_ident[elfinfo_mag2_index] != ord(elfinfo_mag2)) or \
       (elf_header.e_ident[elfinfo_mag3_index] != ord(elfinfo_mag3)):
        return False
    return True


class ElfIdent:
    """ define elf ident """
    s = struct.Struct('4sBBB9s')

    def __init__(self, data):
        unpacked_data       = (ElfIdent.s).unpack(data)
        self.unpacked_data  = unpacked_data
        self.ei_magic       = unpacked_data[0]
        self.ei_class       = unpacked_data[1]
        self.ei_data        = unpacked_data[2]
        self.ei_ver         = unpacked_data[3]
        self.ei_pad         = unpacked_data[4]


#----------------------------------------------------------------------------
# ELF Header Class
#----------------------------------------------------------------------------
class Elf32Ehdr:
    """ 32bit elf file header """
    s = struct.Struct('16sHHIIIIIHHHHHH')

    def __init__(self, data):
        unpacked_data       = (Elf32Ehdr.s).unpack(data)
        self.unpacked_data  = unpacked_data
        self.e_ident        = unpacked_data[0]
        self.e_type         = unpacked_data[1]
        self.e_machine      = unpacked_data[2]
        self.e_version      = unpacked_data[3]
        self.e_entry        = unpacked_data[4]
        self.e_phoff        = unpacked_data[5]
        self.e_shoff        = unpacked_data[6]
        self.e_flags        = unpacked_data[7]
        self.e_ehsize       = unpacked_data[8]
        self.e_phentsize    = unpacked_data[9]
        self.e_phnum        = unpacked_data[10]
        self.e_shentsize    = unpacked_data[11]
        self.e_shnum        = unpacked_data[12]
        self.e_shstrndx     = unpacked_data[13]


class Elf64Ehdr:
    """ 64bit elf file header """
    s = struct.Struct('16sHHIQQQIHHHHHH')

    def __init__(self, data):
        unpacked_data       = (Elf64Ehdr.s).unpack(data)
        self.unpacked_data  = unpacked_data
        self.e_ident        = unpacked_data[0]
        self.e_type         = unpacked_data[1]
        self.e_machine      = unpacked_data[2]
        self.e_version      = unpacked_data[3]
        self.e_entry        = unpacked_data[4]
        self.e_phoff        = unpacked_data[5]
        self.e_shoff        = unpacked_data[6]
        self.e_flags        = unpacked_data[7]
        self.e_ehsize       = unpacked_data[8]
        self.e_phentsize    = unpacked_data[9]
        self.e_phnum        = unpacked_data[10]
        self.e_shentsize    = unpacked_data[11]
        self.e_shnum        = unpacked_data[12]
        self.e_shstrndx     = unpacked_data[13]


#----------------------------------------------------------------------------
# ELF Header Class
#----------------------------------------------------------------------------
class Elf32Phdr:
    """ 32bit elf file Phdr """
    s = struct.Struct('IIIIIIII')

    def __init__(self, data):
        unpacked_data       = (Elf32Phdr.s).unpack(data)
        self.unpacked_data  = unpacked_data
        self.p_type         = unpacked_data[0]
        self.p_offset       = unpacked_data[1]
        self.p_vaddr        = unpacked_data[2]
        self.p_paddr        = unpacked_data[3]
        self.p_filesz       = unpacked_data[4]
        self.p_memsz        = unpacked_data[5]
        self.p_flags        = unpacked_data[6]
        self.p_align        = unpacked_data[7]


class Elf64Phdr:
    """ 64bit elf file Phdr """
    s = struct.Struct('IIQQQQQQ')

    def __init__(self, data):
        unpacked_data       = (Elf64Phdr.s).unpack(data)
        self.unpacked_data  = unpacked_data
        self.p_type         = unpacked_data[0]
        self.p_flags        = unpacked_data[1]
        self.p_offset       = unpacked_data[2]
        self.p_vaddr        = unpacked_data[3]
        self.p_paddr        = unpacked_data[4]
        self.p_filesz       = unpacked_data[5]
        self.p_memsz        = unpacked_data[6]
        self.p_align        = unpacked_data[7]


#----------------------------------------------------------------------------
# generate hash use SHA256
#----------------------------------------------------------------------------
def generate_sha256_hash_hex(in_buf):
    """ initialize a SHA256 object from the Python hash library """
    m = hashlib.sha256()
    # Set the input buffer and return the output digest
    m.update(in_buf)
    return m.hexdigest()


def get_elf_file_hash(file_name):
    """ get elf file hash """
    with open(file_name, 'rb') as elf_file_fp:
        elf_buf = elf_file_fp.read()
        return generate_sha256_hash_hex(elf_buf)


class ElfInfo:
    """ elf info message """

    def __init__(self):
        self.elf32_phdr_size  = 32
        self.elf64_phdr_size  = 56
        self.elf_ident_size   = 16
        self.elf64_hdr_size   = 64
        self.elf32_hdr_size   = 52
        self.elfinfo_class_32 = 1
        self.elfinfo_class_64 = 2
        self.load_type        = 0x1
        self.write_flag       = 0x2
        self.exec_flag        = 0x1


def base64url_encode(data):
    """ encode data with base64Url """
    return urlsafe_b64encode(data).rstrip(b'=')


def calculate_mem_hash(elf_file_name):
    """ calculate mem hash summary """
    hash_value_summary = ""
    elf_info = ElfInfo()

    with open(elf_file_name, 'rb') as elf_fp:
        elf_ident_buf = elf_fp.read(elf_info.elf_ident_size)
        elf_ident     = ElfIdent(elf_ident_buf)
        elf_fp.seek(0)
        if elf_ident.ei_class   == elf_info.elfinfo_class_64:
            elf_hd_buf = elf_fp.read(elf_info.elf64_hdr_size)
            elf_header = Elf64Ehdr(elf_hd_buf)
        elif elf_ident.ei_class == elf_info.elfinfo_class_32:
            elf_hd_buf = elf_fp.read(elf_info.elf32_hdr_size)
            elf_header = Elf32Ehdr(elf_hd_buf)
        else:
            logging.error("No Support ELFINFO_CLASS")

        if elf_header_verify_check(elf_header) is False:
            logging.error("ELF file failed verification: %s", elf_file_name)

        for i_phd in range(0, elf_header.e_phnum):
            if elf_ident.ei_class == elf_info.elfinfo_class_64:
                elf_phd_header = Elf64Phdr(elf_fp.read(elf_info.elf64_phdr_size))
            elif elf_ident.ei_class == elf_info.elfinfo_class_32:
                elf_phd_header = Elf32Phdr(elf_fp.read(elf_info.elf32_phdr_size))
            else:
                logging.error("No Support ELFINFO_CLASS")

            if (elf_phd_header.p_type != elf_info.load_type) or \
               (elf_phd_header.p_flags & elf_info.write_flag == elf_info.write_flag):
                continue

            # get segment buf form elf file
            elf_fp.seek(elf_phd_header.p_offset)
            elf_segment_buf = elf_fp.read(elf_phd_header.p_memsz)

            # buf 4k alignment
            if len(elf_segment_buf) % 4096 != 0:
                alignment_len = (len(elf_segment_buf) // 4096 + 1) * 4096
            elf_segment_buf = elf_segment_buf.ljust(alignment_len, b'\0')
            # get hash from segment buf
            hash_value_summary = generate_sha256_hash_hex(elf_segment_buf) + hash_value_summary

            # move the read pointer of the file to the original position.
            if elf_ident.ei_class == elf_info.elfinfo_class_64:
                elf_fp.seek((i_phd + 1) * elf_info.elf64_phdr_size + elf_info.elf64_hdr_size)
            elif elf_ident.ei_class == elf_info.elfinfo_class_32:
                elf_fp.seek((i_phd + 1) * elf_info.elf32_phdr_size + elf_info.elf32_hdr_size)

        elf_fp.seek(0)
        return hash_value_summary


def check_if_pack_app(elf_file_name, sign_data, out_hash_file_name, out_hash_file_path):
    """ check if app files """
    if "pack-App" in elf_file_name:
        out_path = os.path.join(out_hash_file_path, 'hash_{}.txt'.format(out_hash_file_name))
        with os.fdopen(os.open(out_path, os.O_RDWR | os.O_CREAT, 0o755), \
                       "w+", 0o755) as file_ob:
            with os.fdopen(os.open(elf_file_name, os.O_RDWR | os.O_CREAT, 0o755), \
                           "rb", 0o755) as tgz_file:
                tgz_file_data = tgz_file.read(os.path.getsize(elf_file_name))
            mem_hash = generate_sha256_hash_hex(tgz_file_data)
            img_hash = generate_sha256_hash_hex(sign_data)
            file_ob.write("mem_hash : {}\n".format(mem_hash))
            file_ob.write("img_hash : {}\n".format(img_hash))
            file_ob.write("mem_hash_base64url : {}\n".format(base64url_encode(bytes.fromhex(mem_hash)).decode('utf-8')))
            file_ob.write("img_hash_base64url : {}".format(base64url_encode(bytes.fromhex(img_hash)).decode('utf-8')))
        return True

    return False


def get_code_segment_from_elf(elf_file_name, sign_data, out_hash_file_name, out_hash_file_path):
    """ verify ELF header information """
    if whitelist_check(elf_file_name):
        logging.error("file name is incorrect.")
        return

    elf_file_name = os.path.realpath(elf_file_name)
    if check_if_pack_app(elf_file_name, sign_data, out_hash_file_name, out_hash_file_path) is True:
        return

    hash_value_summary = calculate_mem_hash(elf_file_name)
    out_path = os.path.join(out_hash_file_path, 'hash_{}.txt'.format(out_hash_file_name))
    mem_hash = generate_sha256_hash_hex(bytes.fromhex(hash_value_summary))
    img_hash = generate_sha256_hash_hex(sign_data)

    with os.fdopen(os.open(out_path, os.O_RDWR | os.O_CREAT, 0o755), "w+", 0o755) as file_ob:
        file_ob.write("mem_hash : {}\n".format(mem_hash))
        file_ob.write("img_hash : {}\n".format(img_hash))
        file_ob.write("mem_hash_base64url : {}\n".format(base64url_encode(bytes.fromhex(mem_hash)).decode('utf-8')))
        file_ob.write("img_hash_base64url : {}".format(base64url_encode(bytes.fromhex(img_hash)).decode('utf-8')))


def main():
    """ main function """
    get_code_segment_from_elf(sys.argv[1], "test", sys.argv[3], sys.argv[4])


if __name__ == '__main__':
    main()
