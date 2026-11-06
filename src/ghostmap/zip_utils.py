import struct
from dataclasses import dataclass
from typing import List, Tuple

LOCAL_FILE_HEADER_SIG = 0x04034B50
CENTRAL_DIRECTORY_SIG = 0x02014B50
END_OF_CENTRAL_DIR_SIG = 0x06054B50

COMP_STORED = 0
COMP_DEFLATED = 8

LFH_STRUCT = struct.Struct("<IHHHHHIIIHH")
CDH_STRUCT = struct.Struct("<IHHHHHHIIIHHHHHII")
EOCD_STRUCT = struct.Struct("<IHHHHIIH")


@dataclass
class ZipEntryHeader:
    version_needed: int
    flags: int
    compression_method: int
    last_mod_time: int
    last_mod_date: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    filename: bytes
    extra_field: bytes = b""
    comment: bytes = b""
    header_offset: int = 0
    data_offset: int = 0


def parse_zip_file(file_path: str) -> Tuple[List[ZipEntryHeader], int]:
    with open(file_path, "rb") as f:
        data = f.read()

    eocd_idx = data.rfind(struct.pack("<I", END_OF_CENTRAL_DIR_SIG))
    if eocd_idx == -1:
        raise ValueError("Not a valid ZIP/APK archive")

    eocd_tuple = EOCD_STRUCT.unpack_from(data, eocd_idx)
    num_entries = eocd_tuple[4]
    cd_offset = eocd_tuple[6]

    entries = []
    curr_offset = cd_offset

    for _ in range(num_entries):
        if curr_offset + CDH_STRUCT.size > len(data):
            break

        cdh_tuple = CDH_STRUCT.unpack_from(data, curr_offset)
        sig = cdh_tuple[0]
        if sig != CENTRAL_DIRECTORY_SIG:
            break

        fn_len = cdh_tuple[10]
        extra_len = cdh_tuple[11]
        comment_len = cdh_tuple[12]
        local_header_offset = cdh_tuple[16]

        fn_start = curr_offset + CDH_STRUCT.size
        fn = data[fn_start : fn_start + fn_len]
        extra_start = fn_start + fn_len
        extra = data[extra_start : extra_start + extra_len]
        comment_start = extra_start + extra_len
        comment = data[comment_start : comment_start + comment_len]

        lfh_tuple = LFH_STRUCT.unpack_from(data, local_header_offset)
        lfh_fn_len = lfh_tuple[9]
        lfh_extra_len = lfh_tuple[10]
        data_offset = local_header_offset + LFH_STRUCT.size + lfh_fn_len + lfh_extra_len

        entry = ZipEntryHeader(
            version_needed=cdh_tuple[2],
            flags=cdh_tuple[3],
            compression_method=cdh_tuple[4],
            last_mod_time=cdh_tuple[5],
            last_mod_date=cdh_tuple[6],
            crc32=cdh_tuple[7],
            compressed_size=cdh_tuple[8],
            uncompressed_size=cdh_tuple[9],
            filename=fn,
            extra_field=extra,
            comment=comment,
            header_offset=local_header_offset,
            data_offset=data_offset,
        )
        entries.append(entry)
        curr_offset += CDH_STRUCT.size + fn_len + extra_len + comment_len

    return entries, cd_offset
