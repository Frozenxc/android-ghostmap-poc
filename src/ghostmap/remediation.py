import struct
from .zip_utils import CDH_STRUCT, EOCD_STRUCT, END_OF_CENTRAL_DIR_SIG, COMP_STORED, COMP_DEFLATED


def sanitize_apk(input_path, output_path):
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    eocd_idx = data.rfind(struct.pack("<I", END_OF_CENTRAL_DIR_SIG))
    if eocd_idx == -1:
        raise ValueError("Not a valid ZIP file")

    eocd = EOCD_STRUCT.unpack_from(data, eocd_idx)
    num_entries = eocd[4]
    cd_offset = eocd[6]

    fixed = 0
    pos = cd_offset

    for _ in range(num_entries):
        if pos + CDH_STRUCT.size > len(data):
            break
        cdh = CDH_STRUCT.unpack_from(data, pos)
        method = cdh[4]
        comp_size = cdh[8]
        uncomp_size = cdh[9]
        fn_len = cdh[10]
        extra_len = cdh[11]
        comment_len = cdh[12]
        local_offset = cdh[16]

        needs_fix = False
        if method not in (COMP_STORED, COMP_DEFLATED):
            needs_fix = True
        elif method == COMP_STORED and uncomp_size != comp_size:
            needs_fix = True

        if needs_fix:
            struct.pack_into("<H", data, pos + 10, COMP_STORED)
            struct.pack_into("<I", data, pos + 24, comp_size)
            struct.pack_into("<H", data, local_offset + 8, COMP_STORED)
            struct.pack_into("<I", data, local_offset + 22, comp_size)
            fixed += 1

        pos += CDH_STRUCT.size + fn_len + extra_len + comment_len

    with open(output_path, "wb") as f:
        f.write(data)

    return (fixed > 0, fixed)
