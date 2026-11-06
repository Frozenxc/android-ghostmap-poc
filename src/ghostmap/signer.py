import os
import struct
import hashlib
import zlib
import base64
import tempfile
import subprocess

from .zip_utils import (
    LFH_STRUCT, CDH_STRUCT, EOCD_STRUCT,
    LOCAL_FILE_HEADER_SIG, CENTRAL_DIRECTORY_SIG, END_OF_CENTRAL_DIR_SIG,
)


class ApkSigner:

    @staticmethod
    def generate_debug_key(key_dir="keystore"):
        os.makedirs(key_dir, exist_ok=True)
        key_path = os.path.join(key_dir, "debug.key")
        cert_path = os.path.join(key_dir, "debug.crt")

        if not os.path.exists(key_path) or not os.path.exists(cert_path):
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "3650", "-nodes",
                "-subj", "/CN=Android Debug/O=Android/C=US",
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return key_path, cert_path

    @classmethod
    def sign_apk(cls, input_path, output_path, key_path=None, cert_path=None):
        if not key_path or not cert_path:
            key_path, cert_path = cls.generate_debug_key()

        with open(input_path, "rb") as f:
            raw = f.read()

        eocd_idx = raw.rfind(struct.pack("<I", END_OF_CENTRAL_DIR_SIG))
        eocd = EOCD_STRUCT.unpack_from(raw, eocd_idx)
        num_entries = eocd[4]
        cd_offset = eocd[6]

        file_entries = []
        pos = cd_offset
        for _ in range(num_entries):
            cdh = CDH_STRUCT.unpack_from(raw, pos)
            fn_len = cdh[10]
            extra_len = cdh[11]
            comment_len = cdh[12]
            local_offset = cdh[16]

            fn_bytes = raw[pos + CDH_STRUCT.size : pos + CDH_STRUCT.size + fn_len]
            fn_str = fn_bytes.decode("utf-8", errors="ignore")

            lfh = LFH_STRUCT.unpack_from(raw, local_offset)
            lfh_fn_len = lfh[9]
            lfh_extra_len = lfh[10]
            payload_offset = local_offset + LFH_STRUCT.size + lfh_fn_len + lfh_extra_len
            comp_size = cdh[8]
            payload = raw[payload_offset : payload_offset + comp_size]

            if not fn_str.startswith("META-INF/"):
                file_entries.append((fn_str, payload, cdh[4], cdh[9]))

            pos += CDH_STRUCT.size + fn_len + extra_len + comment_len

        manifest_lines = ["Manifest-Version: 1.0", "Created-By: 1.0 (GhostMap Toolkit)", ""]
        entry_digests = {}
        for name, payload, method, uncomp in file_entries:
            digest = base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
            manifest_lines.extend([f"Name: {name}", f"SHA-256-Digest: {digest}", ""])
            entry_digests[name] = digest

        manifest_bytes = "\r\n".join(manifest_lines).encode("utf-8")

        manifest_hash = base64.b64encode(hashlib.sha256(manifest_bytes).digest()).decode("ascii")
        sf_lines = [
            "Signature-Version: 1.0",
            "Created-By: 1.0 (GhostMap Toolkit)",
            f"SHA-256-Digest-Manifest: {manifest_hash}",
            "",
        ]
        for name, digest in entry_digests.items():
            block = f"Name: {name}\r\nSHA-256-Digest: {digest}\r\n\r\n".encode("utf-8")
            block_hash = base64.b64encode(hashlib.sha256(block).digest()).decode("ascii")
            sf_lines.extend([f"Name: {name}", f"SHA-256-Digest: {block_hash}", ""])

        sf_bytes = "\r\n".join(sf_lines).encode("utf-8")

        sf_tmp = tempfile.NamedTemporaryFile("wb", delete=False)
        rsa_tmp = tempfile.NamedTemporaryFile("rb", delete=False)
        sf_tmp.write(sf_bytes)
        sf_tmp.close()

        try:
            subprocess.run([
                "openssl", "smime", "-sign",
                "-in", sf_tmp.name, "-out", rsa_tmp.name,
                "-outform", "DER", "-signer", cert_path,
                "-inkey", key_path, "-nodetach",
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(rsa_tmp.name, "rb") as rf:
                rsa_bytes = rf.read()
        finally:
            os.remove(sf_tmp.name)
            os.remove(rsa_tmp.name)

        all_entries = [
            ("META-INF/MANIFEST.MF", manifest_bytes, 0, len(manifest_bytes)),
            ("META-INF/CERT.SF", sf_bytes, 0, len(sf_bytes)),
            ("META-INF/CERT.RSA", rsa_bytes, 0, len(rsa_bytes)),
        ] + file_entries

        output = bytearray()
        cd_records = []

        for name, data, method, uncomp_len in all_entries:
            name_bytes = name.encode("utf-8")
            comp_len = len(data)
            crc = zlib.crc32(data) & 0xFFFFFFFF
            local_off = len(output)

            padding = 0
            if method == 0:
                data_start = local_off + 30 + len(name_bytes)
                remainder = data_start % 4
                if remainder != 0:
                    padding = 4 - remainder

            extra = b"\x00" * padding

            lfh = LFH_STRUCT.pack(
                LOCAL_FILE_HEADER_SIG, 20, 0, method, 0, 0,
                crc, comp_len, uncomp_len, len(name_bytes), len(extra),
            )
            output.extend(lfh)
            output.extend(name_bytes)
            output.extend(extra)
            output.extend(data)

            cd_records.append({
                "name": name_bytes, "extra": extra, "method": method,
                "crc": crc, "comp_len": comp_len, "uncomp_len": uncomp_len,
                "local_offset": local_off,
            })

        cd_start = len(output)
        for rec in cd_records:
            cdh = CDH_STRUCT.pack(
                CENTRAL_DIRECTORY_SIG, 20, 20, 0,
                rec["method"], 0, 0, rec["crc"],
                rec["comp_len"], rec["uncomp_len"],
                len(rec["name"]), len(rec["extra"]),
                0, 0, 0, 0, rec["local_offset"],
            )
            output.extend(cdh)
            output.extend(rec["name"])
            output.extend(rec["extra"])

        cd_size = len(output) - cd_start

        eocd_out = EOCD_STRUCT.pack(
            END_OF_CENTRAL_DIR_SIG, 0, 0,
            len(cd_records), len(cd_records),
            cd_size, cd_start, 0,
        )
        output.extend(eocd_out)

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(output)

        return output_path
