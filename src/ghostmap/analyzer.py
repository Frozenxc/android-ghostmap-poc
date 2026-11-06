from dataclasses import dataclass
from typing import Tuple
from enum import Enum


class ParserStatus(str, Enum):
    OK = "OK"
    REJECTED = "REJECTED"
    SIGBUS = "SIGBUS"


@dataclass
class AnalysisResult:
    filename: str
    compression_method: int
    compressed_size: int
    uncompressed_size: int
    file_size: int
    libziparchive_status: ParserStatus
    libziparchive_detail: str
    libandroidfw_status: ParserStatus
    libandroidfw_detail: str
    is_ghostmap: bool


def check_libziparchive(method, data_offset, uncompressed_length, cd_offset):
    if method == 0:
        if (data_offset + uncompressed_length) > cd_offset:
            return (
                ParserStatus.REJECTED,
                "Stored entry rejected: offset + uncompressed_length exceeds central directory"
            )
        return (ParserStatus.OK, "Valid stored entry")
    elif method == 8:
        return (ParserStatus.OK, "Valid deflated entry")
    else:
        return (
            ParserStatus.OK,
            f"Method {method} bypasses bounds check (only checked when method == 0)"
        )


def check_libandroidfw(method, data_offset, uncompressed_length, actual_file_size):
    if method == 8:
        return (ParserStatus.OK, "Deflated entry, handled via streaming decompression")
    else:
        mapped_end = data_offset + uncompressed_length
        if mapped_end > actual_file_size:
            overshoot = mapped_end - actual_file_size
            return (
                ParserStatus.SIGBUS,
                f"Method {method} treated as stored, mmap({uncompressed_length} bytes) "
                f"exceeds file boundary by {overshoot} bytes -> SIGBUS on read"
            )
        return (ParserStatus.OK, "Memory mapping within file bounds")
