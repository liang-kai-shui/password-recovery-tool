"""Read RAR5 password-check metadata and test candidates without launching 7-Zip.

The RAR5 layout follows RARLAB's format note. Archives without a trustworthy
password-check record return None and should use a full archive test instead.
"""

import hashlib
import hmac
import zlib
from typing import NamedTuple, Optional


SIGNATURE = b"Rar!\x1a\x07\x01\x00"
MAX_HEADER = 2 * 1024 * 1024
MAX_KDF_LOG2 = 24


class Rar5Check(NamedTuple):
    kdf_log2: int
    salt: bytes
    value: bytes


def _vint(data: bytes, offset: int):
    result = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("Truncated RAR5 vint")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7f) << shift
        if byte < 0x80:
            return result, offset
    raise ValueError("Oversized RAR5 vint")


def _stream_vint(stream):
    raw = bytearray()
    for _ in range(10):
        byte = stream.read(1)
        if not byte:
            raise ValueError("Truncated RAR5 header")
        raw += byte
        if byte[0] < 0x80:
            return _vint(raw, 0)[0], bytes(raw)
    raise ValueError("Oversized RAR5 header")


def _check_record(payload: bytes, archive_header: bool) -> Optional[Rar5Check]:
    version, offset = _vint(payload, 0)
    flags, offset = _vint(payload, offset)
    if version != 0 or not (flags & 1):
        return None
    needed = 1 + 16 + (0 if archive_header else 16) + 12
    if len(payload) - offset < needed:
        return None
    kdf_log2 = payload[offset]
    if kdf_log2 > MAX_KDF_LOG2:
        return None
    offset += 1
    salt = payload[offset:offset + 16]
    offset += 16 + (0 if archive_header else 16)  # Skip the per-file IV.
    check = payload[offset:offset + 12]
    if not hmac.compare_digest(hashlib.sha256(check[:8]).digest()[:4], check[8:]):
        return None
    return Rar5Check(kdf_log2, salt, check[:8])


def load_rar5_check(path: str) -> Optional[Rar5Check]:
    """Return a verified RAR5 check record, or None for unsupported archives."""
    try:
        with open(path, "rb") as stream:
            if stream.read(len(SIGNATURE)) != SIGNATURE:
                return None
            while True:
                stored_crc = stream.read(4)
                if not stored_crc:
                    return None
                if len(stored_crc) != 4:
                    return None
                header_size, raw_size = _stream_vint(stream)
                if header_size > MAX_HEADER:
                    return None
                header = stream.read(header_size)
                if len(header) != header_size:
                    return None
                if zlib.crc32(raw_size + header) != int.from_bytes(stored_crc, "little"):
                    return None
                block_type, offset = _vint(header, 0)
                flags, offset = _vint(header, offset)
                extra_size = data_size = 0
                if flags & 1:
                    extra_size, offset = _vint(header, offset)
                if flags & 2:
                    data_size, offset = _vint(header, offset)
                if extra_size > len(header) - offset:
                    return None

                if block_type == 4:
                    return _check_record(header[offset:], archive_header=True)
                if block_type in (2, 3) and extra_size:
                    extra = header[-extra_size:]
                    position = 0
                    while position < len(extra):
                        record_size, position = _vint(extra, position)
                        end = position + record_size
                        if end > len(extra):
                            return None
                        record_type, position = _vint(extra, position)
                        if record_type == 1:
                            found = _check_record(extra[position:end], archive_header=False)
                            if found is not None:
                                return found
                        position = end
                if block_type == 5:
                    return None
                stream.seek(data_size, 1)
    except (OSError, ValueError, OverflowError):
        return None


def check_rar5_password(metadata: Rar5Check, password: bytes) -> bool:
    """Check RAR5's 64-bit verifier; a hit must still pass a full 7-Zip test."""
    try:
        # RAR's password limit is 127 Unicode characters.
        encoded = password.decode("utf-8")[:127].encode("utf-8")
    except UnicodeError:
        return False
    derived = hashlib.pbkdf2_hmac(
        "sha256", encoded, metadata.salt, (1 << metadata.kdf_log2) + 32, 32
    )
    folded = bytes(
        derived[i] ^ derived[i + 8] ^ derived[i + 16] ^ derived[i + 24]
        for i in range(8)
    )
    return hmac.compare_digest(folded, metadata.value)
