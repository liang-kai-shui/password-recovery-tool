import importlib.util
import hashlib
import sys
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "password-recovery-tool.py"
sys.path.insert(0, str(SOURCE.parent))
spec = importlib.util.spec_from_file_location("password_recovery_tool", SOURCE)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
from rar5_fast import SIGNATURE, check_rar5_password, load_rar5_check


def vint(value):
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


class ThreadProcess:
    """Run the worker entry point in a thread to test coordination deterministically."""

    def __init__(self, target, args, daemon):
        self.thread = threading.Thread(target=target, args=args, daemon=daemon)

    def start(self):
        self.thread.start()

    def is_alive(self):
        return self.thread.is_alive()

    def join(self, timeout=None):
        self.thread.join(timeout)

    def terminate(self):
        raise AssertionError("A completed worker should not need termination")


class SevenZipCoordinationTests(unittest.TestCase):
    def test_last_candidate_is_tested_and_returned_without_truncation(self):
        password = b"long-" + b"x" * 300
        words = [b"wrong", password]
        with tempfile.TemporaryDirectory(dir=SOURCE.parent) as directory:
            dictionary = Path(directory) / "dict.txt"
            dictionary.write_bytes(b"\n".join(words) + b"\n")

            def slow_test(_sevenzip, _archive, candidate):
                if candidate == password:
                    # The parent must wait even after the last index is claimed.
                    time.sleep(0.15)
                    return True
                return False

            with patch.object(recovery.mp, "Process", ThreadProcess), \
                 patch.object(recovery.os, "cpu_count", return_value=1), \
                 patch.object(recovery, "test_7z_password", side_effect=slow_test):
                result = recovery.crack_7z_process(
                    "sample.rar", str(dictionary), "7z", words, 0, {},
                    threading.Event(),
                )

        self.assertEqual(result, ("found", password))


class Rar5CheckTests(unittest.TestCase):
    def test_encrypted_file_record_checks_password(self):
        salt = bytes(range(16))
        derived = hashlib.pbkdf2_hmac("sha256", b"1234", salt, (1 << 3) + 32, 32)
        check = bytes(
            derived[i] ^ derived[i + 8] ^ derived[i + 16] ^ derived[i + 24]
            for i in range(8)
        )
        check += hashlib.sha256(check).digest()[:4]
        encryption = vint(0) + vint(1) + bytes([3]) + salt + bytes(16) + check
        record = vint(len(vint(1) + encryption)) + vint(1) + encryption
        header = vint(2) + vint(1) + vint(len(record)) + record
        size = vint(len(header))
        crc = zlib.crc32(size + header).to_bytes(4, "little")
        with tempfile.TemporaryDirectory(dir=SOURCE.parent) as directory:
            archive = Path(directory) / "test.rar"
            archive.write_bytes(SIGNATURE + crc + size + header)
            metadata = load_rar5_check(str(archive))

        self.assertIsNotNone(metadata)
        self.assertTrue(check_rar5_password(metadata, b"1234"))
        self.assertFalse(check_rar5_password(metadata, b"wrong"))


if __name__ == "__main__":
    unittest.main()
