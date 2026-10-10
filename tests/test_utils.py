import hashlib

import pytest

from malview.utils import calculate_entropy, calculate_hashes


def test_entropy_bounds():
    assert calculate_entropy(b"") == 0.0
    assert calculate_entropy(b"\x00" * 1000) == 0.0
    assert calculate_entropy(bytes(range(256))) == pytest.approx(8.0)
    assert calculate_entropy(b"ab" * 50) == pytest.approx(1.0)


def test_hashes_match_hashlib(tmp_path):
    data = b"malview test data\n" * 1000  # spans several 8 KiB read chunks
    path = tmp_path / "f.bin"
    path.write_bytes(data)
    assert calculate_hashes(str(path)) == {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
