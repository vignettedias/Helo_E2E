"""Padding (length hiding) and STREAM attachment encryption."""

import pytest
from helo_ref import attachment, padding
from helo_ref.errors import AuthenticationError, InvalidEncodingError
from helo_ref.padding import POLICIES, PaddingPolicy, pad, padme, unpad
from helo_ref.primitives import AES_GCM_TAG_LEN

# --------------------------------------------------------------- padding

@pytest.mark.parametrize("payload", [b"", b"x", b"hello", bytes(255), bytes(256), bytes(1000)])
@pytest.mark.parametrize("name", list(POLICIES))
def test_pad_round_trips(payload, name):
    padded = pad(payload, POLICIES[name])
    assert unpad(padded) == payload
    assert len(padded) >= len(payload) + 1


def test_block_policy_boundaries():
    block = PaddingPolicy("block", 256)
    assert len(pad(b"", block)) == 256
    assert len(pad(bytes(254), block)) == 256      # 254 + marker = 255
    assert len(pad(bytes(255), block)) == 256      # 255 + marker = 256 exactly
    assert len(pad(bytes(256), block)) == 512      # marker spills into the next block


def test_short_messages_are_indistinguishable_by_size():
    """A receipt, a typing event and a short text all land in one bucket."""
    sizes = {len(pad(p)) for p in (b'{"k":"typing"}', b"ok", b"see you at 7", bytes(200))}
    assert sizes == {256}


def test_pow2_and_none_policies():
    assert len(pad(bytes(300), PaddingPolicy("pow2", 256))) == 512
    assert len(pad(bytes(10), PaddingPolicy("pow2", 256))) == 256
    assert len(pad(bytes(10), PaddingPolicy("none"))) == 11


@pytest.mark.parametrize("length,expected", [
    # Worked by hand from the paper: E=floor(log2 L), S=floor(log2 E)+1,
    # mask=2^(E-S)-1, padded=(L+mask) & ~mask.
    (1, 1), (2, 2), (9, 10), (100, 104), (1000, 1024), (65535, 65536),
])
def test_padme_values(length, expected):
    assert padme(length) == expected


def test_padme_overhead_is_bounded():
    worst = max((padme(n) - n) / n for n in range(1, 70000))
    assert worst <= 0.12, worst


@pytest.mark.parametrize("bad", [
    b"",                       # nothing at all
    bytes(16),                 # zeros only, no marker
    b"abc",                    # no marker
    b"abc\x80\x00\x01",        # marker followed by a non-zero byte
    b"abc\x81\x00",            # wrong marker
])
def test_malformed_padding_is_rejected(bad):
    with pytest.raises(InvalidEncodingError):
        unpad(bad)


def test_marker_inside_payload_is_preserved():
    payload = b"\x80\x00\x80\x00"
    assert unpad(pad(payload)) == payload


def test_oversized_message_is_rejected_before_encryption():
    with pytest.raises(InvalidEncodingError):
        pad(bytes(padding.MAX_PADDED_LEN))


def test_unknown_policy_is_refused():
    with pytest.raises(ValueError):
        PaddingPolicy("random")


# ----------------------------------------------------------- attachments

KEY = bytes(range(32))
CHUNK = 64  # small chunks so multi-chunk cases stay cheap


@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 7])
def test_attachment_round_trip(size):
    data = bytes((i * 7) % 256 for i in range(size))
    ct = attachment.encrypt(KEY, data, CHUNK)
    assert len(ct) == attachment.ciphertext_length(size, CHUNK)
    assert attachment.decrypt(KEY, ct, CHUNK) == data


def _three_chunks():
    data = bytes(range(256))[: 3 * CHUNK]
    return data, attachment.encrypt(KEY, data, CHUNK)


def _segments(ct):
    seg = CHUNK + AES_GCM_TAG_LEN
    return [ct[i:i + seg] for i in range(0, len(ct), seg)]


def test_any_flipped_bit_is_detected():
    _, ct = _three_chunks()
    for pos in (0, len(ct) // 2, len(ct) - 1):
        bad = bytearray(ct)
        bad[pos] ^= 0x01
        with pytest.raises(AuthenticationError):
            attachment.decrypt(KEY, bytes(bad), CHUNK)


def test_wrong_key_is_detected():
    _, ct = _three_chunks()
    with pytest.raises(AuthenticationError):
        attachment.decrypt(bytes(32), ct, CHUNK)


def test_reordered_chunks_are_detected():
    _, ct = _three_chunks()
    s = _segments(ct)
    with pytest.raises(AuthenticationError):
        attachment.decrypt(KEY, s[1] + s[0] + s[2], CHUNK)


def test_dropped_final_chunk_is_detected():
    """The classic truncation attack on naive chunking: cut whole chunks off
    the end. STREAM catches it because the new last chunk was sealed as
    NON-final."""
    _, ct = _three_chunks()
    s = _segments(ct)
    with pytest.raises(AuthenticationError):
        attachment.decrypt(KEY, s[0] + s[1], CHUNK)


def test_missing_middle_chunk_is_detected():
    _, ct = _three_chunks()
    s = _segments(ct)
    with pytest.raises(AuthenticationError):
        attachment.decrypt(KEY, s[0] + s[2], CHUNK)


def test_duplicated_chunk_is_detected():
    _, ct = _three_chunks()
    s = _segments(ct)
    with pytest.raises(AuthenticationError):
        attachment.decrypt(KEY, s[0] + s[0] + s[1] + s[2], CHUNK)


@pytest.mark.parametrize("cut", [1, AES_GCM_TAG_LEN, CHUNK])
def test_truncated_bytes_are_detected(cut):
    _, ct = _three_chunks()
    with pytest.raises(AuthenticationError):
        attachment.decrypt(KEY, ct[:-cut], CHUNK)


def test_appended_bytes_are_detected():
    _, ct = _three_chunks()
    with pytest.raises(AuthenticationError):
        attachment.decrypt(KEY, ct + b"\x00", CHUNK)


def test_empty_or_tiny_ciphertext_is_rejected():
    for ct in (b"", bytes(5)):
        with pytest.raises(AuthenticationError):
            attachment.decrypt(KEY, ct, CHUNK)


def test_digest_detects_substitution():
    _, ct = _three_chunks()
    attachment.verify_digest(ct, attachment.digest(ct))
    with pytest.raises(AuthenticationError):
        attachment.verify_digest(ct[:-1] + b"\x00", attachment.digest(ct))


def test_chunk_nonces_never_repeat_under_a_key():
    nonces = {attachment._nonce(i, i == 999) for i in range(1000)}
    assert len(nonces) == 1000
    assert attachment._nonce(5, True) != attachment._nonce(5, False)


def test_fresh_key_per_attachment():
    assert attachment.generate_key() != attachment.generate_key()


def test_oversized_attachment_is_refused():
    with pytest.raises(InvalidEncodingError):
        attachment.encrypt(KEY, bytes(attachment.MAX_ATTACHMENT_BYTES + 1))
