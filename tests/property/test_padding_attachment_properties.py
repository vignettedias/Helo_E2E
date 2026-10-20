"""Property-based tests for padding and STREAM attachments."""

import pytest
from helo_ref import attachment
from helo_ref.errors import AuthenticationError
from helo_ref.padding import POLICIES, pad, unpad
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

pytestmark = pytest.mark.property

SETTINGS = settings(
    max_examples=80,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
KEY = bytes(range(32))


@SETTINGS
@given(payload=st.binary(max_size=5000), name=st.sampled_from(sorted(POLICIES)))
def test_padding_round_trips_for_any_payload(payload, name):
    padded = pad(payload, POLICIES[name])
    assert unpad(padded) == payload


@SETTINGS
@given(a=st.binary(max_size=4000), b=st.binary(max_size=4000),
       name=st.sampled_from(sorted(POLICIES)))
def test_padded_length_is_monotonic(a, b, name):
    """A longer payload is never padded to a SHORTER length: the bucket is a
    function of length only, so equal buckets reveal nothing finer."""
    policy = POLICIES[name]
    if len(a) <= len(b):
        assert len(pad(a, policy)) <= len(pad(b, policy))


@SETTINGS
@given(data=st.binary(max_size=700), chunk=st.integers(min_value=1, max_value=128))
def test_attachment_round_trips_for_any_size_and_chunking(data, chunk):
    assert attachment.decrypt(KEY, attachment.encrypt(KEY, data, chunk), chunk) == data


@SETTINGS
@given(data=st.binary(min_size=1, max_size=400), chunk=st.integers(min_value=8, max_value=64),
       position=st.integers(min_value=0), bit=st.integers(min_value=0, max_value=7))
def test_any_single_bit_flip_in_an_attachment_is_detected(data, chunk, position, bit):
    ct = bytearray(attachment.encrypt(KEY, data, chunk))
    ct[position % len(ct)] ^= 1 << bit
    with pytest.raises(AuthenticationError):
        attachment.decrypt(KEY, bytes(ct), chunk)


@SETTINGS
@given(data=st.binary(min_size=1, max_size=400), chunk=st.integers(min_value=8, max_value=64),
       cut=st.integers(min_value=1))
def test_any_truncation_of_an_attachment_is_detected(data, chunk, cut):
    ct = attachment.encrypt(KEY, data, chunk)
    cut = 1 + (cut % len(ct))
    with pytest.raises(AuthenticationError):
        attachment.decrypt(KEY, ct[:-cut], chunk)
