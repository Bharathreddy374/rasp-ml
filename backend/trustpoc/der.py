"""Minimal DER (ASN.1) reader for the Android Key Attestation extension.

Only what the KeyDescription structure needs: definite lengths, multi-byte
(high) tag numbers, INTEGER, ENUMERATED, BOOLEAN, OCTET STRING, SEQUENCE, SET
and context-specific explicit tags. No third-party ASN.1 library required.
"""
from dataclasses import dataclass

UNIVERSAL, APPLICATION, CONTEXT, PRIVATE = 0, 1, 2, 3

TAG_BOOLEAN = 1
TAG_INTEGER = 2
TAG_OCTET_STRING = 4
TAG_NULL = 5
TAG_ENUMERATED = 10
TAG_SEQUENCE = 16
TAG_SET = 17


class DERError(ValueError):
    pass


@dataclass
class TLV:
    cls: int
    constructed: bool
    tag: int
    value: bytes

    def children(self) -> list["TLV"]:
        if not self.constructed:
            raise DERError("primitive element has no children")
        return parse_all(self.value)

    def as_int(self) -> int:
        if not self.value:
            raise DERError("empty integer")
        return int.from_bytes(self.value, "big", signed=True)

    def as_bool(self) -> bool:
        if len(self.value) != 1:
            raise DERError("bad boolean")
        return self.value != b"\x00"


def _read_one(buf: bytes, pos: int) -> tuple[TLV, int]:
    if pos >= len(buf):
        raise DERError("unexpected end of data")
    first = buf[pos]
    pos += 1
    cls = first >> 6
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    if tag == 0x1F:  # high tag number form, base-128
        tag = 0
        while True:
            if pos >= len(buf):
                raise DERError("truncated tag")
            b = buf[pos]
            pos += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
            if tag > 1 << 24:
                raise DERError("tag too large")
    if pos >= len(buf):
        raise DERError("truncated length")
    length = buf[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(buf):
            raise DERError("unsupported length encoding")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(buf):
        raise DERError("length exceeds data")
    return TLV(cls, constructed, tag, buf[pos:end]), end


def parse_one(buf: bytes) -> TLV:
    tlv, end = _read_one(buf, 0)
    if end != len(buf):
        raise DERError("trailing data")
    return tlv


def parse_all(buf: bytes) -> list[TLV]:
    out, pos = [], 0
    while pos < len(buf):
        tlv, pos = _read_one(buf, pos)
        out.append(tlv)
    return out


# --- encoder, used only by tests to build synthetic attestation certificates ---

def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def encode(cls: int, constructed: bool, tag: int, value: bytes) -> bytes:
    first = (cls << 6) | (0x20 if constructed else 0)
    if tag < 0x1F:
        head = bytes([first | tag])
    else:
        parts = []
        t = tag
        while True:
            parts.append(t & 0x7F)
            t >>= 7
            if not t:
                break
        parts.reverse()
        head = bytes([first | 0x1F]) + bytes(
            [(p | 0x80) if i < len(parts) - 1 else p for i, p in enumerate(parts)])
    return head + _enc_len(len(value)) + value


def enc_int(v: int, tag: int = TAG_INTEGER) -> bytes:
    n = (v.bit_length() + 8) // 8 if v >= 0 else (v.bit_length() + 8) // 8
    return encode(UNIVERSAL, False, tag, v.to_bytes(max(n, 1), "big", signed=True))


def enc_octets(b: bytes) -> bytes:
    return encode(UNIVERSAL, False, TAG_OCTET_STRING, b)


def enc_bool(v: bool) -> bytes:
    return encode(UNIVERSAL, False, TAG_BOOLEAN, b"\xff" if v else b"\x00")


def enc_seq(*items: bytes) -> bytes:
    return encode(UNIVERSAL, True, TAG_SEQUENCE, b"".join(items))


def enc_set(*items: bytes) -> bytes:
    return encode(UNIVERSAL, True, TAG_SET, b"".join(items))


def enc_explicit(tag: int, inner: bytes) -> bytes:
    return encode(CONTEXT, True, tag, inner)
