#!/usr/bin/env python3
"""Re-encode SEDSnet 6 wire frames in the SEDSnet 7 wire format.

SEDSnet 7 changed the canonical frame layout (see CHANGELOG 7.0.0 and
docs/wiki/Technical-Wire-Format.md). Captured frames used as test fixtures
can be carried over with this converter: every logical field is preserved,
so packet IDs are unchanged.

Library use:
    convert_canonical(v6_frame: bytes) -> bytes
    reassemble_v6_chunks(frames) -> list of (transfer id, whole frame)
    chunk_v7(frame, max_frame_bytes, transfer) -> list of chunk frames

Command line:
    wire_v6_to_v7.py FRAME.bin [OUT.bin]      one canonical frame
    wire_v6_to_v7.py --hex HEX                one canonical frame, hex in/out

Only canonical frames and SDT kind-0x03 chunk transfers of canonical frames
are converted. Header-template (SDT kind 0x01/0x02) streams depend on the
sender's dictionary state and are not converted: capture them again.
"""

import binascii
import struct
import sys
import zlib


def _uleb(buf, off):
    value = 0
    shift = 0
    while True:
        byte = buf[off]
        off += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, off
        shift += 7


def _put_uleb(out, value):
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return


def _crc(data):
    return struct.pack("<I", zlib.crc32(bytes(data)) & 0xFFFFFFFF)


def convert_canonical(frame):
    """A SEDSnet 6 canonical frame (CRC included) in the SEDSnet 7 layout."""
    frame = bytes(frame)
    data, crc = frame[:-4], frame[-4:]
    if _crc(data) != crc:
        raise ValueError("SEDSnet 6 frame CRC mismatch")
    flags = data[0]
    nep = data[1]
    off = 2
    ty, off = _uleb(data, off)
    dsz, off = _uleb(data, off)
    ts, off = _uleb(data, off)
    nonce = None
    if flags & 0x08:
        nonce, off = _uleb(data, off)
    src, off = _uleb(data, off)
    endpoints = None
    if flags & 0x80:
        endpoints = []
        for _ in range(nep):
            ep, off = _uleb(data, off)
            endpoints.append(ep)
    elif flags & 0x20:
        bitmap = data[off:off + 32]
        off += 32
        endpoints = [i for i in range(256) if bitmap[i // 8] >> (i % 8) & 1]
    epoch = 0
    contract = None
    contract_reliable = False
    if flags & 0x04:
        length, off = _uleb(data, off)
        if length == 0:
            epoch, off = _uleb(data, off)
        else:
            body = data[off:off + length]
            off += length
            cflags = body[0]
            c = 1
            out = bytearray([cflags & 0x07])
            if cflags & 0x02:
                packed = body[c]
                c += 1
                out.append(packed)
                if packed & 0x40:
                    count, c2 = _uleb(body, c)
                    out += body[c:c2]
                    c = c2
            if cflags & 0x01:
                count, c2 = _uleb(body, c)
                out += body[c:c2 + 8 * count]
                c = c2 + 8 * count
            if cflags & 0x08:
                epoch, c = _uleb(body, c)
            if c != len(body):
                raise ValueError("trailing contract bytes")
            contract_reliable = bool(cflags & 0x04)
            # SEDSnet 7 carries a contract only for a shape or targets.
            if cflags & 0x03:
                contract = bytes(out)
    reliable = None
    if flags & 0x02 or contract_reliable:
        if flags & 0x40:
            wire = data[off]
            start = off
            off += 1
            seq = ack = 0
            if wire & 0x04:
                seq, off = _uleb(data, off)
            if wire & 0x08:
                ack, off = _uleb(data, off)
            reliable = (wire & 0x83, seq, ack)
        else:
            rflags = data[off]
            seq, ack = struct.unpack_from("<II", data, off + 1)
            off += 9
            reliable = (rflags, seq, ack)
    payload = data[off:]

    nflags = flags & 0x1F  # compressed, reliable, contract, nonce, e2e
    if contract is None:
        nflags &= ~0x04
    if reliable is not None:
        nflags |= 0x02
    if endpoints is not None:
        nflags |= 0x20 if len(endpoints) == 1 else 0x40
    if epoch:
        nflags |= 0x80
    out = bytearray([nflags])
    _put_uleb(out, ty)
    _put_uleb(out, src)
    if epoch:
        _put_uleb(out, epoch)
    if endpoints is not None:
        if len(endpoints) != 1:
            _put_uleb(out, len(endpoints))
        for ep in endpoints:
            _put_uleb(out, ep)
    if contract is not None:
        _put_uleb(out, len(contract))
        out += contract
    _put_uleb(out, ts)
    if nflags & 0x11:
        _put_uleb(out, dsz)
    if nonce is not None:
        _put_uleb(out, nonce)
    if reliable is not None:
        rflags, seq, ack = reliable
        wire = rflags & 0x83
        if seq:
            wire |= 0x04
        if ack or rflags & 0x01:
            wire |= 0x08
        out.append(wire)
        if seq:
            _put_uleb(out, seq)
        if ack or rflags & 0x01:
            _put_uleb(out, ack)
    out += payload
    return bytes(out + _crc(out))


def parse_v6_chunk(frame):
    """(transfer, index, total, payload) of a SEDSnet 6 SDT chunk, or None.

    Both the 6.0 layout (u32 transfer, u16 index, u16 total) and the compact
    6.x layout (u16 transfer, ULEB128 position) are recognised by length
    consistency with the CRC; pass `compact=True` for the latter.
    """
    frame = bytes(frame)
    if frame[:4] != b"SDT\x03" or _crc(frame[:-4]) != frame[-4:]:
        return None
    body = frame[4:-4]
    transfer, index, total = struct.unpack_from("<IHH", body, 0)
    return transfer, index, total, body[8:]


def parse_v6_compact_chunk(frame):
    frame = bytes(frame)
    if frame[:4] != b"SDT\x03" or _crc(frame[:-4]) != frame[-4:]:
        return None
    body = frame[4:-4]
    transfer = struct.unpack_from("<H", body, 0)[0]
    position, off = _uleb(body, 2)
    total = 1
    while total * (total + 1) // 2 <= position:
        total += 1
    index = position - total * (total - 1) // 2
    return transfer, index, total, body[off:]


def reassemble_v6_chunks(frames, compact=False):
    """Whole frames carried by SEDSnet 6 SDT chunk transfers, in order of
    completion, as (transfer, bytes); other frames as (None, bytes)."""
    parse = parse_v6_compact_chunk if compact else parse_v6_chunk
    pending = {}
    out = []
    for frame in frames:
        parsed = parse(frame)
        if parsed is None:
            out.append((None, bytes(frame)))
            continue
        transfer, index, total, payload = parsed
        slots = pending.setdefault(transfer, [None] * total)
        slots[index] = payload
        if all(part is not None for part in slots):
            out.append((transfer, b"".join(slots)))
            del pending[transfer]
    return out


def chunk_v7(frame, max_frame_bytes, transfer):
    """SEDSnet 7 chunk frames (kind 0x61, CRC32 trailer) for `frame`."""
    transfer = (transfer & 0xFFFF) or 1
    for position_bytes in range(1, 6):
        budget = max_frame_bytes - 7 - position_bytes
        total = max(1, -(-len(frame) // budget))
        position = total * (total - 1) // 2 + total - 1
        if position < 1 << (7 * position_bytes):
            break
    out = []
    for index in range(total):
        chunk = bytearray([0x61])
        chunk += struct.pack("<H", transfer)
        _put_uleb(chunk, total * (total - 1) // 2 + index)
        chunk += frame[index * budget:(index + 1) * budget]
        out.append(bytes(chunk + _crc(chunk)))
    return out


def main(argv):
    if len(argv) >= 3 and argv[1] == "--hex":
        print(binascii.hexlify(convert_canonical(binascii.unhexlify(argv[2]))).decode())
        return 0
    if len(argv) in (2, 3):
        with open(argv[1], "rb") as handle:
            converted = convert_canonical(handle.read())
        with open(argv[2] if len(argv) == 3 else argv[1], "wb") as handle:
            handle.write(converted)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
