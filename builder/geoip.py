def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _len_field(num: int, payload: bytes) -> bytes:
    return _varint((num << 3) | 2) + _varint(len(payload)) + payload


def _uint_field(num: int, value: int) -> bytes:
    return _varint(num << 3) + _varint(value)


def encode_geoip_list(entries: dict) -> bytes:
    out = bytearray()
    for code, nets in entries.items():
        entry = bytearray(_len_field(1, code.upper().encode("ascii")))
        for net in nets:
            cidr = _len_field(1, net.network_address.packed)
            if net.prefixlen:
                cidr += _uint_field(2, net.prefixlen)
            entry += _len_field(2, bytes(cidr))
        out += _len_field(1, bytes(entry))
    return bytes(out)
