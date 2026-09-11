"""Write a v2fly/Xray compatible geoip.dat containing only the given entries.

Wire format (protobuf, hand encoded so the build stays dependency free):

    message CIDR      { bytes ip = 1; uint32 prefix = 2; }
    message GeoIP     { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3; }
    message GeoIPList { repeated GeoIP entry = 1; }

Use the result as `ext:cgp.dat:ir` in an Xray routing rule.
"""


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
    """entries: {country_code: iterable of ip_network}. Codes are stored upper-case."""
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
