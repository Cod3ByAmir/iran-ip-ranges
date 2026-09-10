"""Turn raw source bodies into lists of ip_network objects."""
import csv
import io
import ipaddress
import logging
import re

log = logging.getLogger("parse")

# Split on anything that cannot be part of an address or prefix.
_TOKEN_SPLIT = re.compile(r"[^0-9a-fA-F:./]+")
_LOOKS_V4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
_LOOKS_V6 = re.compile(r"^[0-9a-fA-F:]*:[0-9a-fA-F:.]*(/\d{1,3})?$")


def _net(text: str):
    """Parse a prefix or bare address into a canonical network, or None."""
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False)
        addr = ipaddress.ip_address(text)
        return ipaddress.ip_network(addr)
    except ValueError:
        return None


def parse_tokens(body: bytes) -> list:
    """Generic parser: plain lists, comma separated, MikroTik .rsc, netset, v2fly text.

    Lines starting with '#' or ';' are comments and skipped. Every remaining token that
    looks like an IPv4/IPv6 address or prefix is kept.
    """
    out = []
    text = body.decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        for tok in _TOKEN_SPLIT.split(line):
            if not tok or "." not in tok and ":" not in tok:
                continue
            if _LOOKS_V4.match(tok) or _LOOKS_V6.match(tok):
                net = _net(tok)
                if net is not None:
                    out.append(net)
    return out


def parse_ripestat_country(body: bytes) -> tuple[list, list[str]]:
    """Return (networks, asn list) from RIPEstat country-resource-list JSON."""
    import json
    data = json.loads(body.decode("utf-8"))
    if data.get("status") != "ok":
        raise ValueError(f"RIPEstat status {data.get('status')}")
    res = data["data"]["resources"]
    nets = []
    for item in res.get("ipv4", []) + res.get("ipv6", []):
        if "-" in item:  # range form "a-b" in case v4_format is ignored
            a, b = item.split("-", 1)
            nets.extend(ipaddress.summarize_address_range(ipaddress.ip_address(a), ipaddress.ip_address(b)))
        else:
            net = _net(item)
            if net is not None:
                nets.append(net)
    asns = [str(a) for a in res.get("asn", [])]
    return nets, asns


def parse_dbip_csv(body: bytes, country: str = "IR") -> list:
    """DB-IP country lite CSV: start,end,country. Also fits the sapics mirror layout."""
    out = []
    reader = csv.reader(io.StringIO(body.decode("utf-8", errors="replace")))
    for row in reader:
        if len(row) < 3 or row[2].strip().upper() != country:
            continue
        try:
            start = ipaddress.ip_address(row[0].strip())
            end = ipaddress.ip_address(row[1].strip())
        except ValueError:
            continue
        if start.version != end.version or start > end:
            continue
        out.extend(ipaddress.summarize_address_range(start, end))
    return out


def parse_cached(lines: list[str]) -> list:
    nets = []
    for ln in lines:
        net = _net(ln)
        if net is not None:
            nets.append(net)
    return nets
