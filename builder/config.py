"""Source definitions and thresholds."""
from dataclasses import dataclass, field

REPO = "Cod3ByAmir/iran-ip-ranges"
USER_AGENT = f"iran-ip-ranges-builder (+https://github.com/{REPO})"
RIPESTAT_APP = "iran-ip-ranges-github"

FETCH_TIMEOUT = 60          # seconds per HTTP request
FETCH_RETRIES = 3
ASN_CONCURRENCY = 6         # parallel RIPEstat announced-prefix requests
ASN_MAX_FAILURE_RATIO = 0.10
VERDICT_TTL_DAYS = 30       # re-verify Tier D country lookups after this many days

MIN_PREFIXLEN = {4: 8, 6: 19}   # anything shorter (larger block) is rejected

MIN_TIER_A_FRESH = 2        # refuse to publish with fewer fresh Tier A sources
MAX_CHANGE_RATIO = {        # refuse to publish if the output moves more than this vs previous
    "v4_prefixes": 0.10, "v4_addresses": 0.10,
    "v6_prefixes": 0.15, "v6_addresses": 0.25,
}
MIN_OUTPUT = {4: 1000, 6: 100}

KEEP_RELEASES = 30

_GH = "https://raw.githubusercontent.com"
_JSD = "https://cdn.jsdelivr.net/gh"


@dataclass
class Source:
    name: str
    tier: str                      # A registry, B geolocation, C routing, D community
    urls: list = field(default_factory=list)
    parser: str = "tokens"         # tokens | ripestat_country | dbip_csv | announced
    description: str = ""


SOURCES = [
    # ---- Tier A: registry delegations (authoritative) ----
    Source("ripestat-country", "A",
           ["https://stat.ripe.net/data/country-resource-list/data.json"
            f"?resource=IR&v4_format=prefix&sourceapp={RIPESTAT_APP}"],
           "ripestat_country", "RIPEstat country resource list (IPv4, IPv6, ASNs)"),
    Source("ipverse-rir-ipv4", "A",
           [f"{_GH}/ipverse/rir-ip/master/country/ir/ipv4-aggregated.txt",
            f"{_JSD}/ipverse/rir-ip@master/country/ir/ipv4-aggregated.txt"],
           description="ipverse rir-ip IPv4 aggregated"),
    Source("ipverse-rir-ipv6", "A",
           [f"{_GH}/ipverse/rir-ip/master/country/ir/ipv6-aggregated.txt",
            f"{_JSD}/ipverse/rir-ip@master/country/ir/ipv6-aggregated.txt"],
           description="ipverse rir-ip IPv6 aggregated"),
    Source("ipdeny-ipv4", "A", ["https://www.ipdeny.com/ipblocks/data/countries/ir.zone"],
           description="ipdeny IPv4 country zone"),
    Source("ipdeny-ipv6", "A", ["https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ir-aggregated.zone"],
           description="ipdeny IPv6 aggregated zone"),

    # ---- Tier B: geolocation databases ----
    Source("iwik-geolite2", "B", ["https://www.iwik.org/ipcountry/IR.cidr"],
           description="iwik.org, MaxMind GeoLite2 based, daily"),
    Source("firehol-geolite2", "B",
           [f"{_GH}/firehol/blocklist-ipsets/master/geolite2_country/country_ir.netset",
            f"{_JSD}/firehol/blocklist-ipsets@master/geolite2_country/country_ir.netset"],
           description="FireHOL GeoLite2 country netset"),
    Source("firehol-ip2location", "B",
           [f"{_GH}/firehol/blocklist-ipsets/master/ip2location_country/ip2location_country_ir.netset",
            f"{_JSD}/firehol/blocklist-ipsets@master/ip2location_country/ip2location_country_ir.netset"],
           description="FireHOL IP2Location country netset"),
    Source("dbip-country-lite", "B",
           ["https://download.db-ip.com/free/dbip-country-lite-{ym}.csv.gz",
            "https://download.db-ip.com/free/dbip-country-lite-{ym_prev}.csv.gz",
            f"{_GH}/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv"],
           "dbip_csv", "DB-IP country lite (monthly CSV)"),
    Source("loyalsoldier-geoip", "B",
           [f"{_GH}/Loyalsoldier/geoip/release/text/ir.txt",
            f"{_JSD}/Loyalsoldier/geoip@release/text/ir.txt"],
           description="Loyalsoldier v2fly GeoIP text export"),

    # ---- Tier C: routing (what Iranian ASNs announce) ----
    Source("ripestat-announced", "C", [], "announced",
           "RIPEstat announced prefixes for every Iranian ASN"),

    # ---- Tier D: community / manual lists (cleaned against A+B+C and registry country) ----
    Source("arastu", "D",
           [f"{_GH}/arastu/iran_ip_ranges/master/iran_ip_range.txt",
            f"{_JSD}/arastu/iran_ip_ranges@master/iran_ip_range.txt"],
           description="arastu/iran_ip_ranges (manual, 2018)"),
    Source("ramtiiin", "D",
           [f"{_GH}/Ramtiiin/iran-ip/main/ip-list.rsc",
            f"{_JSD}/Ramtiiin/iran-ip@main/ip-list.rsc"],
           description="Ramtiiin/iran-ip MikroTik list (manual, 2023)"),
    Source("arvancloud", "D", ["https://www.arvancloud.ir/en/ips.txt"],
           description="ArvanCloud CDN edge ranges"),
    Source("farshidmousavii", "D",
           [f"{_GH}/farshidmousavii/iran-ip-ranges/main/dist/raw/ipv4.txt",
            f"{_JSD}/farshidmousavii/iran-ip-ranges@main/dist/raw/ipv4.txt"],
           description="farshidmousavii/iran-ip-ranges (RIPEstat derived)"),
]
