# iran-ip-ranges

Daily built, de-duplicated and aggregated lists of Iranian IPv4 and IPv6 prefixes, merged from
many independent sources and published as GitHub release assets. Built for routers with little
CPU and RAM: all the heavy lifting happens here, the router only downloads a ready made file
and hands it to `nft`.

## Download

Stable URLs, always pointing at the newest release:

| File | Content |
|---|---|
| `https://github.com/Cod3ByAmir/iran-ip-ranges/releases/latest/download/iran-ipv4.txt` | one IPv4 prefix per line, sorted, aggregated |
| `.../iran-ipv6.txt` | same for IPv6 |
| `.../iran-ipv4.nft`, `.../iran-ipv6.nft` | the same lists pre-joined as `a, b, c` for an nft `add element` |
| `.../iran-ipv4.rsc`, `.../iran-ipv6.rsc` | MikroTik RouterOS address-list import |
| `.../sha256sums.txt` | checksums of every asset |
| `.../version.txt` | build timestamp |
| `.../meta.json` | per-source status and counts for the build |
| `.../rejected-ipv4.txt`, `.../rejected-ipv6.txt` | what the cleaning rule removed from community lists, and why |

The same files are also committed under [`dist/`](dist/) and can be fetched from
`https://raw.githubusercontent.com/Cod3ByAmir/iran-ip-ranges/main/dist/<file>`.

## Sources

| Tier | Source | Basis |
|---|---|---|
| A | RIPEstat country resource list | registry delegations, plus the list of Iranian ASNs |
| A | ipverse rir-ip | registry delegations |
| A | ipdeny | registry delegations |
| B | iwik.org | MaxMind GeoLite2 |
| B | FireHOL geolite2 country | MaxMind GeoLite2 |
| B | FireHOL ip2location country | IP2Location LITE |
| B | DB-IP country lite | DB-IP |
| B | Loyalsoldier geoip | v2fly GeoIP text export |
| C | RIPEstat announced prefixes | everything announced by every Iranian ASN |
| D | arastu/iran_ip_ranges | community list, manual, last updated 2018 |
| D | Ramtiiin/iran-ip | community list, manual, last updated 2023 |
| D | ArvanCloud ips.txt | CDN edge ranges |
| D | farshidmousavii/iran-ip-ranges | RIPEstat derived |

Tiers A, B and C are trusted as they are. Tier D lists are cleaned: an entry is kept where it
falls inside the union of A, B and C, or where RIPEstat says the registry country of the address
space is IR. Only the Iranian parts of a mixed prefix survive. Everything removed is listed in
`rejected-ipv4.txt` with a reason. Registry lookups are cached in `state/verdicts.json` for 30 days.

## Pipeline

1. Fetch every source with retries and mirrors. A source that fails falls back to its last good
   copy in `cache/` and is marked `fresh: false` in `meta.json`.
2. Parse every format (plain lists, MikroTik `.rsc`, comma separated, netset, JSON, start-end CSV).
3. Normalise: canonical prefixes, drop anything not globally routable, drop blocks larger than
   IPv4 /8 or IPv6 /19.
4. Clean Tier D as described above.
5. Collapse the union so overlapping and adjacent prefixes merge, sort numerically.
6. Guards: refuse to publish if fewer than two Tier A sources were fresh, if the output is
   implausibly small, or if it moved more than 10 percent (IPv4) against the previous build.
   A failed run opens an issue labelled `build-failure`.
7. Commit `cache/`, `state/` and `dist/`, then publish a release tagged `vYYYY.MM.DD` when the
   lists changed. The newest 30 releases are kept.

Runs daily at 04:00 UTC and on manual dispatch. Python 3 standard library only, no dependencies.

```sh
python3 -m builder            # build into dist/
python3 -m builder --force    # ignore the guards
```

## OpenWrt / pbr

[`openwrt/pbr.user.iran`](openwrt/pbr.user.iran) is a user file for the
[pbr](https://docs.openwrt.melmac.net/pbr/) package. It downloads the two `.nft` files and the
checksum file, verifies them with busybox `sha256sum`, checks a minimum element count, and loads
each family into the pbr user sets `pbr_wan_4_dst_ip_user` and `pbr_wan_6_dst_ip_user` in a
single atomic `flush set` + `add element` transaction. No grep, awk or sort runs on the router.
It is stateless: no cache, no version comparison, every call does the whole job. A failure in
one family never blocks the other.

```sh
# install
cp pbr.user.iran /usr/share/pbr/pbr.user.iran
chmod +x /usr/share/pbr/pbr.user.iran
# enable in pbr: add it as a user file in /etc/config/pbr, then
service pbr reload
```

Because there is no cache, the sets stay empty after a reboot if GitHub is unreachable at that
moment. A cron line retries a few times a day:

```
0 */6 * * * /usr/share/pbr/pbr.user.iran
```

## Licence

MIT. The upstream data carries the licences of the respective providers.
