"""The build pipeline: gather -> normalize -> clean Tier D -> aggregate -> guard -> write."""
import hashlib
import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import config, fetch, geoip, parse, ripestat

log = logging.getLogger("pipeline")
DIST = Path("dist")
ASN_CACHE = Path("cache/asns.txt")


@dataclass
class SourceResult:
    name: str
    tier: str
    fresh: bool = False
    url: str = ""
    error: str = ""
    raw_count: int = 0
    nets: list = field(default_factory=list)      # normalized networks
    dropped: int = 0                              # removed by normalize()


# ---------------------------------------------------------------- normalize

def normalize(nets) -> tuple[list, int]:
    """Canonical, globally routable, not absurdly large. Returns (kept, dropped_count)."""
    kept, dropped = [], 0
    for net in nets:
        if not net.is_global or net.prefixlen < config.MIN_PREFIXLEN[net.version]:
            dropped += 1
            continue
        kept.append(net)
    return kept, dropped


def collapse(nets) -> list:
    return list(ipaddress.collapse_addresses(nets))


def by_family(nets) -> dict:
    fam = {4: [], 6: []}
    for n in nets:
        fam[n.version].append(n)
    return fam


# ------------------------------------------------------------------ gather

def _finish(result: SourceResult, nets, url: str) -> SourceResult:
    result.raw_count = len(nets)
    result.nets, result.dropped = normalize(nets)
    result.fresh, result.url = True, url
    fetch.cache_write(result.name, sorted(result.nets, key=lambda n: (n.version, n)))
    return result


def _fallback(result: SourceResult, error: str) -> SourceResult:
    result.error = error
    cached = fetch.cache_read(result.name)
    if cached:
        result.nets = parse.parse_cached(cached)
        result.raw_count = len(result.nets)
        log.warning("%s: using cached copy (%d prefixes): %s", result.name, len(result.nets), error)
    else:
        log.error("%s: failed and no cache: %s", result.name, error)
    return result


def gather() -> dict[str, SourceResult]:
    results: dict[str, SourceResult] = {}
    asns: list[str] = []

    for src in config.SOURCES:
        res = SourceResult(src.name, src.tier)
        if src.parser == "announced":
            continue  # needs the ASN list, handled below
        try:
            body, url = fetch.fetch_first(src.urls)
            if src.parser == "ripestat_country":
                nets, asns = parse.parse_ripestat_country(body)
                ASN_CACHE.parent.mkdir(exist_ok=True)
                ASN_CACHE.write_text("".join(f"{a}\n" for a in sorted(asns, key=int)), encoding="utf-8")
            elif src.parser == "dbip_csv":
                nets = parse.parse_dbip_csv(body)
            else:
                nets = parse.parse_tokens(body)
            if not nets:
                raise RuntimeError("parsed zero prefixes")
            results[src.name] = _finish(res, nets, url)
            log.info("%s: %d prefixes from %s", src.name, len(res.nets), url)
        except Exception as exc:  # noqa: BLE001
            results[src.name] = _fallback(res, str(exc))

    # Tier C: announced prefixes for every Iranian ASN
    src = next(s for s in config.SOURCES if s.parser == "announced")
    res = SourceResult(src.name, src.tier)
    if not asns and ASN_CACHE.is_file():
        asns = [a.strip() for a in ASN_CACHE.read_text().splitlines() if a.strip()]
    if not asns:
        results[src.name] = _fallback(res, "no ASN list available")
    else:
        nets, ok, failed = ripestat.announced_prefixes(asns)
        ratio = failed / max(1, ok + failed)
        if ratio > config.ASN_MAX_FAILURE_RATIO or not nets:
            results[src.name] = _fallback(res, f"{failed}/{ok + failed} ASN lookups failed")
        else:
            results[src.name] = _finish(res, nets, f"RIPEstat announced-prefixes for {ok} ASNs")
            res.error = f"{failed} ASN lookups failed" if failed else ""
            log.info("%s: %d prefixes from %d ASNs (%d failed)", src.name, len(res.nets), ok, failed)
    return results


# ------------------------------------------------------------ Tier D clean

def _covered(net, trusted_set: set) -> bool:
    for plen in range(net.prefixlen, -1, -1):
        if net.supernet(new_prefix=plen) in trusted_set:
            return True
    return False


def clean_tier_d(d_nets, trusted_by_family: dict, verdicts: dict) -> tuple[list, list[dict]]:
    """Return (accepted networks, rejection records)."""
    trusted_set = {n for fam in trusted_by_family.values() for n in fam}
    accepted, rejected = [], []
    seen = set()
    for net in sorted(set(d_nets), key=lambda n: (n.version, n)):
        if net in seen:
            continue
        seen.add(net)
        if _covered(net, trusted_set):
            accepted.append(net)
            continue
        parts = ripestat.country_parts(net, verdicts)
        if parts is None:
            rejected.append({"prefix": str(net), "reason": "registry lookup failed, will retry next build"})
            continue
        parts = collapse(parts)
        accepted.extend(parts)
        if not parts:
            rejected.append({"prefix": str(net), "reason": "registry country is not IR"})
            continue
        # report the non-IR remainder
        remainder = [net]
        for p in parts:
            nxt = []
            for r in remainder:
                nxt.extend(r.address_exclude(p) if p.subnet_of(r) else [r])
            remainder = nxt
        for r in collapse(remainder):
            rejected.append({"prefix": str(r), "reason": f"non-IR part of {net}, IR parts kept"})
    # de-duplicate identical records and give the report a stable order
    unique = {(r["prefix"], r["reason"]): r for r in rejected}
    rejected = sorted(unique.values(), key=lambda r: (ipaddress.ip_network(r["prefix"]).version,
                                                       ipaddress.ip_network(r["prefix"]), r["reason"]))
    return accepted, rejected


# ------------------------------------------------------------------ guards

def _addr_count(nets) -> int:
    return sum(n.num_addresses for n in nets)


def _previous(fam: int) -> list | None:
    path = DIST / f"iran-ipv{fam}.txt"
    if not path.is_file():
        return None
    return parse.parse_cached([ln for ln in path.read_text().splitlines()])


def guard(results: dict, final: dict, force: bool) -> list[str]:
    problems = []
    fresh_a = sum(1 for r in results.values() if r.tier == "A" and r.fresh)
    if fresh_a < config.MIN_TIER_A_FRESH:
        problems.append(f"only {fresh_a} fresh Tier A sources (need {config.MIN_TIER_A_FRESH})")
    for fam in (4, 6):
        if len(final[fam]) < config.MIN_OUTPUT[fam]:
            problems.append(f"IPv{fam} output has {len(final[fam])} prefixes (min {config.MIN_OUTPUT[fam]})")
        prev = _previous(fam)
        if not prev:
            continue
        for label, new, old in ((f"v{fam}_prefixes", len(final[fam]), len(prev)),
                                (f"v{fam}_addresses", _addr_count(final[fam]), _addr_count(prev))):
            ratio = abs(new - old) / max(1, old)
            if ratio > config.MAX_CHANGE_RATIO[label]:
                problems.append(f"{label} moved {ratio:.1%} ({old} -> {new}), limit {config.MAX_CHANGE_RATIO[label]:.0%}")
    if problems and force:
        log.warning("guards overridden by --force: %s", "; ".join(problems))
        return []
    return problems


# ------------------------------------------------------------------ output

def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_outputs(results: dict, final: dict, rejected: list[dict], tier_d_accepted: int, changed: bool) -> dict:
    DIST.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc)
    tag = now.strftime("v%Y.%m.%d")

    for fam in (4, 6):
        nets = final[fam]
        (DIST / f"iran-ipv{fam}.txt").write_text("".join(f"{n}\n" for n in nets), encoding="utf-8")
        (DIST / f"iran-ipv{fam}.nft").write_text(", ".join(map(str, nets)) + "\n", encoding="utf-8")
        table = "/ip firewall address-list" if fam == 4 else "/ipv6 firewall address-list"
        (DIST / f"iran-ipv{fam}.rsc").write_text(
            table + "\n" + "".join(f"add address={n} list=IRAN\n" for n in nets), encoding="utf-8")
        rej = [r for r in rejected if ipaddress.ip_network(r["prefix"]).version == fam]
        (DIST / f"rejected-ipv{fam}.txt").write_text(
            "# Tier D (community list) entries removed by the cleaning rule\n"
            + "".join(f"{r['prefix']}\t{r['reason']}\n" for r in rej), encoding="utf-8")

    # Xray / v2fly GeoIP file with a single IR entry, IPv4 only: use as ext:cgp.dat:ir
    (DIST / "cgp.dat").write_bytes(geoip.encode_geoip_list({"IR": final[4]}))

    (DIST / "version.txt").write_text(now.strftime("%Y-%m-%dT%H:%M:%SZ") + "\n", encoding="utf-8")

    meta = {
        "build_time": now.isoformat(timespec="seconds"),
        "tag": tag,
        "changed": changed,
        "sources": {
            name: {"tier": r.tier, "fresh": r.fresh, "url": r.url, "error": r.error,
                   "prefixes": len(r.nets), "dropped_by_normalize": r.dropped}
            for name, r in results.items()
        },
        "tier_d": {"accepted_prefixes": tier_d_accepted, "rejected_records": len(rejected)},
        "output": {f"ipv{fam}": {"prefixes": len(final[fam]), "addresses": _addr_count(final[fam])}
                   for fam in (4, 6)},
    }
    (DIST / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    sums = []
    for path in sorted(DIST.iterdir()):
        if path.name in ("sha256sums.txt", "release-notes.md") or not path.is_file():
            continue
        sums.append(f"{_sha256(path)}  {path.name}\n")
    (DIST / "sha256sums.txt").write_text("".join(sums), encoding="utf-8")

    notes = [f"# Iran IP ranges {tag}", "", f"Built {meta['build_time']}.", "",
             "| Family | Prefixes | Addresses |", "|---|---|---|"]
    for fam in (4, 6):
        o = meta["output"][f"ipv{fam}"]
        notes.append(f"| IPv{fam} | {o['prefixes']} | {o['addresses']:,} |")
    notes += ["", "| Source | Tier | Fresh | Prefixes |", "|---|---|---|---|"]
    for name, s in meta["sources"].items():
        notes.append(f"| {name} | {s['tier']} | {'yes' if s['fresh'] else 'cached'} | {s['prefixes']} |")
    notes += ["", f"Tier D cleaning: {tier_d_accepted} prefixes accepted, {len(rejected)} rejection records "
              "(see rejected-ipv4.txt / rejected-ipv6.txt).", ""]
    (DIST / "release-notes.md").write_text("\n".join(notes), encoding="utf-8")
    return meta


# -------------------------------------------------------------------- main

def build(force: bool = False) -> int:
    results = gather()

    trusted_nets = [n for r in results.values() if r.tier in "ABC" for n in r.nets]
    trusted = {fam: collapse(nets) for fam, nets in by_family(trusted_nets).items()}
    d_nets = [n for r in results.values() if r.tier == "D" for n in r.nets]

    verdicts = ripestat.load_verdicts()
    accepted_d, rejected = clean_tier_d(d_nets, trusted, verdicts)
    ripestat.save_verdicts(verdicts)
    log.info("Tier D: %d input, %d accepted, %d rejection records", len(d_nets), len(accepted_d), len(rejected))

    final = {}
    for fam in (4, 6):
        final[fam] = collapse(trusted[fam] + [n for n in accepted_d if n.version == fam])
        log.info("IPv%d: %d prefixes, %d addresses", fam, len(final[fam]), _addr_count(final[fam]))

    problems = guard(results, final, force)
    if problems:
        for p in problems:
            log.error("GUARD: %s", p)
        return 2

    changed = any((_previous(fam) or []) != final[fam] for fam in (4, 6))
    meta = write_outputs(results, final, rejected, len(accepted_d), changed)

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"changed={'true' if changed else 'false'}\ntag={meta['tag']}\n")
    log.info("done: tag=%s changed=%s", meta["tag"], changed)
    return 0
