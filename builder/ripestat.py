"""RIPEstat helpers: announced prefixes per ASN and registry-country verdicts."""
import ipaddress
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path

from . import config
from .fetch import http_get_json

log = logging.getLogger("ripestat")
VERDICT_FILE = Path("state/verdicts.json")


def announced_prefixes(asns: list[str]) -> tuple[list, int, int]:
    """Return (networks, ok_count, fail_count) for the announced prefixes of all ASNs."""
    nets, ok, fail = [], 0, 0

    def one(asn: str):
        url = (f"https://stat.ripe.net/data/announced-prefixes/data.json"
               f"?resource=AS{asn}&sourceapp={config.RIPESTAT_APP}")
        data = http_get_json(url, timeout=45)
        if data.get("status") != "ok":
            raise RuntimeError(f"status {data.get('status')}")
        return [p["prefix"] for p in data["data"].get("prefixes", [])]

    with ThreadPoolExecutor(max_workers=config.ASN_CONCURRENCY) as pool:
        futures = {pool.submit(one, a): a for a in asns}
        for fut in as_completed(futures):
            asn = futures[fut]
            try:
                for pfx in fut.result():
                    try:
                        nets.append(ipaddress.ip_network(pfx, strict=False))
                    except ValueError:
                        pass
                ok += 1
            except Exception as exc:  # noqa: BLE001
                fail += 1
                log.warning("AS%s: %s", asn, exc)
    return nets, ok, fail


# ---- registry country verdicts for Tier D cleaning ----

def load_verdicts() -> dict:
    if VERDICT_FILE.is_file():
        return json.loads(VERDICT_FILE.read_text(encoding="utf-8"))
    return {}


def save_verdicts(verdicts: dict) -> None:
    VERDICT_FILE.parent.mkdir(exist_ok=True)
    VERDICT_FILE.write_text(json.dumps(verdicts, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def _stale(entry: dict) -> bool:
    checked = datetime.fromisoformat(entry["checked"])
    return datetime.now(timezone.utc) - checked > timedelta(days=config.VERDICT_TTL_DAYS)


def country_parts(prefix, verdicts: dict, country: str = "IR"):
    """Return the sub-parts of `prefix` whose registry country is `country`, or None on lookup failure.

    Verdicts are cached as {"located": [[prefix, cc], ...], "checked": iso}.
    """
    key = str(prefix)
    entry = verdicts.get(key)
    if entry is None or _stale(entry):
        url = (f"https://stat.ripe.net/data/rir-stats-country/data.json"
               f"?resource={key}&sourceapp={config.RIPESTAT_APP}")
        try:
            data = http_get_json(url, timeout=45)
            if data.get("status") != "ok":
                raise RuntimeError(f"status {data.get('status')}")
            located = [[r["resource"], (r.get("location") or "").upper()]
                       for r in data["data"].get("located_resources", [])]
            entry = {"located": located, "checked": datetime.now(timezone.utc).isoformat(timespec="seconds")}
            verdicts[key] = entry
            time.sleep(0.15)  # be polite to RIPEstat
        except Exception as exc:  # noqa: BLE001
            log.warning("country lookup failed for %s: %s", key, exc)
            if entry is None:
                return None  # unknown, retry next run
            # stale verdict is better than nothing
    parts = []
    for res, cc in entry["located"]:
        if cc != country:
            continue
        try:
            net = ipaddress.ip_network(res, strict=False)
        except ValueError:
            continue
        if net.version != prefix.version:
            continue
        if net.subnet_of(prefix):
            parts.append(net)
        elif prefix.subnet_of(net):
            parts.append(prefix)
    return parts
