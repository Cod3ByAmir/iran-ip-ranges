"""HTTP fetching with retries, mirrors and a committed per-source cache."""
import gzip
import json
import logging
import time
import urllib.error
import urllib.request
from datetime import date, timedelta
from pathlib import Path

from . import config

log = logging.getLogger("fetch")
CACHE_DIR = Path("cache")


def _expand(url: str) -> str:
    today = date.today().replace(day=1)
    prev = (today - timedelta(days=1)).replace(day=1)
    return url.format(ym=today.strftime("%Y-%m"), ym_prev=prev.strftime("%Y-%m"))


def http_get(url: str, timeout: int = config.FETCH_TIMEOUT, retries: int = config.FETCH_RETRIES) -> bytes:
    """GET a URL, following redirects, transparently un-gzipping. Raises on final failure."""
    last = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            if data[:2] == b"\x1f\x8b":
                data = gzip.decompress(data)
            if not data.strip():
                raise ValueError("empty response body")
            return data
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError, OSError) as exc:
            last = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code in (404, 410):
                break  # a mirror that does not have the file will not grow it on retry
            log.warning("attempt %d/%d failed for %s: %s", attempt, retries, url, exc)
            time.sleep(min(2 ** attempt, 15))
    raise RuntimeError(f"fetch failed: {url}: {last}")


def http_get_json(url: str, **kw) -> dict:
    return json.loads(http_get(url, **kw).decode("utf-8"))


def fetch_first(urls: list[str]) -> tuple[bytes, str]:
    """Try each mirror in order; return (body, url_used)."""
    errors = []
    for raw_url in urls:
        url = _expand(raw_url)
        try:
            return http_get(url), url
        except RuntimeError as exc:
            errors.append(str(exc))
    raise RuntimeError("; ".join(errors))


# ---- committed cache of the *parsed* prefix list per source ----

def cache_path(name: str) -> Path:
    return CACHE_DIR / f"{name}.txt"


def cache_write(name: str, prefixes) -> None:
    CACHE_DIR.mkdir(exist_ok=True)
    cache_path(name).write_text("".join(f"{p}\n" for p in prefixes), encoding="utf-8")


def cache_read(name: str) -> list[str] | None:
    path = cache_path(name)
    if not path.is_file():
        return None
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
