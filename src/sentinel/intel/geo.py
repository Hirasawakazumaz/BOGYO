"""IP -> country geolocation (public API, offline-safe) + country centroids.

``lookup_ip`` uses a keyless public endpoint only when enabled and reachable;
otherwise it returns an "unknown" result. Private/reserved IPs are never sent
anywhere. ``country_centroid`` maps an ISO-3166 alpha-2 code to an approximate
(lat, lon) used to place markers on the ASCII world map.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

from ..core.config import GeoConfig

# Approximate country centroids (ISO alpha-2 -> lat, lon). Not exhaustive; the
# world map degrades gracefully to "unknown" for anything missing.
COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    "JP": (36.2, 138.3), "US": (39.8, -98.6), "CN": (35.9, 104.2), "RU": (61.5, 105.3),
    "KR": (36.5, 127.8), "KP": (40.3, 127.5), "IN": (22.0, 79.0), "DE": (51.2, 10.4),
    "FR": (46.6, 2.2), "GB": (54.0, -2.0), "BR": (-10.3, -53.2), "CA": (56.1, -106.3),
    "AU": (-25.3, 133.8), "NL": (52.1, 5.3), "SG": (1.35, 103.8), "HK": (22.3, 114.2),
    "TW": (23.7, 121.0), "VN": (14.1, 108.3), "ID": (-2.5, 118.0), "TH": (15.0, 101.0),
    "IR": (32.4, 53.7), "TR": (39.0, 35.2), "UA": (48.4, 31.2), "PL": (51.9, 19.1),
    "IT": (41.9, 12.6), "ES": (40.0, -3.7), "SE": (62.2, 17.6), "FI": (64.0, 26.0),
    "NO": (64.6, 17.9), "ZA": (-30.6, 22.9), "EG": (26.8, 30.8), "NG": (9.1, 8.7),
    "MX": (23.6, -102.5), "AR": (-38.4, -63.6), "CL": (-35.7, -71.5), "SA": (23.9, 45.1),
    "AE": (23.4, 53.8), "IL": (31.0, 34.8), "PK": (30.4, 69.3), "BD": (23.7, 90.4),
    "MY": (4.2, 101.9), "PH": (12.9, 121.8), "RO": (45.9, 24.9), "CZ": (49.8, 15.5),
    "CH": (46.8, 8.2), "AT": (47.6, 14.6), "BE": (50.6, 4.6), "GR": (39.1, 21.8),
}


@dataclass(frozen=True)
class GeoResult:
    ip: str
    country_code: str = "??"
    country: str = "Unknown"
    lat: Optional[float] = None
    lon: Optional[float] = None
    ok: bool = False


def _is_public(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (obj.is_private or obj.is_loopback or obj.is_reserved or obj.is_link_local or obj.is_multicast)


def country_centroid(country_code: str) -> Optional[tuple[float, float]]:
    return COUNTRY_CENTROIDS.get((country_code or "").upper())


def lookup_ip(ip: str, config: GeoConfig) -> GeoResult:
    """Resolve an IP's country. Offline/by-default -> unknown (never fails)."""
    if not _is_public(ip):
        return GeoResult(ip=ip, country="Private/Local", ok=False)
    if not config.enable_geo_lookup:
        return GeoResult(ip=ip, ok=False)
    try:
        import requests  # optional dependency
    except ImportError:
        return GeoResult(ip=ip, ok=False)
    try:
        resp = requests.get(config.geo_api_url.format(ip=ip), timeout=8)
        resp.raise_for_status()
        data = resp.json()
    except Exception:  # noqa: BLE001 - geo is best-effort
        return GeoResult(ip=ip, ok=False)
    if data.get("status") != "success":
        return GeoResult(ip=ip, ok=False)
    cc = data.get("countryCode", "??")
    lat, lon = data.get("lat"), data.get("lon")
    if lat is None or lon is None:
        c = country_centroid(cc)
        if c:
            lat, lon = c
    return GeoResult(
        ip=ip, country_code=cc, country=data.get("country", "Unknown"),
        lat=lat, lon=lon, ok=True,
    )
