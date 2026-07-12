from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any


DEFAULT_DB_PATHS = (
    "~/.local/share/bs/GeoLite2-City.mmdb",
    "~/.local/share/bs/GeoLite2-Country.mmdb",
    "~/.local/share/bs/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
)

CITY_DB_PATHS = (
    "~/.local/share/bs/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
)

COUNTRY_DB_PATHS = (
    "~/.local/share/bs/GeoLite2-Country.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
)

ASN_DB_PATHS = (
    "~/.local/share/bs/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
)


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def non_public_location_reason(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "invalid IP address"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_loopback:
        return "loopback address (local host)"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_private:
        return "private address (local network)"
    return "non-public address"


def find_geo_db(explicit_path: str | None = None) -> str | None:
    candidates = [explicit_path] if explicit_path else []
    env_path = os.environ.get("BS_GEOIP_DB")
    if env_path:
        candidates.append(env_path)
    candidates.extend(DEFAULT_DB_PATHS)
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.exists():
            return str(path)
    return None


def _find_first(paths: tuple[str, ...]) -> str | None:
    for candidate in paths:
        path = Path(candidate).expanduser()
        if path.exists():
            return str(path)
    return None


def find_geo_dbs(explicit_path: str | None = None) -> dict[str, str]:
    dbs: dict[str, str] = {}
    if explicit_path:
        path = Path(explicit_path).expanduser()
        if path.exists():
            dbs["explicit"] = str(path)
            return dbs
    env_path = os.environ.get("BS_GEOIP_DB")
    if env_path:
        path = Path(env_path).expanduser()
        if path.exists():
            dbs["explicit"] = str(path)
            return dbs
    for name, paths in (("city", CITY_DB_PATHS), ("country", COUNTRY_DB_PATHS), ("asn", ASN_DB_PATHS)):
        found = _find_first(paths)
        if found:
            dbs[name] = found
    return dbs


def lookup_geo(ip: str, db_path: str | None = None) -> dict[str, Any] | None:
    if not is_public_ip(ip):
        return None
    resolved_dbs = find_geo_dbs(db_path)
    if not resolved_dbs:
        return {"ip": ip, "available": False, "reason": "no GeoLite/GeoIP .mmdb database found"}

    try:
        import geoip2.database
        import geoip2.errors
    except ImportError:
        return {"ip": ip, "available": False, "reason": "geoip2 Python package is not installed"}

    result: dict[str, Any] = {"ip": ip, "available": False, "databases": resolved_dbs}

    location_db = resolved_dbs.get("explicit") or resolved_dbs.get("city") or resolved_dbs.get("country")
    if location_db:
        try:
            with geoip2.database.Reader(location_db) as reader:
                try:
                    city = reader.city(ip)
                    result.update(
                        {
                            "available": True,
                            "country": city.country.iso_code,
                            "country_name": city.country.name,
                            "region": city.subdivisions.most_specific.name,
                            "city": city.city.name,
                            "latitude": city.location.latitude,
                            "longitude": city.location.longitude,
                            "accuracy_radius_km": city.location.accuracy_radius,
                        }
                    )
                except (geoip2.errors.AddressNotFoundError, AttributeError):
                    try:
                        country = reader.country(ip)
                        result.update(
                            {
                                "available": True,
                                "country": country.country.iso_code,
                                "country_name": country.country.name,
                            }
                        )
                    except (geoip2.errors.AddressNotFoundError, AttributeError):
                        pass
        except OSError as exc:
            result["location_error"] = str(exc)

    asn_db = resolved_dbs.get("asn")
    if asn_db and asn_db != location_db:
        try:
            with geoip2.database.Reader(asn_db) as reader:
                try:
                    asn = reader.asn(ip)
                    result.update(
                        {
                            "available": True,
                            "asn": asn.autonomous_system_number,
                            "organization": asn.autonomous_system_organization,
                        }
                    )
                except geoip2.errors.AddressNotFoundError:
                    pass
        except OSError as exc:
            result["asn_error"] = str(exc)

    if not result["available"]:
        result["reason"] = "address not found"
    return result
