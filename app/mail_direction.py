from __future__ import annotations

import re
from typing import Any

_EMAIL_RE = re.compile(
    r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}",
    re.I,
)


def organization_domains(raw_value: str) -> set[str]:
    return {
        value.strip().lower().rstrip(".")
        for value in raw_value.split(",")
        if value.strip()
    }


def extract_addresses(raw_value: Any) -> list[str]:
    """Return normalized addresses while preserving repeated deliveries."""
    return [
        address.lower()
        for address in _EMAIL_RE.findall(str(raw_value or ""))
    ]


def is_internal_address(address: str, domains: set[str]) -> bool:
    if "@" not in address:
        return False
    return address.rsplit("@", 1)[-1].lower().rstrip(".") in domains


def split_recipients(
    raw_value: Any,
    domains: set[str],
) -> tuple[list[str], list[str], list[str]]:
    addresses = extract_addresses(raw_value)
    internal = [address for address in addresses if is_internal_address(address, domains)]
    external = [address for address in addresses if not is_internal_address(address, domains)]
    return addresses, internal, external


def selected_recipient_count(
    all_addresses: list[str],
    selected_addresses: list[str],
    reported_count: Any,
) -> int:
    """Count only the selected side of a direction, conservatively for mixed rows."""
    try:
        reported = max(0, int(reported_count or 0))
    except (TypeError, ValueError):
        reported = 0
    parsed = len(selected_addresses)
    if parsed == len(all_addresses) and reported > parsed:
        return reported
    return parsed
