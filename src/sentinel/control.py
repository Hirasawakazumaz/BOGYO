"""Machine-readable control surface so other apps can read and change every
display and settings item via internal commands / JSON.

Exposed through the CLI as:
  sentinel config dump            # full settings as JSON
  sentinel config get  <dotted>   # one value as JSON
  sentinel config set  <dotted> <value>   # set + persist (JSON result)
  sentinel state --json           # live dashboard state as JSON

Safety: ``set`` is limited to operational keys (ui/toggles/limits/usage/geo/
intake/dry_run). It refuses to touch ``paths.*`` and the signed scope/consent
artifacts — those have their own signed flows — so the control API can never
quietly undermine the scope/consent guarantees. The guard still enforces
consent, scope, sandbox-only and production rules at action time regardless of
any toggle flipped here.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from .core.config import Settings
from .core.errors import ConfigError

#: Dotted-key prefixes an external app may change via `config set`.
SETTABLE_PREFIXES = ("dry_run", "ui.", "toggles.", "limits.", "usage.", "geo.", "intake.", "mesh.")
#: Never settable through the control API (signed / path-sensitive).
FORBIDDEN_PREFIXES = ("paths.",)


def dump(settings: Settings) -> dict:
    return settings.model_dump(mode="json")


def get_value(settings: Settings, dotted: str) -> Any:
    node: Any = settings
    for part in dotted.split("."):
        if isinstance(node, dict):
            if part not in node:
                raise ConfigError(f"no such key: {dotted}")
            node = node[part]
        elif hasattr(node, part):
            node = getattr(node, part)
        else:
            raise ConfigError(f"no such key: {dotted}")
    if dataclasses.is_dataclass(node):
        return dataclasses.asdict(node)
    if hasattr(node, "model_dump"):
        return node.model_dump(mode="json")
    return node


def _is_settable(dotted: str) -> bool:
    if any(dotted == p or dotted.startswith(p) for p in FORBIDDEN_PREFIXES):
        return False
    return dotted == "dry_run" or any(
        dotted == p.rstrip(".") or dotted.startswith(p) for p in SETTABLE_PREFIXES
    )


def set_value(settings: Settings, dotted: str, raw_value: str, settings_path: str) -> dict:
    """Coerce + set one key, re-validate the whole config, and persist. JSON result."""
    if not _is_settable(dotted):
        raise ConfigError(
            f"key {dotted!r} is not settable via the control API "
            f"(allowed: {', '.join(SETTABLE_PREFIXES)}; scope/consent/paths use signed flows)"
        )
    # Parse the value as JSON when possible (true/1/"x"/[...]) else treat as string.
    try:
        value: Any = json.loads(raw_value)
    except (json.JSONDecodeError, TypeError):
        value = raw_value

    data = settings.model_dump(mode="json")
    node: Any = data
    parts = dotted.split(".")
    for part in parts[:-1]:
        if not isinstance(node, dict) or part not in node:
            raise ConfigError(f"no such key: {dotted}")
        node = node[part]
    leaf = parts[-1]
    if not isinstance(node, dict) or leaf not in node:
        raise ConfigError(f"no such key: {dotted}")
    node[leaf] = value

    try:
        new_settings = Settings.model_validate(data)  # fail closed on bad types
    except Exception as exc:  # noqa: BLE001
        raise ConfigError(f"invalid value for {dotted}: {exc}") from exc
    new_settings.save(settings_path)
    return {"ok": True, "key": dotted, "value": value}


def state_dict(settings: Settings) -> dict:
    """Live dashboard state as a plain dict (for `sentinel state --json`)."""
    from .dashboard import DashboardModel

    st = DashboardModel(settings).build()
    return dataclasses.asdict(st)
