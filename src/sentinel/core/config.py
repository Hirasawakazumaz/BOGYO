"""Configuration and ownership-scope models (pydantic v2).

Two documents:

* **settings** (``settings.yaml``) — operational knobs. All active capabilities
  default OFF; ``dry_run`` defaults ON.
* **scope** (``scope.yaml`` + detached ``scope.yaml.sig``) — the signed ownership
  attestation. The guard refuses every target that is not inside it, and the
  signature must verify against the scope public key or the whole program
  fails closed at startup.

API keys are referenced here only by *environment-variable name*. Secret values
are never stored in config files.
"""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, time
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator

from .errors import ConfigError
from .signing import canonical_bytes, load_public_key, sha256_hex, verify


# --------------------------------------------------------------------------- #
# settings.yaml
# --------------------------------------------------------------------------- #
class Toggles(BaseModel):
    """Every active capability is opt-in and defaults to False (default-deny)."""

    enable_blocking: bool = False
    enable_active_scan: bool = False
    enable_sandbox_redteam: bool = False
    enable_patch_apply: bool = False


class Limits(BaseModel):
    max_targets_per_run: int = Field(default=16, ge=1, le=4096)
    max_concurrency: int = Field(default=4, ge=1, le=64)
    rate_per_minute: int = Field(default=60, ge=1, le=10_000)
    scan_timeout_seconds: int = Field(default=900, ge=1, le=86_400)
    #: Optional allowed daily window, "HH:MM-HH:MM" local time. Empty = always.
    time_window: str = ""

    def window_bounds(self) -> Optional[tuple[time, time]]:
        if not self.time_window:
            return None
        try:
            start_s, end_s = self.time_window.split("-", 1)
            sh, sm = (int(x) for x in start_s.strip().split(":"))
            eh, em = (int(x) for x in end_s.strip().split(":"))
            return time(sh, sm), time(eh, em)
        except Exception as exc:  # noqa: BLE001
            raise ConfigError(f"invalid time_window {self.time_window!r}: {exc}") from exc


class IntakeConfig(BaseModel):
    #: Local log files to watch for attack signals.
    log_paths: list[str] = Field(default_factory=list)
    #: Threat-intel providers, each referencing an env var holding the API key.
    #: e.g. {"abuseipdb": "ABUSEIPDB_API_KEY"}
    threatintel_api_env: dict[str, str] = Field(default_factory=dict)

    def resolved_keys(self) -> dict[str, str]:
        """Return provider -> key value, pulling secrets from the environment only."""
        out: dict[str, str] = {}
        for provider, env_name in self.threatintel_api_env.items():
            val = os.environ.get(env_name)
            if val:
                out[provider] = val
        return out


class UIConfig(BaseModel):
    """User-interface preferences (chosen at init; editable via the control API)."""

    language: str = "en"  # English only; kept for settings compatibility


class GeoConfig(BaseModel):
    """Home location + attacker-IP geolocation for the dashboard world map."""

    #: ISO-3166 alpha-2 of the country you defend from (e.g. "JP").
    home_country: str = "JP"
    home_label: str = "HOME"
    #: Enable looking up attacker-IP countries via a public geo API (keyless).
    enable_geo_lookup: bool = False
    #: Keyless public endpoint; {ip} is substituted. Offline fallback = unknown.
    geo_api_url: str = "http://ip-api.com/json/{ip}?fields=status,countryCode,country,lat,lon"
    #: Offline, deterministic overrides {ip: ISO2}. Checked before the network, so
    #: known IPs resolve with no lookup (also powers the offline live demo).
    static_map: dict[str, str] = Field(default_factory=dict)


class UsageConfig(BaseModel):
    """Claude usage accounting + automatic throttling.

    provider "api": metered Claude API — a daily token budget governs how much
    runs; as the budget is consumed the governor downgrades the model and lowers
    run frequency, then stops, resuming when the daily window rolls over.
    provider "cli": Claude Code CLI subscription — no token metering, but run
    frequency can still be capped.
    """

    provider: str = "api"  # "api" (metered) | "cli" (subscription) | "local" (local AI)
    #: Local AI (OpenAI-compatible / Ollama) endpoint + model, used when provider=="local".
    local_endpoint: str = "http://localhost:11434/v1/chat/completions"
    local_model: str = "llama3.1"
    daily_token_budget: int = Field(default=1_000_000, ge=0)
    #: Model tiers from most to least capable; the governor steps down these.
    model_tiers: list[str] = Field(
        default_factory=lambda: ["claude-opus-4-8", "claude-sonnet-4-8", "claude-haiku-4-8"]
    )
    #: Budget fractions at which to downgrade model / halve frequency / stop.
    downgrade_at: float = Field(default=0.60, ge=0.0, le=1.0)
    throttle_at: float = Field(default=0.80, ge=0.0, le=1.0)
    stop_at: float = Field(default=1.0, ge=0.0, le=1.0)
    #: Baseline runs per hour when not throttled (frequency governor).
    base_runs_per_hour: int = Field(default=12, ge=1, le=3600)


class MeshPeer(BaseModel):
    name: str
    ed25519_pub: str = ""   # hex
    x25519_pub: str = ""    # hex
    domain: str = ""        # the patch domain this peer owns (e.g. "nginx")
    endpoint: str = ""      # transport address (reference; loopback used in-process)


class MeshConfig(BaseModel):
    """Distributed parallel-patch network among the operator's OWN servers only.

    Nodes authenticate with a machine-bound encrypted key file (not an API key),
    talk over a rolling-key channel, and share patches on a signed hash chain.
    Using it on anything other than your own servers is a consent violation.
    """

    enabled: bool = False
    node_name: str = ""
    domain: str = ""                         # this node's patch specialization
    key_file: str = "config/node.key.enc"    # encrypted node identity (machine-bound)
    chain_file: str = "state/patchchain.jsonl"
    time_window_seconds: int = Field(default=30, ge=1, le=3600)
    peers: list[MeshPeer] = Field(default_factory=list)


class Paths(BaseModel):
    scope_file: str = "config/scope.yaml"
    scope_sig_file: str = "config/scope.yaml.sig"
    scope_pubkey_file: str = "config/scope.pub"
    consent_file: str = "config/consent.signed"
    consent_pubkey_file: str = "config/consent.pub"
    audit_file: str = "state/audit.jsonl"
    usage_file: str = "state/usage.jsonl"
    killswitch_file: str = "state/KILL"
    state_dir: str = "state"


class Settings(BaseModel):
    dry_run: bool = True
    ui: UIConfig = Field(default_factory=UIConfig)
    toggles: Toggles = Field(default_factory=Toggles)
    limits: Limits = Field(default_factory=Limits)
    intake: IntakeConfig = Field(default_factory=IntakeConfig)
    usage: UsageConfig = Field(default_factory=UsageConfig)
    geo: GeoConfig = Field(default_factory=GeoConfig)
    mesh: MeshConfig = Field(default_factory=MeshConfig)
    paths: Paths = Field(default_factory=Paths)

    def save(self, path: str | Path) -> None:
        """Persist settings back to a YAML file (used by the TUI config screen)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump(self.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> "Settings":
        path = Path(path)
        if not path.exists():
            raise ConfigError(f"settings file not found: {path}")
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ConfigError("settings file must be a YAML mapping")
        return cls.model_validate(data)


# --------------------------------------------------------------------------- #
# scope.yaml  (signed ownership attestation)
# --------------------------------------------------------------------------- #
class ScopeDoc(BaseModel):
    """The operator's signed attestation of which assets they own / may test."""

    owner_name: str
    owner_org: str = ""
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    #: Hosts/CIDRs that are PRODUCTION. Active attack (redteam) is hard-refused here.
    production_hosts: list[str] = Field(default_factory=list)
    created_at: str = ""
    nonce: str = ""

    @field_validator("allowed_cidrs", "production_hosts")
    @classmethod
    def _validate_entries(cls, v: list[str]) -> list[str]:
        return [s.strip() for s in v if s.strip()]

    # -- hashing / identity -------------------------------------------------- #
    def canonical(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json"))

    def scope_hash(self) -> str:
        """Stable id of this scope; consent is bound to it, re-consent on change."""
        return sha256_hex(self.canonical())

    # -- membership tests ---------------------------------------------------- #
    @staticmethod
    def _as_ip(target: str):
        try:
            return ipaddress.ip_address(target)
        except ValueError:
            return None

    def _matches_set(self, target: str, hosts: list[str], cidrs: list[str]) -> bool:
        t = target.strip().lower()
        if t in {h.strip().lower() for h in hosts}:
            return True
        ip = self._as_ip(target)
        if ip is not None:
            for cidr in cidrs:
                try:
                    if ip in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
        return False

    def contains(self, target: str) -> bool:
        """True iff target is inside the attested ownership scope."""
        return self._matches_set(target, self.allowed_hosts, self.allowed_cidrs)

    def is_production(self, target: str) -> bool:
        """True iff target is flagged production (never an attack target)."""
        # production entries may be plain hostnames or CIDRs
        prod_hosts = [h for h in self.production_hosts if self._as_ip_network(h) is None]
        prod_cidrs = [h for h in self.production_hosts if self._as_ip_network(h) is not None]
        return self._matches_set(target, prod_hosts, prod_cidrs)

    @staticmethod
    def _as_ip_network(value: str):
        try:
            return ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None


def load_verified_scope(
    scope_file: str | Path,
    sig_file: str | Path,
    pubkey_file: str | Path,
) -> ScopeDoc:
    """Load the scope and verify its Ed25519 signature. Fail closed on any problem.

    The signature is computed over the scope's canonical bytes, so editing the
    scope file by hand (adding a host) invalidates it until re-signed.
    """
    scope_file, sig_file, pubkey_file = Path(scope_file), Path(sig_file), Path(pubkey_file)
    for p in (scope_file, sig_file, pubkey_file):
        if not p.exists():
            raise ConfigError(f"required scope artifact missing: {p}")

    data = yaml.safe_load(scope_file.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ConfigError("scope file must be a YAML mapping")
    scope = ScopeDoc.model_validate(data)

    pub = load_public_key(pubkey_file)
    signature = sig_file.read_bytes()
    # verify() raises SigningError on mismatch -> fail closed
    verify(pub, scope.canonical(), signature)
    return scope
