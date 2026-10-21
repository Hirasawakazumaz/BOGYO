"""External control API (config get/set/dump, state) + i18n + static geo map."""

from __future__ import annotations

import pytest

from sentinel import control
from sentinel.core.config import GeoConfig, Settings
from sentinel.core.errors import ConfigError
from sentinel.i18n import normalize_lang, t
from sentinel.intel.geo import lookup_ip


def _settings_file(env, tmp_path):
    sp = str(tmp_path / "settings.yaml")
    env.settings.save(sp)
    return Settings.load(sp), sp


def test_config_get_set_dump_roundtrip(make_env, tmp_path):
    s, sp = _settings_file(make_env(), tmp_path)
    assert control.get_value(s, "usage.daily_token_budget") == 1_000_000
    res = control.set_value(s, "usage.daily_token_budget", "500000", sp)
    assert res["ok"] and res["value"] == 500000
    assert Settings.load(sp).usage.daily_token_budget == 500000
    assert control.dump(Settings.load(sp))["usage"]["daily_token_budget"] == 500000


def test_config_set_bool_and_nested(make_env, tmp_path):
    s, sp = _settings_file(make_env(), tmp_path)
    control.set_value(s, "dry_run", "false", sp)
    control.set_value(Settings.load(sp), "toggles.enable_blocking", "true", sp)
    control.set_value(Settings.load(sp), "ui.language", '"en"', sp)
    out = Settings.load(sp)
    assert out.dry_run is False and out.toggles.enable_blocking is True and out.ui.language == "en"


def test_config_set_forbidden_path_refused(make_env, tmp_path):
    s, sp = _settings_file(make_env(), tmp_path)
    with pytest.raises(ConfigError):
        control.set_value(s, "paths.audit_file", '"/tmp/evil"', sp)


def test_config_set_invalid_type_refused(make_env, tmp_path):
    s, sp = _settings_file(make_env(), tmp_path)
    with pytest.raises(ConfigError):
        control.set_value(s, "usage.daily_token_budget", '"not-a-number"', sp)


def test_state_dict_is_json_serializable(make_env, tmp_path):
    s, sp = _settings_file(make_env(), tmp_path)
    d = control.state_dict(s)
    assert "home_country" in d and "attackers" in d and "usage" in d


def test_i18n_english_only():
    assert t("panel.status", "en") == "DEFENSE STATUS"
    assert t("panel.status", "ja") == "DEFENSE STATUS"  # legacy setting -> English
    assert t("nonexistent.key") == "nonexistent.key"  # falls back to key
    assert normalize_lang("JA") == "en" and normalize_lang("xx") == "en"


def test_static_geo_map_resolves_offline():
    g = GeoConfig(static_map={"203.0.113.9": "RU"})
    r = lookup_ip("203.0.113.9", g)  # no network, geo lookup disabled
    assert r.ok and r.country_code == "RU" and r.lat is not None and r.lon is not None
