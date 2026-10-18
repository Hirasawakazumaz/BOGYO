"""Tiny i18n layer (English / Japanese) for dashboard and CLI strings.

Chosen at ``sentinel init`` and stored as ``ui.language`` in settings; any
external app can read or change it through the control API (``sentinel config``).
``t(key, lang)`` falls back to English, then to the key itself.
"""

from __future__ import annotations

LANGUAGES = ("en", "ja")

_T: dict[str, dict[str, str]] = {
    "en": {
        "app.title": "SENTINEL-GUARD // GLOBAL DEFENSE GRID",
        "panel.worldmap": "WORLD MAP",
        "panel.status": "DEFENSE STATUS",
        "panel.usage": "CLAUDE USAGE GOVERNOR",
        "panel.ips": "ATTACKER IPs",
        "panel.patches": "PATCHES",
        "panel.config": "CONFIG",
        "lbl.blocked_ips": "blocked IPs",
        "lbl.breaches": "breaches",
        "lbl.vulns": "vulns",
        "lbl.authorizations": "authorizations",
        "lbl.tests": "tests",
        "lbl.patches": "patches",
        "lbl.audit": "audit",
        "lbl.provider": "provider",
        "lbl.level": "level",
        "lbl.model": "model",
        "lbl.tokens_today": "tokens today",
        "lbl.runs_per_hour": "runs/hour",
        "lbl.run_allowed": "run allowed",
        "lbl.resets": "resets",
        "lbl.home": "HOME",
        "lbl.blocked": "blocked",
        "lbl.active": "active",
        "lbl.none_yet": "(none yet)",
        "init.choose_language": "Choose language / 言語を選択 [en/ja]",
    },
    "ja": {
        "app.title": "SENTINEL-GUARD // 世界防衛グリッド",
        "panel.worldmap": "世界地図",
        "panel.status": "防御ステータス",
        "panel.usage": "CLAUDE 使用量ガバナー",
        "panel.ips": "攻撃元IP",
        "panel.patches": "パッチ",
        "panel.config": "設定",
        "lbl.blocked_ips": "遮断IP数",
        "lbl.breaches": "突破件数",
        "lbl.vulns": "脆弱件数",
        "lbl.authorizations": "認可",
        "lbl.tests": "テスト",
        "lbl.patches": "パッチ",
        "lbl.audit": "監査",
        "lbl.provider": "プロバイダ",
        "lbl.level": "状態",
        "lbl.model": "モデル",
        "lbl.tokens_today": "本日のトークン",
        "lbl.runs_per_hour": "実行回数/時",
        "lbl.run_allowed": "実行可否",
        "lbl.resets": "リセット",
        "lbl.home": "自国",
        "lbl.blocked": "遮断",
        "lbl.active": "進行中",
        "lbl.none_yet": "(まだありません)",
        "init.choose_language": "Choose language / 言語を選択 [en/ja]",
    },
}


def normalize_lang(lang: str) -> str:
    lang = (lang or "en").strip().lower()[:2]
    return lang if lang in LANGUAGES else "en"


def t(key: str, lang: str = "en") -> str:
    lang = normalize_lang(lang)
    return _T.get(lang, {}).get(key) or _T["en"].get(key) or key
