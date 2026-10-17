"""Diagnostics: active scanning of in-scope hosts and passive CVE lookups."""

from .scanner import ScanPlan, Scanner

__all__ = ["Scanner", "ScanPlan"]
