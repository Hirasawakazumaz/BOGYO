"""Core safety primitives: config, signing, consent, audit, kill-switch, errors.

These are implemented and loaded *before* any feature module. Feature modules
must not import network/agent dependencies at module import time.
"""
