"""Credential-safe build/release diagnostics; never read credential files or stores."""
from __future__ import annotations
import json
import os
import re
import urllib.parse


def redact_output(text: str, env: dict[str, str] | None = None) -> str:
    values = dict(os.environ)
    if env is not None:
        values.update(env)
    secrets = {value for key, value in values.items() if value and
               re.search(r'(?:^|_)(?:TOKEN|PASSWORD|SECRET|API_KEY)$', key, re.I)}
    variants = set()
    for secret in secrets:
        variants.update((secret, json.dumps(secret)[1:-1], urllib.parse.quote(secret, safe=''),
                         urllib.parse.quote_plus(secret, safe='')))
    variants.update(re.sub(r'%[A-F0-9]{2}', lambda match: match[0].lower(), value)
                    for value in tuple(variants))
    for value in sorted(variants, key=len, reverse=True):
        # Percent-escape hex digits are case-insensitive independently per byte.
        pattern = re.sub(r'%([0-9a-fA-F]{2})', lambda match: '%' + ''.join(
            '[' + char.lower() + char.upper() + ']' if char.isalpha() else char
            for char in match[1]), re.escape(value))
        text = re.sub(pattern, '[REDACTED]', text)
    text = re.sub(r'\b(?:pypi-|cio)[A-Za-z0-9_-]+', '[REDACTED]', text)
    # Child HTTP diagnostics may quote headers as JSON or Python dictionaries.
    text = re.sub(r'''(?i)(\bauthorization["']?\s*[:=]\s*["']?(?:basic|bearer)\s+)(?!\[REDACTED\])[^\s"',}\]]+''',
                  r'\1[REDACTED]', text)
    # URL userinfo/query diagnostics must also be safe for saved-store tokens
    # whose exact value is intentionally unknown to this process.
    text = re.sub(r'(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/@]+@', r'\1[REDACTED]@', text)
    text = re.sub(r'''(?i)(\b(?:[a-z0-9_]*(?:token|password|secret|api_key))["']?\s*[:=]\s*)(?!\[REDACTED\])(?:"[^"\n]*"|'[^'\n]*'|[^\s,;&}\]]+)''',
                  r'\1[REDACTED]', text)
    return text


def safe_command(cmd: list[str], env: dict[str, str] | None = None) -> list[str]:
    safe = []
    hide_next = False
    options = ('--token', '--password', '-p', '--api-key', '--secret', '--access-token')
    for arg in cmd:
        if hide_next:
            safe.append('[REDACTED]')
            hide_next = False
            continue
        hide_next = arg in options
        arg = re.sub(r'^(--(?:token|password|api-key|secret|access-token)=).*', r'\1[REDACTED]', arg)
        safe.append(redact_output(arg, env))
    return safe
