# SPDX-License-Identifier: MPL-2.0
"""Small publication guard. This is not a replacement for a secret scanner."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', '.venv', '.venv-public', '__pycache__', '.pytest_cache'}
PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'github-token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b'),
    'google-client-secret': re.compile(r'\bGOCSPX-[A-Za-z0-9_-]{20,}\b'),
    'jwt-literal': re.compile(r'\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b'),
}
failures = []
for path in ROOT.rglob('*'):
    rel = path.relative_to(ROOT)
    if not path.is_file() or any(part in SKIP for part in rel.parts):
        continue
    if (path.name.startswith('.env') and path.name != '.env.example') or path.suffix.lower() in {'.eml', '.mbox', '.pem', '.key', '.log', '.zip', '.jpg', '.png'}:
        failures.append((str(rel), 'private-artifact'))
        continue
    try:
        text = path.read_text(encoding='utf-8')
    except UnicodeError:
        failures.append((str(rel), 'unexpected-binary'))
        continue
    for rule, pattern in PATTERNS.items():
        if pattern.search(text):
            failures.append((str(rel), rule))
    if path.name == '.env.example':
        for line in text.splitlines():
            if line.startswith(('MAILRU_APP_PASSWORD=', 'MCP_ACCESS_TOKEN=', 'GOOGLE_CLIENT_SECRET=', 'GOOGLE_CLIENT_ID=')) and line.split('=', 1)[1].strip():
                failures.append((str(rel), 'nonempty-example-secret'))
for path, rule in failures:
    print(f'{path}: {rule}')  # Never print the matched value.
if failures:
    sys.exit(1)
print('Publication guard passed: no forbidden artifacts or known credential patterns found.')
