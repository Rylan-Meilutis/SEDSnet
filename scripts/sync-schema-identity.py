#!/usr/bin/env python3
"""Explicit developer sync/check; ordinary builds never modify source files."""
import argparse
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
authoritative = (root / 'src/schema_identity.rs').read_bytes()
mirror = b'// Generated mirror of src/schema_identity.rs; run scripts/sync-schema-identity.py.\n' + authoritative
# Extract protocol mappings from the authoritative resolver. Application names
# never appear here; both language bindings use the same u32 FNV namespace.
text = authoritative.decode()
endpoints, types = text.split('pub const fn type_id', 1)
def protocol_table(source):
    return {name: int(value) for name, value in re.findall(r'=> \("([A-Z0-9_]+)", (\d+)\)', source)}
py = '''# Generated from src/schema_identity.rs by scripts/sync-schema-identity.py.
# No application or test identity belongs in the protocol tables.
ENDPOINT_PROTOCOL = %r
TYPE_PROTOCOL = %r


def resolve_id(name, explicit=None, *, endpoint=False):
    if not isinstance(name, str) or not name:
        raise ValueError("schema name must not be empty")
    table = ENDPOINT_PROTOCOL if endpoint else TYPE_PROTOCOL
    value = 0x811C9DC5 ^ (0x4550 if endpoint else 0x5459)
    for byte in name.encode("utf-8"):
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    default = table.get(name, 0x10000 | (value & 0x0FFFFFFF))
    if explicit is not None and (type(explicit) is not int or not 0 <= explicit <= 0xFFFFFFFF):
        raise ValueError("schema id must be a u32 integer")
    value = default if explicit is None else explicit
    reserved = 200 <= value <= 202 if endpoint else 0 <= value <= 18
    if (name in table and value != default) or (reserved and table.get(name) != value):
        raise ValueError("schema ID conflicts with a reserved SEDSNET protocol identity")
    return value
''' % (protocol_table(endpoints), protocol_table(types.split('const fn equal', 1)[0]))
outputs = {root / 'sedsnet_macros/src/schema_identity.rs': mirror,
           root / 'schema_identity.py': py.encode()}
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
for path, contents in outputs.items():
    if args.check:
        if path.read_bytes() != contents:
            raise SystemExit(f'Generated schema identity mirror differs: {path}')
    else:
        path.write_bytes(contents)
