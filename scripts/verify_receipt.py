"""Check SHA-256 commitments in an exported receipt or live-demo report.

This verifies local integrity only. Obtain the receipt independently from the chain
before relying on it, and compare previous_hash to the prior stored receipt.
"""
import argparse
import hashlib
import json
from pathlib import Path

def digest(value):
    encoded=json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('file',type=Path)
a=p.parse_args()
data=json.loads(a.file.read_text())
r=data.get('receipt',data)
if digest(r['decision']) != r['decision_hash']:
    p.error('decision hash mismatch')
if digest({k:v for k,v in r.items() if k!='receipt_hash'}) != r['receipt_hash']:
    p.error('receipt hash mismatch')
if r['attempt']==1 and r['previous_hash']!='0'*64:
    p.error('invalid genesis link')
print(f"Integrity verified: {r['claim_id']} attempt {r['attempt']} => {r['decision']['outcome']}")
