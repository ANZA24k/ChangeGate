"""Print the byte-bound manifest for a committed synthetic evidence file."""
import argparse
import hashlib
import json
import re
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('file',type=Path)
p.add_argument('commit')
a=p.parse_args()
if not re.fullmatch('[0-9a-f]{40}',a.commit): p.error('commit must be a full lowercase SHA')
root=Path(__file__).resolve().parents[1]
f=a.file.resolve(); relative=f.relative_to(root).as_posix()
b=f.read_bytes(); e=json.loads(b)
print(json.dumps({'change_id':e['change_id'],'artifact':e['artifact'],
 'url':f'https://raw.githubusercontent.com/ANZA24k/ChangeGate/{a.commit}/{relative}',
 'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)},indent=2))
