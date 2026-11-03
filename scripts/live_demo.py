"""Deploy or exercise ChangeGate using a disposable, externally supplied Studionet key.

Private keys are read from CHANGEGATE_KEY_FILE and never written to reports.
The demo uses only synthetic evidence. No real-world certification is implied.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from eth_account import Account
from genlayer_py import create_client
from genlayer_py.chains import studionet
from genlayer_py.types.transactions import TransactionStatus
ROOT=Path(__file__).resolve().parents[1]
def canonical(x): return json.dumps(x,sort_keys=True,separators=(',', ':'),ensure_ascii=True)
def digest(x): return hashlib.sha256(canonical(x).encode()).hexdigest()
def hx(x):
    v=x.hex() if hasattr(x,'hex') else str(x)
    return v if v.startswith('0x') else '0x'+v

def summary(r):
    leaders=r.get('consensus_data',{}).get('leader_receipt',[])
    if isinstance(leaders,dict): leaders=[leaders]
    return {'hash':r.get('hash'),'status':r.get('status_name'), 'consensus_result':r.get('result_name'),
            'to':r.get('to_address'),'leader_only':r.get('leader_only'),
            'leaders':[{'mode':x.get('mode'),'execution_result':x.get('execution_result'),'result':x.get('result'),
                        'genvm_result':x.get('genvm_result')} for x in leaders if x.get('mode')=='leader'],
            'votes':r.get('consensus_data',{}).get('votes',{})}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--address',required=True)
    ap.add_argument('--commit',required=True); ap.add_argument('--variant',default='compliant',choices=['compliant','violation','injection','ambiguous'])
    args=ap.parse_args()
    account=Account.from_key(Path(os.environ['CHANGEGATE_KEY_FILE']).read_text().strip())
    client=create_client(chain=studionet,account=account)
    report_path=ROOT/'deployments'/('live-'+args.variant+'.json')
    report=json.loads(report_path.read_text()) if report_path.exists() else {'network':'studionet','chain_id':61999,'contract':args.address,'evidence_commit':args.commit,'transactions':{}}
    if report['contract'] != args.address or report['evidence_commit'] != args.commit:
        raise RuntimeError('Saved run belongs to a different contract or evidence commit; archive it first')
    if report.get('signer',account.address) != account.address:
        raise RuntimeError('Saved run belongs to another signer')
    report['signer']=account.address
    def save(): report_path.write_text(json.dumps(report,indent=2,default=str)+'\n')
    def send(label,method,params):
        if label not in report['transactions']:
            tx=client.write_contract(address=args.address,function_name=method,args=params,consensus_max_rotations=3)
            report['transactions'][label]={'hash':hx(tx)}; save(); print(label,hx(tx),flush=True)
        txid=report['transactions'][label]['hash']
        r=client.wait_for_transaction_receipt(txid,status=TransactionStatus.FINALIZED,interval=3000,retries=100)
        s=summary(r); report['transactions'][label]=s; save()
        print(label,s['status'],[(x['execution_result']) for x in s['leaders']],flush=True)
        if not s['leaders'] or any(x['execution_result']!='SUCCESS' for x in s['leaders']):
            raise RuntimeError('Execution failed; see saved report')
    p=json.loads((ROOT/'fixtures/policy.json').read_text())
    pid=digest({'owner':account.address,'policy':p})
    # Reuse immutable policy already registered by this key.
    try: registered=client.read_contract(address=args.address,function_name='get_policy',args=[pid])
    except Exception: registered=None
    if not registered: send('register_policy','register_policy',[canonical(p)])
    report['policy_id']=pid
    b=(ROOT/'fixtures'/f'{args.variant}.json').read_bytes(); e=json.loads(b)
    m={'change_id':e['change_id'],'artifact':e['artifact'],'url':f'https://raw.githubusercontent.com/ANZA24k/ChangeGate/{args.commit}/fixtures/{args.variant}.json','sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)}
    claim=digest({'policy_id':pid,'manifest':m}); report['claim_id']=claim; report['manifest']=m; save()
    send('submit_change','submit_change',[pid,canonical(m)])
    send('evaluate_change','evaluate_change',[claim])
    receipt=client.read_contract(address=args.address,function_name='get_receipt',args=[claim,1])
    report['receipt']=json.loads(receipt); save()
    print('VERDICT',report['receipt']['decision']['outcome'],report['receipt']['decision']['error'],flush=True)

if __name__=='__main__': main()
