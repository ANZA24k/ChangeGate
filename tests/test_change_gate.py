import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def data(cg_module):
    c=cg_module
    p=json.loads((ROOT/'fixtures/policy.json').read_text())
    e=json.loads((ROOT/'fixtures/compliant.json').read_text())
    body=(ROOT/'fixtures/compliant.json').read_bytes()
    m={'change_id':e['change_id'],'artifact':e['artifact'],'url':'https://raw.githubusercontent.com/ANZA24k/ChangeGate/'+'a'*40+'/fixtures/compliant.json','sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body)}
    return c,p,e,m,body

def findings(c,e,status='SUPPORTED'):
    return {k:{'status':status,'quote':e['narratives'][k][:45],'reason':'The quoted context supports this assessment.'} for k in c.CONTROLS}

def test_roundtrip(data):
    c,p,e,m,b=data
    assert c.policy_data(json.dumps(p))==p
    assert c.manifest_data(json.dumps(m),p)==m
    assert c.evidence_data(b,p,m,c.digest(p))==e
    assert c.deterministic(p,e)==[]

@pytest.mark.parametrize('patch,code',[
    ({'deployed_at':1793750400},'OUTSIDE_WINDOW'),
    ({'tests_passed':False},'TEST_FAILED'),
    ({'test_completed_at':1793746800},'TEST_NOT_BEFORE_DEPLOYMENT'),
    ({'rollback_ready':False},'ROLLBACK_NOT_READY')])
def test_deterministic(data,patch,code):
    c,p,e,m,b=data; e.update(patch)
    assert code in c.deterministic(p,e)

@pytest.mark.parametrize('field,value,code',[
    ('at',1793746801,'APPROVAL_SEQUENCE'),('identity','mallory','UNAUTHORIZED_APPROVAL'),
    ('identity','carol@example.test','UNAUTHORIZED_APPROVAL'),('artifact','other','APPROVAL_ARTIFACT'),
    ('at',1793743300,'APPROVAL_SEQUENCE')])
def test_approval_attacks(data,field,value,code):
    c,p,e,m,b=data; e['approvals'][1][field]=value
    assert any(x.startswith(code) for x in c.deterministic(p,e))

@pytest.mark.parametrize('mode',['duplicate','missing','extra'])
def test_approval_cardinality(data,mode):
    c,p,e,m,b=data
    if mode=='duplicate': e['approvals'].append(copy.deepcopy(e['approvals'][0]))
    if mode=='missing': e['approvals']=[]
    if mode=='extra': e['approvals'].append(dict(role='attacker',identity='x',at=1,artifact='x'))
    assert c.deterministic(p,e)

@pytest.mark.parametrize('url',[
    'http://127.0.0.1/x','https://raw.githubusercontent.com.evil/a',
    'https://raw.githubusercontent.com/ANZA24k/ChangeGate/main/a.json',
    'https://raw.githubusercontent.com/ANZA24k/Other/'+'a'*40+'/a.json',
    'https://raw.githubusercontent.com/ANZA24k/ChangeGate/'+'a'*40+'/../a.json',
    'https://raw.githubusercontent.com/ANZA24k/ChangeGate/'+'a'*40+'/a.json?x=1'])
def test_urls(data,url):
    c,p,e,m,b=data; m['url']=url
    with pytest.raises(Exception): c.manifest_data(json.dumps(m),p)

@pytest.mark.parametrize('mode',['bytes','hash','identity','policy','boolean','float','duplicate'])
def test_bad_evidence(data,mode):
    c,p,e,m,b=data
    if mode=='bytes': m['bytes']+=1
    elif mode=='hash': m['sha256']='0'*64
    else:
        if mode=='identity': e['artifact']='other'
        if mode=='policy': e['policy_hash']='0'*64
        if mode=='boolean': e['tests_passed']=1
        if mode=='float': e['deployed_at']=1.0
        b=json.dumps(e).encode()
        if mode=='duplicate': b=b.replace(b'"change_id":',b'"change_id":"forged","change_id":')
        m['bytes']=len(b); m['sha256']=hashlib.sha256(b).hexdigest()
    with pytest.raises(Exception): c.evidence_data(b,p,m,c.digest(p))

@pytest.mark.parametrize('status,expected',[('SUPPORTED','COMPLIANT'),('GAP','CONDITIONAL'),('BREACH','VIOLATION'),('UNKNOWN','INCONCLUSIVE')])
def test_outcomes(data,status,expected):
    c,p,e,m,b=data; f=findings(c,e,status)
    assert c.outcome([],c.grounded(f,e))==expected
    assert c.outcome(['FAIL'],f)=='VIOLATION'

@pytest.mark.parametrize('mode',['quote','enum','extra','missing','reason'])
def test_ai_invalid(data,mode):
    c,p,e,m,b=data; f=findings(c,e)
    if mode=='quote': f['scope']['quote']='This text never occurred anywhere'
    if mode=='enum': f['scope']['status']='APPROVE'
    if mode=='extra': f['extra']={}
    if mode=='missing': del f['rollback']
    if mode=='reason': f['scope']['reason']=''
    with pytest.raises(Exception): c.grounded(f,e)

def test_consensus_independent(data,monkeypatch):
    c,p,e,m,b=data
    monkeypatch.setattr(c.gl.nondet.web,'get',lambda url:SimpleNamespace(status=200,body=b))
    answers=[findings(c,e),findings(c,e,'BREACH')]
    monkeypatch.setattr(c.gl.nondet,'exec_prompt',lambda *a,**k: answers.pop(0))
    one=c.assess(p,m,c.digest(p)); two=c.assess(p,m,c.digest(p))
    assert not c.equivalent(one,two)
    same=copy.deepcopy(one); same['findings']['scope']['reason']='Different wording is fine.'
    assert c.equivalent(one,same)

def test_fail_closed(data,monkeypatch):
    c,p,e,m,b=data
    monkeypatch.setattr(c.gl.nondet.web,'get',lambda url:SimpleNamespace(status=200,body=b+b' '))
    assert c.assess(p,m,c.digest(p))['outcome']=='INCONCLUSIVE'
    monkeypatch.setattr(c.gl.nondet.web,'get',lambda url:SimpleNamespace(status=200,body=b))
    monkeypatch.setattr(c.gl.nondet,'exec_prompt',lambda *a,**k: {'fake':'answer'})
    assert c.assess(p,m,c.digest(p))['error']=='AI_OUTPUT_INVALID'

def test_contract_lifecycle(data,monkeypatch):
    c,p,e,m,b=data
    state=SimpleNamespace(policies={},claims={},attempts={},receipts={},heads={})
    message=SimpleNamespace(sender_address='alice',contract_address='contract',chain_id=61999)
    monkeypatch.setattr(c.gl,'message',message)
    cls=c.ChangeGate
    pid=cls.register_policy(state,json.dumps(p))
    with pytest.raises(Exception): cls.register_policy(state,json.dumps(p))
    claim=cls.submit_change(state,pid,json.dumps(m))
    with pytest.raises(Exception): cls.submit_change(state,pid,json.dumps(m))
    message.sender_address='mallory'
    with pytest.raises(Exception): cls.submit_change(state,pid,json.dumps(dict(m,change_id='other')))
    with pytest.raises(Exception): cls.evaluate_change(state,claim)
    message.sender_address='alice'
    monkeypatch.setattr(c.gl.nondet.web,'get',lambda url:SimpleNamespace(status=200,body=b))
    monkeypatch.setattr(c.gl.nondet,'exec_prompt',lambda *a,**k: findings(c,e))
    calls=[]
    def consensus(leader,validator):
        result=leader(); assert validator(c.gl.vm.Return(result)); calls.append(1); return result
    monkeypatch.setattr(c.gl.vm,'run_nondet_unsafe',consensus)
    previous='0'*64
    for attempt in range(1,4):
        r=json.loads(cls.evaluate_change(state,claim))
        assert r['previous_hash']==previous and r['attempt']==attempt
        previous=r.pop('receipt_hash'); assert previous==c.digest(r)
        assert r['decision_hash']==c.digest(r['decision'])
        assert json.loads(cls.get_receipt(state,claim,attempt))['receipt_hash']==previous
    with pytest.raises(Exception): cls.evaluate_change(state,claim)
    assert len(calls)==3
    assert json.loads(cls.get_status(state,claim))['head']==previous

@pytest.mark.parametrize('attack',['fabricated_quote','changed_status','vm_error'])
def test_validator_rejects_proposals_without_consuming_attempt(data,monkeypatch,attack):
    c,p,e,m,b=data
    state=SimpleNamespace(policies={},claims={},attempts={},receipts={},heads={})
    monkeypatch.setattr(c.gl,'message',SimpleNamespace(sender_address='alice',contract_address='contract',chain_id=61999))
    pid=c.ChangeGate.register_policy(state,json.dumps(p))
    claim=c.ChangeGate.submit_change(state,pid,json.dumps(m))
    fetches=[]
    def fetch(url):
        fetches.append(url); return SimpleNamespace(status=200,body=b)
    monkeypatch.setattr(c.gl.nondet.web,'get',fetch)
    monkeypatch.setattr(c.gl.nondet,'exec_prompt',lambda *a,**k: findings(c,e))
    def consensus(leader,validator):
        proposed=copy.deepcopy(leader())
        if attack=='fabricated_quote': proposed['findings']['scope']['quote']='A fabricated approval that is not in this evidence'
        if attack=='changed_status': proposed['findings']['scope']['status']='BREACH'
        result=c.gl.vm.VMError('simulated') if attack=='vm_error' else c.gl.vm.Return(proposed)
        assert validator(result) is False
        raise RuntimeError('Rejected by simulated protocol')
    monkeypatch.setattr(c.gl.vm,'run_nondet_unsafe',consensus)
    with pytest.raises(RuntimeError): c.ChangeGate.evaluate_change(state,claim)
    assert state.attempts[claim]==0 and state.receipts=={} and state.heads[claim]=='0'*64
    if attack!='vm_error': assert len(fetches)>=2  # independent retrieval really occurred
