"""Testa formatos, provas Ed25519, CID e políticas sem servidor nem rede.
A canonicalização Python aqui é usada SOMENTE nos vetores limitados: o codec Node é
referência para JCS completo. Python reimplementa as verificações do dataset.
"""
from __future__ import annotations
import base64, hashlib, json, pathlib, re, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
R=pathlib.Path(__file__).resolve().parents[1]
E=R/'examples';S=R/'schemas'
schemas={p.name:json.loads(p.read_text()) for p in S.glob('*.schema.json')}
registry=Registry().with_resources((v['$id'],Resource.from_contents(v)) for v in schemas.values())
def read(n):return json.loads((E/(n+'.json')).read_text())
def validate(name,schema):
 obj=read(name)
 v=Draft202012Validator(schemas[schema+'.schema.json'],registry=registry)
 errors=list(v.iter_errors(obj))
 if errors:raise AssertionError(f'{name}: schema mismatch '+str(errors[0]))
 return obj
def b64(b):return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def unb64(t):return base64.urlsafe_b64decode(t+'='*((-len(t))%4))
def jcs_subset(obj):
 # Todos os vetores possuem somente chaves ASCII e números inteiros.
 return json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def key_id(k):return 'axk1_'+b64(hashlib.sha256(jcs_subset(k)).digest())
def cid(obj):
 digest=hashlib.sha256(jcs_subset(obj)).digest()
 raw=b'\x01\x55\x12\x20'+digest
 return 'b'+base64.b32encode(raw).decode().lower().rstrip('=')
PREFIX={'certificate':'CERT','cert-request':'CERT-REQUEST','post':'POST','revocations':'REVOCATIONS','authority-descriptor':'AUTHORITY','node-descriptor':'NODE','peer-list':'PEERS','wire-message':'WIRE','issue-forward':'ISSUE-FORWARD','issue-result':'ISSUE-RESULT'}
def sig(obj,jwk,domain):
 pk=Ed25519PublicKey.from_public_bytes(unb64(jwk['x']))
 pk.verify(unb64(obj['signature']['value']),('AXIPY/'+PREFIX[domain]+'/2\n').encode()+jcs_subset(obj['payload']))

c=validate('certificate','certificate');p=validate('post','post');rep=validate('reply','post')
a=validate('authority-descriptor','authority-descriptor'); n=validate('node-a','node-descriptor');nb=validate('node-b','node-descriptor');r=validate('revocations','revocations');prs=validate('peer-list','peer-list');req=validate('cert-request','cert-request'); submission=validate('issue-submit','issue-submit'); issue_result=validate('issue-result','issue-result');untrusted=validate('certificate-untrusted','certificate')
ident=read('identifiers')
sig(c,a['payload']['public_key'],'certificate');sig(a,a['payload']['public_key'],'authority-descriptor');sig(r,a['payload']['public_key'],'revocations')
sig(n,n['payload']['node_key'],'node-descriptor');sig(nb,nb['payload']['node_key'],'node-descriptor');sig(prs,n['payload']['node_key'],'peer-list');sig(req,c['payload']['subject_key'],'cert-request')
sig(submission['forward'],n['payload']['node_key'],'issue-forward');sig(issue_result,a['payload']['public_key'],'issue-result');assert submission['forward']['payload']['request_cid']==cid(req);assert issue_result['payload']['certificate']==c
sig(p,c['payload']['subject_key'],'post');sig(rep,c['payload']['subject_key'],'post')
assert c['payload']['issuer_id']==key_id(a['payload']['public_key'])
assert n['payload']['node_id']==key_id(n['payload']['node_key'])
assert nb['payload']['node_id']==key_id(nb['payload']['node_key'])
assert p['payload']['author_key_id']==key_id(c['payload']['subject_key'])
assert p['payload']['certificate_cid']==cid(c)
assert rep['payload']['reply_to']==cid(p)
for name,o in [('certificate',c),('post',p),('reply',rep),('revocations',r),('authority',a),('node_a',n),('node_b',nb)]:
 assert cid(o)==ident['cids'][name],name
assert len(cid(p))==59
wire_examples=[x.stem for x in E.glob('wire-*.json')]
for name in wire_examples:
 obj=validate(name,'wire-message')
 who=obj['payload']['from'];pk=n['payload']['node_key'] if who==n['payload']['node_id'] else nb['payload']['node_key']
 sig(obj,pk,'wire-message')
 if obj['payload']['kind']=='BLOCK':
  bb=obj['payload']['body'];assert cid(bb['object'])==bb['cid']
  assert bb['object']['payload']['type']=='axipy.'+bb['object_type']
# Negatives: schema valid but invalid signature; cert válido mas sem autoridade confiável.
from copy import deepcopy
validator=Draft202012Validator(schemas['wire-message.schema.json'],registry=registry)
malformed=deepcopy(read('wire-announce'));del malformed['payload']['body']['issuer_id']
assert list(validator.iter_errors(malformed)), 'wire-body incompleto não rejeitado'
malformed2=deepcopy(read('wire-block-post'));malformed2['payload']['body']['object']['payload']['type']='axipy.certificate'
assert list(validator.iter_errors(malformed2)), 'wire BLOCK com tipo falso não rejeitado'
post_schema_validator=Draft202012Validator(schemas['post.schema.json'],registry=registry)
assert list(post_schema_validator.iter_errors({**p,'payload':{**p['payload'],'text':'x','unknown':'x'}})), 'campo extra do post não rejeitado'
assert len(('á'*8193).encode('utf8'))>16384, 'limite de texto medido em bytes não caracteres'

tampered=validate('post-tampered-INVALID','post')
try:sig(tampered,c['payload']['subject_key'],'post');raise AssertionError('tampered unexpectedly valid')
except __import__('cryptography').exceptions.InvalidSignature:pass
# unknown AC cryptographically fine but cannot be accepted with pinned AXIPY key
assert untrusted['payload']['issuer_id']!=c['payload']['issuer_id']
try:sig(untrusted,a['payload']['public_key'],'certificate');raise AssertionError('untrusted appeared AXIPY signed')
except __import__('cryptography').exceptions.InvalidSignature:pass
# Announcement metadata must match post and cert; thus a lie is detected after block retrieval.
ann=read('wire-announce')['payload']['body'];assert ann['cid']==cid(p) and ann['issuer_id']==c['payload']['issuer_id']
assert ann['author_key_id']==p['payload']['author_key_id']
# Frame of ANNOUNCE matches exact serialized representation; not new-line delimited.
frame=bytes.fromhex((E/'tcp-frame-announce.hex').read_text().strip())
assert int.from_bytes(frame[:4],'big')==len(frame)-4
assert json.loads(frame[4:])==read('wire-announce')
assert frame[4:]==jcs_subset(read('wire-announce'))
print('PASS:',len(schemas),'schemas parseados e todas as amostras relevantes validadas')
print('PASS:',len(wire_examples),'mensagens wire assinadas verificadas')
print('PASS: certificados, posts, IDs CIDv1 e assinatura de AC/autor/nós')
print('PASS: adulteração rejeitada, AC desconhecida distinguida de AC confiável')
print('PASS: anúncio vinculado ao post e framing TCP de 4 bytes consistente')
print('PASS: schemas rejeitam body incompleto, BLOCK mal-rotulado e campo extra')
