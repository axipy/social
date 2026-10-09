// Produz vetores determinísticos. Chaves intencionalmente previsíveis: SÓ TESTES.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {deterministicTestKey,nonceTest,signObject,cidOf,encodeFrame,b64,verifyObject,keyId} from '../reference/codec.mjs';
const dir=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../examples');fs.mkdirSync(dir,{recursive:true});
const A=deterministicTestKey('authority-axipy');const X=deterministicTestKey('authority-untrusted');const U=deterministicTestKey('user-ana');const N=deterministicTestKey('node-alpha');const B=deterministicTestKey('node-beta');
const moment='2026-10-09T02:30:00Z';
function save(n,x){fs.writeFileSync(path.join(dir,n+'.json'),JSON.stringify(x,null,2)+'\n');}
function signed(n,p,key,domain){const x=signObject(p,key.privatePem,domain);save(n,x);return x;}
const req=signed('cert-request',{type:'axipy.cert_request',version:'2',subject_key:U.publicJwk,nonce:nonceTest('registration'),created_at:moment},U,'request');
const issueSubmit={request:req,forward:signed('issue-forward',{type:'axipy.issue_forward',version:'2',node_id:N.id,node_key:N.publicJwk,request_cid:cidOf(req),nonce:nonceTest('forward'),sent_at:moment},N,'forward')};save('issue-submit',issueSubmit);
const cert=signed('certificate',{type:'axipy.certificate',version:'2',issuer_id:A.id,subject_key:U.publicJwk,issued_at:'2026-10-09T00:00:00Z',expires_at:'2027-10-09T00:00:00Z',policy_id:'axipy-basic-v1',registration:{requested_by:N.id,requester_verification:'cryptographic',method:'signed-request'},claims:{}},A,'certificate');
const issueResult=signed('issue-result',{type:'axipy.issue_result',version:'2',issuer_id:A.id,request_nonce:req.payload.nonce,status:'issued',issued_at:moment,certificate:cert,reason:null},A,'issue_result');
const cCid=cidOf(cert);
const post=signed('post',{type:'axipy.post',version:'2',author_key_id:U.id,certificate_cid:cCid,created_at:moment,text:'Olá, AXIPY! Texto puro, identidade certificada e CID verificável.',reply_to:null},U,'post');
const pCid=cidOf(post);
const reply=signed('reply',{type:'axipy.post',version:'2',author_key_id:U.id,certificate_cid:cCid,created_at:'2026-10-09T02:31:00Z',text:'Uma resposta também é um post.',reply_to:pCid},U,'post');
const rev=signed('revocations',{type:'axipy.revocations',version:'2',issuer_id:A.id,sequence:1,issued_at:moment,next_update:'2026-10-10T02:30:00Z',revoked:[]},A,'revocations');
const authority=signed('authority-descriptor',{type:'axipy.authority',version:'2',authority_id:A.id,public_key:A.publicJwk,policy_id:'axipy-basic-v1',policy_uri:null,addresses:[{profile:'axipy-issuer-tcp/1',multiaddr:'/dns4/ac.axipy.example/tcp/4100'}],revocations_cid:cidOf(rev),issued_at:moment},A,'authority');
function node(name,K,port){return signed(name,{type:'axipy.node',version:'2',node_id:K.id,node_key:K.publicJwk,addresses:[{profile:'axipy-tcp/1',multiaddr:'/ip4/127.0.0.1/tcp/'+port}],supported_wire_versions:['2'],issued_at:moment,expires_at:'2026-10-10T02:30:00Z'},K,'node');}
const nodeA=node('node-a',N,4101);const nodeB=node('node-b',B,4102);
const peers=signed('peer-list',{type:'axipy.peer_list',version:'2',node_id:N.id,issued_at:moment,expires_at:'2026-10-10T02:30:00Z',nodes:[nodeB]},N,'peers');
const bodyBase=(kind,from,request_id,session_id,body)=>({type:'axipy.wire',version:'2',kind,from,request_id,session_id,sent_at:moment,body});
function msg(name,kind,key,session,body,requestId){return signed(name,bodyBase(kind,key.id,requestId||nonceTest(name),session,body),key,'wire');}
const handshakeId=nonceTest('handshake');const na=nonceTest('nonce-a'),nb=nonceTest('nonce-b'),sess=nonceTest('session');
const hello=msg('wire-hello','HELLO',N,null,{node_key:N.publicJwk,nonce_a:na,authorities:[A.id],wire_versions:['2']},handshakeId);
const challenge=msg('wire-challenge','CHALLENGE',B,null,{node_key:B.publicJwk,nonce_a:na,nonce_b:nb,accepted_authorities:[A.id],session:sess},handshakeId);
const confirm=msg('wire-confirm','CONFIRM',N,sess,{nonce_a:na,nonce_b:nb,session:sess},handshakeId);
const ready=msg('wire-ready','READY',B,sess,{session:sess,accepted_authorities:[A.id]},handshakeId);
const ann=msg('wire-announce','ANNOUNCE',N,sess,{cid:pCid,issuer_id:A.id,author_key_id:U.id});
const decision=msg('wire-decision','DECISION',B,sess,{cid:pCid,decision:'WANT',reason:null},ann.payload.request_id);
const want=msg('wire-want','WANT',B,sess,{cid:pCid});
const block=msg('wire-block-post','BLOCK',N,sess,{cid:pCid,object_type:'post',object:post},want.payload.request_id);
const wantCert=msg('wire-want-certificate','WANT',B,sess,{cid:cCid});
const blockCert=msg('wire-block-certificate','BLOCK',N,sess,{cid:cCid,object_type:'certificate',object:cert},wantCert.payload.request_id);
const found=msg('wire-find-providers','FIND_PROVIDERS',B,sess,{cid:pCid});
const providers=msg('wire-providers','PROVIDERS',N,sess,{cid:pCid,providers:[nodeA]},found.payload.request_id);
const peersWire=msg('wire-peers','PEERS',N,sess,{list:peers});
const goodbye=msg('wire-goodbye','GOODBYE',N,sess,{reason:null});
const badCert=signed('certificate-untrusted',{...cert.payload,issuer_id:X.id,policy_id:'outsider-basic-v1'},X,'certificate');
const tampered=JSON.parse(JSON.stringify(post));tampered.payload.text+=' adulterado';save('post-tampered-INVALID',tampered);
const manifest={spec_revision:'0.2',wire_version:'2',test_only:true,key_ids:{authority:A.id,other_authority:X.id,user:U.id,node_a:N.id,node_b:B.id},cids:{certificate:cCid,post:pCid,reply:cidOf(reply),revocations:cidOf(rev),authority:cidOf(authority),node_a:cidOf(nodeA),node_b:cidOf(nodeB)},session:sess};save('identifiers',manifest);
fs.writeFileSync(path.join(dir,'tcp-frame-announce.hex'),encodeFrame(ann).toString('hex')+'\n');
fs.writeFileSync(path.join(dir,'README.md'),'# Exemplos determinísticos AXIPY v2\n\nArquivos assinado com chaves de teste previsíveis. Nunca usar essas chaves para produção. O teste `post-tampered-INVALID.json` é deliberadamente inválido. `certificate-untrusted.json` tem assinatura correta, mas é recusado por quem só confia na autoridade AXIPY de teste.\n');
console.log('Generated',fs.readdirSync(dir).length,'example files');
console.log('Certificate CID:',cCid);console.log('Post CID:',pCid);
