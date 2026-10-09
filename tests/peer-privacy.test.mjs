import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {PeerNetwork} from '../src/peers.mjs';
import {cidOf,decodeFrames,deterministicTestKey,signObject,verifyObject} from '../protocol/reference/codec.mjs';
import {checkSchema,iso} from '../src/contract.mjs';

const waitFor=async predicate=>{
  for(let i=0;i<100;i++){
    if(predicate())return;
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  throw Error('Timed out waiting for peer message');
};

function socketPair(){
  class Socket extends EventEmitter{
    messages=[];
    setNoDelay(){}
    write(raw){
      this.messages.push(...decodeFrames(raw).messages);
      queueMicrotask(()=>this.other.emit('data',raw));
    }
    destroy(){this.emit('close');}
    end(){this.destroy();}
  }
  const a=new Socket(),b=new Socket();a.other=b;b.other=a;return [a,b];
}

test('handshake keeps CA lists private; recipient filters and verifies announcements locally', {timeout:10000}, async()=>{
  const nodeA=deterministicTestKey('privacy-node-a');
  const nodeB=deterministicTestKey('privacy-node-b');
  const issuer=deterministicTestKey('privacy-ca');
  const otherIssuer=deterministicTestKey('privacy-other-ca');
  const author=deterministicTestKey('privacy-author');
  const identity=k=>({id:k.id,pub:k.publicJwk,privatePem:k.privatePem});
  const issuedAt=new Date(Date.now()-60000).toISOString().slice(0,19)+'Z';
  const expiresAt=new Date(Date.now()+86400000).toISOString().slice(0,19)+'Z';
  const cert=signObject({type:'axipy.certificate',version:'2',issuer_id:issuer.id,subject_key:author.publicJwk,issued_at:issuedAt,expires_at:expiresAt,policy_id:'test',registration:{requested_by:null,requester_verification:null,method:null},claims:{}},issuer.privatePem,'certificate');
  const makePost=text=>signObject({type:'axipy.post',version:'2',author_key_id:author.id,certificate_cid:cidOf(cert),created_at:iso(),text,reply_to:null},author.privatePem,'post');
  const post=makePost('A locally trusted post');
  const spoofed=makePost('A post with a false announced issuer');
  const aPosts=new Map([[cidOf(post),post],[cidOf(spoofed),spoofed]]);
  const bPosts=new Map(),bCerts=new Map();
  const trustA=new Map([[issuer.id,issuer.publicJwk]]);
  const trustB=new Map();
  const storeA={get:async(type,cid)=>type==='posts'?aPosts.get(cid):cid===cidOf(cert)?cert:null,feed:async()=>[]};
  const storeB={get:async(type,cid)=>type==='posts'?bPosts.get(cid):bCerts.get(cid),put:async(type,obj)=>{(type==='posts'?bPosts:bCerts).set(cidOf(obj),obj);},feed:async()=>[]};
  const common={port:0,host:'127.0.0.1',publicHost:'127.0.0.1'};
  const A=new PeerNetwork({...common,identity:identity(nodeA),store:storeA,getTrust:()=>({trust:trustA})});
  const B=new PeerNetwork({...common,identity:identity(nodeB),store:storeB,getTrust:()=>({trust:trustB})});
  const [socketA,socketB]=socketPair();
  const peerB=B.attach(socketB,false),peerA=A.attach(socketA,true);
  peerA.startHandshake();
  await waitFor(()=>peerA.ready&&peerB.ready);
  for(const [kind,socket,key] of [['HELLO',socketA,nodeA],['CHALLENGE',socketB,nodeB],['CONFIRM',socketA,nodeA],['READY',socketB,nodeB]]){
    const message=socket.messages.find(x=>x.payload.kind===kind);
    assert.ok(message,kind);
    assert.ok(checkSchema('wire-message.schema.json',message),kind+' schema');
    assert.ok(verifyObject(message,key.publicJwk,'wire'),kind+' signature');
    assert.ok(!Object.hasOwn(message.payload.body,'authorities'));
    assert.ok(!Object.hasOwn(message.payload.body,'accepted_authorities'));
  }
  assert.equal(peerA.session,peerB.session);
  assert.equal(peerA.requestId,peerB.requestId);
  assert.equal(peerA.nonceA,peerB.nonceA);
  assert.equal(peerA.nonceB,peerB.nonceB);

  await A.announceTo(peerA,post,cidOf(post));
  await waitFor(()=>socketB.messages.some(x=>x.payload.kind==='DECISION'));
  const first=socketB.messages.find(x=>x.payload.kind==='DECISION');
  assert.equal(first.payload.body.decision,'REJECT');
  assert.equal(first.payload.body.reason,null);
  assert.equal(socketB.messages.some(x=>x.payload.kind==='WANT'),false);
  assert.equal(bPosts.size,0);

  trustB.set(issuer.id,issuer.publicJwk);
  await A.announceTo(peerA,post,cidOf(post));
  await waitFor(()=>bPosts.has(cidOf(post)));
  assert.ok(socketB.messages.some(x=>x.payload.kind==='DECISION'&&x.payload.body.decision==='WANT'));
  assert.equal(bPosts.get(cidOf(post)).payload.certificate_cid,cidOf(cert));

  trustB.set(otherIssuer.id,otherIssuer.publicJwk);
  A.send(peerA,'ANNOUNCE',{cid:cidOf(spoofed),issuer_id:otherIssuer.id,author_key_id:author.id});
  await waitFor(()=>B.events.some(x=>x.message.includes('Anúncio diverge')));
  assert.equal(bPosts.has(cidOf(spoofed)),false);
  A.close();B.close();
});
