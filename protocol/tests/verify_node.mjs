import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {cidOf,cidMatches,keyId,verifyObject,decodeCid,jcs,encodeFrame,decodeFrames} from '../reference/codec.mjs';
const E=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../examples');
const read=n=>JSON.parse(fs.readFileSync(path.join(E,n+'.json')));
function assert(x,msg){if(!x)throw Error(msg);}
const A=read('authority-descriptor'), C=read('certificate'), P=read('post'), R=read('reply'),N=read('node-a'),B=read('node-b'),REV=read('revocations'),IDs=read('identifiers');
const aKey=A.payload.public_key,uKey=C.payload.subject_key,nKey=N.payload.node_key,bKey=B.payload.node_key;
for(const [obj,k,domain] of [[A,aKey,'authority'],[C,aKey,'certificate'],[P,uKey,'post'],[R,uKey,'post'],[N,nKey,'node'],[B,bKey,'node'],[REV,aKey,'revocations']]) assert(verifyObject(obj,k,domain),'signature '+domain);
assert(P.payload.certificate_cid===cidOf(C),'referência ao certificado');
assert(P.payload.author_key_id===keyId(uKey),'vínculo do autor');
assert(C.payload.issuer_id===keyId(aKey),'vínculo da AC');
assert(R.payload.reply_to===cidOf(P),'referência ao post pai');
assert(cidOf(C)===IDs.cids.certificate && cidOf(P)===IDs.cids.post,'CID vs Python');
assert(decodeCid(cidOf(P)).length===32,'digest do CID');
const bad=read('post-tampered-INVALID');
assert(!verifyObject(bad,uKey,'post') && !cidMatches(cidOf(P),bad),'post adulterado');
const unk=read('certificate-untrusted');
assert(unk.payload.issuer_id!==C.payload.issuer_id,'autoridade fora do conjunto local');
for(const f of fs.readdirSync(E).filter(n=>n.startsWith('wire-')&&n.endsWith('.json'))){
 const obj=JSON.parse(fs.readFileSync(path.join(E,f)));
 const k=obj.payload.from===N.payload.node_id?nKey:bKey;
 assert(verifyObject(obj,k,'wire'),'wire signature '+f);
 const framed=encodeFrame(obj);
 const a=decodeFrames(framed.subarray(0,2)); assert(a.messages.length===0 && a.remainder.length===2,'prefixo fragmentado');
 const b=decodeFrames(Buffer.concat([a.remainder,framed.subarray(2)]));
 assert(b.messages.length===1 && b.remainder.length===0,'recomposição TCP');
 assert(jcs(b.messages[0]).equals(jcs(obj)),'frame roundtrip');
}
const issue=read('issue-result'),sub=read('issue-submit');
assert(verifyObject(issue,aKey,'issue_result'),'resultado emitido pela autoridade');
assert(verifyObject(sub.forward,nKey,'forward'),'encaminhamento assinado');
assert(sub.forward.payload.request_cid===cidOf(sub.request),'encaminhamento ligado ao pedido');
assert(jcs(P).length<262144,'bloco dentro dos limites');
assert(Buffer.byteLength(P.payload.text,'utf8')<=16384,'text dentro do limite');
console.log('PASS: Node Ed25519, CIDv1 raw, autor/certificado, mensagem Wire e cadastro');
console.log('PASS: frames TCP fragmentados, conteúdo adulterado rejeitado, AC distinta identificada');
