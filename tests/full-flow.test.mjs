import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {generateKeyPairSync,createPublicKey,sign as signRaw} from 'node:crypto';
import {cidOf,nonceRandom,signObject,keyId,jcs,verifyObject} from '../protocol/reference/codec.mjs';
import {postVerify,checkSchema} from '../src/contract.mjs';
const root=resolve(import.meta.dirname,'..');
const nap=ms=>new Promise(r=>setTimeout(r,ms));
async function waitFor(url,deadline=12000){const until=Date.now()+deadline;while(Date.now()<until){try{const r=await fetch(url);if(r.ok)return r;}catch{}await nap(180);}throw Error('timeout: '+url);}
function launch(file,env){const p=spawn(process.execPath,[file],{cwd:root,env:{...process.env,...env},stdio:['ignore','pipe','pipe']});p.stderr.on('data',d=>process.stderr.write('[child] '+d));return p;}
async function post(port,path,data,cookie=''){const r=await fetch(`http://127.0.0.1:${port}${path}`,{method:'POST',headers:{'content-type':'application/json',origin:`http://127.0.0.1:${port}`,...(cookie?{cookie}: {})},body:JSON.stringify(data)});return {status:r.status,data:await r.json(),cookie:r.headers.get('set-cookie')};}

test('AXIPY: cadastro -> login por chave -> assinatura -> propagação TCP -> CID', {timeout:65000}, async()=>{
  const home=await mkdtemp(join(tmpdir(),'axipy-social-test-'));const processes=[];
  const caPort=4857,aWeb=3357,bWeb=3358,aPeer=4457,bPeer=4458;
  try{
    const caDir=join(home,'ca');await mkdir(caDir);
    processes.push(launch('dev/authority.mjs',{DEMO_CA_DIR:caDir,DEMO_CA_PORT:String(caPort)}));
    let pub;for(let i=0;i<60;i++){try{pub=JSON.parse(await readFile(join(caDir,'authority-public.json'),'utf8'));break;}catch{await nap(80);}}
    assert.ok(pub,'test issuer public key');const authorityId=keyId(pub);
    const trustPath=join(home,'trust.json');await writeFile(trustPath,JSON.stringify({authorities:[{name:'AXIPY',issuer_url:`http://127.0.0.1:${caPort}/v2/issue`,public_key:pub}]}));
    const makeEnv=(tag,web,peer,bootstrap='')=>({HOST:'127.0.0.1',PORT:String(web),PEER_HOST:'127.0.0.1',PEER_PORT:String(peer),PUBLIC_PEER_HOST:'127.0.0.1',DATA_DIR:join(home,tag),TRUST_CONFIG:trustPath,CERT_URL:`http://127.0.0.1:${caPort}/v2/issue`,BOOTSTRAPS:bootstrap});
    processes.push(launch('src/main.mjs',makeEnv('a',aWeb,aPeer)));await waitFor(`http://127.0.0.1:${aWeb}/api/status`);
    processes.push(launch('src/main.mjs',makeEnv('b',bWeb,bPeer,`/ip4/127.0.0.1/tcp/${aPeer}`)));await waitFor(`http://127.0.0.1:${bWeb}/api/status`);
    const {privateKey,publicKey}=generateKeyPairSync('ed25519');const k=publicKey.export({format:'jwk'});const pubUser={kty:'OKP',crv:'Ed25519',x:k.x},userId=keyId(pubUser);
    const certificateRequest=signObject({type:'axipy.cert_request',version:'2',subject_key:pubUser,nonce:nonceRandom(),created_at:new Date().toISOString().slice(0,19)+'Z'},privateKey.export({format:'pem',type:'pkcs8'}),'request');
    assert.equal(checkSchema('cert-request.schema.json',certificateRequest),true);
    const issuance=await post(aWeb,'/api/issue',{request:certificateRequest});assert.equal(issuance.status,200,JSON.stringify(issuance.data));
    const cert=issuance.data.result.payload.certificate;assert.equal(cert.payload.issuer_id,authorityId);assert.equal(checkSchema('certificate.schema.json',cert),true);
    const challenge=await post(aWeb,'/api/auth/challenge',{public_key:pubUser});assert.equal(challenge.status,200);
    const nonce=challenge.data.nonce;const signedLogin=Buffer.concat([Buffer.from('AXIPY/WEB-LOGIN/1\n'),jcs({nonce,key_id:userId})]);
    const signature=signRaw(null,signedLogin,privateKey).toString('base64url');
    const login=await post(aWeb,'/api/auth/login',{nonce,key_id:userId,signature,certificate:cert});assert.equal(login.status,200,JSON.stringify(login.data));
    const cookie=login.cookie.split(';')[0];
    const postObj=signObject({type:'axipy.post',version:'2',author_key_id:userId,certificate_cid:cidOf(cert),created_at:new Date().toISOString().slice(0,19)+'Z',text:'AXIPY integra dois nós por Wire TCP. Olá, federação!',reply_to:null},privateKey.export({format:'pem',type:'pkcs8'}),'post');
    assert.equal(postVerify(postObj,cert,new Map([[authorityId,pub]])),cidOf(postObj));
    const invalid={...postObj,payload:{...postObj.payload,text:'ALTERADO'}};
    const bad=await post(aWeb,'/api/posts',{post:invalid,certificate:cert},cookie);assert.notEqual(bad.status,201);
    const pubResult=await post(aWeb,'/api/posts',{post:postObj,certificate:cert},cookie);assert.equal(pubResult.status,201,JSON.stringify(pubResult.data));
    const cid=pubResult.data.cid;
    let found=false;for(let i=0;i<90;i++){const feed=await (await fetch(`http://127.0.0.1:${bWeb}/api/feed`)).json();if(feed.posts.some(p=>p.cid===cid)){found=true;break;}await nap(220);}
    assert.ok(found,'segundo nó deve receber o post');
    const object=await (await fetch(`http://127.0.0.1:${bWeb}/api/posts/${cid}`)).json();assert.equal(cidOf(object.post),cid);assert.equal(object.certificate.payload.issuer_id,authorityId);
    console.log('PASS: CA, chave, certificado, login, assinatura, CID e sincronização entre dois nós');
  }finally{for(const p of processes)p.kill('SIGTERM');await nap(250);await rm(home,{recursive:true,force:true});}
});
