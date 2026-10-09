// Somente desenvolvimento local. NÃO é cert.axipy.org de produção.
import http from 'node:http';
import {generateKeyPairSync,createPrivateKey,createPublicKey} from 'node:crypto';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {keyId,cidOf,verifyObject,signObject,nonceRandom} from '../protocol/reference/codec.mjs';
import {checkSchema,iso} from '../src/contract.mjs';
const root=resolve(process.env.DEMO_CA_DIR||'var/authority-dev');await mkdir(root,{recursive:true,mode:0o700});
let privatePem;try{privatePem=await readFile(join(root,'authority-private.pem'),'utf8');}catch{
  const {privateKey}=generateKeyPairSync('ed25519');privatePem=privateKey.export({format:'pem',type:'pkcs8'}).toString();await writeFile(join(root,'authority-private.pem'),privatePem,{mode:0o600,flag:'wx'});
}
const exported=createPublicKey(createPrivateKey(privatePem)).export({format:'jwk'});
const pub={kty:'OKP',crv:'Ed25519',x:exported.x},id=keyId(pub);
await writeFile(join(root,'authority-public.json'),JSON.stringify({kty:'OKP',crv:'Ed25519',x:pub.x},null,2));
const port=Number(process.env.DEMO_CA_PORT||4800);
const server=http.createServer(async(req,res)=>{
  const reply=(code,data)=>{res.writeHead(code,{'content-type':'application/json'});res.end(JSON.stringify(data));};
  if(req.method!=='POST'||req.url!=='/v2/issue')return reply(404,{error:'not found'});
  let body='';for await(const chunk of req){body+=chunk;if(body.length>100000)return reply(413,{error:'too large'});}try{
    const value=JSON.parse(body);if(!checkSchema('issue-submit.schema.json',value))return reply(400,{error:'schema'});
    const request=value.request;if(!verifyObject(request,request.payload.subject_key,'request'))return reply(400,{error:'bad request signature'});
    if(Math.abs(Date.parse(request.payload.created_at)-Date.now())>600000)return reply(400,{error:'expired request'});
    let by=null,verification=null;
    if(value.forward){const f=value.forward;if(f.payload.request_cid!==cidOf(request)||f.payload.node_id!==keyId(f.payload.node_key)||!verifyObject(f,f.payload.node_key,'forward'))return reply(400,{error:'bad forward'});by=f.payload.node_id;verification='cryptographic';}
    const issued=new Date(),expires=new Date(issued.getTime()+365*24*3600000);
    const cert=signObject({type:'axipy.certificate',version:'2',issuer_id:id,subject_key:request.payload.subject_key,issued_at:issued.toISOString().slice(0,19)+'Z',expires_at:expires.toISOString().slice(0,19)+'Z',policy_id:'axipy-demo-only',registration:{requested_by:by,requester_verification:verification,method:'demo-local'},claims:{}},privatePem,'certificate');
    const result=signObject({type:'axipy.issue_result',version:'2',issuer_id:id,request_nonce:request.payload.nonce,status:'issued',issued_at:iso(),certificate:cert,reason:null},privatePem,'issue_result');
    return reply(200,result);
  }catch(e){console.error(e);return reply(400,{error:e.message});}
});server.listen(port,'127.0.0.1',()=>{console.log(`CERTIFICADORA DE TESTE: http://127.0.0.1:${port}/v2/issue`);console.log('ID:',id);console.log('PUBLIC KEY:',JSON.stringify(pub));console.log('chave pública armazenada em: '+join(root,'authority-public.json'));});
