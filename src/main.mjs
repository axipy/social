import http from 'node:http';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {readFileSync} from 'node:fs';
import {resolve,join,extname,normalize,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,randomBytes,createPublicKey,verify as verifyRaw} from 'node:crypto';
import {Store} from './store.mjs';
import {loadNodeIdentity} from './identity.mjs';
import {PeerNetwork} from './peers.mjs';
import {checkSchema,trustFromConfig,certVerify,postVerify,validNewKey,iso,CIDS,KEYIDS} from './contract.mjs';
import {cidOf,nonceRandom,signObject,verifyObject,keyId,jcs,unb64} from '../protocol/reference/codec.mjs';

const ROOT=resolve(fileURLToPath(new URL('..',import.meta.url)));
const ENV=resolve(ROOT,'.env');
try{const contents=readFileSync(ENV,'utf8');for(const line of contents.split(/\r?\n/)){const m=line.match(/^\s*([A-Z][A-Z0-9_]*)=(.*)\s*$/);if(m&&process.env[m[1]]===undefined)process.env[m[1]]=m[2].trim();}}catch{}
const host=process.env.HOST||'127.0.0.1',port=Number(process.env.PORT||3000);
const peerHost=process.env.PEER_HOST||'0.0.0.0',peerPort=Number(process.env.PEER_PORT||4101);
const publicPeerHost=process.env.PUBLIC_PEER_HOST||'127.0.0.1';
const dataDir=resolve(ROOT,process.env.DATA_DIR||'var');
const trustConfig=resolve(ROOT,process.env.TRUST_CONFIG||'config/trusted-authorities.json');
const peerConfig=resolve(ROOT,'config/peers.json');
const certUrl=process.env.CERT_URL||'https://cert.axipy.org/v2/issue';
const sessions=new Map(),challenges=new Map(),rates=new Map(),profilePath=join(dataDir,'profiles.json');
const store=new Store(dataDir);await store.init();
const identity=await loadNodeIdentity(dataDir);
let profileLabels={};try{profileLabels=JSON.parse(await readFile(profilePath,'utf8'));}catch{}
const saveLabels=async()=>writeFile(profilePath,JSON.stringify(profileLabels),{mode:0o600});
const getTrust=()=>trustFromConfig(trustConfig);
let bootstraps=[];try{bootstraps=JSON.parse(await readFile(peerConfig,'utf8')).bootstrap??[];}catch{}
bootstraps.push(...(process.env.BOOTSTRAPS||'').split(',').map(s=>s.trim()).filter(Boolean));
const network=new PeerNetwork({identity,store,getTrust,host:peerHost,port:peerPort,publicHost:publicPeerHost,bootstraps});
await network.listen();
const publicDir=resolve(ROOT,'public');
const contentTypes={'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.jpg':'image/jpeg','.svg':'image/svg+xml','.ico':'image/x-icon','.json':'application/json; charset=utf-8'};
function send(res,status,data,headers={}){const text=JSON.stringify(data);res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers});res.end(text);}
function fail(res,status,message){send(res,status,{error:message});}
function getCookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').map(c=>c.trim().split('=').slice(0,2)).filter(([k,v])=>k&&v));}
function session(req){const token=getCookies(req).axipy_session;const s=token?sessions.get(createHash('sha256').update(token).digest('hex')):null;if(!s||s.expires<Date.now())return null;return s;}
function requireLogin(req){const s=session(req);if(!s)throw Object.assign(Error('Faça login com sua chave privada'),{status:401});return s;}
function clientIP(req){if(process.env.USE_PROXY_HEADERS==='true'){const forwarded=req.headers['x-forwarded-for'];if(typeof forwarded==='string'&&forwarded.length<512)return forwarded.split(',')[0].trim();}return req.socket.remoteAddress||'unknown';}
function limit(req,bucket,max,windowMs=60000){const key=bucket+clientIP(req),now=Date.now(),entry=rates.get(key)||{n:0,until:now+windowMs};if(entry.until<now){entry.n=0;entry.until=now+windowMs;}entry.n++;rates.set(key,entry);if(entry.n>max)throw Object.assign(Error('Muitas tentativas; aguarde um pouco'),{status:429});}
function enforceOrigin(req){const origin=req.headers.origin;if(!origin)throw Object.assign(Error('Origin obrigatório'),{status:403});const hostHeader=req.headers.host;const expectedProto=process.env.USE_PROXY_HEADERS==='true'&&req.headers['x-forwarded-proto']==='https'?'https':req.socket.encrypted?'https':'http';if(origin!==`${expectedProto}://${hostHeader}`)throw Object.assign(Error('Origem não autorizada'),{status:403});}
async function bodyJson(req,max=262144){let total=0;const chunks=[];for await(const c of req){total+=c.length;if(total>max)throw Object.assign(Error('Corpo excede limite'),{status:413});chunks.push(c);}const b=Buffer.concat(chunks).toString('utf8');let obj;try{obj=JSON.parse(b);}catch{throw Object.assign(Error('JSON malformado'),{status:400});}if(!obj||typeof obj!=='object'||Array.isArray(obj))throw Object.assign(Error('JSON deve ser um objeto'),{status:400});return obj;}
async function serveFile(url,res){let name=url.pathname;if(name==='/')name='/index.html';if(!/^\/[a-zA-Z0-9_./-]+$/.test(name)||name.includes('..'))return fail(res,404,'Não encontrado');const filepath=resolve(publicDir,'.'+name);if(!filepath.startsWith(publicDir+sep))return fail(res,404,'Não encontrado');try{const buff=await readFile(filepath);res.writeHead(200,{'content-type':contentTypes[extname(filepath)]||'application/octet-stream','cache-control':'public, max-age=120','x-content-type-options':'nosniff'});res.end(buff);}catch{fail(res,404,'Arquivo não encontrado');}}
function records(){return {trusted:getTrust().entries,ready:getTrust().trust.size>0};}
function trimKey(k){return typeof k==='string'?k.slice(0,18):'';}
async function handler(req,res){
  res.setHeader('x-content-type-options','nosniff');res.setHeader('referrer-policy','no-referrer');res.setHeader('x-frame-options','DENY');res.setHeader('permissions-policy','camera=(),microphone=(),geolocation=()');
  res.setHeader('content-security-policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  const url=new URL(req.url||'/',`http://${req.headers.host||'localhost'}`);const path=url.pathname;
  try{
    if(!path.startsWith('/api/')){if(req.method!=='GET')return fail(res,405,'Método não permitido');return await serveFile(url,res);}
    if(req.method==='GET'&&path==='/api/status')return send(res,200,{project:'AXIPY Social',wire_version:'2',node_id:identity.id,authority:records(),issuer_endpoint:certUrl,network:network.status(),text_limit_bytes:16384,session:session(req)?{id:session(req).id}:null});
    if(req.method==='GET'&&path==='/api/feed'){
      const limitN=Math.min(100,Math.max(1,Number(url.searchParams.get('limit')||60)));
      let rows=await store.feed(1000);
      if(url.searchParams.has('author'))rows=rows.filter(r=>r.object.payload.author_key_id===url.searchParams.get('author'));
      if(url.searchParams.has('reply_to'))rows=rows.filter(r=>r.object.payload.reply_to===url.searchParams.get('reply_to'));
      return send(res,200,{posts:rows.slice(0,limitN).map(({cid,object})=>({cid,...object.payload,issuer_id:null,author_name:profileLabels[object.payload.author_key_id]||null})),total:rows.length});
    }
    if(req.method==='GET'&&/^\/api\/posts\/b[a-z2-7]{58}$/.test(path)){
      const cid=path.split('/').pop();const post=await store.get('posts',cid);if(!post)return fail(res,404,'Post não encontrado');const certificate=await store.get('certificates',post.payload.certificate_cid);return send(res,200,{cid,post,certificate});
    }
    if(req.method==='GET'&&path==='/api/peers')return send(res,200,network.status());
    if(req.method==='POST')enforceOrigin(req);
    if(req.method==='POST'&&path==='/api/issue'){
      limit(req,'issuer:',8);const {request}=await bodyJson(req);
      if(!checkSchema('cert-request.schema.json',request)||!verifyObject(request,request.payload.subject_key,'request'))return fail(res,400,'Solicitação de certificação inválida');
      if(Math.abs(Date.parse(request.payload.created_at)-Date.now())>600000)return fail(res,400,'Solicitação expirada');
      if(!getTrust().trust.size)return fail(res,503,'Chave pública da certificadora ainda não configurada no nó');
      const forward=signObject({type:'axipy.issue_forward',version:'2',node_id:identity.id,node_key:identity.pub,request_cid:cidOf(request),nonce:nonceRandom(),sent_at:iso()},identity.privatePem,'forward');
      const envelope={request,forward};
      if(!checkSchema('issue-submit.schema.json',envelope))return fail(res,500,'Erro criando envelope para certificadora');
      const abort=new AbortController();const timeout=setTimeout(()=>abort.abort(),12000);
      let response;try{response=await fetch(certUrl,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(envelope),signal:abort.signal});}catch{return fail(res,503,'A certificadora cert.axipy.org está indisponível');}finally{clearTimeout(timeout);}
      let result;try{result=await response.json();}catch{return fail(res,502,'Resposta inválida da certificadora');}
      if(!checkSchema('issue-result.schema.json',result)||result.payload.request_nonce!==request.payload.nonce)return fail(res,502,'Resultado de certificação incompatível');
      const authorityKey=getTrust().trust.get(result.payload.issuer_id);
      if(!authorityKey||!verifyObject(result,authorityKey,'issue_result'))return fail(res,502,'Assinatura de emissão não reconhecida');
      if(result.payload.status==='issued'){
        try{certVerify(result.payload.certificate,getTrust().trust);if(keyId(result.payload.certificate.payload.subject_key)!==keyId(request.payload.subject_key))throw Error();}
        catch{return fail(res,502,'Certificado da autoridade não confere com a chave solicitada');}
        await store.put('certificates',result.payload.certificate);
      }
      return send(res,200,{result});
    }
    if(req.method==='POST'&&path==='/api/auth/challenge'){
      limit(req,'challenge:',30);const data=await bodyJson(req,4096);
      const id=validNewKey(data.public_key);const challenge=nonceRandom();
      challenges.set(challenge,{id,publicKey:data.public_key,expires:Date.now()+120000});
      if(challenges.size>5000)for(const [n,s] of challenges)if(s.expires<Date.now())challenges.delete(n);
      return send(res,200,{nonce:challenge,key_id:id,expires_in_seconds:120});
    }
    if(req.method==='POST'&&path==='/api/auth/login'){
      limit(req,'login:',20);const data=await bodyJson(req,262144);const entry=challenges.get(data.nonce);challenges.delete(data.nonce);
      if(!entry||entry.expires<Date.now())return fail(res,401,'Desafio expirou');
      if(data.key_id!==entry.id)return fail(res,401,'Chave divergente');
      const cert=data.certificate;
      try{certVerify(cert,getTrust().trust);if(keyId(cert.payload.subject_key)!==entry.id)throw Error('Certificado pertence a outra chave');}
      catch(e){return fail(res,401,e.message);}
      if(typeof data.signature!=='string')return fail(res,401,'Assinatura ausente');
      const signed=Buffer.concat([Buffer.from('AXIPY/WEB-LOGIN/1\n'),jcs({nonce:data.nonce,key_id:entry.id})]);
      let valid=false;try{valid=verifyRaw(null,signed,createPublicKey({key:entry.publicKey,format:'jwk'}),unb64(data.signature));}catch{}
      if(!valid)return fail(res,401,'Prova de posse inválida');
      const token=randomBytes(32).toString('base64url');sessions.set(createHash('sha256').update(token).digest('hex'),{id:entry.id,expires:Date.now()+Number(process.env.SESSION_HOURS||12)*3600000});
      const isTLS=req.socket.encrypted||process.env.USE_PROXY_HEADERS==='true'&&req.headers['x-forwarded-proto']==='https';
      res.setHeader('set-cookie',`axipy_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Number(process.env.SESSION_HOURS||12)*3600}${isTLS?'; Secure':''}`);
      await store.put('certificates',cert);
      return send(res,200,{ok:true,key_id:entry.id});
    }
    if(req.method==='POST'&&path==='/api/auth/logout'){
      const cookie=getCookies(req).axipy_session;if(cookie)sessions.delete(createHash('sha256').update(cookie).digest('hex'));
      res.setHeader('set-cookie','axipy_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return send(res,200,{ok:true});
    }
    if(req.method==='POST'&&path==='/api/profile'){
      const s=requireLogin(req);limit(req,'profile:'+s.id+':',20);const {display_name}=await bodyJson(req,1024);
      if(typeof display_name!=='string'||[...display_name].length>40||!display_name.trim()||/[\x00-\x1f<>]/.test(display_name))return fail(res,400,'Nome inválido');
      profileLabels[s.id]=display_name.trim();await saveLabels();return send(res,200,{ok:true,display_name:profileLabels[s.id]});
    }
    if(req.method==='POST'&&path==='/api/posts'){
      const s=requireLogin(req);limit(req,'post:'+s.id+':',20);const {post,certificate}=await bodyJson(req);
      const cid=postVerify(post,certificate,getTrust().trust);if(post.payload.author_key_id!==s.id)return fail(res,403,'Você não é o autor deste post');
      await store.put('certificates',certificate);await store.put('posts',post);await network.broadcast(post,cid);
      network.emit('post',cid);return send(res,201,{ok:true,cid});
    }
    return fail(res,404,'Rota inexistente');
  }catch(e){const status=e.status||400;console.error('[AXIPY]',req.method,path,e.message);return fail(res,status,status>=500?'Erro interno: '+e.message:e.message);}
}
const server=http.createServer(handler);server.listen(port,host,()=>{console.log(`\nAXIPY Social → http://${host}:${port}`);console.log(`AXIPY Wire/TCP → ${peerHost}:${peerPort}`);console.log(`Nó: ${identity.id}`);console.log(getTrust().trust.size?'Certificadora reconhecida.':'CONFIGURAÇÃO PENDENTE: instale a chave pública da certificadora.');});
process.on('SIGTERM',()=>{network.close();server.close();});
process.on('SIGINT',()=>{network.close();server.close();});
