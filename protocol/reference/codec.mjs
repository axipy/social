// Implementação mínima das operações determinísticas do protocolo AXIPY v2.
// NÃO é uma implementação obrigatória, nem servidor. Somente referência/testes.
import {createHash,createPrivateKey,createPublicKey,sign,verify,randomBytes} from 'node:crypto';
export const domains={certificate:'AXIPY/CERT/2\n',request:'AXIPY/CERT-REQUEST/2\n',post:'AXIPY/POST/2\n',authority:'AXIPY/AUTHORITY/2\n',revocations:'AXIPY/REVOCATIONS/2\n',node:'AXIPY/NODE/2\n',peers:'AXIPY/PEERS/2\n',wire:'AXIPY/WIRE/2\n',forward:'AXIPY/ISSUE-FORWARD/2\n',issue_result:'AXIPY/ISSUE-RESULT/2\n'};
export const b64=x=>Buffer.from(x).toString('base64url');
export function unb64(t){if(typeof t!=='string'|| !/^[A-Za-z0-9_-]+$/.test(t))throw Error('base64url');const b=Buffer.from(t,'base64url');if(b64(b)!==t)throw Error('noncanonical base64url');return b;}
export const hash=x=>createHash('sha256').update(x).digest();
function safeUnicode(s){for(let i=0;i<s.length;i++){const n=s.charCodeAt(i);if(n>=0xD800&&n<=0xDBFF){if(i+1===s.length||s.charCodeAt(i+1)<0xDC00||s.charCodeAt(i+1)>0xDFFF)throw Error('surrogate inválido');i++;}else if(n>=0xDC00&&n<=0xDFFF)throw Error('surrogate inválido');}}
// RFC8785 para I-JSON: strings e números ECMAScript, ordenação UTF-16.
export function jcs(v){function f(x){if(x===null)return 'null';if(typeof x==='string'){safeUnicode(x);return JSON.stringify(x);}if(typeof x==='boolean')return x?'true':'false';if(typeof x==='number'){if(!Number.isFinite(x)||Number.isInteger(x)&&!Number.isSafeInteger(x))throw Error('número inválido');return JSON.stringify(x);}if(Array.isArray(x))return '['+x.map(f).join(',')+']';if(x&&typeof x==='object'&&Object.getPrototypeOf(x)===Object.prototype){return '{'+Object.keys(x).sort().map(k=>{safeUnicode(k);return JSON.stringify(k)+':'+f(x[k]);}).join(',')+'}';}throw Error('JSON inválido');}return Buffer.from(f(v),'utf8');}
export function validatePublicKey(k){if(!k||Object.keys(k).sort().join(',')!=='crv,kty,x'||k.kty!=='OKP'||k.crv!=='Ed25519'||unb64(k.x).length!==32)throw Error('JWK inválida');return k;}
export function keyId(k){return 'axk1_'+b64(hash(jcs(validatePublicKey(k))));}
export function signObject(payload,pem,domain){if(!domains[domain])throw Error('contexto desconhecido');const data=Buffer.concat([Buffer.from(domains[domain]),jcs(payload)]);return {payload,signature:{algorithm:'Ed25519',value:b64(sign(null,data,createPrivateKey(pem)))}};}
export function verifyObject(o,k,domain){try {if(!o||o.signature?.algorithm!=='Ed25519'||unb64(o.signature.value).length!==64)return false;const data=Buffer.concat([Buffer.from(domains[domain]),jcs(o.payload)]);return verify(null,data,createPublicKey({key:validatePublicKey(k),format:'jwk'}),unb64(o.signature.value));}catch{return false;}}
const AB='abcdefghijklmnopqrstuvwxyz234567';
function base32(b){let bits=0,x=0,out='';for(const n of b){x=(x<<8)|n;bits+=8;while(bits>=5){out+=AB[(x>>>(bits-5))&31];bits-=5;}}if(bits)out+=AB[(x<<(5-bits))&31];return out;}
function unbase32(t){let bits=0,x=0,out=[];for(const c of t){const n=AB.indexOf(c);if(n<0)throw Error('base32 char');x=(x<<5)|n;bits+=5;if(bits>=8){out.push((x>>>(bits-8))&255);bits-=8;}}if(bits&&((x&((1<<bits)-1))!==0))throw Error('base32 padding bits');const b=Buffer.from(out);if(base32(b)!==t)throw Error('base32 não canônico');return b;}
export function cidOf(o){const raw=hash(jcs(o));return 'b'+base32(Buffer.concat([Buffer.from([1,0x55,0x12,0x20]),raw]));}
export function decodeCid(cid){if(typeof cid!=='string'||!/^b[a-z2-7]{58}$/.test(cid))throw Error('CID inválido');const x=unbase32(cid.slice(1));if(x.length!==36||x[0]!==1||x[1]!==0x55||x[2]!==0x12||x[3]!==0x20)throw Error('CIDv1 raw sha256 obrigatório');return x.subarray(4);}
export function cidMatches(cid,o){try{return hash(jcs(o)).equals(decodeCid(cid));}catch{return false;}}
export function encodeFrame(o){const body=jcs(o);if(body.length>1048576)throw Error('frame grande');const result=Buffer.alloc(4+body.length);result.writeUInt32BE(body.length,0);body.copy(result,4);return result;}
export function decodeFrames(buffer){const out=[];let p=0;while(p+4<=buffer.length){const n=buffer.readUInt32BE(p);if(n<1||n>1048576)throw Error('frame inválido');if(p+4+n>buffer.length)break;const raw=buffer.subarray(p+4,p+4+n);const obj=JSON.parse(raw.toString('utf8'));if(!jcs(obj).equals(raw))throw Error('frame não JCS');out.push(obj);p+=4+n;}return {messages:out,remainder:buffer.subarray(p)};}
export function deterministicTestKey(label){const seed=hash(Buffer.from('AXIPY-TEST-ONLY:'+label));const pkcs8=Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]);const priv=createPrivateKey({key:pkcs8,format:'der',type:'pkcs8'});const pub=createPublicKey(priv).export({format:'jwk'});return {privatePem:priv.export({format:'pem',type:'pkcs8'}).toString(),publicJwk:pub,id:keyId(pub)};}
export const nonceTest=label=>b64(hash(Buffer.from('AXIPY-NONCE-TEST:'+label)));
export const nonceRandom=()=>b64(randomBytes(32));
