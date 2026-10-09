import {readFile,writeFile} from 'node:fs/promises';
import {createPublicKey} from 'node:crypto';
import {resolve} from 'node:path';
import {keyId,validatePublicKey} from '../protocol/reference/codec.mjs';
const [input,outArg]=process.argv.slice(2);
if(!input){console.error('Uso: node tools/install-authority.mjs CAMINHO_DA_CHAVE_PUBLICA [CAMINHO_DO_TRUST_JSON]');process.exit(1);}
const file=resolve(input);let k;const content=await readFile(file,'utf8');
if(content.trim().startsWith('{')){const o=JSON.parse(content);k=o.public_key||o;}else{k=createPublicKey(content).export({format:'jwk'});}
const pub={kty:'OKP',crv:'Ed25519',x:k.x};validatePublicKey(pub);const id=keyId(pub);
const out=resolve(outArg||'config/trusted-authorities.json');
const json={authorities:[{name:'AXIPY',issuer_url:'https://cert.axipy.org/v2/issue',public_key:pub}]};
await writeFile(out,JSON.stringify(json,null,2)+'\n',{mode:0o600});
console.log('Chave pública da autoridade instalada em:',out);console.log('issuer_id:',id);console.log('ATENÇÃO: a identidade desta autoridade deve ser confirmada por um canal confiável antes de aceitar certificados em produção.');
