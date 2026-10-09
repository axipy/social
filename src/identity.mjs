import {generateKeyPairSync,createPrivateKey,createPublicKey,randomBytes} from 'node:crypto';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {keyId,nonceRandom,signObject} from '../protocol/reference/codec.mjs';
export async function loadNodeIdentity(dataDir){
  await mkdir(dataDir,{recursive:true,mode:0o700});
  const filename=join(dataDir,'node-identity.pem');let privatePem;
  try {privatePem=await readFile(filename,'utf8');}
  catch(e){if(e.code!=='ENOENT')throw e;const {privateKey}=generateKeyPairSync('ed25519');privatePem=privateKey.export({format:'pem',type:'pkcs8'}).toString();await writeFile(filename,privatePem,{mode:0o600,flag:'wx'});}
  const publicKey=createPublicKey(createPrivateKey(privatePem)).export({format:'jwk'});
  const pub={kty:'OKP',crv:'Ed25519',x:publicKey.x};
  return {privatePem,pub,id:keyId(pub)};
}
export function createNodeDescriptor(identity,peerHost,peerPort){
  const address=peerHost.includes(':')?`/ip6/${peerHost}/tcp/${peerPort}`:peerHost.match(/^\d+\.\d+\.\d+\.\d+$/)?`/ip4/${peerHost}/tcp/${peerPort}`:`/dns4/${peerHost}/tcp/${peerPort}`;
  const issued=new Date(),expires=new Date(issued.valueOf()+23*3600000);
  return signObject({type:'axipy.node',version:'2',node_id:identity.id,node_key:identity.pub,addresses:[{profile:'axipy-tcp/1',multiaddr:address}],supported_wire_versions:['2'],issued_at:issued.toISOString().slice(0,19)+'Z',expires_at:expires.toISOString().slice(0,19)+'Z'},identity.privatePem,'node');
}
