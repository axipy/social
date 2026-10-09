import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';
import {createPublicKey} from 'node:crypto';
import {cidOf,cidMatches,keyId,validatePublicKey,verifyObject,unb64,jcs} from '../protocol/reference/codec.mjs';

export const CIDS=/^b[a-z2-7]{58}$/;
export const KEYIDS=/^axk1_[A-Za-z0-9_-]{43}$/;
export const CLOCK=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
export const NONCE=/^[A-Za-z0-9_-]{43}$/;
const schemasDir=resolve(dirname(fileURLToPath(import.meta.url)),'../protocol/schemas');
const schemas=new Map();
function schema(name){if(!schemas.has(name))schemas.set(name,JSON.parse(readFileSync(resolve(schemasDir,name),'utf8')));return schemas.get(name);}
// Interpretador restrito do JSON Schema Draft 2020-12 para os schemas oficiais AXIPY v2.
// Não substitui um validador JSON Schema genérico; suporta as palavras-chave que a especificação utiliza.
export function checkSchema(name,value){
  function check(s,v,depth=0){
    if(depth>35)return false;
    if(s.$ref)return check(schema(s.$ref),v,depth+1);
    if(s.const!==undefined&&v!==s.const)return false;
    if(s.enum&&!s.enum.some(x=>x===v))return false;
    const types=Array.isArray(s.type)?s.type:[s.type];
    const typeIs=t=>t==='null'?v===null:t==='array'?Array.isArray(v):t==='object'?v!==null&&typeof v==='object'&&!Array.isArray(v):t==='integer'?Number.isSafeInteger(v):typeof v===t;
    if(s.type&&!types.some(typeIs))return false;
    if(s.anyOf&&!s.anyOf.some(a=>check(a,v,depth+1)))return false;
    if(s.oneOf&&s.oneOf.filter(a=>check(a,v,depth+1)).length!==1)return false;
    if(s.allOf&&!s.allOf.every(a=>check(a,v,depth+1)))return false;
    if(s.not&&check(s.not,v,depth+1))return false;
    if(s.if&&check(s.if,v,depth+1)&&s.then&&!check(s.then,v,depth+1))return false;
    if(s.if&&!check(s.if,v,depth+1)&&s.else&&!check(s.else,v,depth+1))return false;
    if(typeof v==='string'){
      if(s.minLength!==undefined&&[...v].length<s.minLength)return false;
      if(s.maxLength!==undefined&&[...v].length>s.maxLength)return false;
      if(s.pattern&&!new RegExp(s.pattern,'u').test(v))return false;
    }
    if(Array.isArray(v)){
      if(s.minItems!==undefined&&v.length<s.minItems)return false;
      if(s.maxItems!==undefined&&v.length>s.maxItems)return false;
      if(s.uniqueItems&&new Set(v.map(x=>jcs(x).toString())).size!==v.length)return false;
      if(s.items&&!v.every(item=>check(s.items,item,depth+1)))return false;
    }
    if(v&&typeof v==='object'&&!Array.isArray(v)){
      const keys=Object.keys(v);
      if(s.required&&!s.required.every(k=>Object.hasOwn(v,k)))return false;
      if(s.minProperties!==undefined&&keys.length<s.minProperties)return false;
      if(s.maxProperties!==undefined&&keys.length>s.maxProperties)return false;
      for(const k of keys){
        if(s.properties&&Object.hasOwn(s.properties,k)){if(!check(s.properties[k],v[k],depth+1))return false;}
        else if(s.additionalProperties===false)return false;
        else if(s.additionalProperties&&typeof s.additionalProperties==='object'&&!check(s.additionalProperties,v[k],depth+1))return false;
      }
    }
    if(typeof v==='number'){
      if(s.minimum!==undefined&&v<s.minimum)return false;
      if(s.maximum!==undefined&&v>s.maximum)return false;
    }
    return true;
  }
  try{return check(schema(name),value);}catch{return false;}
}
export function iso(){return new Date().toISOString().slice(0,19)+'Z';}
export function certVerify(cert,trust,{clock=Date.now()}={}){
  if(!checkSchema('certificate.schema.json',cert)||!checkJcs(cert))throw Error('Certificado: formato inválido');
  const issuer=cert.payload.issuer_id;
  const key=trust.get(issuer);
  if(!key)throw Error('Autoridade não reconhecida');
  if(!verifyObject(cert,key,'certificate'))throw Error('Certificado: assinatura inválida');
  if(!Number.isFinite(Date.parse(cert.payload.issued_at))||!Number.isFinite(Date.parse(cert.payload.expires_at))||Date.parse(cert.payload.issued_at)>clock+300000||Date.parse(cert.payload.expires_at)<=clock||Date.parse(cert.payload.expires_at)<=Date.parse(cert.payload.issued_at))throw Error('Certificado fora de validade');
  return issuer;
}
function checkJcs(obj){try{return jcs(obj).length<=262144;}catch{return false;}}
export function postVerify(post,cert,trust){
  if(!checkSchema('post.schema.json',post)||!checkJcs(post))throw Error('Post: estrutura inválida');
  if(Buffer.byteLength(post.payload.text,'utf8')>16384)throw Error('Post: texto excedeu 16KiB');
  certVerify(cert,trust);
  if(post.payload.certificate_cid!==cidOf(cert))throw Error('Certificado não corresponde ao CID do post');
  if(post.payload.author_key_id!==keyId(cert.payload.subject_key))throw Error('Autor não corresponde ao certificado');
  if(!verifyObject(post,cert.payload.subject_key,'post'))throw Error('Assinatura do post inválida');
  if(Date.parse(post.payload.created_at)>Date.now()+300000)throw Error('Post datado no futuro');
  if(Date.parse(post.payload.created_at)<Date.parse(cert.payload.issued_at))throw Error('Post anterior à certificação');
  return cidOf(post);
}
export function trustFromConfig(filename){
  const conf=JSON.parse(readFileSync(filename,'utf8'));
  const trust=new Map();
  const entries=[];
  for(const a of conf.authorities??[]){
    if(a.public_key){const k=validatePublicKey(a.public_key);const id=keyId(k);trust.set(id,k);entries.push({name:a.name||id,issuer_id:id,issuer_url:a.issuer_url||null,enabled:true});}
    else entries.push({name:a.name||'Autoridade',issuer_id:null,issuer_url:a.issuer_url||null,enabled:false});
  }
  return {trust,entries};
}
export function wireVerify(msg,key,peer,session){
  if(!checkSchema('wire-message.schema.json',msg))throw Error('Mensagem AXIPY inválida');
  if(msg.payload.from!==peer||!verifyObject(msg,key,'wire'))throw Error('Assinatura de peer inválida');
  if(msg.payload.session_id!==session)throw Error('Sessão incorreta');
  if(Math.abs(Date.parse(msg.payload.sent_at)-Date.now())>600000)throw Error('Relógio de peer fora de janela');
  return msg.payload;
}
export function validNewKey(jwk){validatePublicKey(jwk);createPublicKey({key:jwk,format:'jwk'});return keyId(jwk);}
