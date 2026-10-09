import {mkdir,readFile,writeFile,rename,readdir,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {cidOf,jcs} from '../protocol/reference/codec.mjs';
import {CIDS} from './contract.mjs';
export class Store {
  constructor(path){this.base=path;}
  async init(){await Promise.all(['posts','certificates'].map(t=>mkdir(join(this.base,t),{recursive:true,mode:0o700})));}
  location(type,cid){if(!CIDS.test(cid)||!['posts','certificates'].includes(type))throw Error('CID inválido');return join(this.base,type,cid+'.json');}
  async put(type,obj){const cid=cidOf(obj),p=this.location(type,cid);const bytes=jcs(obj);if(bytes.length>262144)throw Error('Objeto excede 256 KiB');const tmp=p+'.'+randomBytes(6).toString('hex')+'.tmp';await writeFile(tmp,bytes,{flag:'wx',mode:0o600});await rename(tmp,p);return cid;}
  async get(type,cid){try{return JSON.parse(await readFile(this.location(type,cid),'utf8'));}catch(e){if(e.code==='ENOENT')return null;throw e;}}
  async all(type,cap=3000){const files=(await readdir(join(this.base,type))).filter(f=>/^b[a-z2-7]{58}\.json$/.test(f)).slice(0,cap);const out=[];for(const f of files){try{const o=await this.get(type,f.slice(0,-5));if(o&&cidOf(o)===f.slice(0,-5))out.push({cid:f.slice(0,-5),object:o});}catch{}}return out;}
  async feed(cap=100){const files=await this.all('posts');return files.sort((a,b)=>b.object.payload.created_at.localeCompare(a.object.payload.created_at)||a.cid.localeCompare(b.cid)).slice(0,cap);}
}
