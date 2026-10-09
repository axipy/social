import net from 'node:net';
import {EventEmitter} from 'node:events';
import {encodeFrame,decodeFrames,nonceRandom,signObject,verifyObject,keyId,cidOf} from '../protocol/reference/codec.mjs';
import {wireVerify,validNewKey,checkSchema,certVerify,postVerify,iso,CIDS} from './contract.mjs';
import {createNodeDescriptor} from './identity.mjs';

export function parseAddress(address){
  const match=address.match(/^\/(?:dns4|ip4|ip6)\/([^/]+)\/tcp\/(\d{1,5})$/);
  if(!match)throw Error('Multiaddr TCP inválida: '+address);
  const port=Number(match[2]);if(!port||port>65535)throw Error('Porta inválida');return {host:match[1],port};
}
export class PeerNetwork extends EventEmitter{
  constructor({identity,store,trust,getTrust,port,host,publicHost,bootstraps=[]}){
    super();Object.assign(this,{identity,store,trust,getTrust,port,host,publicHost,bootstraps});
    this.clients=new Set();this.served=new Map();this.seen=new Map();this.connecting=new Set();this.events=[];
  }
  log(message){this.events.unshift({at:iso(),message});this.events=this.events.slice(0,80);this.emit('event',message);}
  recognizes(issuerId){return this.getTrust().trust.has(issuerId);}
  descriptor(){return createNodeDescriptor(this.identity,this.publicHost,this.port);}
  async listen(){this.server=net.createServer(socket=>this.attach(socket,false));await new Promise((resolve,reject)=>{this.server.once('error',reject);this.server.listen(this.port,this.host,resolve);});this.log('AXIPY Wire escutando '+this.host+':'+this.port);this.timer=setInterval(()=>this.bootstrap(),30000);this.timer.unref();setTimeout(()=>this.bootstrap(),800).unref();}
  status(){return {node_id:this.identity.id,peer_count:[...this.clients].filter(x=>x.ready).length,known_peers:[...this.seen.values()].slice(0,40),events:this.events.slice(0,20),listening:this.port,advertised:this.descriptor().payload.addresses};}
  async bootstrap(){const seen=new Set(this.bootstraps);for(const addr of seen){if(!addr)continue;const connected=[...this.clients].some(x=>x.target===addr&&x.ready);if(connected||this.connecting.has(addr))continue;this.connecting.add(addr);try{const {host,port}=parseAddress(addr);await this.connect(host,port,addr);}catch(e){this.log('Bootstrap indisponível '+addr+': '+e.message);}finally{this.connecting.delete(addr);}}}
  connect(host,port,target=''){return new Promise((resolve,reject)=>{const socket=net.connect({host,port});let done=false;socket.setTimeout(15000);socket.once('connect',()=>{const p=this.attach(socket,true,target);p.connectedResolve=()=>{if(!done){done=true;resolve(p);}};p.connectedReject=e=>{if(!done){done=true;reject(e);}};p.startHandshake();});socket.once('error',e=>{if(!done){done=true;reject(e);}});socket.once('timeout',()=>{if(!done){done=true;reject(Error('timeout'));}socket.destroy();});});}
  attach(socket,outbound,target=''){
    const p={socket,outbound,target,buf:Buffer.alloc(0),key:null,id:null,ready:false,session:null,nonceA:null,nonceB:null,requestId:null,pending:new Map(),requests:new Map(),lastIds:new Set()};
    this.clients.add(p);socket.setNoDelay(true);
    socket.on('data',raw=>{try{p.buf=Buffer.concat([p.buf,raw]);if(p.buf.length>3*1048576)throw Error('buffer overflow');const {messages,remainder}=decodeFrames(p.buf);p.buf=remainder;for(const message of messages)this.handle(p,message).catch(e=>this.fail(p,e));}catch(e){this.fail(p,e);}});
    socket.on('error',e=>{this.log('Socket: '+e.message);});socket.on('close',()=>{this.clients.delete(p);p.connectedReject?.(Error('Conexão encerrada antes do handshake'));});
    p.startHandshake=()=>{p.nonceA=nonceRandom();p.requestId=nonceRandom();this.send(p,'HELLO',{node_key:this.identity.pub,nonce_a:p.nonceA,wire_versions:['2']},null,p.requestId);};return p;
  }
  fail(p,e){this.log('Conexão encerrada: '+e.message);p.connectedReject?.(e);p.socket.destroy();}
  send(p,kind,body,session=p.session,requestId=nonceRandom()){
    const message=signObject({type:'axipy.wire',version:'2',kind,from:this.identity.id,request_id:requestId,session_id:session,sent_at:iso(),body},this.identity.privatePem,'wire');
    if(!checkSchema('wire-message.schema.json',message))throw Error('Erro interno: mensagem '+kind+' fora do schema');
    p.socket.write(encodeFrame(message));return requestId;
  }
  validatePeer(p,m,session){return wireVerify(m,p.key,p.id,session);}
  async handle(p,msg){
    const q=msg.payload;if(!q||q.type!=='axipy.wire')throw Error('Mensagem desconhecida');
    if(!p.ready){
      if(!p.outbound&&!p.id&&q.kind==='HELLO'){
        const k=q.body?.node_key;const id=validNewKey(k);
        if(id===this.identity.id)throw Error('Self peer');
        if(!verifyObject(msg,k,'wire')||q.from!==id||q.session_id!==null||!checkSchema('wire-message.schema.json',msg))throw Error('HELLO inválido');
        if(Math.abs(Date.parse(q.sent_at)-Date.now())>600000)throw Error('HELLO expirado');
        if(!q.body.wire_versions.includes('2'))throw Error('Versão não suportada');
        p.key=k;p.id=id;p.requestId=q.request_id;p.nonceA=q.body.nonce_a;p.nonceB=nonceRandom();p.session=nonceRandom();
        this.send(p,'CHALLENGE',{node_key:this.identity.pub,nonce_a:p.nonceA,nonce_b:p.nonceB,session:p.session},null,p.requestId);return;
      }
      if(p.outbound&&!p.id&&q.kind==='CHALLENGE'){
        const k=q.body?.node_key;const id=validNewKey(k);
        if(!verifyObject(msg,k,'wire')||q.from!==id||q.session_id!==null||q.request_id!==p.requestId||!checkSchema('wire-message.schema.json',msg))throw Error('CHALLENGE inválido');
        if(q.body.nonce_a!==p.nonceA)throw Error('Nonce inválido');
        p.key=k;p.id=id;p.nonceB=q.body.nonce_b;p.session=q.body.session;
        this.send(p,'CONFIRM',{nonce_a:p.nonceA,nonce_b:p.nonceB,session:p.session},p.session,p.requestId);return;
      }
      if(!p.outbound&&p.id&&q.kind==='CONFIRM'){
        this.validatePeer(p,msg,p.session);if(q.request_id!==p.requestId||q.body.nonce_a!==p.nonceA||q.body.nonce_b!==p.nonceB||q.body.session!==p.session)throw Error('CONFIRM inválido');
        p.ready=true;this.send(p,'READY',{session:p.session},p.session,p.requestId);await this.onReady(p);return;
      }
      if(p.outbound&&p.id&&q.kind==='READY'){
        this.validatePeer(p,msg,p.session);if(q.request_id!==p.requestId||q.body.session!==p.session)throw Error('READY inválido');
        p.ready=true;p.connectedResolve?.();await this.onReady(p);return;
      }
      throw Error('Handshake inesperado: '+q.kind);
    }
    this.validatePeer(p,msg,p.session);
    if(q.kind==='GOODBYE'){p.socket.end();return;}
    if(q.kind==='ERROR'){this.log('Peer '+p.id.slice(0,12)+' erro: '+q.body.error.code);return;}
    if(q.kind==='ANNOUNCE'){
      const {cid,issuer_id}=q.body;
      const exists=await this.store.get('posts',cid);
      const decision=!this.recognizes(issuer_id)?'REJECT':exists?'SKIP':'WANT';
      this.send(p,'DECISION',{cid,decision,reason:null},p.session,q.request_id);
      if(decision==='WANT'){p.pending.set(cid,{issuer_id,author_key_id:q.body.author_key_id});this.send(p,'WANT',{cid},p.session);}
    } else if(q.kind==='DECISION'){ /* confirmação de anúncio; WANT é enviada separadamente pelo receptor */ }
    else if(q.kind==='WANT'){
      const cid=q.body.cid;const post=await this.store.get('posts',cid),cert=post?null:await this.store.get('certificates',cid);
      if(post||cert){this.send(p,'BLOCK',{cid,object_type:post?'post':'certificate',object:post||cert},p.session,q.request_id);}
      else this.send(p,'NOT_FOUND',{cid},p.session,q.request_id);
    } else if(q.kind==='BLOCK'){
      await this.onBlock(p,q.body);
    } else if(q.kind==='FIND_PROVIDERS'){
      const cid=q.body.cid;const have=await this.store.get('posts',cid)||await this.store.get('certificates',cid);
      this.send(p,'PROVIDERS',{cid,providers:have?[this.descriptor()]:[]},p.session,q.request_id);
    } else if(q.kind==='PROVIDERS'){for(const d of q.body.providers)this.discover(d);}
    else if(q.kind==='PEERS'){const list=q.body.list;if(!checkSchema('peer-list.schema.json',list)||!verifyObject(list,p.key,'peers')||list.payload.node_id!==p.id)throw Error('Lista de peers inválida');for(const d of list.payload.nodes)this.discover(d);}
    else if(q.kind==='NOT_FOUND'){this.log('Objeto ausente '+q.body.cid.slice(0,15));}
    else throw Error('Comando inesperado '+q.kind);
  }
  async onReady(p){this.seen.set(p.id,{id:p.id,target:p.target,at:iso()});this.log('Handshake válido: '+p.id.slice(0,20));const posts=await this.store.feed(500);for(const row of posts)await this.announceTo(p,row.object,row.cid);}
  async announceTo(p,post,cid){if(!p.ready)return;const cert=await this.store.get('certificates',post.payload.certificate_cid);if(!cert)return;this.send(p,'ANNOUNCE',{cid,issuer_id:cert.payload.issuer_id,author_key_id:post.payload.author_key_id});}
  async broadcast(post,cid,except=null){for(const p of this.clients){if(p!==except){try{await this.announceTo(p,post,cid);}catch(e){this.log('Falha anunciando post: '+e.message);}}}}
  async onBlock(p,{cid,object_type,object}){
    if(cidOf(object)!==cid)throw Error('BLOCK CID incorreto');
    if(object_type==='certificate'){
      certVerify(object,this.getTrust().trust);await this.store.put('certificates',object);
      for(const [pc,rec] of [...p.pending])if(rec.post&&rec.post.payload.certificate_cid===cid){p.pending.delete(pc);await this.accept(p,rec.post,object,pc,rec);}
      return;
    }
    if(object_type==='post'){
      if(!p.pending.has(cid))throw Error('Post não solicitado');
      if(!checkSchema('post.schema.json',object))throw Error('Post inválido');
      const rec=p.pending.get(cid);if(rec.author_key_id!==object.payload.author_key_id)throw Error('Autor anunciado diverge');
      const cert=await this.store.get('certificates',object.payload.certificate_cid);
      if(!cert){p.pending.set(cid,{...rec,post:object});this.send(p,'WANT',{cid:object.payload.certificate_cid});return;}
      p.pending.delete(cid);await this.accept(p,object,cert,cid,rec);return;
    }
    // Outros blocos normativos são reconhecidos, mas não persistidos por esta aplicação social.
    const schemaFor={authority:'authority-descriptor.schema.json',node:'node-descriptor.schema.json',revocations:'revocations.schema.json',peer_list:'peer-list.schema.json'}[object_type];
    if(!schemaFor||!checkSchema(schemaFor,object))throw Error('Bloco auxiliar inválido');
  }
  async accept(p,post,cert,cid,announcement){
    const parsed=postVerify(post,cert,this.getTrust().trust);
    if(parsed!==cid||announcement.issuer_id!==cert.payload.issuer_id||announcement.author_key_id!==post.payload.author_key_id)throw Error('Anúncio diverge do objeto assinado');
    const already=await this.store.get('posts',cid);if(already)return;
    await this.store.put('posts',post);this.log('Post recebido '+cid.slice(0,16));this.emit('post',cid);await this.broadcast(post,cid,p);
  }
  discover(desc){
    if(!checkSchema('node-descriptor.schema.json',desc))return;
    if(!verifyObject(desc,desc.payload.node_key,'node'))return;
    if(desc.payload.node_id!==keyId(desc.payload.node_key)||Date.parse(desc.payload.expires_at)<=Date.now())return;
    if(desc.payload.node_id===this.identity.id)return;
    for(const a of desc.payload.addresses)if(a.profile==='axipy-tcp/1'&&!this.bootstraps.includes(a.multiaddr)&&this.bootstraps.length<100)this.bootstraps.push(a.multiaddr);
  }
  close(){clearInterval(this.timer);for(const p of this.clients)p.socket.destroy();this.server?.close();}
}
