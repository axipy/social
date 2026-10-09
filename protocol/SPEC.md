# AXIPY — Especificação de Protocolo, revisão 0.2

**Estado:** especificação oficial em desenvolvimento, revisão 0.2. **Versão de objetos e mensagens:** `2`. **Tipo:** protocolo de rede peer-to-peer para objetos sociais textuais, independente da aplicação, do transporte e do armazenamento.

Nesta especificação, os termos em destaque **DEVE** (`MUST`), **NÃO DEVE** (`MUST NOT`), **RECOMENDA-SE** (`SHOULD`) e **PODE** (`MAY`) têm o sentido da [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) e da [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174). Seu uso normativo fica restrito aos requisitos do protocolo; descrições de política local e recomendações de implementação identificadas como não normativas não criam requisitos de conformidade. A versão 2 é intencionalmente incompatível nos endereços de conteúdo e formatos de mensagem com o rascunho HTTP v0.1; não há conversão implícita.

## 1. Definição, alcance e papéis

AXIPY especifica: (a) como identificar por conteúdo objetos assinados, (b) como certificar chaves de autores, (c) como nós negociam comunicação, (d) como descobrem a localização de objetos e os transferem, (e) como decidem a validade dos objetos, independentemente de quem os transportou.

**Não** especifica interface, rede social, feed, moderação, banco de dados, framework, linguagem, hospedagem, DNS obrigatório, quantidade de nós, ranking, alcance global ou obrigação de armazenar/propagar.

Entidades distintas:

- **Usuário/autor:** controla uma chave privada Ed25519 e assina posts.
- **Autoridade certificadora (AC):** certifica o vínculo entre uma chave pública e uma identidade conforme suas próprias regras; assina certificados. Não é um nó por definição.
- **Nó AXIPY:** estabelece sessões, localiza, recebe, valida, serve e eventualmente retransmite objetos. Não é uma AC por definição.
- **Bootstrap:** endereço de nó usado para iniciar descoberta. Não tem privilégios de certificação nem autoridade superior na rede.
- **Objeto:** bloco JSON assinado com CID calculável por qualquer implementação.

Uma mesma organização pode operar AC e vários nós, com **pares de chaves e papéis separados**. AXIPY pode ser a primeira AC e operar três bootstraps, mas nenhum é obrigatório no protocolo.

## 2. Criptografia e codificação

### 2.1. Primitivas obrigatórias

- Assinatura: Ed25519, 64 bytes, chave pública de 32 bytes; representações base64url sem `=`.
- Hash: SHA-256.
- Chave pública: JWK **público** `{"kty":"OKP","crv":"Ed25519","x":"..."}`. Campos adicionais, sobretudo `d`, são proibidos em objetos de rede.
- JSON de assinatura: I-JSON e canonicalização **RFC 8785 (JCS)**, em UTF-8; rejeitar chaves duplicadas, surrogate isolado e dados não representáveis em I-JSON. O texto NÃO é normalizado em NFC/NFD automaticamente.
- Horário: texto UTC em formato exato `YYYY-MM-DDTHH:MM:SSZ`; sem milissegundos. Nonces: 32 bytes gerados com aleatoriedade criptográfica, codificados em base64url.
- IDs de chave: `axk1_` + `base64url(SHA-256(JCS(JWK pública Ed25519)))` (forma de thumbprint JWK). O papel da chave (usuário, AC ou nó) não é inferido do ID; vem do protocolo e de sua utilização.

### 2.2. Contextos de assinatura

O campo `signature` contém `{ "algorithm": "Ed25519", "value": "base64url(64 bytes)" }`. A assinatura cobre exatamente:

`UTF8(PREFIXO) || JCS_UTF8(objeto.payload)`

| Objeto | Prefixo exato, incluindo LF ASCII final | Signatário |
|---|---|---|
| Certificado | `AXIPY/CERT/2\n` | AC |
| Solicitação de certificado | `AXIPY/CERT-REQUEST/2\n` | usuário requerente |
| Post | `AXIPY/POST/2\n` | usuário autor |
| Descriptor de AC | `AXIPY/AUTHORITY/2\n` | AC |
| Revogações | `AXIPY/REVOCATIONS/2\n` | AC |
| Descriptor de nó | `AXIPY/NODE/2\n` | nó |
| Lista de peers | `AXIPY/PEERS/2\n` | nó |
| Mensagem AXIPY | `AXIPY/WIRE/2\n` | nó emissor |
| Encaminhamento de cadastro | `AXIPY/ISSUE-FORWARD/2\n` | nó encaminhador |
| Resultado de cadastro | `AXIPY/ISSUE-RESULT/2\n` | AC |

O `signature` é externo ao `payload` e não participa dos dados assinados. Não é permitido reaproveitar assinatura de um contexto em outro. Chaves privadas NUNCA são transmitidas em mensagens do protocolo.

## 3. Endereçamento por conteúdo: CIDv1, como no IPFS

### 3.1. Regra única para todos os objetos assinados

O conteúdo de um bloco AXIPY é **exatamente os bytes JCS UTF-8 do objeto completo** `{payload, signature}`. Blocos de certificados, posts, descriptors, revogações e listas seguem a mesma regra. JSON formatado com espaçamento arbitrário pode ser recebido, mas DEVE ser canonicalizado antes de calcular o CID; os bytes servidos em `BLOCK` DEVEM ser os bytes canônicos.

O identificador é **CIDv1**, com multicodec `raw` (código `0x55`) e multihash `sha2-256` (código `0x12`, comprimento `0x20`), codificado em **multibase base32 minúscula sem padding**, prefixo `b`:

`CID_bytes = 0x01 || 0x55 || 0x12 || 0x20 || SHA256(JCS_UTF8(objeto_completo))`

`CID_texto = "b" || BASE32_lower_sem_padding(CID_bytes)`

O CID aqui tem tamanho fixo de 59 caracteres (incluindo `b`). Um receptor DEVE verificar versão, codec, hash, tamanho, base32 canônico e coincidência dos bytes recebidos. Ao usar `raw`, o bloco é interoperável com sistemas compatíveis com CIDv1: isso **não** significa que um serviço IPFS qualquer publica, autentica ou aceita automaticamente objetos AXIPY.

### 3.2. Consequências

- A localização/hospedagem não entra no CID. Múltiplos nós podem fornecer o mesmo objeto.
- O mesmo objeto e a mesma assinatura produzem o mesmo CID. Alterar texto, certificado referenciado ou assinatura altera o CID.
- Post e certificado são blocos independentes. `certificate_cid` no post referencia seu certificado; `reply_to` referencia outro post por CID ou é `null`.
- A autoria exige assinatura, chave pública e certificado confiável; o CID **sozinho** demonstra correspondência de conteúdo, não identidade confiável.
- Não há fragmentação/chunking de posts v2, UnixFS, upload de mídia ou DAG genérico arbitrário: os objetos textuais são blocos pequenos e autocontidos em seu formato.

## 4. Certificação de usuários

### 4.1. Certificado

`schemas/certificate.schema.json` define `{payload, signature}`:

```
payload = {
  "type":"axipy.certificate", "version":"2",
  "issuer_id":"axk1_...",
  "subject_key":{"kty":"OKP","crv":"Ed25519","x":"..."},
  "issued_at":"2026-10-09T00:00:00Z", "expires_at":"2027-10-09T00:00:00Z",
  "policy_id":"axipy-basic-v1",
  "registration":{"requested_by":null,"requester_verification":null,"method":null},
  "claims":{}
}
```

O certificado é assinado pela AC apontada em `issuer_id`, e o verificador obtém a chave da AC de seu conjunto local de confiança (não confia automaticamente em uma chave recebida pela rede). `expires_at` deve superar `issued_at`. O campo `policy_id` remete às regras próprias daquela AC; não existe identidade civil obrigatória do usuário no protocolo.

`registration.requested_by` é o ID de um nó/solicitante **observado pela autoridade** no cadastro, não uma string arbitrária declarada no pedido. `requester_verification` pode ser `cryptographic`, `observed`, `declared` ou `null`. `method` pode ser string ou `null`. Esses dados são assinados pela AC. A semântica de `null` é **não atestado**, não “comprovadamente inexistente”. Cada receptor escolhe se exige esses metadados.

### 4.2. Solicitação de certificado

`schemas/cert-request.schema.json`: `subject_key`, `nonce` e `created_at`, assinados pela própria chave futura titular com `AXIPY/CERT-REQUEST/2\n` como prova de posse. A autoridade aplica **seus próprios critérios** antes da emissão. Emissão, pendência ou recusa são resultados possíveis. O protocolo define o objeto solicitado e a validação do certificado emitido; o método de cadastro da AC é uma interface independente, não um endpoint HTTP AXIPY obrigatório.

### 4.3. Descritores e revogação

A AC pode anunciar um `authority-descriptor` assinado com chave, política, endereços de serviço e CID do snapshot de revogações (`revocations_cid`). O descriptor é descobrível, **não concede confiança**. A AC pode emitir `revocations` assinado com `issuer_id`, `sequence`, `issued_at`, `next_update` e lista de CIDs de certificados revogados.

**Validação do protocolo:** o receptor DEVE conferir o CID, verificar a assinatura com a chave pública da AC emissora e rejeitar retrocessos de `sequence` em relação ao maior valor já aceito para a mesma AC. A verificação criptográfica da assinatura é distinta do reconhecimento local da AC: um snapshot assinado por AC não reconhecida não se torna fonte confiável de revogações desse nó. `issued_at` declara quando a AC emitiu o snapshot. `next_update` é a data UTC em que a AC declara esperar publicar informação mais recente; usa o formato exato de horário da [seção 2.1](#21-primitivas-obrigatórias). `revocations_cid` aponta para um snapshot específico, não para um estado global permanentemente atualizado. Um snapshot autenticado continua sendo aquele mesmo objeto assinado quando o horário atual alcança ou ultrapassa `next_update`; somente essa passagem do tempo não altera sua assinatura, seu CID, sua `sequence` nem revoga automaticamente os certificados.

**Política local, não normativa:** o nó decide se aceita, limita ou suspende o uso de certificados quando seu conhecimento de revogação está atrasado, indisponível ou incompleto. `next_update` não garante ausência de revogação desde `issued_at` e não determina uma escolha universal entre aceitar e rejeitar. A AC não precisa ser consultada a cada publicação: snapshots assinados podem ser distribuídos e verificados por CID.

**Recomendação de implementação, não normativa:** para sinalizar um snapshot como atrasado, uma implementação pode comparar o horário UTC atual com `next_update` e considerar o prazo alcançado quando `agora >= next_update`. Ao detectar atraso ou indisponibilidade, pode buscar informação mais recente pelas fontes permitidas por sua política. Essa avaliação temporal e a decisão operacional permanecem separadas da validação criptográfica e do reconhecimento local da AC. Veja também [Considerações de Segurança](#11-considerações-de-segurança).

## 5. Posts: apenas texto puro

`schemas/post.schema.json` define payload fechado:

```
{
 "type":"axipy.post", "version":"2",
 "author_key_id":"axk1_...", "certificate_cid":"b...",
 "created_at":"2026-10-09T00:00:00Z", "text":"Olá, rede!",
 "reply_to":null
}
```

O campo `text` é uma string Unicode não vazia de até **16.384 bytes UTF-8**, medidos após decodificação, independentemente do comprimento em caracteres. O texto é conteúdo literal; URLs/Markdown são caracteres de texto e não definem anexos, links baixáveis, HTML executável ou mídia no protocolo. `reply_to` é um CID de outro post; uma resposta é um post normal. Não há campos de curtidas, moderação, hashtags, links externos estruturados, anexos, upload ou perfil social na versão 2.

O post é assinado com a chave privada correspondente ao `subject_key` do certificado referenciado. O autor não precisa pedir assinatura à autoridade para cada post. Um post construído manualmente é aceitável se passar pelas mesmas verificações.

`created_at` é uma declaração do autor incluída no payload assinado. A assinatura autentica essa declaração, mas não prova o momento real da criação nem estabelece ordem global entre posts. Aplicações podem escolher como apresentar horários divergentes ou futuros, sem alterar o campo ou a identidade do objeto. O texto não sofre normalização Unicode antes de JCS e CID: sequências Unicode diferentes, ainda que visualmente semelhantes, podem gerar CIDs diferentes.

### 5.1. Ordem normativa de validação de um post

1. Conferir tamanho, JSON/I-JSON e schema v2, rejeitando campos não definidos.
2. Recalcular CID do bloco completo e compará-lo ao CID solicitado/anunciado.
3. Obter bloco do certificado usando `certificate_cid` (local ou pela rede); conferir schema, CID e assinatura da AC.
4. Conferir que a AC pertence ao conjunto reconhecido localmente e validar o certificado, incluindo sua vigência e os dados de revogação disponíveis segundo as regras da seção 4.
5. Conferir `author_key_id == keyId(certificado.payload.subject_key)`.
6. Conferir assinatura Ed25519 do post usando a chave do usuário certificada.

**Decisão operacional, não normativa:** após as verificações, o nó aplica sua política local de aceitação, disponibilidade e retenção. A validade do `reply_to` não exige que o post pai esteja imediatamente disponível: a referência pode permanecer pendente.

Como `certificate_cid` integra o payload assinado do post, substituir o certificado por outro bloco, mesmo com o mesmo `subject_key`, muda seu CID e rompe essa referência. Alterar `certificate_cid` no post exige nova assinatura do autor. O receptor não pode substituir silenciosamente o certificado apontado por outro que considere equivalente.

Um nó intermediário NÃO DEVE reescrever o post. O recebimento por um nó não produz assinatura de autoridade, nem confere privilégios adicionais de origem ao conteúdo.

## 6. Nós, descoberta e confiança

### 6.1. Nó

Um nó tem identidade criptográfica própria (`node_id`, chave Ed25519) e publica um `node-descriptor` assinado, com lista de endereços de perfis de transporte, versão AXIPY e validade temporal. `node_id` é o thumbprint da JWK do nó, não a chave de um usuário nem a chave da AC. `node-descriptor` pode ser indexado por CID. Nenhum endereço ou PeerId não autenticado substitui verificação da assinatura de nó.

### 6.2. Seleção de confiança

Cada nó escolhe, sem necessidade de consenso global:

- quais ACs reconhece para certificados de usuários;
- quais peers aceita contatar/receber e por quais transportes;
- se armazena, oferece ou propaga um objeto estruturalmente válido;
- o que faz em caso de certificado revogado, informação indisponível ou quotas excedidas.

O protocolo define **validade criptográfica e estrutural**. Não define aprovação universal, censura global ou admissão obrigatória. Um nó pode aceitar certificados da AXIPY e B, mas rejeitar D. Outro pode fazer o inverso. Um nó não é obrigado a confiar na autoridade que certificou seu vizinho.

### 6.3. Bootstrap, descoberta de peers e localização de conteúdo

As três responsabilidades são separadas, à maneira do IPFS:

1. **Descoberta de peers:** obter endereços candidatos via bootstrap ou `PEERS` com lista assinada de descriptors. Descobrir não significa confiar.
2. **Descoberta de conteúdo:** aprender o CID via `ANNOUNCE`, referência em post, `FIND_PROVIDERS` e `PROVIDERS`, ou mecanismo complementar. Anúncio de disponibilidade é uma pista, não prova do conteúdo.
3. **Transferência:** usar `WANT`/`BLOCK` com o CID, conferir os bytes independentemente e validar o objeto assinado.

Roteamento via DHT/GossipSub é **opcional**, nunca condição para conformidade nuclear. Descoberta não garante localização de todos os objetos. Os endereços dos bootstrap podem deixar de ser usados depois da descoberta inicial. A política de confiança se aplica também a respostas de descoberta e ao recebimento dos objetos.

## 7. Protocolo de comunicação abstrato: AXIPY Wire 2

**Nenhum endpoint HTTP faz parte do núcleo.** Implementações trocam mensagens assinadas `wire-message.schema.json` em canais confiáveis de bytes orientados a mensagens providos por perfis de transporte; o perfil define o enquadramento (*framing*). Os transportes padronizados na revisão 0.2 estão em `profiles/TCP.md` e `profiles/LIBP2P.md`. A emissão de certificados é definida separadamente em `profiles/ISSUER.md`.

### 7.1. Envelope comum

```
{
 "payload":{
   "type":"axipy.wire", "version":"2", "kind":"ANNOUNCE",
   "from":"axk1_...", "request_id":"<nonce-base64url>",
   "session_id":"<nonce-base64url ou null>",
   "sent_at":"2026-10-09T00:00:00Z", "body": { ... }
 },
 "signature":{"algorithm":"Ed25519","value":"..."}
}
```

`from` identifica a chave do nó signatário. `request_id` é gerado por solicitação, permitindo correlação de respostas; cada resposta DEVE ecoar o `request_id` da mensagem a que responde (ou iniciar novo identificador no caso de mensagens espontâneas). O receptor DEVE conferir essa correlação no contexto da sessão, e uma mensagem já processada não deve produzir o mesmo efeito outra vez. Cada envelope é assinado com `AXIPY/WIRE/2\n`.

Mensagens `HELLO` e `CHALLENGE` têm `session_id:null`; após `CHALLENGE`, `CONFIRM`, `READY` e mensagens posteriores usam o ID de sessão recebido. Os corpos são schemas fechados `schemas/body-*.schema.json`, escolhidos pelo campo `kind`. Todos os campos são obrigatórios nos respectivos corpos; ausência não pode ser confundida com `null`.

### 7.2. Handshake de nós

**Estados:** `DISCONNECTED → HELLO_SENT → CHALLENGED → CONFIRMED → READY`; qualquer rejeição encerra tentativa de sessão. O lado B pode começar como `LISTENING` e só entra em sessão após autenticação das mensagens.

1. **A → B `HELLO`:** JWK de A, `nonce_a` e versões Wire aceitas. A assina; B verifica `from == keyId(node_key)` e assinatura com a JWK apresentada, e aplica sua política local de peer. Sem versão comum, B pode responder `ERROR` e encerrar.
2. **B → A `CHALLENGE`:** JWK de B, eco de `nonce_a`, novo `nonce_b` e `session` aleatório. A confere assinatura e identidade de B segundo sua política local, além do eco do nonce.
3. **A → B `CONFIRM`:** eco dos dois nonces e do `session`, assinado por A.
4. **B → A `READY`:** confirma `session`, assinado por B.

Ambos verificam `request_id`, identidade dos signatários, vínculo dos nonces à sessão e ausência de reutilização. `CHALLENGE`, `CONFIRM` e `READY` ecoam o `request_id` de `HELLO`; `CONFIRM` e `READY` vinculam o `session_id` do envelope ao `session` do corpo. B só considera A autenticado para aquela tentativa depois de conferir `CONFIRM`; A só considera a sessão pronta depois de conferir `READY`. A assinatura de `CHALLENGE`, com `nonce_a` recém-gerado por A, autentica a chave apresentada por B para a tentativa, sujeita à política local de identidade do peer. Nonces não são credenciais permanentes. Sessões possuem duração e limites estabelecidos localmente. O handshake **não certifica o usuário**, não divulga autoridades reconhecidas por nenhum participante e não declara automaticamente que qualquer post do peer é válido. Chaves de nó autenticam os peers; não representam uma lista de ACs reconhecidas.

O receptor decide localmente quais ACs reconhece ao processar `ANNOUNCE` e ao validar o certificado apontado pelo post após `BLOCK`. Não há negociação de conjunto de ACs no handshake, nem requisito de uma interseção de confiança para estabelecer a sessão. A rejeição de um anúncio não exige divulgação das autoridades reconhecidas pelo receptor.

O handshake assinado confirma posse das chaves AXIPY apresentadas e vincula mensagens à tentativa por nonces e `session`, mas **não negocia chave de cifragem, não fornece sigilo nem forward secrecy**. No TCP básico, um observador pode ler o tráfego e um adversário ativo pode retransmitir mensagens; assinaturas e verificações de estado impedem que uma mensagem antiga seja aceita como nova sem os nonces e a sessão correspondentes, desde que IDs e nonces não sejam reutilizados. O handshake não vincula criptograficamente a sessão AXIPY aos bytes de uma conexão TCP ou a um canal libp2p específico; por isso não promete impedir retransmissão em tempo real por um intermediário. O perfil libp2p distingue as garantias do canal das assinaturas AXIPY em [profiles/LIBP2P.md](profiles/LIBP2P.md).

A ausência de lista de ACs no handshake evita essa divulgação direta, mas não proporciona anonimato. Padrões de anúncio, aceitação, rejeição e tráfego podem permitir inferências sobre políticas locais. `ANNOUNCE.issuer_id` continua visível para quem puder observar essa mensagem; sigilo do canal depende do perfil de transporte e da configuração utilizada.

### 7.3. Tipos de mensagens

| Tipo | Corpo | Efeito |
|---|---|---|
| `HELLO` | `node_key`, `nonce_a`, `wire_versions` | Solicitar sessão |
| `CHALLENGE` | `node_key`, `nonce_a`, `nonce_b`, `session` | Desafio assinado de B |
| `CONFIRM` | `nonce_a`, `nonce_b`, `session` | Confirmar posse de chave de A |
| `READY` | `session` | Sessão pronta |
| `ANNOUNCE` | `cid`, `issuer_id`, `author_key_id` | Anunciar CID de post e AC declarada |
| `DECISION` | `cid`, `decision: WANT/SKIP/REJECT`, `reason` | Filtrar sem baixar post |
| `WANT` | `cid` | Pedir bloco por CID |
| `BLOCK` | `cid`, `object_type`, `object` | Responder com objeto canônico associado ao CID |
| `NOT_FOUND` | `cid` | Informar ausência local |
| `PEERS` | `list` | Anunciar descriptors de outros nós, em lista assinada |
| `FIND_PROVIDERS` | `cid` | Pedir indicações de peers que alegam possuir CID |
| `PROVIDERS` | `cid`, `providers` | Informar descriptors candidatos |
| `GOODBYE` | `reason` | Encerrar voluntariamente sessão |
| `ERROR` | `error: {code,detail}` | Rejeição/falha de protocolo |

Todos os corpos estão definidos nos schemas. O campo `object_type` em `BLOCK` também determina o schema obrigatório do objeto transportado. Valores de `kind` fora da versão 2 são rejeitados com `UNSUPPORTED_VERSION` ou `MALFORMED` conforme o caso. Não se admite que uma mensagem `BLOCK` seja “validada” apenas porque o nó emissor assinou seu envelope.

### 7.4. Propagação e filtragem antecipada

`A → B: ANNOUNCE(post_cid, issuer_id, author_key_id)` → `B → A: DECISION(WANT|SKIP|REJECT)` → (se WANT) `B → A: WANT(post_cid)` → `A → B: BLOCK(post)` → eventualmente `B → A: WANT(certificate_cid)` → `A → B: BLOCK(certificate)`.

B pode recusar na etapa `ANNOUNCE` quando a AC declarada não for reconhecida. `issuer_id` e `author_key_id` no anúncio são **declarações preliminares do peer**, não provas de certificação ou autoria. Se B prosseguir, DEVE verificar o post, obter o certificado exato apontado por `certificate_cid`, verificar a assinatura da AC reconhecida localmente e comparar `issuer_id` anunciado com `certificate.payload.issuer_id` e `author_key_id` anunciado com `post.payload.author_key_id`. Uma divergência torna o anúncio inconsistente e jamais torna o objeto legítimo por si só; a validade do objeto obtido por outra via continua sujeita às verificações normais. B pode solicitar o certificado a qualquer peer que o possua, não apenas ao transmissor do post. `SKIP` não significa objeto inválido; `REJECT` significa que B não deseja aquela transferência. Anúncios não implicam entrega garantida nem propagação automática.

### 7.5. Recuperação independente do emissor

Um nó pode solicitar qualquer CID conhecido diretamente via `WANT`, sem que esse CID tenha sido anunciado antes, se sua política permitir. Um peer pode retornar `NOT_FOUND`. `FIND_PROVIDERS`/`PROVIDERS` retornam pistas de localização, verificadas uma a uma; não substituem `BLOCK` nem dão confiança às autoridades contidas nos posts recuperados.

### 7.6. Fluxo e limite normativo

- Máximo do envelope Wire canonicalizado: **1 MiB**. Máximo de objeto `BLOCK`: **256 KiB** canonicalizado, incluindo certificado e assinatura quando aplicável. `text` do post permanece limitado a **16.384 bytes UTF-8**.
- Frames maiores devem ser rejeitados antes da alocação integral.
- Sem broadcast global obrigatório, sem obrigação de retransmitir tudo, sem ordenação global de posts.
- A ordem de mensagens de uma mesma sessão segue o protocolo de estados; respostas podem chegar fora de ordem desde que `request_id` permita correlação e a conexão suporte multiplexação.
- Para `BLOCK`, comparar CID sobre JCS do objeto completo e validar schema específico de `object_type`; o receptor pode descartar bloco inválido.

## 8. Perfis de transporte

O núcleo AXIPY especifica conteúdo e semântica das mensagens, **não o transporte**. A revisão 0.2 padroniza dois perfis opcionais:

- `axipy-tcp/1`: streams TCP, enquadramento length-prefix; documentado em `profiles/TCP.md`.
- `axipy-libp2p/1`: stream libp2p `/axipy/2.0.0`, multiaddr/PeerId e mesmo framing de aplicação; documentado em `profiles/LIBP2P.md`.

Um nó DEVE anunciar **ao menos um perfil** que implementa em seu descriptor; não há exigência universal de implementar TCP, libp2p ou HTTP. Dois nós só se comunicam diretamente quando compartilham um perfil de transporte ou utilizam uma ponte que implemente os dois. Um gateway HTTP pode existir, mas **não define as mensagens da rede**.

## 9. Conformidade, extensões e versionamento

**Conformidade de objeto:** validar JCS, CIDs, schemas, assinaturas e vínculo com o certificado exato. O reconhecimento da AC é uma decisão local separada da validade criptográfica do objeto. **Conformidade de nó:** tratar os 14 tipos Wire, aplicar handshake, validação CID antes de declarar sucesso de transferência e anunciar ao menos um perfil padronizado. **Conformidade de AC:** validar prova de posse, emitir certificados conforme schema, utilizar chaves corretas e assinar seu próprio descriptor/snapshots quando publicados.

Campos desconhecidos nos tipos nucleares são rejeitados (schemas fechados). Extensões futuras devem receber nova versão de objeto ou namespace/estrutura expressamente definida; não alterar silenciosamente dados assinados de v2. `claims` é o único espaço estruturado de claims da autoridade, sem novos campos arbitrários em posts.

A v0.2 define **versão de wire/objetos `2`**, não uma promessa de compatibilidade automática com v0.1. Transportes diferentes não devem alterar o CID do mesmo bloco nem a assinatura do mesmo autor. A especificação do protocolo não obriga atualização automática de implementações existentes.

## 10. Propriedades e limites intencionais

- Content addressing garante que os bytes correspondam ao CID, não a veracidade de uma afirmação textual.
- Certificado válido identifica a chave e a autoridade que o assinou, não um endosso global ao usuário.
- Um nó pode ser modificado ou não confiável e ainda transportar um objeto AXIPY válido; o receptor valida independentemente.
- A confiança em uma AC não exige confiar no servidor que hospeda o post; também não impõe confiar em todos os nós usados como bootstrap.
- Sem disponibilidade assegurada, nenhuma implementação é obrigada a hospedar todos os textos.
- Conformidade não implica um feed público único ou uma rede social globalmente descoberta.

## 11. Considerações de Segurança

Esta seção reúne propriedades e limites de segurança da versão 2. As regras de validação estão nas seções [2](#2-criptografia-e-codificação), [4](#4-certificação-de-usuários), [5](#5-posts-apenas-texto-puro) e [7](#7-protocolo-de-comunicação-abstrato-axipy-wire-2); recomendações operacionais não criam uma política global de aceitação.

- **Integridade e autenticidade:** o CID confirma os bytes canônicos do objeto completo; as assinaturas autenticam o payload em seu contexto e o verificador confere o vínculo entre `certificate_cid`, `author_key_id`, `subject_key` e assinatura da AC. Isso não prova a veracidade do texto, a identidade civil do autor nem a confiabilidade do nó que o entregou.
- **Confiança seletiva:** a validade estrutural e criptográfica é distinta da decisão local de reconhecer uma AC e distribuir um objeto. Descriptors, bootstraps, anúncios e indicações de providers não concedem confiança. Nenhuma AC é universalmente obrigatória.
- **Revogação:** snapshots são assinados, identificados por CID e ordenados por `sequence` por AC. `issued_at` e `next_update` não atestam instantaneamente o estado de toda a rede. Um `next_update` ultrapassado indica possível desatualização, sem invalidar a assinatura ou revogar certificados por si só. Cada nó escolhe localmente como operar com informação atrasada ou indisponível; não há consulta online obrigatória por post nem escolha global entre aceitar e rejeitar.
- **Reutilização e replay:** nonces frescos, `request_id`, `session_id`, assinaturas e estados de handshake vinculam mensagens a uma tentativa e permitem rejeitar duplicatas e mensagens de outra sessão. O receptor precisa manter estado suficiente enquanto a sessão está ativa. `sent_at` é declarado pelo emissor e, sozinho, não é prova de frescor; um relay ativo em tempo real não é excluído pelo handshake AXIPY.
- **Anúncios enganosos:** `ANNOUNCE.issuer_id` permite filtrar antes do download, mas é alegação do transmissor. A AC efetiva só é verificada no certificado assinado referido pelo post; anúncios falsos não validam objetos. Como recomendação de implementação não normativa, operadores podem limitar anúncios, pedidos, bytes e sessões por peer e registrar inconsistências para decisões locais, sem reputação ou penalização universal.
- **Transporte:** autenticação de mensagens não equivale a confidencialidade. O TCP básico expõe conteúdo e metadados na rede; uma sessão libp2p protegida pode acrescentar sigilo e autenticação do PeerId, conforme seu protocolo de segurança negociado. O vínculo PeerId–`node_id` ainda deve ser verificado separadamente. Veja [TCP](profiles/TCP.md) e [libp2p](profiles/LIBP2P.md).
- **Unicode e apresentação:** o texto é assinado e identificado sem normalização automática. Sequências Unicode distintas podem ter aparência igual e CIDs diferentes. Homóglifos, caracteres de controle e marcadores bidirecionais podem induzir uma leitura visual enganosa. Como recomendação de implementação não normativa, aplicações podem tratar esse risco na apresentação, sem formato de interface imposto pelo protocolo.
- **Identidades e chaves:** o protocolo não impede que uma pessoa crie várias chaves ou obtenha certificados de mais de uma AC. Uma chave privada comprometida permite assinar novos objetos com aquela identidade até que os receptores a tratem conforme certificados, revogação e política local. O protocolo não oferece recuperação automática, proteção da chave no dispositivo, prevenção global de abuso, disponibilidade de blocos nem consenso sobre horário ou ordem de publicações.

## 12. Material verificável deste pacote

- `schemas/*.schema.json`: formatos verificáveis em JSON Schema Draft 2020-12.
- `examples/*.json`: certificado, post, descriptors, anúncio e blocos completos reais assinados por chaves **somente de teste**.
- `tests/`: gerador determinístico de exemplos, testes de schemas, CIDs e assinaturas, e vetores positivos/negativos.
- `profiles/`: regras específicas de TCP e libp2p; `reference/`: codec interoperável mínimo (não é servidor social).
- `MIGRATION.md`: mudanças explícitas em relação à v0.1.
- `REFERENCES.md`: especificações consolidadas aproveitadas (CID, JCS, libp2p etc.).
