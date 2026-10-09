# AXIPY Wire 2 — fluxos completos de interação

Este documento ilustra sequências com os **mesmos tipos e campos** definidos nos schemas. É explicativo e não acrescenta requisitos à [especificação normativa](SPEC.md). Exemplos assinados estão em `examples/`. Um passo não implica que todos os peers armazenem ou redistribuam conteúdo; escolhas de conexão, armazenamento e propagação são políticas locais.

## Cenário 1 — nascer uma rede com três bootstraps

Uma organização opera a **AC AXIPY** e os nós `AXIPY-N1`, `AXIPY-N2`, `AXIPY-N3`. Eles podem ser serviços independentes, em máquinas distintas, cada um com sua própria identidade de nó. A AC certifica chaves de usuários. Os três bootstraps não possuem automaticamente a chave privada da AC.

Um desenvolvedor cria `Node D` com chave Ed25519. Em sua configuração local registra:

- Chave pública confiável da AC AXIPY (para validar certificados de usuários).
- Multiaddrs de N1, N2 e N3, somente como pontos de partida para descoberta.
- Perfis de transporte efetivamente suportados (`axipy-tcp/1` e/ou `axipy-libp2p/1`).

Node D obtém descriptors assinados de peers; A e D estabelecem sessão via protocolo negociado. Pode receber candidatos adicionais em `PEERS`. D não é obrigado a aceitar N2, N3 nem os candidatos apenas porque o primeiro bootstrap os indicou.

## Cenário 2 — primeiro cadastro de usuário

```text
Usuário gera par Ed25519 próprio
   |
   v
cert-request: assinatura do pedido pela chave do usuário
   |
   +------> Nó D inclui issue-forward assinado (se atuou como intermediário)
   |              |
   v              v
Autoridade AXIPY: issue-submit (request + forward opcional)
   |
   +--> verifica posse de chave e identidade do encaminhador, se houver
   +--> aplica sua política própria de certificação
   v
issue-result: issued / pending / denied (assinado pela AC)
   |
   v
Se issued: certificado assinado pela AC; CID do certificado verificável
```

Nenhuma etapa concede a D autoridade para certificar outros usuários em nome da AXIPY. O mesmo usuário pode publicar em implementações diferentes com a chave privada correspondente ao certificado.

## Cenário 3 — propagar post entre dois nós

```text
[Nó A]                                 [Nó B]
  |                                      |
  |--- HELLO(key_A, nonce_A, versions) -->|
  |<-- CHALLENGE(key_B, nonce_A, nonce_B, session) --|
  |--- CONFIRM(nonce_A, nonce_B, session) -->|
  |<-- READY(session) ------------------|
  |                                      |
  |--- ANNOUNCE(CID_P, AC, autor) ----->|
  |<-- DECISION(WANT, CID_P) -----------|
  |<-- WANT(CID_P) ---------------------|
  |--- BLOCK(CID_P, post) ------------->|
  |                                      |-- verifica CID_P
  |                                      |-- lê certificate_cid
  |<-- WANT(CID_C) ---------------------|
  |--- BLOCK(CID_C, certificado) ------>|
  |                                      |-- verifica CID_C
  |                                      |-- verifica assinatura AC
  |                                      |-- verifica assinatura autor
  |                                      |-- aplica política local
```

Em caso de autoridade não reconhecida, B pode responder `DECISION(REJECT, reason=null)` antes de baixar `BLOCK`, sem transmitir sua lista de ACs. A resposta ainda permite inferências sobre a decisão local. Ao baixar `BLOCK`, B continua obrigado a verificar que o certificado de fato pertence à AC anunciada. O mesmo certificado pode ser obtido de outro fornecedor; A não monopoliza o acesso ao objeto.

O `issuer_id` de `ANNOUNCE` é apenas a alegação preliminar de A. Se diferir do `issuer_id` do certificado assinado apontado pelo post, B identifica um anúncio inconsistente; não passa a confiar no objeto por causa da declaração. A validade estrutural/criptográfica do post continua separada da decisão local de B de aceitá-lo.

## Cenário 4 — localizar objeto por CID sem saber quem publicou

```text
D tem CID_P, mas não possui seu bloco.
D -> peers conhecidos: FIND_PROVIDERS(CID_P)
B -> D: PROVIDERS(CID_P, [descriptor C, descriptor E])
D negocia sessão com C, se aceitar o peer.
D -> C: WANT(CID_P)
C -> D: BLOCK(CID_P, post)
D confere CID, certificado e assinatura, independentemente de B e C.
```

Um `PROVIDERS` só indica fornecedores **alegados**. Um fornecedor pode não possuir mais o bloco ou não autorizar D a recebê-lo. DHT libp2p é opção de descoberta, não uma condição para usar o Wire AXIPY.

## Cenário 5 — grupos de confiança parcialmente isolados

- Node X confia nas ACs **AXIPY** e **A**.
- Node Y confia nas ACs **A** e **B**.
- Node Z confia somente na AC **D**.

X e Y podem estabelecer sessão sem divulgar seus conjuntos de ACs e trocar posts de usuários certificados por A, desde que suas políticas de peer permitam. X pode recusar um anúncio de autor certificado somente por B; Y pode aceitá-lo. Z não é obrigado a estabelecer sessões com nenhum dos dois. Uma ponte voluntária pode existir, mas não ganha poder de alterar assinaturas ou de criar confiança em D.

## Cenário 6 — certificado revogado, conteúdo ainda imutável

A AC publica novo snapshot `revocations` com sequência crescente. O CID do post anteriormente publicado permanece **idêntico**, porque o texto e a assinatura não mudaram. Um nó que recebe o novo snapshot pode recusar passar a aceitar aquele certificado conforme sua política; outro nó que ainda não sincronizou a AC pode ter informação de revogação mais antiga. O protocolo não afirma que a rede inteira possui um estado de revogação instantaneamente idêntico.

Quando o horário UTC atual alcança `next_update`, o snapshot pode estar desatualizado, mas sua assinatura e seu CID continuam verificáveis. A passagem do prazo não revoga certificados nem obriga o nó a aceitá-los ou rejeitá-los; essa é uma decisão local. `next_update` não prova ausência de revogação nem exige consulta online à AC para cada post.
