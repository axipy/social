# AXIPY 2 — checklist de conformidade por implementador

**Core independente da linguagem.** Este checklist resume requisitos de interoperabilidade da [especificação normativa](SPEC.md), que é a única fonte de verdade em caso de divergência. Marque cada item aplicável se a implementação o satisfizer; a escolha de transporte é separada. Critérios de confiança e políticas de operação são tratados abaixo, fora do checklist de conformidade.

## Objetos e identidade

- [ ] Parse JSON I-JSON estrito (sem chaves duplicadas); canonicalizar JCS RFC 8785 em UTF-8.
- [ ] Reconhecer apenas Ed25519 e JWK público `{kty,crv,x}` para tipos v2.
- [ ] Calcular e comparar thumbprint `axk1_` da chave pública.
- [ ] Validar assinatura com prefixo de contexto correto para cada tipo.
- [ ] Produzir CIDv1 multibase base32, raw + SHA-256 sobre JCS do objeto assinado completo, e rejeitar CID não canônico.
- [ ] Implementar schemas fechados; rejeitar campos extras ou versões não suportadas.
- [ ] Verificar certificado com chave de AC **reconhecida localmente**, não extraída de um descriptor sem aprovação.
- [ ] Verificar vinculação entre usuário certificado e post, datas e dados de revogação aplicáveis conforme a especificação.
- [ ] Resolver o `certificate_cid` assinado pelo autor para o certificado exato; não substituir por outro certificado da mesma chave.
- [ ] Rejeitar posts com campo text vazio ou com mais de 16384 bytes UTF-8 (não confundir bytes com caracteres Unicode).
- [ ] Tratar `reply_to` como referência por CID e não exigir a existência imediata do objeto pai.
- [ ] Tratar `created_at` como declaração assinada do autor, sem inferir prova do horário real ou ordem global; preservar bytes de texto sem normalização Unicode automática para calcular assinatura/CID.

## Nós e sessões

- [ ] Nó publica descriptor assinado, identificador consistente e ao menos um transporte suportado.
- [ ] Processa HELLO, CHALLENGE, CONFIRM, READY, incluindo assinatura, nonces e sessão, sem divulgar conjuntos de ACs reconhecidas nos corpos do handshake.
- [ ] Autentica mensagem Wire com a chave do nó emissor; confere estados, eco de `request_id`, `session_id` e nonces, e não processa duplicatas como novas solicitações.
- [ ] Trata `issuer_id` e `author_key_id` de `ANNOUNCE` como alegações; se baixar `BLOCK`, confere ambos contra post/certificado e não aceita o objeto por causa do anúncio.
- [ ] Verifica assinatura, CID e `sequence` dos snapshots de revogação; rejeita assinatura inválida e retrocesso de `sequence` por AC, sem tratar uma assinatura válida como reconhecimento automático da emissora.
- [ ] Implementa DECISION, WANT, BLOCK, NOT_FOUND, PEERS, FIND_PROVIDERS, PROVIDERS, GOODBYE, ERROR.
- [ ] Trata endereços de peers descobertos como indicações, sem atribuir a eles autoridade criptográfica.
- [ ] Não assume que bootstrap, provedor ou PeerId de libp2p garantem a confiança do conteúdo.
- [ ] Recusa frames acima de 1 MiB e blocos acima de 256 KiB.
- [ ] Não reescreve, não reassina e não reidentifica um post em cada salto.

## Serviços de autoridade (se implementar uma AC)

- [ ] Aceita `issue-submit`, verifica `cert-request` assinado pelo titular.
- [ ] Se houver `issue-forward`, confere chave do nó e vínculo ao CID do pedido antes de afirmar origem criptograficamente verificada.
- [ ] Devolve `issue-result` assinado; quando `issued`, anexa um certificado também assinado pela AC.
- [ ] Não interpreta `requested_by` enviado pelo usuário como identidade verificada por padrão.

## Perfis

- [ ] Perfil TCP, se anunciado: `uint32be || JCS(objeto)` por frame, com parser de stream que suporta fragmentação.
- [ ] Perfil TCP: não atribui confidencialidade ou forward secrecy ao handshake assinado AXIPY.
- [ ] Perfil libp2p, se anunciado: negociar `/axipy/2.0.0`, manter vínculo PeerId/node_id e mesmo framing.
- [ ] Perfil issuer, se anunciado pela AC: `/axipy/issuer/2.0.0` ou TCP de emissão com mensagens de cadastro distintas do Wire de nós.

## Políticas locais, fora da conformidade

O operador escolhe quais ACs reconhecer, com quais peers conectar, quando buscar snapshots recentes e o que fazer se `next_update` passou ou um snapshot está indisponível. Também define rate limiting, quotas de armazenamento, retenção, priorização de peers e propagação. Essas escolhas não são requisitos do Wire 2 e não substituem validação de formato, CID, assinaturas, vínculo do certificado ou rejeição de retrocesso de `sequence`. Um snapshot que passou de `next_update` não perde autenticidade por isso e não revoga certificados automaticamente. Veja [SPEC.md, seção 4.3](SPEC.md#43-descritores-e-revogação).

## Recomendações de implementação, não normativas

Uma implementação pode registrar separadamente o resultado da validação criptográfica, a decisão de reconhecer a AC e a decisão operacional de aceitar ou distribuir o objeto. Também pode sinalizar quando `agora >= next_update` em UTC e tentar obter um snapshot mais recente por fontes que o operador permita. Esses procedimentos ajudam no diagnóstico, mas não acrescentam condições de conformidade.

## Testes de interoperabilidade do pacote

```bash
node tests/generate_vectors.mjs
node tests/verify_node.mjs
python tests/verify_vectors.py
```

Os testes cobrem vetores de assinatura e schema. **Eles não substituem testes reais de interoperabilidade na rede**, que exigem pelo menos dois nós desenvolvidos/operados separadamente e testes de sessão, descoberta, filtragem e transferência.
