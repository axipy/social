# AXIPY 2 — checklist de conformidade por implementador

**Core independente da linguagem.** Marque cada item se a implementação o satisfizer; a escolha de transporte é separada.

## Objetos e identidade

- [ ] Parse JSON I-JSON estrito (sem chaves duplicadas); canonicalizar JCS RFC 8785 em UTF-8.
- [ ] Reconhecer apenas Ed25519 e JWK público `{kty,crv,x}` para tipos v2.
- [ ] Calcular e comparar thumbprint `axk1_` da chave pública.
- [ ] Validar assinatura com prefixo de contexto correto para cada tipo.
- [ ] Produzir CIDv1 multibase base32, raw + SHA-256 sobre JCS do objeto assinado completo, e rejeitar CID não canônico.
- [ ] Implementar schemas fechados; rejeitar campos extras ou versões não suportadas.
- [ ] Verificar certificado com chave AC **previamente confiável localmente**, não extraída de um descriptor sem aprovação.
- [ ] Verificar vinculação entre usuário certificado e post, datas e estado de revogação conforme política.
- [ ] Rejeitar posts com campo text vazio ou com mais de 16384 bytes UTF-8 (não confundir bytes com caracteres Unicode).
- [ ] Tratar `reply_to` como referência por CID e não exigir a existência imediata do objeto pai.

## Nós e sessões

- [ ] Nó publica descriptor assinado, identificador consistente e ao menos um transporte suportado.
- [ ] Processa HELLO, CHALLENGE, CONFIRM, READY, incluindo assinatura, nonces e autoridades aceitas.
- [ ] Autentica mensagem Wire com a chave do nó emissor e verifica correlação request_id/session_id.
- [ ] Filtra ANNOUNCE antes de baixar; revalida origem real em BLOCK.
- [ ] Implementa DECISION, WANT, BLOCK, NOT_FOUND, PEERS, FIND_PROVIDERS, PROVIDERS, GOODBYE, ERROR.
- [ ] Aplica sua política de conexão a novos peers descobertos, sem confiar automaticamente nos endereços indicados.
- [ ] Não assume que bootstrap, provedor ou PeerId de libp2p garantem a confiança do conteúdo.
- [ ] Recusa frames acima de 1 MiB e blocos acima de 256 KiB.
- [ ] Não reescreve, não reassina e não reidentifica um post em cada salto.

## Serviços de autoridade (se implementar uma AC)

- [ ] Aceita `issue-submit`, verifica `cert-request` assinado pelo titular.
- [ ] Se houver `issue-forward`, confere chave do nó e vínculo ao CID do pedido antes de afirmar origem criptograficamente verificada.
- [ ] Devolve `issue-result` assinado; quando `issued`, anexa um certificado também assinado pela AC.
- [ ] Não interpreta `requested_by` enviado pelo usuário como identidade verificada por padrão.
- [ ] Expõe seus próprios critérios de cadastro e revogação sem torná-los regras globais.

## Perfis

- [ ] Perfil TCP, se anunciado: `uint32be || JCS(objeto)` por frame, com parser de stream que suporta fragmentação.
- [ ] Perfil libp2p, se anunciado: negociar `/axipy/2.0.0`, manter vínculo PeerId/node_id e mesmo framing.
- [ ] Perfil issuer, se anunciado pela AC: `/axipy/issuer/2.0.0` ou TCP de emissão com mensagens de cadastro distintas do Wire de nós.

## Testes de interoperabilidade do pacote

```bash
node tests/generate_vectors.mjs
node tests/verify_node.mjs
python tests/verify_vectors.py
```

Os testes cobrem vetores de assinatura e schema. **Eles não substituem testes reais de interoperabilidade na rede**, que exigem pelo menos dois nós desenvolvidos/operados separadamente e testes de sessão, descoberta, filtragem e transferência.
