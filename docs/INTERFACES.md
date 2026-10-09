# Interfaces da aplicação AXIPY Social v0.1

> Estes HTTP endpoints servem **somente à interface web do nó social** e à ponte para a certificadora. **Não** fazem parte do protocolo P2P AXIPY Wire 2, que opera com mensagens sobre TCP ou outros transportes.

## Social / browser — HTTP(S)

| Método e caminho | Corpo ou retorno | Sessão? |
|---|---|---|
| `GET /api/status` | Configuração da AC, identidade do nó, peers, sessão | Não |
| `GET /api/feed?limit=60` | Publicações locais reconhecidas; filtro `author` e `reply_to` | Não |
| `GET /api/posts/:cid` | Objeto assinado completo e certificado | Não |
| `GET /api/peers` | Estado da comunicação AXIPY Wire | Não |
| `POST /api/issue` | `{ "request": <axipy.cert_request> }` | Não; pedido assinado |
| `POST /api/auth/challenge` | `{ "public_key": <JWK pública> }` | Não |
| `POST /api/auth/login` | `{ "nonce", "key_id", "signature", "certificate" }` | Prova criptográfica |
| `POST /api/auth/logout` | `{}` | Sim |
| `POST /api/profile` | `{ "display_name": "..." }` (metadado local, não federado) | Sim |
| `POST /api/posts` | `{ "post": <axipy.post>, "certificate": <axipy.certificate> }` | Sim |

Para `POST /api/auth/login`, o browser assina com Ed25519 os bytes UTF-8 `AXIPY/WEB-LOGIN/1\n` concatenados com a canonicalização JCS de `{ "nonce": "...", "key_id": "..." }`. O servidor responde com cookie HttpOnly, SameSite=Strict. O usuário não transmite a chave privada.

Para publicar, assinar `AXIPY/POST/2\n || JCS(post.payload)` e enviar certificado cuja chave pública e `certificate_cid` correspondam ao autor. O servidor verifica tudo antes de armazenar.

## Certificadora — contrato futuro em `cert.axipy.org`

`POST https://cert.axipy.org/v2/issue` recebe a mensagem `issue-submit` (pedido assinado do titular e encaminhamento assinado do nó social) e devolve a mensagem `issue-result` (assinada pela AC), conforme os schemas normativos. A implementação da AC **não está neste repositório**. Há apenas uma certificadora descartável para desenvolvimento em `dev/authority.mjs`.

Esse endpoint HTTP é uma conveniência entre a aplicação social e a autoridade. Perfis issuer TCP e libp2p são descritos no protocolo `profiles/ISSUER.md`. Não é necessário que a AC ofereça um nó `AXIPY Wire` para emissão.

## Nó / nó — Wire 2/TCP

Porta padrão `4101`: frames de 4 octetos big-endian (`uint32`) + bytes JCS/UTF-8 do envelope completo, máximo 1 MiB. `HELLO` e `CHALLENGE` em sessão nula, seguidos de `CONFIRM` e `READY`; após isso: `ANNOUNCE → DECISION(WANT|SKIP|REJECT) → WANT → BLOCK` para post e certificado. Nunca assumir validade apenas porque o peer assinou o envelope. Ver `protocol/SPEC.md` e `protocol/profiles/TCP.md`.

## Observações de implantação

- Não use a chave privada da AC no nó social.
- Não exponha a porta web sem HTTPS fora de localhost.
- Abra TCP na porta peer para participar efetivamente da rede.
- Inspecione e ajuste `config/trusted-authorities.json` antes da abertura pública.
- Dados persistentes e a chave do nó ficam em `var/` e não devem ser enviados ao GitHub.
