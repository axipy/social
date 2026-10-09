<p align="center">
  <img src="public/assets/axipy-brand.webp" alt="AXIPY" width="600">
</p>

<h1 align="center">AXIPY Social</h1>

<p align="center">
  Aplicação social e nó de referência para publicar, validar e distribuir posts no AXIPY Wire 2.
</p>

## Sobre o projeto

AXIPY Social combina uma interface web com um nó que troca objetos assinados com outros nós por TCP. Autores controlam suas próprias chaves Ed25519, publicam texto puro e podem responder a posts. Cada publicação tem um CIDv1 calculado sobre o objeto assinado; o nó verifica CID, assinatura e certificado antes de armazená-la.

Este é o repositório da **aplicação**. A especificação é mantida separadamente em [axipy/protocol](https://github.com/axipy/protocol). A pasta [`protocol/`](protocol/SPEC.md) contém uma cópia da revisão 0.2, incluindo os schemas e o codec usados pelo código e pelos testes deste nó; ela não é outro repositório Git.

## O que está implementado

- Feed textual, respostas, consulta e download do JSON original por CID.
- Identidade Ed25519 criada no navegador, com chave privada não exportável em IndexedDB e backup criptografado restaurável por senha.
- Login por desafio assinado e sessão HTTP com cookie `HttpOnly` e `SameSite=Strict`.
- Solicitação de certificado assinada pelo usuário e encaminhada à autoridade pelo nó.
- Comunicação entre nós com handshake AXIPY Wire 2, anúncios, decisão de recebimento, busca de provedores e transferência de blocos pelo perfil TCP.
- Política local de autoridades confiáveis e identidade de nó separada das identidades dos usuários e da autoridade.

O handshake Wire 2 autentica os nós sem enviar listas de autoridades reconhecidas. O receptor consulta sua configuração local ao receber `ANNOUNCE` e valida novamente a AC real no certificado do post. Um `DECISION(REJECT)` pode revelar algo sobre o comportamento do nó; no TCP básico, o canal também não oferece sigilo por si só.

A interface usa HTTP(S) entre navegador e nó. A federação entre nós usa AXIPY Wire 2 sobre TCP. O perfil libp2p pertence à especificação, mas não está implementado nesta aplicação.

## Executar localmente

Requer **Node.js 22 ou superior**. Não há dependências npm para instalar.

```bash
git clone https://github.com/axipy/social.git
cd social
npm test
npm start
```

A interface abre em [http://127.0.0.1:3000](http://127.0.0.1:3000). O nó usa a porta TCP `4101` para comunicação AXIPY. No Windows, use `npm.cmd` no lugar de `npm` se o PowerShell bloquear `npm.ps1`.

Para configurar portas, endereços, bootstraps e diretório de dados, copie [`.env.example`](.env.example) para `.env`, ajuste os valores e inicie com `node --env-file=.env src/main.mjs`. O comando `npm start` usa os valores padrão do código e as variáveis já presentes no ambiente; ele não lê `.env` automaticamente.

| Configuração | Função |
|---|---|
| `HOST`, `PORT` | Endereço e porta HTTP da interface. |
| `PEER_HOST`, `PEER_PORT`, `PUBLIC_PEER_HOST` | Escuta TCP e endereço anunciado a outros nós. |
| `BOOTSTRAPS` | Multiaddrs TCP dos nós usados na descoberta inicial. |
| `CERT_URL` | Endpoint da autoridade certificadora para pedidos de certificado. |
| `DATA_DIR` | Dados locais do nó, incluindo sua identidade e objetos recebidos. |

O arquivo [`config/trusted-authorities.json`](config/trusted-authorities.json) começa sem chave pública instalada. O cadastro e a publicação dependem de uma autoridade configurada. Para instalar uma **chave pública** Ed25519 verificada, execute `node tools/install-authority.mjs /caminho/para/chave-publica.pem`. A chave privada da autoridade pertence somente ao serviço emissor.

### Fluxo local com a autoridade de desenvolvimento

Em um terminal, execute `npm run dev:ca`. Em outro, instale a chave pública gerada em `var/authority-dev/authority-public.json` com `node tools/install-authority.mjs var/authority-dev/authority-public.json`. Defina `CERT_URL=http://127.0.0.1:4800/v2/issue` no ambiente e inicie o nó. No PowerShell:

```powershell
$env:CERT_URL = 'http://127.0.0.1:4800/v2/issue'
npm.cmd start
```

Esse fluxo permite testar cadastro e publicação sem uma autoridade externa; o teste integrado faz isso automaticamente em diretórios temporários.

## Docker e operação

O [Compose](compose.yaml) executa a interface e o peer TCP, persiste `var/` e monta `config/` em modo leitura. Copie `.env.example` para `.env`, defina `HOST=0.0.0.0` e mantenha `PEER_PORT=4101` para o mapeamento padrão. Depois execute:

```bash
docker compose up -d --build
```

O HTTP é publicado apenas em `127.0.0.1` do host; use um proxy HTTPS para acesso remoto à interface. Há um [Caddyfile de exemplo](Caddyfile.example). Para conexão entre nós, a porta TCP do peer precisa estar acessível aos peers desejados. WebCrypto e IndexedDB exigem HTTPS ou `localhost` no navegador.

## Testes e referências

```bash
npm test
node protocol/tests/verify_node.mjs
```

O teste integrado inicia uma autoridade local e dois nós TCP, emite um certificado, autentica o usuário por assinatura, publica um post e confirma o recebimento no segundo nó. O verificador adicional confere vetores e regras criptográficas do protocolo.

| Caminho | Conteúdo |
|---|---|
| [`src/`](src/) | API HTTP, sessões, política de confiança, identidade e comunicação entre peers. |
| [`public/`](public/) | Interface e identidade no navegador. |
| [`protocol/`](protocol/SPEC.md) | Snapshot local da especificação, schemas e codec AXIPY v0.2. |
| [`docs/INTERFACES.md`](docs/INTERFACES.md) | Contratos da interface e da integração com o nó. |
| [`docs/ADAPTADORES.md`](docs/ADAPTADORES.md) | Pontos de adaptação para outros transportes. |
| [`tests/`](tests/) | Teste de fluxo completo entre autoridade, usuário e dois nós. |

**Licença:** [MIT](LICENSE).
