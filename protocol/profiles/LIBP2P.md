# Perfil de transporte AXIPY/libp2p/1

**Papel:** executar AXIPY Wire 2 como protocolo de aplicação sobre streams libp2p. Não exige HTTP nem libp2p para outros transportes.

## Identificador do protocolo

`/axipy/2.0.0`

O nó registra um handler de stream bidirecional libp2p para esse identificador. O stream transporta frames AXIPY com o **mesmo formato uint32 big-endian + JCS UTF-8** definido em [TCP.md](TCP.md) (nunca assumir que chunks do stream delimitam mensagens). Multiplexação e negociação do stream são fornecidas pelo stack libp2p; assinaturas de mensagens e validação AXIPY continuam obrigatórias.

### Segurança do canal e da sessão AXIPY

Uma conexão libp2p que negociou e verificou um protocolo seguro, como Noise ou TLS conforme a configuração do stack, fornece as garantias desse canal: autenticação da identidade libp2p observada, integridade e confidencialidade do tráfego da conexão. O handshake AXIPY `HELLO → CHALLENGE → CONFIRM → READY` é uma negociação de aplicação **sobre** esse canal: autentica as chaves AXIPY apresentadas e estabelece `session_id`, sem divulgar listas de ACs reconhecidas. Ele não substitui Noise/TLS, não negocia sua própria chave de cifragem e não herda automaticamente um vínculo entre PeerId e `node_id`.

O receptor confere assinatura, nonces, `request_id`, `session_id` e estado conforme [SPEC.md §7.2](../SPEC.md#72-handshake-de-nós). Ao usar libp2p, também confere que o PeerId autenticado pelo canal corresponde ao peer esperado por sua política e que qualquer associação prévia PeerId–`node_id` permanece consistente. A sessão AXIPY só fica pronta após `READY`; B autentica a confirmação de A em `CONFIRM`. A proteção contra replay entre sessões depende de nonces e IDs novos e da rejeição de mensagens/solicitações duplicadas, não de uma promessa genérica da multiplexação libp2p. O handshake AXIPY não vincula criptograficamente seu transcript aos bytes do canal libp2p; a associação é uma verificação local entre identidades observadas na mesma conexão.

## Identidades

O endereço é multiaddr com sufixo `/p2p/<PeerId>`, por exemplo `/ip4/203.0.113.10/tcp/4101/p2p/<PeerId>` (valor ilustrativo). O PeerId libp2p **não** substitui `node_id` AXIPY. Na primeira mensagem `HELLO`, o nó apresenta JWK AXIPY; o receptor confere `node_id = keyId(node_key)` e valida assinatura da mensagem, e pode associar PeerId observado e chave AXIPY àquela sessão. Uma divergência com o vínculo previamente conhecido deve resultar em recusa de peer; a descoberta de multiaddr por si só não estabelece confiança.

## Descoberta e roteamento

Identify, Kademlia DHT, mDNS, relay e mecanismos de descoberta da libp2p **podem** ser usados para encontrar peers e conectar; nenhum é obrigatório para AXIPY Core. `PEERS` permanece válido para descoberta assinada. `FIND_PROVIDERS/PROVIDERS` no nível AXIPY permite consulta de candidatos sem depender de uma DHT global; implementações podem acelerar essas consultas usando a DHT libp2p, respeitando as políticas de confiança.

Não se usa GossipSub aberto como substituto automático da filtragem `ANNOUNCE → DECISION` por autoridade. Se existir disseminação PubSub, deve ser especificada separadamente (tópicos, escopo de visibilidade e confiança) e não altera requisitos de validação de `BLOCK`.

## Compatibilidade

Implementações libp2p em JS, Go e Rust podem interoperar quando negociam `/axipy/2.0.0`, transportam o mesmo framing e respeitam os mesmos schemas e decisões. Um nó **somente** libp2p não pode se comunicar diretamente com um nó **somente** TCP simples sem uma ponte compatível.
