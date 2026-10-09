# Perfil de transporte AXIPY/TCP/1

**Papel:** carregar exatamente as mensagens `axipy.wire` v2 sem HTTP. **Obrigatório para todos os nós? NÃO.** Quem anunciar `axipy-tcp/1` DEVE implementar este perfil.

## Endereçamento

O endereço anunciado é uma multiaddr que termina em `/tcp/<porta>` (por exemplo `/ip4/127.0.0.1/tcp/4101` ou `/dns4/no.example/tcp/4101`). `node-descriptor` vincula essa multiaddr à chave `node_id` via assinatura. A porta sozinha não identifica uma chave. IPv6 pode ser usado via `/ip6/.../tcp/porta`.

## Bytes da conexão

Após abrir conexão TCP, cada mensagem é um frame:

```
[4 octetos: comprimento N, uint32 big-endian, 1 <= N <= 1048576]
[N octetos: UTF-8 de JCS(objeto axipy.wire completo)]
```

O emissor DEVE usar bytes JCS; o receptor DEVE verificar framing, JSON/I-JSON, schema, assinatura e sessão. Não há um marcador extra de versão fora do envelope: a primeira mensagem AXIPY é `HELLO`, já contém `version:"2"`. Um frame com comprimento acima do máximo é rejeitado antes de ler/alocar o corpo. TCP pode fragmentar uma escrita ou agrupar várias escritas; leitores DEVEM remontar por comprimento, não por delimitador de linha.

A aplicação pode enviar múltiplos frames na mesma conexão. `request_id` correlaciona respostas. Encerra-se com `GOODBYE` ou fechamento de socket. Reabertura exige novo handshake. O limite de fluxos simultâneos é uma política local, fora dos requisitos de conformidade deste perfil.

### Privacidade

Este perfil básico **não promete sigilo do tráfego** apenas por haver assinatura Ed25519 de mensagens. O handshake AXIPY autentica as chaves de nó apresentadas e vincula a tentativa por nonces e ID de sessão, após as verificações de [SPEC.md §7.2](../SPEC.md#72-handshake-de-nós); ele não negocia cifra, não fornece forward secrecy nem vincula criptograficamente a identidade AXIPY à conexão TCP. Um observador pode ler mensagens e blocos, e um intermediário pode retransmitir tráfego em tempo real. **Recomendação de implementação não normativa:** uma implantação que exija sigilo pode usar um transporte protegido de forma compatível ou o perfil libp2p. O perfil básico não fornece criptografia para ser anunciada.

`HELLO`, `CHALLENGE` e `READY` não transportam conjuntos de ACs reconhecidas, mas isso não oculta o `issuer_id` de `ANNOUNCE` nem padrões de aceitação, rejeição e tráfego. O receptor consulta sua confiança local quando processa anúncios e certificados; a proteção do canal cabe ao transporte utilizado.

### Teste mínimo de conformidade

Enviar `HELLO`, obter `CHALLENGE`, responder `CONFIRM`, receber `READY`, enviar `ANNOUNCE`, receber `DECISION`, efetuar `WANT`/`BLOCK`, verificar CID e assinatura; fragmentar o prefixo de comprimento em diferentes `write()`s não deve quebrar o parser.
