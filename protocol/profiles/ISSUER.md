# AXIPY Issuer Exchange 2 — obtenção de certificados

**A certificadora é uma entidade diferente de um nó AXIPY.** Ela pode operar um serviço independente para emitir certificados. Esse serviço não participa da propagação de posts, não precisa disponibilizar `HELLO`, `ANNOUNCE` ou `WANT`, e não recebe automaticamente poderes de nó. O protocolo define as mensagens da certificação, mas não impõe cadastro com identidade civil nem interface visual.

## Tipos de mensagem

1. O titular assina `cert-request` com `AXIPY/CERT-REQUEST/2\n`: `subject_key`, `nonce` e `created_at`. Isso demonstra posse da chave privada correspondente.
2. O cliente transmite um `issue-submit` `{ "request": <cert-request>, "forward": null | <issue-forward> }`.
3. O serviço da AC valida o pedido e aplica sua própria política (pode solicitar documentos, verificações complementares etc. por mecanismos próprios). Responde com `issue-result` assinado usando `AXIPY/ISSUE-RESULT/2\n`:
   - `status="issued"` e `certificate` não nulo;
   - `status="pending"` e `certificate=null`;
   - `status="denied"` e `certificate=null`.
   O campo `request_nonce` associa o resultado ao pedido original. A resposta deve estar assinada pela AC já conhecida pelo destinatário, e o certificado, quando emitido, também deve ter a própria assinatura independente da AC.

## Encaminhamento por um nó

Se o pedido for submetido por um nó que deseja registrar **quem originou o cadastro**, o nó pode incluir `issue-forward`: objeto assinado com `AXIPY/ISSUE-FORWARD/2\n` contendo sua identidade de nó (`node_id`, `node_key`), CID do pedido `request_cid`, nonce e horário. A AC verifica a assinatura e a correspondência do `request_cid`. Esse registro permite à AC atestar `registration.requested_by=<node_id>` e `requester_verification="cryptographic"` quando de fato verificou esse vínculo. Se não houver comprovação, a AC usa `observed`, `declared` ou `null` conforme a informação efetivamente observada. Campos de certificação não são preenchidos sob ordens do cliente sem checagem da AC.

## Endereçamento e transporte

O `authority-descriptor` anuncia endereços opcionais com perfil `axipy-issuer-tcp/1` ou `axipy-issuer-libp2p/1`.

- **TCP:** conexão ao multiaddr publicado; envia-se frame de quatro bytes uint32 big-endian seguido de JCS UTF-8 de `issue-submit`, recebe-se frame com JCS UTF-8 de `issue-result`. Tamanho máximo de 1 MiB; múltiplos pedidos na mesma conexão podem ser suportados por correlação de `request_nonce`, mas não são obrigatórios.
- **libp2p:** abrir stream com identificador `/axipy/issuer/2.0.0`, transmitir os mesmos frames. O PeerId é apenas identidade da conexão libp2p; a autenticidade do resultado advém da assinatura Ed25519 da AC confiável.

Um serviço de certificação pode, além disso, oferecer uma interface HTTP, aplicativo, formulário ou integração de terceiros, **sem que isso se torne o formato de mensagens universal**. Um nó AXIPY não precisa implementar esse serviço para ser um nó válido.

## Privacidade e alcance

O protocolo padroniza apenas campos compartilhados do certificado (`policy_id`, `registration`, `claims`) e suas assinaturas. Dados sensíveis coletados por uma autoridade não devem ser presumidos públicos nem incluídos no certificado por padrão. A política da autoridade determina retenção, forma de cadastro e requisitos. O protocolo não confere confiança automática a autoridades recém-descobertas.
