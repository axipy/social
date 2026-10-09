# Transporte não é protocolo

O formato de certificado, CID e assinatura da AXIPY não depende de TCP, libp2p, HTTP nem da linguagem da aplicação.

**Neste repositório**: a comunicação peer-to-peer é AXIPY Wire v2 sobre TCP (`src/peers.mjs`). A UI web usa HTTP localmente, mas nenhuma API HTTP é requisito do protocolo.

**Outro desenvolvedor pode escolher libp2p**: abrir um stream identificado por `/axipy/2.0.0`, enviar os mesmos frames descritos em `protocol/profiles/LIBP2P.md`, passar os envelopes ao mesmo verificador e aplicar a mesma política local. Se a instalação libp2p só conversar com peers libp2p, ela não conectará diretamente a um nó que tenha apenas TCP; para isso, a própria implementação deve habilitar ambos perfis ou haver uma ponte AXIPY entre os transportes.

Esta aplicação ainda não fornece um adaptador libp2p pronto. Não há simulação de libp2p nem uma API HTTP se passando por ele.
