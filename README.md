# Cybersec-APS2-DiffieHellman-Chat

Esse repositório contém uma implementação de chat em Rust utilizando uma troca de chaves Diffie-Hellman.

Para essa finalidade, foi implementado um protocolo simples de chat cliente/servidor, baseado em pacotes JSON enviados linha a linha. Os clientes negociam entre si os parâmetros utilizados ao gerar as chaves (valor de geração de `p` e `g`), e a chave privada de cada cliente.

Após a geração das chaves públicas, os clientes e o servidor trocam as chaves, e o servidor encaminha as chaves públicas de cada cliente para o outro. Assim, todos podem calcular a chave secreta DH, que é utilizada para criptografar as mensagens, utilizando a cifra de César.

O programa é estruturado em dois _bins_ do Rust: `server` e `client`. Cada um pode ser executado como `cargo run --bin <nome>`.

O servidor espera uma mensagem inicial de cada cliente contendo as seguintes informações:

- Nome de usuário
- Número aleatório `a`
- Chave pública `A = g^a mod p`

Após receber os dados de cada cliente, o servidor repassa as informações de cada cliente para os outros, e inicia o processo de troca de mensagens.
