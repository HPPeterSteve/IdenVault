# 🦎 Komodo Core (VaranusCore)

**Komodo Core** é uma engine de cofre digital (digital vault) e ambiente de execução restrito, focada em segurança prática e projetada nativamente para **Linux**.

Construído com uma fundação robusta em **Rust** e um core de alta performance em **C**, o projeto fornece ferramentas maduras para proteger seus arquivos sensíveis e isolar execuções perigosas, extraindo o melhor das APIs do kernel Linux.

## 🎯 Por que o Komodo Core?

Armazenar arquivos sensíveis ou rodar scripts de origens desconhecidas exige cautela no ambiente Linux. O Komodo Core atua em duas frentes:

1. **Cofres Criptografados:** Diretórios protegidos localmente com criptografia forte (AES-256-GCM + Argon2).
2. **Sandboxing Nativo:** Execução isolada impedindo acesso indevido ao `/` (root) ou à rede.

---
*(Insira a Imagem da Interface Aqui)*  
<!-- Exemplo: ![Interface do Komodo](img/interface_qt.png) -->
---

## 🛡️ Mecanismos de Segurança (Linux Native)

Aproveitamos a segurança embutida no próprio kernel:
- **Namespaces (PID, Mount, Network):** Criação de ambientes isolados para os processos.
- **Seccomp (Secure Computing):** Filtragem estrita de chamadas de sistema (Syscalls).
- **inotify:** Rastreamento em tempo real de alterações de arquivos.
- **OpenSSL/Rust Crypto:** Criptografia em repouso imune a vazamentos físicos.

## 💻 Comandos e Uso (Linux)

O projeto roda como uma interface de linha de comando iterativa no Linux. Compile com o Cargo e execute:

```bash
cargo build --release
./target/release/VaranusCore
```

---
*(Insira a Imagem do Terminal Aqui)*  
<!-- Exemplo: ![Terminal do Komodo](img/terminal.png) -->
---

Abaixo estão os comandos do console do Komodo para aplicar as políticas de segurança no seu sistema Linux:

### Sandboxing e Isolamento
O core extrai o poder das restrições do Linux para os seguintes comandos:

- **Isolar um diretório:**
  ```text
  isolate-directory /caminho/do/diretorio
  ```
  *(Aplica políticas e bloqueia acessos externos ao diretório)*

- **Rodar processo em Sandbox:**
  ```text
  run-in-sandbox /caminho/do/script.sh
  ```
  *(Utiliza Namespaces e Seccomp para rodar o processo de forma isolada, protegendo o sistema host)*

### Operações do Cofre (Vault)
Comandos para manipular diretamente a criptografia e os cofres no sistema de arquivos do Linux:

- **Criar cofre protegido:**
  ```text
  vault-create meu_cofre /home/usuario/cofres/meu_cofre protected
  ```

- **Proteger arquivo (Move e criptografa):**
  ```text
  secure-copy /home/usuario/docs/secreto.pdf /home/usuario/cofres/meu_cofre
  ```

- **Bloqueio e Desbloqueio de Arquivos (Criptografia):**
  ```text
  vault-encrypt <id_do_cofre>
  vault-decrypt <id_do_cofre>
  ```

- **Gerar Chave de Segurança Física:**
  ```text
  derive-master-key
  ```
  *(Utiliza uma chave USB/Hex combinada com senha para máxima segurança)*

## 🤝 Interface Gráfica e FFI (C/C++)

A engine expõe uma interface **FFI C-Bindings**. Como o projeto foi desenvolvido em Rust/C, ele está totalmente preparado para ser integrado de forma nativa e super rápida em aplicações C++. 

Isso possibilita o controle total da engine por meio de interfaces gráficas maduras para o desktop Linux, como as desenvolvidas em **Qt (QML / C++)**, unindo a performance do back-end de segurança com um front-end moderno.
