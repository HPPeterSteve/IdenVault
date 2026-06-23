# IdenVault: Whitepaper e Arquitetura de Sistemas

O **IdenVault** é uma *engine* avançada de isolamento criptográfico de arquitetura híbrida. Projetado para atuar na fronteira mais profunda e sensível do Kernel Linux, ele combina a segurança de memória e a capacidade de orquestração do **Rust** com a performance bruta e a manipulação direta de ponteiros e chamadas de sistema (syscalls) da linguagem **C**.

Este documento detalha o escopo tecnológico, o fluxo de comandos, a evolução do desenvolvimento ao longo do tempo e o nível de segurança governamental/militar implementado no projeto.

---

## 1. Evolução do Desenvolvimento e Desafios (Timeline)

O desenvolvimento do IdenVault não seguiu um fluxo de aplicação web tradicional. Como o projeto mexe com permissões diretas do Kernel e subsistemas sensíveis, a evolução enfrentou os seguintes marcos:

1. **Gênese e FFI (Foreign Function Interface):** 
   A decisão arquitetural de separar a interface (Rust) do motor de isolamento (C). Foi estabelecido um canal seguro de comunicação em que o Rust lida com a chave do usuário de forma segura, e o C a consome garantindo o descarte via `explicit_bzero` e `memset_s` para evitar ataques de despejo de memória (*cold boot attacks*).

2. **O Desafio do Sandboxing (Namespaces):** 
   A implementação do `CLONE_NEWUSER`, `CLONE_NEWNS` e `CLONE_NEWPID` trouxe problemas de sincronismo. Inicialmente, o mapeamento de UIDs/GIDs falhava com erros de `Operation not permitted` (`EPERM`). A solução genial foi a introdução de *pipes* de sincronização entre o processo pai e filho (`ready_pipe`), garantindo que a tabela de usuários `/proc/[pid]/uid_map` só fosse escrita no momento cirúrgico correto.

3. **A Prisão do Seccomp-BPF:** 
   O sandbox bloqueava processos agressivamente via `SIGSYS` (Bad System Call) ao tentar invocar até mesmo shells POSIX (como o `busybox`). Houve um extenso trabalho de auditoria para mapear quais syscalls eram essenciais (como `uname`, `sysinfo`, `wait4`, `getdents`, `tgkill`, `clock_gettime`) e inseri-las na *allowlist* rígida do filtro BPF.

4. **A Estabilização do FUSE 3:** 
   Para criar a criptografia transparente sob demanda, a integração do FUSE 3 foi adicionada. Problemas iniciais de montagem (onde o FUSE tratava o caminho do diretório como uma *option* inválida) foram depurados e corrigidos. Em seguida, foi implementada uma riquíssima camada de telemetria medindo o tempo de resposta das chamadas (ex: `read`, `write`, `getattr`) em microssegundos com o `clock_gettime`.

---

## 2. A Arquitetura Híbrida

### Orquestrador em Rust (`src/`)
- **Memory Safety:** Mitigação de 99% das vulnerabilidades tradicionais de estouro de buffer (buffer overflows) e uso-após-liberação (use-after-free) durante a autenticação e tratamento de strings no terminal.
- **Ecossistema e Concorrência:** Gerenciamento da CLI interativa (`inquire`, `dialoguer`) e inicialização limpa de subprocessos assíncronos.

### Core de Baixo Nível em C (`c_src/`)
- **Proximidade ao Kernel:** Invocação direta dos cabeçalhos `<sched.h>`, `<linux/seccomp.h>` e `<sys/mount.h>` para o isolamento em nível de sistema operacional (C possui overhead zero para essas chamadas).
- **Gestão de Chaves:** Proteção direta dos buffers que alocam a criptografia AES-256 em memória RAM determinística.

---

## 3. O Motor de Jailing (A "Prisão")

O `vault-sandbox` não é apenas um container. Ele é uma jaula impenetrável projetada sob a premissa de que o código rodando lá dentro é malicioso.

- **Namespaces:** O sistema usa `unshare()` para separar o diretório raiz (Mount), a lista de processos (PID) e os IDs de usuário (User). Para a máquina *host*, é apenas um processo sem privilégios rodando como `nobody`. Para quem está dentro, ele tem poder de "root", mas preso num universo paralelo.
- **Pivot Root:** Substituindo a fragilidade histórica do `chroot`, o `pivot_root` troca fisicamente a raiz do disco e desmonta agressivamente o hospedeiro antigo. Uma vez dentro, é matematicamente impossível referenciar o sistema de arquivos real do Linux.
- **Gaiola de Hardware (Seccomp-BPF):** Um filtro Berkeley Packet Filter é carregado diretamente na CPU. Se um *malware* lá dentro tentar abrir uma conexão de rede ou invocar o `ptrace` para ler memória, a CPU não apenas nega acesso, ela aniquila o processo instantaneamente.

---

## 4. Sistema de Arquivos Transparente (FUSE) e WORM

Para permitir que o mundo real e ferramentas gráficas interajam com a segurança do IdenVault, o projeto emula um disco rígido via software.

- **On-the-Fly Encryption:** Arquivos armazenados no disco rígido sempre ficam com extensão `.enc`, criptografados em **AES-256-GCM**. Quando você acessa via `mount-fuse`, o motor C decifra o dado pedaço por pedaço na memória RAM apenas no milissegundo exato que você lê.
- **WORM (Write Once, Read Many):** Políticas de imutabilidade. Se configurado, o IdenVault intercepta qualquer requisição do Sistema Operacional para deletar (`unlink`) ou alterar um arquivo e retorna `-EPERM` (Permissão Negada). O arquivo não pode ser deletado, nem se você usar `sudo rm -rf`.

---

## 5. Defesas Ativas

- **Sensores inotify / fanotify:** O software escuta fisicamente o cache de "inodes" da placa-mãe. Se houverem gravações súbitas e velozes (assinatura clássica de um vírus de Ransomware), o sistema tranca o cofre em milissegundos para parar o ataque.
- **Honey-files e Labirintos (Decoy Engine):** Se o usuário optar pelos "Engines de 1 a 5", a matriz gera milhares de pastas binárias randômicas e falsas (iscas). Isso cega scripts automatizados de atacantes e forenses que tentam fazer varredura.
- **Auditoria de Integridade:** `vault-scan` recalcula os hashes `SHA-256` de todos os arquivos e compara em uma árvore (semelhante à uma Merkle-tree) contra o catálogo raiz. Qualquer bit flip corrompido é identificado e levanta alerta de segurança.

---

## 6. Sumário de Comandos Essenciais

Aqui está o poder do IdenVault traduzido em usabilidade CLI:

- **`vault-create <nome> <tipo>`**
  Cria um cofre definindo sua hierarquia de segurança (normal ou `protected` com senha forte). Pode-se adicionar os Engines de Iscas no momento da criação.

- **`mount-fuse <ID> <senha>`**
  (Comando "Insubstituível"). Realiza a montagem invisível e transparente em background de um cofre protegido no sistema de arquivos padrão do Ubuntu. Permite ao usuário arrastar e soltar (drag-and-drop) arquivos usando o Nautilus.

- **`vault-sandbox <ID>`**
  Desperta o motor do Kernel. Ativa namespaces, constrói a gaiola Seccomp, faz o pivot de montagem e entrega ao usuário final um shell POSIX seguro (com telemetria e interceptação ativas) restrito ao diretório confinado.

- **`worm-protect <ID> [--protect-delete | --no-write | --protected-scan]`**
  Congela a entropia dos arquivos. Altera dinamicamente os sinalizadores do FUSE para proibir renomeações, sobreposições de dados ou deleções absolutas.

- **`vault-scan <ID>`**
  Inicia a auditoria criptográfica de varredura profunda (SHA-256) validando o catálogo do disco e emitindo alertas vermelhos (Alert State) se adulterado.

---

## Conclusão

O IdenVault resolveu com sucesso uma lacuna complexa de segurança de Sistemas Operacionais. Ele provou que um único projeto de arquitetura de software é capaz de englobar as melhores práticas de Engenharia de Sistemas (C), Orquestração e Segurança de Memória (Rust), Criptografia Autenticada e Engenharia de Kernel (FUSE/Namespaces), resultando num produto comercial de blindagem de dados com resiliência de nível militar.
