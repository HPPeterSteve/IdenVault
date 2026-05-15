# Idenvault v0.8.15 - Nota de Evolução Contínua

A segurança não é um estado estático, mas um compromisso de vigilância constante. A versão **0.8.15** não representa a resolução definitiva de todos os desafios, mas um passo necessário e urgente na evolução da resiliência do ecossistema **Idenvault**.

## 🛡️ Evolução da Camada de Segurança

### 1. Mitigação de Instabilidades no Módulo Inotify
Identificamos que as falhas estruturais observadas na versão 0.8.1 podiam comprometer a integridade do monitoramento no ambiente sandbox. Nesta atualização, implementamos reforços críticos para mitigar os efeitos em cascata. Embora o comportamento tenha sido significativamente estabilizado, mantemos a vigilância técnica sobre a interação entre o kernel e o nosso core de segurança.

### 2. Ajustes de Precisão Anti-Ransomware
Reduzimos a incidência de disparos indevidos durante operações legítimas do software. Esta melhoria na sensibilidade dos filtros visa equilibrar a proteção agressiva com a operabilidade necessária, buscando um ajuste fino que não reduza a guarda contra ameaças externas, mas minimize fricções sistêmicas.

### 3. Escalação de Privilégios em `vault-sandbox`
Como medida de responsabilidade com a integridade dos dados, o comando `vault-sandbox <id>` agora exige privilégios de **root**. Esta mudança é uma resposta direta à necessidade de um isolamento mais profundo e rigoroso que apenas as camadas de sistema de baixo nível podem oferecer de forma confiável.

## 🎯 Responsabilidade Técnica
O foco da v0.8.15 é a **continuidade**. Não prometemos a ausência de desafios, mas garantimos um esforço incansável na mitigação de riscos e no endurecimento das defesas. A atualização para esta versão é recomendada como parte fundamental da nossa estratégia de melhoria contínua e resiliência cibernética.

---
*Idenvault: Evolução constante, vigilância inabalável.*
