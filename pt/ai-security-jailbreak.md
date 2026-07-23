# 🛡️ LLM Security Architecture: Defense-in-Depth Against Prompt Injection & Jailbreaking

![Category](https://img.shields.io/badge/Category-AI_Security-blue)
![Focus](https://img.shields.io/badge/Focus-Defensive_Engineering-success)
![Framework](https://img.shields.io/badge/Framework-OWASP_LLM_Top_10-orange)

## 📌 Visão Geral

Com a rápida integração de modelos de linguagem de grande porte (*Large Language Models - LLMs*) em ecossistemas corporativos, a superfície de ataque migrou do código determinístico para a manipulação contextual em linguagem natural. 

Ataques como **Indirect Prompt Injection** e **Jailbreaking via Roleplay** exploram a forma como a camada de atenção dos LLMs processa instruções, sobrepondo dados fornecidos pelo usuário às diretrizes de segurança da aplicação.

Este repositório documenta uma arquitetura de **Defesa em Profundidade (Defense-in-Depth)** projetada para mitigar desvios de conduta, vazamento de contexto e execução não autorizada de chamadas de sistema (*Tool Calls*).

---

## 🏗️ Arquitetura de Defesa em Profundidade

Confiar apenas no *System Prompt* para manter a segurança do modelo é uma falha estrutural de design. Uma arquitetura resiliente exige validação determinística e semântica antes da entrada no modelo primário, além de inspeção assíncrona antes do envio da resposta ao usuário final.

```mermaid
flowchart TD
    A[Entrada do Usuário] --> B{Layer 1: Input Guardrail}
    B -- Injection / Suspeito --> C[❌ Block & Log]
    B -- Sanitizado / Aprovado --> D[Layer 2: Core LLM + System Prompt Hardening]
    D --> E[Resposta Gerada]
    E --> F{Layer 3: Output Guardrail}
    F -- PII / Secret / Violation --> G[❌ Redact / Block]
    F -- Resposta Segura --> H[Resposta Final ao Usuário]
