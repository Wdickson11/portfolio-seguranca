---
layout: post
title: "Engenharia de Detecção: Amplificando a Visibilidade de Endpoint com Sysmon"
date: 2026-01-29
categories: [Blue Team, Detection Engineering, Scripting]
tags: [Sysmon, Action1, PowerShell, Threat Hunting, MITRE ATT&CK]
description: "Do deploy à detecção: Como implementei o Sysmon em escala via RMM, criei regras de caça a ameaças personalizadas e validei a telemetria sem impactar a produção."
---

# 🕵️‍♂️ Amplificando a Visibilidade: Detecção de Ameaças com Sysmon

Em ambientes corporativos modernos, especialmente em cenários de trabalho remoto (*Home Office*), a visibilidade do endpoint é a linha tênue entre um incidente contido e um vazamento de dados em larga escala.

Os logs nativos do Windows são vitais, mas sofrem de uma "cegueira técnica" para correlacionar eventos complexos. Perguntas como *"Qual processo pai originou essa conexão?"* ou *"Houve injeção de código na memória do LSASS?"* são difíceis de responder apenas com o Event Viewer padrão.

Este projeto detalha a implementação do **Sysmon (System Monitor)** como sensor primário de telemetria, orquestrado via **Action1 RMM**.

---

## 🎯 Objetivos de Engenharia

1.  **Deploy Automatizado:** Instalar o Sysmon em escala com configuração de alta fidelidade (*Infrastructure as Code*).
2.  **Monitoramento de Credential Dumping:** Detectar técnicas de roubo de senhas (T1003 do MITRE ATT&CK).
3.  **Validação Segura:** Testar a eficácia dos alertas sem introduzir malware real ou derrubar serviços críticos.

---

## 🛠️ Arquitetura da Solução

* **Sensor:** Sysmon v15.0 (Microsoft Sysinternals).
* **Configuração:** [SwiftOnSecurity Config](https://github.com/SwiftOnSecurity/sysmon-config) (Base de mercado para redução de ruído).
* **Orchestration:** Action1 RMM (Deploy e Execução de Scripts).
* **Linguagem:** PowerShell 5.1+.

---

## 🚀 Fase 1: Deploy Automatizado (IaC)

O maior desafio não é instalar o Sysmon, mas garantir que a **configuração XML** seja aplicada corretamente para não saturar o disco com logs inúteis. Utilize um script PowerShell empacotado no Action1 para garantir a integridade da instalação.

**Snippet do Script de Instalação:**

```powershell
# Instalação e Configuração Automatizada
$SysmonBinary = "Sysmon64.exe"
$ConfigFile = "sysmonconfig-export.xml"

if (Test-Path $SysmonBinary -and Test-Path $ConfigFile) {
    Write-Output "Aplicando configuração de alta fidelidade..."
    # -i: Instala/Atualiza a configuração
    # -accepteula: Aceite automático dos termos
    Start-Process -FilePath ".\$SysmonBinary" -ArgumentList "-accepteula -i $ConfigFile" -Wait
    Write-Output "Sysmon implantado com sucesso."
} else {
    Write-Error "Arquivos de configuração não encontrados."
}

---
*Tags: #BlueTeam #DetectionEngineering #PowerShell #Sysmon #Action1*
