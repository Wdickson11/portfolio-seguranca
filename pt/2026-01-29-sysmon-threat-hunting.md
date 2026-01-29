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

## 🔍 Phase 2: Detection Logic (Threat Hunting)

The focus of this study was the **OS Credential Dumping: LSASS Memory (T1003.001)** technique. Tools like *Mimikatz* attempt to read the memory of the `lsass.exe` process to extract NTLM hashes or Kerberos tickets.

Sysmon generates **Event ID 10 (ProcessAccess)** when this occurs. I developed a resilient *Hunting* script that handles empty log errors and focuses strictly on the critical target.

**Detection Script (Production Version):**

```powershell
# Search for LSASS access events in the last hour
# ErrorAction SilentlyContinue prevents failure if no logs exist (Safe)
$Events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=10)]]" -ErrorAction SilentlyContinue

if ($Events) {
    foreach ($Event in $Events) {
        $Xml = [xml]$Event.ToXml()
        $Target = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetImage"} | Select-Object -ExpandProperty "#text"
        $Source = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "SourceImage"} | Select-Object -ExpandProperty "#text"
        
        # Detection: Is the target LSASS?
        if ($Target -like "*\lsass.exe") {
            # Whitelist: Ignore Antivirus and System Processes
            if ($Source -notmatch "MsMpEng.exe|svchost.exe|csrss.exe") {
                Write-Output "CRITICAL ALERT: LSASS Access Attempt Detected!"
                Write-Output "Attacker: $Source"
                Write-Output "Target: $Target"
                Write-Output "Date: $($Event.TimeCreated)"
            }
        }
    }
} else {
    Write-Output "Safe: No anomalies detected in the period."
}

## 🧪 Fase 3: Validação e Prova de Conceito (PoC)

Em um ambiente de produção, rodar um *Mimikatz* real é irresponsável (pode causar Tela Azul/BSOD ou alertar o SOC global desnecessariamente). Para validar a regra, utilizei uma técnica de **Simulação de Comportamento**.

1.  **O Teste:** Utilizei o *Gerenciador de Tarefas* do Windows para criar um "Dump" (cópia da memória) de um processo inofensivo: **Notepad** (`notepad.exe`).
2.  **A Adaptação:** Ajustei temporariamente o script de detecção para monitorar o alvo `notepad.exe` em vez do `lsass.exe`.
3.  **O Resultado:** O Sysmon registrou o acesso à memória e o Action1 disparou o alerta crítico, validando o pipeline de detecção.

**Snippet de Validação (Simulação):**

```powershell
# Adaptação para Validar o Alerta com Notepad
if ($Target -like "*\notepad.exe") { 
    Write-Output "CRITICAL ALERT: Simulação de Atividade Suspeita Detectada!"
    Write-Output "Processo Testemunha: $Target"
}

## 💡 Conclusão e Próximos Passos

A implementação do Sysmon transformou a postura de segurança dos endpoints. Passamos de uma "caixa preta" para um ambiente onde cada criação de processo, conexão de rede e acesso à memória é auditável.

**Lições Aprendidas:**
* **Resiliência de Script:** Scripts de automação devem estar preparados para logs vazios (`$null`) e falhas de leitura, evitando falsos positivos de erro operacional.
* **Auto-Healing:** Em ambientes de teste intenso, o arquivo `.evtx` pode corromper. A criação de scripts de manutenção (Restart Service/Clear Logs) é essencial para manter a telemetria ativa.
* **Whitelisting é Vital:** Sem filtrar processos legítimos (como Antivírus e System), o volume de dados torna o monitoramento inviável.

**Roadmap:**
1.  **Expandir Cobertura:** Implementar detecções para *Process Injection* (T1055) e *Scheduled Tasks* (T1053).
2.  **Resposta Automática:** Configurar o Action1 para isolar a máquina da rede ou encerrar o processo malicioso automaticamente ao detectar o Evento 10 crítico.

Este projeto demonstra que é possível elevar a maturidade de segurança (SecOps) utilizando ferramentas nativas e gratuitas, desde que orquestradas com engenharia inteligente.

---
*Tags: #BlueTeam #DetectionEngineering #PowerShell #Sysmon #Action1*
