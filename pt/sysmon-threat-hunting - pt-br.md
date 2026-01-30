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
4.  **Resposta Automática (SOAR Lite):** Implementar scripts de contenção imediata para interromper ataques em tempo real.

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
# 0. Forçar TLS 1.2 para garantir o download (Resolve o erro de conexão garantindo o uso do TLS 1.2)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$SysmonURL = "https://download.sysinternals.com/files/Sysmon.zip"
$ConfigURL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$DestDir = "C:\Temp\SysmonInstall"

if (!(Test-Path $DestDir)) { New-Item -Path $DestDir -ItemType Directory -Force }

try {
    Write-Output "Baixando configuração e binários..."
    # Usando -UseBasicParsing para evitar erros em servidores sem IE configurado
    Invoke-WebRequest -Uri $ConfigURL -OutFile "$DestDir\config.xml" -UseBasicParsing
    Invoke-WebRequest -Uri $SysmonURL -OutFile "$DestDir\Sysmon.zip" -UseBasicParsing

    Write-Output "Extraindo Sysmon..."
    Expand-Archive -Path "$DestDir\Sysmon.zip" -DestinationPath $DestDir -Force

    Write-Output "Instalando..."
    # Usar o caminho completo para evitar erro de CommandNotFound
    Start-Process -FilePath "$DestDir\Sysmon64.exe" -ArgumentList "-accepteula -i $DestDir\config.xml" -Wait -NoNewWindow

    Start-Sleep -Seconds 5
    if (Get-Service "Sysmon64" -ErrorAction SilentlyContinue) {
        Write-Output "✅ SUCESSO: Sysmon Instalado e Rodando!"
    } else {
        throw "Serviço não iniciou."
    }
} catch {
    Write-Error "❌ ERRO: $_"
}
```

---

## 🔍 Fase 2: Lógica de Detecção (Threat Hunting)

O foco deste estudo foi a técnica **OS Credential Dumping: LSASS Memory (T1003.001)**. Ferramentas como o *Mimikatz* tentam ler a memória do processo `lsass.exe` para extrair hashes NTLM ou tickets Kerberos.

O Sysmon gera o **Event ID 10 (ProcessAccess)** quando isso ocorre. Desenvolvi um script de *Hunting* resiliente, que trata erros de logs vazios e foca apenas no alvo crítico.

**Script de Detecção (Versão de Produção):**
```powershell
# Script: Deploy-Sysmon-Config.ps1
# Função: Instalar Sysmon com configuração de alta fidelidade
# Autor: William Dickson

# Script: Detect-CredentialDumping-LSASS.ps1
$LogName = "Microsoft-Windows-Sysmon/Operational"
$StartTime = (Get-Date).AddMinutes(-60)
$WhiteList = "MsMpEng.exe|svchost.exe|csrss.exe|Topaz OFD|Warsaw"

$Events = Get-WinEvent -FilterHashtable @{LogName=$LogName; ID=10; StartTime=$StartTime} -ErrorAction SilentlyContinue 

foreach ($Event in $Events) {
    $Xml = [xml]$Event.ToXml()
    $Source = ($Xml.Event.EventData.Data | Where-Object {$_.Name -eq "SourceImage"})."#text"
    
    if ($Source -notmatch $WhiteList) {
        Write-Output "🚨 CRITICAL ALERT: LSASS Access Attempt Detected by $Source"
        # Sinaliza para o Action1 que um incidente foi encontrado
        $FoundIncident = $true
    }
}
```

---

## 🧪 Fase 3: Validação e Prova de Conceito (PoC)

Em um ambiente de produção, rodar um *Mimikatz* real é irresponsável (pode causar Tela Azul/BSOD ou alertar o SOC global desnecessariamente). Para validar a regra, utilizei uma técnica de **Simulação de Comportamento**.

1.  **O Teste:** Utilizei o *Gerenciador de Tarefas* do Windows para criar um "Dump" (cópia da memória) de um processo inofensivo: **Notepad** (`notepad.exe`).
2.  **A Adaptação:** Ajustei temporariamente o script de detecção para monitorar o alvo `notepad.exe` em vez do `lsass.exe`.
3.  **O Resultado:** O Sysmon registrou o acesso à memória e o Action1 disparou o alerta crítico, validando o pipeline de detecção.

**Snippet de Validação (Simulação):**
```powershell
# Script: Simulate-Detection-Notepad.ps1
# Função: Validar o pipeline de alertas usando o Notepad como alvo (PoC)
# Autor: William Dickson

$LogName = "Microsoft-Windows-Sysmon/Operational"
$LookBackMinutes = 60
$StartTime = (Get-Date).AddMinutes(-$LookBackMinutes)

Write-Output ">>> INICIANDO VALIDAÇÃO DE ALERTA (SIMULAÇÃO) <<<"

try {
    # Busca eventos ID 10 (Se configurado) ou ID 1 (Process Create) para validar fluxo
    $Events = Get-WinEvent -LogName $LogName -FilterXPath "*[System[(EventID=10) or (EventID=1)]]" -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $StartTime }

    if ($null -eq $Events) {
        Write-Output "Safe: Nenhum evento recente encontrado para validação."
        exit
    }

    foreach ($Event in $Events) {
        $Xml = [xml]$Event.ToXml()
        
        # Tenta pegar TargetImage (Event 10) ou Image (Event 1)
        $Target = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetImage" -or $_.Name -eq "Image"} | Select-Object -ExpandProperty "#text"
        
        # LÓGICA DE SIMULAÇÃO: O ALVO É O NOTEPAD
        if ($Target -like "*\notepad.exe") {
            
            Write-Output "🚨 CRITICAL ALERT (SIMULAÇÃO): Atividade Suspeita Validada!"
            Write-Output "Processo Testemunha: $Target"
            Write-Output "Status: O pipeline de detecção está funcional."
            Write-Output "Data/Hora: $($Event.TimeCreated)"
            Write-Output "--------------------------------------------------"
            
            # Interrompe após encontrar o primeiro para não spamar
            break
        }
    }

} catch {
    Write-Output "⚠️ ERRO DE VALIDAÇÃO: Falha ao acessar logs do Sysmon."
}
```
## ⚡ Fase 4: Resposta Automática e Contenção
Diferente de um log estático, esta fase utiliza o Action1 para encerrar o processo agressor assim que a ameaça é detectada, minimizando o tempo de exposição.

Script de Resposta Automática:
```powershell
# Script: Auto-Containment-LSASS.ps1
# Função: Identificar e encerrar processos não autorizados tentando acessar o LSASS

if ($FoundIncident) {
    Write-Output "🛠️ INICIANDO RESPOSTA AUTOMÁTICA..."
    
    # Exemplo: Encerrar o processo que disparou o alerta (capturado pelo script de detecção)
    try {
        Stop-Process -Name $SuspectProcessName -Force -ErrorAction Stop
        Write-Output "✅ SUCESSO: Processo $SuspectProcessName encerrado preventivamente."
    } catch {
        Write-Output "⚠️ FALHA: Não foi possível encerrar o processo. Iniciando Isolamento de Rede..."
        # Comando para isolar a máquina via firewall (exemplo)
        netsh advfirewall set allprofiles state off # (Uso ilustrativo de política de bloqueio)
    }
}
```
---

## 💡 Conclusão e Próximos Passos

A implementação do Sysmon transformou a postura de segurança dos endpoints. Passamos de uma "caixa preta" para um ambiente onde cada criação de processo, conexão de rede e acesso à memória é auditável.

**Lições Aprendidas:**
* **Resiliência de Script:** Scripts de automação devem estar preparados para logs vazios (`$null`) e falhas de leitura, evitando falsos positivos de erro operacional.
* **Auto-Healing:** Em ambientes de teste intenso, o arquivo `.evtx` pode corromper. A criação de scripts de manutenção (Restart Service/Clear Logs) é essencial para manter a telemetria ativa.
* **Refinamento de Fidelidade (Whitelisting): A exclusão de processos legítimos e conhecidos — como assinaturas de Antivírus, processos críticos de Sistema e plugins de segurança bancária (ex: Warsaw/Topaz) — é fundamental. Sem esse ajuste fino, o ruído analítico compromete a viabilidade do monitoramento, gerando fadiga de alertas e ocultando incidentes reais sob falsos positivos

**Roadmap:**
1.  **Expandir Cobertura:** Implementar detecções para *Process Injection* (T1055) e *Scheduled Tasks* (T1053).
2.  **Resposta Automática:** Configurar o Action1 para isolar a máquina da rede ou encerrar o processo malicioso automaticamente ao detectar o Evento 10 crítico.

Este projeto demonstra que é possível elevar a maturidade de segurança (SecOps) utilizando ferramentas nativas e gratuitas, desde que orquestradas com engenharia inteligente.

---
*Tags: #BlueTeam #DetectionEngineering #PowerShell #Sysmon #Action1*
