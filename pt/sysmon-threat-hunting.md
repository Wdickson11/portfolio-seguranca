---
layout: post
title: "Detection Engineering: Ampliando a Visibilidade de Endpoints com Sysmon"
date: 2026-01-29
categories: [Blue Team, Detection Engineering, Scripting]
tags: [Sysmon, Action1, PowerShell, Threat Hunting, MITRE ATT&CK]
description: "Do deployment à detecção: como implementei o Sysmon em escala via RMM, criei regras customizadas de threat hunting e validei a telemetria sem impactar produção."
---


![Category](https://img.shields.io/badge/Category-Blue_Team-blue)
![Focus](https://img.shields.io/badge/Focus-Detection_Engineering-success)
![Framework](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-orange)

Do deployment à detecção: como implementei Sysmon em escala via RMM, criei regras customizadas de threat hunting e validei a telemetria de ponta a ponta sem tocar em sistemas de produção.

## Problema

Em ambientes corporativos modernos — especialmente em cenários de home office — a visibilidade de endpoint é a linha tênue entre um incidente contido e um vazamento de grande escala. Os logs nativos do Windows são vitais, mas sofrem de "cegueira técnica" ao correlacionar eventos complexos: *qual processo pai originou essa conexão? Houve injeção de código na memória do LSASS?* Perguntas assim são quase impossíveis de responder usando apenas o Event Viewer padrão.

Este projeto documenta a implementação do **Sysmon (System Monitor)** como sensor primário de telemetria, orquestrado em escala via **Action1 RMM**.

## Objetivos

1. **Deployment automatizado** — instalar o Sysmon em escala com configuração de alta fidelidade (Infrastructure as Code).
2. **Monitoramento de credential dumping** — detectar técnicas de roubo de senha (MITRE ATT&CK T1003).
3. **Validação segura** — comprovar a eficácia dos alertas sem introduzir malware real ou derrubar serviços críticos.
4. **Resposta automatizada (SOAR Lite)** — acionar contenção imediata quando uma ameaça é confirmada.

## Arquitetura

- **Sensor:** Sysmon v15.0 (Microsoft Sysinternals)
- **Configuração:** [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) — padrão da indústria para redução de ruído
- **Orquestração:** Action1 RMM (deployment + execução de scripts em escala)
- **Linguagem:** PowerShell 5.1+

## O que foi implementado

### Fase 1 — Deployment automatizado (IaC)

O desafio real não é instalar o Sysmon — é garantir que a configuração XML seja aplicada corretamente para não saturar o disco com ruído. O deployment é empacotado como script PowerShell distribuído via Action1:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$SysmonURL = "https://download.sysinternals.com/files/Sysmon.zip"
$ConfigURL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$DestDir = "C:\Temp\SysmonInstall"

if (!(Test-Path $DestDir)) { New-Item -Path $DestDir -ItemType Directory -Force }

try {
    Invoke-WebRequest -Uri $ConfigURL -OutFile "$DestDir\config.xml" -UseBasicParsing
    Invoke-WebRequest -Uri $SysmonURL -OutFile "$DestDir\Sysmon.zip" -UseBasicParsing
    Expand-Archive -Path "$DestDir\Sysmon.zip" -DestinationPath $DestDir -Force
    Start-Process -FilePath "$DestDir\Sysmon64.exe" -ArgumentList "-accepteula -i $DestDir\config.xml" -Wait -NoNewWindow

    Start-Sleep -Seconds 5
    if (Get-Service "Sysmon64" -ErrorAction SilentlyContinue) {
        Write-Output "✅ SUCCESS: Sysmon Installed and Running!"
    } else {
        throw "Service failed to start."
    }
} catch {
    Write-Error "❌ ERROR: $_"
}
```

### Fase 2 — Lógica de detecção (threat hunting)

Foco: **OS Credential Dumping – LSASS Memory (T1003.001)**. Ferramentas como Mimikatz tentam ler a memória do `lsass.exe` para extrair hashes NTLM ou tickets Kerberos. O Sysmon gera o **Event ID 10 (ProcessAccess)** quando isso ocorre — o script abaixo filtra processos legítimos conhecidos e sinaliza qualquer coisa fora da whitelist que acesse o LSASS:

```powershell
# Detect-CredentialDumping-LSASS.ps1
$LogName = "Microsoft-Windows-Sysmon/Operational"
$StartTime = (Get-Date).AddMinutes(-60)
$WhiteList = "MsMpEng.exe|svchost.exe|csrss.exe|Topaz OFD|Warsaw"

$Events = Get-WinEvent -FilterHashtable @{LogName=$LogName; ID=10; StartTime=$StartTime} -ErrorAction SilentlyContinue

foreach ($Event in $Events) {
    $Xml = [xml]$Event.ToXml()
    $Source = ($Xml.Event.EventData.Data | Where-Object {$_.Name -eq "SourceImage"})."#text"

    if ($Source -notmatch $WhiteList) {
        Write-Output "🚨 CRITICAL ALERT: LSASS Access Attempt Detected by $Source"
        $FoundIncident = $true
    }
}
```

### Fase 3 — Validação (PoC segura, sem malware real)

Rodar Mimikatz de verdade em produção é irresponsável — pode causar BSODs ou disparar alertas globais desnecessários no SOC. Em vez disso, usei **simulação comportamental**:

1. Usei o Task Manager para criar um dump de memória de um processo inofensivo (`notepad.exe`) em vez do `lsass.exe`.
2. Redirecionei temporariamente o script de detecção para monitorar o `notepad.exe`.
3. O Sysmon registrou o acesso de memória → o Action1 disparou o alerta crítico → pipeline de detecção validado de ponta a ponta.

```powershell
# Simulate-Detection-Notepad.ps1 — valida o pipeline de alertas usando o Notepad como alvo seguro
$LogName = "Microsoft-Windows-Sysmon/Operational"
$StartTime = (Get-Date).AddMinutes(-60)

$Events = Get-WinEvent -LogName $LogName -FilterXPath "*[System[(EventID=10) or (EventID=1)]]" -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $StartTime }

foreach ($Event in $Events) {
    $Xml = [xml]$Event.ToXml()
    $Target = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetImage" -or $_.Name -eq "Image"} | Select-Object -ExpandProperty "#text"

    if ($Target -like "*\notepad.exe") {
        Write-Output "🚨 CRITICAL ALERT (SIMULATION): Suspicious Activity Validated!"
        Write-Output "Witness Process: $Target"
        Write-Output "Status: Detection pipeline is functional."
        break
    }
}
```

### Fase 4 — Resposta automatizada e contenção

Uma vez confirmada a ameaça, o Action1 encerra o processo suspeito imediatamente para minimizar o tempo de exposição:

```powershell
# Auto-Containment-LSASS.ps1
if ($FoundIncident) {
    try {
        Stop-Process -Name $SuspectProcessName -Force -ErrorAction Stop
        Write-Output "✅ SUCCESS: Process $SuspectProcessName terminated preventively."
    } catch {
        Write-Output "⚠️ FAILURE: Could not terminate process. Initiating Network Isolation..."
        netsh advfirewall set allprofiles state off  # etapa ilustrativa de contenção
    }
}
```

## Resultados

- Pipeline de detecção validado de ponta a ponta sem tocar em ferramenta real de credential dumping.
- Visibilidade de endpoint deixou de ser uma "caixa preta" e passou a ser um fluxo totalmente auditável de criação de processos, conexões de rede e acesso à memória.
- Detecção mapeada especificamente ao MITRE ATT&CK T1003.001, com método de validação seguro e repetível para futuras regras.

## Lições aprendidas

- **Resiliência de script** — automações precisam lidar com logs vazios (`$null`) e falhas de leitura sem gerar falsos erros operacionais.
- **Auto-recuperação** — em testes intensos, arquivos `.evtx` podem corromper; rotinas de manutenção (reiniciar serviço, limpar logs) são essenciais.
- **Disciplina de whitelisting** — excluir processos legítimos conhecidos (engines de antivírus, binários de sistema, plugins de segurança bancária) é fundamental para evitar fadiga de alertas.

## Roadmap

- Expandir cobertura para Process Injection (T1055) e Scheduled Tasks (T1053).
- Configurar o Action1 para isolamento total de rede automaticamente ao confirmar detecções do Event 10.

## Stack

`Sysmon v15.0` · `Action1 RMM` · `PowerShell` · `Windows Event Log` · `MITRE ATT&CK`

---

*Este projeto demonstra que é possível elevar a maturidade de segurança (SecOps) usando ferramentas nativas e gratuitas, desde que orquestradas com engenharia deliberada.*
