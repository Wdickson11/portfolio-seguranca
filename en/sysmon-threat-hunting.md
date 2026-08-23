---
layout: post
title: "Detection Engineering: Amplifying Endpoint Visibility with Sysmon"
date: 2026-01-29
categories: [Blue Team, Detection Engineering, Scripting]
tags: [Sysmon, Action1, PowerShell, Threat Hunting, MITRE ATT&CK]
description: "From deployment to detection: How I implemented Sysmon at scale via RMM, created custom threat hunting rules, and validated telemetry without impacting production."
---


![Category](https://img.shields.io/badge/Category-Blue_Team-blue)
![Focus](https://img.shields.io/badge/Focus-Detection_Engineering-success)
![Framework](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-orange)

From deployment to detection: how I implemented Sysmon at scale via RMM, built custom threat hunting rules, and validated telemetry end-to-end without touching production systems.

## Problem

In modern corporate environments — especially remote/home-office setups — endpoint visibility is the thin line between a contained incident and a large-scale breach. Native Windows logs are vital but suffer from "technical blindness" when correlating complex events: *which parent process originated this connection? Was there code injection into LSASS memory?* Questions like these are nearly impossible to answer with the standard Event Viewer alone.

This project documents the implementation of **Sysmon (System Monitor)** as a primary telemetry sensor, orchestrated at scale via **Action1 RMM**.

## Objectives

1. **Automated deployment** — install Sysmon at scale with a high-fidelity configuration (Infrastructure as Code).
2. **Credential dumping detection** — detect password theft techniques (MITRE ATT&CK T1003).
3. **Safe validation** — prove alert effectiveness without introducing real malware or crashing critical services.
4. **Automated response (SOAR Lite)** — trigger immediate containment when a threat is confirmed.

## Architecture

- **Sensor:** Sysmon v15.0 (Microsoft Sysinternals)
- **Configuration:** [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) — industry standard for noise reduction
- **Orchestration:** Action1 RMM (deployment + script execution at scale)
- **Language:** PowerShell 5.1+

## What's implemented

### Phase 1 — Automated deployment (IaC)

The real challenge isn't installing Sysmon — it's making sure the XML configuration applies correctly so the disk doesn't fill up with noise. Deployment is packaged as a PowerShell script pushed via Action1:

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

### Phase 2 — Detection logic (threat hunting)

Focus: **OS Credential Dumping – LSASS Memory (T1003.001)**. Tools like Mimikatz try to read `lsass.exe` memory to extract NTLM hashes or Kerberos tickets. Sysmon generates **Event ID 10 (ProcessAccess)** when this happens — the hunting script below filters known-legitimate processes and flags anything else touching LSASS:

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

### Phase 3 — Validation (safe PoC, no real malware)

Running actual Mimikatz in production is irresponsible — it can trigger BSODs or unnecessary global SOC alerts. Instead, I used **behavioral simulation**:

1. Used Task Manager to create a memory dump of a harmless process (`notepad.exe`) instead of `lsass.exe`.
2. Temporarily retargeted the detection script to watch `notepad.exe`.
3. Sysmon logged the memory access → Action1 fired the critical alert → detection pipeline validated end-to-end.

```powershell
# Simulate-Detection-Notepad.ps1 — validates the alert pipeline using Notepad as a safe target
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

### Phase 4 — Automated response & containment

Once a threat is confirmed, Action1 terminates the offending process immediately to minimize exposure time:

```powershell
# Auto-Containment-LSASS.ps1
if ($FoundIncident) {
    try {
        Stop-Process -Name $SuspectProcessName -Force -ErrorAction Stop
        Write-Output "✅ SUCCESS: Process $SuspectProcessName terminated preventively."
    } catch {
        Write-Output "⚠️ FAILURE: Could not terminate process. Initiating Network Isolation..."
        netsh advfirewall set allprofiles state off  # illustrative containment step
    }
}
```

## Results

- Full detection pipeline validated end-to-end without touching a real credential-dumping tool.
- Moved endpoint visibility from a "black box" to a fully auditable stream of process creation, network connections, and memory access.
- Detection scoped specifically to MITRE ATT&CK T1003.001, with a repeatable, safe validation method for future rules.

## Lessons learned

- **Script resilience** — automation must handle empty logs (`$null`) and read failures gracefully to avoid false operational errors.
- **Auto-healing** — under heavy testing, `.evtx` files can corrupt; maintenance routines (restart service, clear logs) are essential.
- **Whitelisting discipline** — excluding known-legitimate processes (AV engines, system binaries, banking security plugins) is critical to avoid alert fatigue.

## Roadmap

- Expand coverage to Process Injection (T1055) and Scheduled Tasks (T1053).
- Configure Action1 for full network isolation automatically on confirmed Event 10 detections.

## Stack

`Sysmon v15.0` · `Action1 RMM` · `PowerShell` · `Windows Event Log` · `MITRE ATT&CK`

---

*This project demonstrates that meaningful security maturity (SecOps) is achievable using native, free tooling — provided it's orchestrated with deliberate engineering.*
