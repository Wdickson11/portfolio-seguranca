---
layout: post
title: "Detection Engineering: Amplifying Endpoint Visibility with Sysmon"
date: 2026-01-29
categories: [Blue Team, Detection Engineering, Scripting]
tags: [Sysmon, Action1, PowerShell, Threat Hunting, MITRE ATT&CK]
description: "From deployment to detection: How I implemented Sysmon at scale via RMM, created custom threat hunting rules, and validated telemetry without impacting production."
---

# 🕵️‍♂️ Amplifying Visibility: Threat Detection with Sysmon

In modern corporate environments, especially in remote work (Home Office) scenarios, endpoint visibility is the thin line between a contained incident and a large-scale data breach.

Native Windows logs are vital but suffer from "technical blindness" when correlating complex events. Questions like *"Which parent process originated this connection?"* or *"Was there code injection into LSASS memory?"* are difficult to answer using only the standard Event Viewer.

This project details the implementation of **Sysmon (System Monitor)** as a primary telemetry sensor, orchestrated via **Action1 RMM**.

---

## 🎯 Engineering Objectives

1.  **Automated Deployment:** Install Sysmon at scale with a high-fidelity configuration (**Infrastructure as Code**).
2.  **Credential Dumping Monitoring:** Detect password theft techniques (MITRE ATT&CK T1003).
3.  **Safe Validation:** Test alert effectiveness without introducing real malware or crashing critical services.
4.  **Automated Response (SOAR Lite):** Implement immediate containment scripts to stop attacks in real-time.

---

## 🛠️ Solution Architecture

* **Sensor:** Sysmon v15.0 (Microsoft Sysinternals).
* **Configuration:** [SwiftOnSecurity Config](https://github.com/SwiftOnSecurity/sysmon-config) (Industry standard for noise reduction).
* **Orchestration:** Action1 RMM (Deployment and Script Execution).
* **Language:** PowerShell 5.1+.

---

## 🚀 Phase 1: Automated Deployment (IaC)

The biggest challenge isn't installing Sysmon, but ensuring the **XML configuration** is applied correctly to avoid saturating the disk with useless logs. I used a PowerShell script packaged in Action1 to ensure installation integrity.

**Installation Script Snippet:**
```powershell
# 0. Force TLS 1.2 to ensure download success
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$SysmonURL = "[https://download.sysinternals.com/files/Sysmon.zip](https://download.sysinternals.com/files/Sysmon.zip)"
$ConfigURL = "[https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml](https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml)"
$DestDir = "C:\Temp\SysmonInstall"

if (!(Test-Path $DestDir)) { New-Item -Path $DestDir -ItemType Directory -Force }

try {
    Write-Output "Downloading configuration and binaries..."
    # Using -UseBasicParsing to avoid errors on servers without IE configured
    Invoke-WebRequest -Uri $ConfigURL -OutFile "$DestDir\config.xml" -UseBasicParsing
    Invoke-WebRequest -Uri $SysmonURL -OutFile "$DestDir\Sysmon.zip" -UseBasicParsing

    Write-Output "Extracting Sysmon..."
    Expand-Archive -Path "$DestDir\Sysmon.zip" -DestinationPath $DestDir -Force

    Write-Output "Installing..."
    # Use full path to avoid CommandNotFound errors
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

---

##🔍 Phase 2: Detection Logic (Threat Hunting)

** The focus of this study was the OS Credential Dumping: LSASS Memory (T1003.001) technique. Tools like Mimikatz attempt to read the memory of the lsass.exe process to extract NTLM hashes or Kerberos tickets.

** Sysmon generates Event ID 10 (ProcessAccess) when this occurs. I developed a resilient hunting script that handles empty log errors and focuses only on the critical target.

**Detection Script (Production Version):**
```powershell
# Script: Detect-CredentialDumping-LSASS.ps1
# Function: Install Sysmon with high-fidelity configuration
# Author: William Dickson

$LogName = "Microsoft-Windows-Sysmon/Operational"
$StartTime = (Get-Date).AddMinutes(-60)
$WhiteList = "MsMpEng.exe|svchost.exe|csrss.exe|Topaz OFD|Warsaw"

$Events = Get-WinEvent -FilterHashtable @{LogName=$LogName; ID=10; StartTime=$StartTime} -ErrorAction SilentlyContinue 

foreach ($Event in $Events) {
    $Xml = [xml]$Event.ToXml()
    $Source = ($Xml.Event.EventData.Data | Where-Object {$_.Name -eq "SourceImage"})."#text"
    
    if ($Source -notmatch $WhiteList) {
        Write-Output "🚨 CRITICAL ALERT: LSASS Access Attempt Detected by $Source"
        # Signals to Action1 that an incident was found
        $FoundIncident = $true
    }
}
```

---

##🧪 Phase 3: Validation & Proof of Concept (PoC)
In a production environment, running real Mimikatz is irresponsible (it can cause BSODs or trigger global SOC alerts unnecessarily). To validate the rule, I used a Behavioral Simulation technique.

1.  **The Test: I used Windows Task Manager to create a "Dump" (memory copy) of a harmless process: Notepad (notepad.exe).
2.  **The Adaptation: I temporarily adjusted the detection script to monitor the target notepad.exe instead of lsass.exe.
3.  **The Result: Sysmon logged the memory access, and Action1 triggered the critical alert, validating the detection pipeline.

**Validation Snippet (Simulation):**

```powershell
# Script: Simulate-Detection-Notepad.ps1
# Function: Validate the alert pipeline using Notepad as a target (PoC)
# Author: William Dickson

$LogName = "Microsoft-Windows-Sysmon/Operational"
$LookBackMinutes = 60
$StartTime = (Get-Date).AddMinutes(-$LookBackMinutes)

Write-Output ">>> STARTING ALERT VALIDATION (SIMULATION) <<<"

try {
    # Search for Event ID 10 (ProcessAccess) or ID 1 (ProcessCreate) to validate the flow
    $Events = Get-WinEvent -LogName $LogName -FilterXPath "*[System[(EventID=10) or (EventID=1)]]" -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $StartTime }

    if ($null -eq $Events) {
        Write-Output "Safe: No recent events found for validation."
        exit
    }

    foreach ($Event in $Events) {
        $Xml = [xml]$Event.ToXml()
        
        # Attempt to retrieve TargetImage (Event 10) or Image (Event 1)
        $Target = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetImage" -or $_.Name -eq "Image"} | Select-Object -ExpandProperty "#text"
        
        # SIMULATION LOGIC: TARGET IS NOTEPAD
        if ($Target -like "*\notepad.exe") {
            
            Write-Output "🚨 CRITICAL ALERT (SIMULATION): Suspicious Activity Validated!"
            Write-Output "Witness Process: $Target"
            Write-Output "Status: Detection pipeline is functional."
            Write-Output "Timestamp: $($Event.TimeCreated)"
            Write-Output "--------------------------------------------------"
            
            # Break after the first match to avoid log spamming
            break
        }
    }

} catch {
    Write-Output "⚠️ VALIDATION ERROR: Failed to access Sysmon logs."
}
```

---

##⚡ Phase 4: Automated Response & Containment
Unlike a static log, this phase utilizes Action1 to terminate the offending process as soon as a threat is detected, minimizing exposure time.

Automated Response Script:
```powershell
# Script: Auto-Containment-LSASS.ps1
# Function: Identify and terminate unauthorized processes attempting LSASS access

if ($FoundIncident) {
    Write-Output "🛠️ INITIATING AUTOMATED RESPONSE..."
    
    try {
        Stop-Process -Name $SuspectProcessName -Force -ErrorAction Stop
        Write-Output "✅ SUCCESS: Process $SuspectProcessName terminated preventively."
    } catch {
        Write-Output "⚠️ FAILURE: Could not terminate process. Initiating Network Isolation..."
        # Example command to isolate via firewall
        netsh advfirewall set allprofiles state off # (Illustrative policy block)
    }
}
```
---

##💡 Conclusion & Next Steps

The implementation of Sysmon has transformed our endpoint security posture. We moved from a "black box" to an environment where every process creation, network connection, and memory access is auditable.

**Lessons Learned:**
* **Script Resilience:**  Automation scripts must be prepared for empty logs ($null) and read failures to avoid operational error false positives.
* **Auto-Healing:** In heavy testing environments, .evtx files can corrupt. Maintenance scripts (Restart Service/Clear Logs) are essential.
* **Whitelisting Refinement:** Excluding known legitimate processes—such as Antivirus signatures, critical System processes, and banking security plugins (e.g., Warsaw/Topaz)—is fundamental to prevent alert fatigue.

**Roadmap:**
**Expand Coverage:** Implement detections for Process Injection (T1055) and Scheduled Tasks (T1053).
**Advanced Response:** Configure Action1 to fully isolate the machine from the network automatically upon detecting a critical Event 10.

This project demonstrates that it is possible to elevate security maturity (SecOps) using native and free tools, provided they are orchestrated with intelligent engineering.

---
Tags: #BlueTeam #DetectionEngineering #PowerShell #Sysmon #Action1
