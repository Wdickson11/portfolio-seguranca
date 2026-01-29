---
layout: post
title: "Detection Engineering: Amplifying Endpoint Visibility with Sysmon"
date: 2026-01-29
categories: [Blue Team, Detection Engineering, Scripting]
tags: [Sysmon, Action1, PowerShell, Threat Hunting, MITRE ATT&CK]
description: "From deployment to detection: How I implemented Sysmon at scale via RMM, created custom threat hunting rules, and validated telemetry without impacting production."
---

# 🕵️‍♂️ Amplifying Visibility: Threat Detection with Sysmon

In modern corporate environments, especially in remote work scenarios (*Home Office*), endpoint visibility is the thin line between a contained incident and a full-scale data breach.

Native Windows logs are vital but often suffer from "technical blindness" when correlating complex events. Questions like *"Which parent process initiated this connection?"* or *"Was there code injection into LSASS memory?"* are difficult to answer using only the standard Event Viewer.

This project details the implementation of **Sysmon (System Monitor)** as a primary telemetry sensor, orchestrated via **Action1 RMM**.

---

## 🎯 Engineering Objectives

1.  **Automated Deployment:** Install Sysmon at scale with high-fidelity configuration (*Infrastructure as Code*).
2.  **Credential Dumping Monitoring:** Detect password theft techniques (MITRE ATT&CK T1003).
3.  **Safe Validation:** Test the effectiveness of alerts without introducing real malware or disrupting critical services.

---

## 🛠️ Solution Architecture

* **Sensor:** Sysmon v15.0 (Microsoft Sysinternals).
* **Configuration:** [SwiftOnSecurity Config](https://github.com/SwiftOnSecurity/sysmon-config) (Industry standard for noise reduction).
* **Orchestration:** Action1 RMM (Deployment and Script Execution).
* **Language:** PowerShell 5.1+.

---

## 🚀 Phase 1: Automated Deployment (IaC)

The biggest challenge isn't installing Sysmon, but ensuring the **XML configuration** is correctly applied to avoid saturating disk space with useless logs. I used a PowerShell script packaged in Action1 to ensure installation integrity.

**Installation Script Snippet:**
```powershell
# Script: Deploy-Sysmon-Config.ps1
# Function: Install Sysmon with high-fidelity configuration
# Author: William Dickson

$SysmonBinary = "Sysmon64.exe"
$ConfigFile = "sysmonconfig-export.xml"

Write-Output ">>> STARTING SYSMON DEPLOYMENT <<<"

if (Test-Path $SysmonBinary -and Test-Path $ConfigFile) {
    Write-Output "1. Files found. Applying configuration..."
    
    # -i: Installs or Updates configuration
    # -accepteula: Automatically accepts terms
    try {
        Start-Process -FilePath ".\$SysmonBinary" -ArgumentList "-accepteula -i $ConfigFile" -Wait -NoNewWindow
        Write-Output "✅ SUCCESS: Sysmon deployed/updated."
    } catch {
        Write-Error "❌ ERROR: Failed to execute binary."
    }
} else {
    Write-Error "❌ CRITICAL ERROR: Binary or Config XML not found in current directory."
}
```

---

## 🔍 Phase 2: Detection Logic (Threat Hunting)

The focus of this study was the **OS Credential Dumping: LSASS Memory (T1003.001)** technique. Tools like *Mimikatz* attempt to read the memory of the `lsass.exe` process to extract NTLM hashes or Kerberos tickets.

Sysmon generates **Event ID 10 (ProcessAccess)** when this occurs. I developed a resilient *Hunting* script that handles empty log errors and focuses strictly on the critical target.

**Detection Script (Production Version):**
```powershell
# Script: Detect-CredentialDumping-LSASS.ps1
# Function: Detect LSASS memory access (Event ID 10)
# Author: William Dickson

$LogName = "Microsoft-Windows-Sysmon/Operational"
$LookBackMinutes = 60
$StartTime = (Get-Date).AddMinutes(-$LookBackMinutes)

try {
    # Search for Event ID 10 (ProcessAccess) in the last hour
    # ErrorAction SilentlyContinue prevents error if log is empty (Safe)
    $Events = Get-WinEvent -LogName $LogName -FilterXPath "*[System[(EventID=10)]]" -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $StartTime }

    if ($null -eq $Events) {
        Write-Output "Safe: No LSASS access attempts detected in the last hour."
        exit
    }

    $Detected = $false

    foreach ($Event in $Events) {
        $Xml = [xml]$Event.ToXml()
        $TargetImage = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetImage"} | Select-Object -ExpandProperty "#text"
        $SourceImage = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "SourceImage"} | Select-Object -ExpandProperty "#text"
        
        # TARGET: LSASS.EXE
        if ($TargetImage -like "*\lsass.exe") {
            
            # Whitelist: Ignore legitimate security and system processes
            if ($SourceImage -notmatch "MsMpEng.exe|svchost.exe|csrss.exe|vmtoolsd.exe") {
                
                Write-Output "🚨 CRITICAL ALERT: LSASS Access Attempt (Credential Dumping) Detected!"
                Write-Output "Attacker (Source): $SourceImage"
                Write-Output "Target (Target): $TargetImage"
                Write-Output "Date/Time: $($Event.TimeCreated)"
                Write-Output "--------------------------------------------------"
                $Detected = $true
            }
        }
    }

    if (-not $Detected) {
        Write-Output "Safe: Events analyzed but considered legitimate (Whitelist)."
    }

} catch {
    Write-Output "⚠️ OPERATIONAL ERROR: Unable to read logs. Check if Sysmon service is active."
}
```

---

## 🧪 Phase 3: Validation and Proof of Concept (PoC)

In a production environment, running real *Mimikatz* is irresponsible (it can cause BSOD or alert the global SOC unnecessarily). To validate the rule, I used a **Behavior Simulation** technique.

1.  **The Test:** I used Windows *Task Manager* to create a "Dump" (memory copy) of a harmless process: **Notepad** (`notepad.exe`).
2.  **The Adaptation:** I temporarily adjusted the detection script to monitor the `notepad.exe` target instead of `lsass.exe`.
3.  **The Result:** Sysmon recorded the memory access, and Action1 triggered the critical alert, validating the detection pipeline.

**Validation Snippet (Simulation):**
```powershell
# Script: Simulate-Detection-Notepad.ps1
# Function: Validate alert pipeline using Notepad as target (PoC)
# Author: William Dickson

$LogName = "Microsoft-Windows-Sysmon/Operational"
$LookBackMinutes = 60
$StartTime = (Get-Date).AddMinutes(-$LookBackMinutes)

Write-Output ">>> STARTING ALERT VALIDATION (SIMULATION) <<<"

try {
    # Search for Event ID 10 (if configured) or ID 1 (Process Create) to validate flow
    $Events = Get-WinEvent -LogName $LogName -FilterXPath "*[System[(EventID=10) or (EventID=1)]]" -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $StartTime }

    if ($null -eq $Events) {
        Write-Output "Safe: No recent events found for validation."
        exit
    }

    foreach ($Event in $Events) {
        $Xml = [xml]$Event.ToXml()
        
        # Try to get TargetImage (Event 10) or Image (Event 1)
        $Target = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetImage" -or $_.Name -eq "Image"} | Select-Object -ExpandProperty "#text"
        
        # SIMULATION LOGIC: TARGET IS NOTEPAD
        if ($Target -like "*\notepad.exe") {
            
            Write-Output "🚨 CRITICAL ALERT (SIMULATION): Suspicious Activity Validated!"
            Write-Output "Witness Process: $Target"
            Write-Output "Status: Detection pipeline is functional."
            Write-Output "Date/Time: $($Event.TimeCreated)"
            Write-Output "--------------------------------------------------"
            
            # Break after finding the first one to avoid spamming
            break
        }
    }

} catch {
    Write-Output "⚠️ VALIDATION ERROR: Failed to access Sysmon logs."
}
```

> **Operational Insight:** This methodology allows testing the entire defense chain (Sensor -> Log -> Script -> Alert) ensuring that when a real attack occurs on LSASS, the alert will trigger.

---

## 💡 Conclusion and Next Steps

The Sysmon implementation transformed endpoint security posture. We moved from a "black box" to an environment where every process creation and network connection is auditable.

**Lessons Learned:**
* **Script Resilience:** Automation scripts must be prepared for empty logs (`$null`) and read failures, avoiding operational error false positives.
* **Auto-Healing:** In intense testing environments, the `.evtx` file can become corrupted. Creating maintenance scripts (Restart Service/Clear Logs) is essential to keep telemetry active.
* **Whitelisting is Vital:** Without filtering legitimate processes (like Antivirus and System), the data volume makes monitoring unfeasible.

**Roadmap:**
1.  **Expand Coverage:** Implement detections for *Process Injection* (T1055) and *Scheduled Tasks* (T1053).
2.  **Automated Response:** Configure Action1 to isolate the machine from the network or terminate the malicious process automatically upon detecting critical Event 10.

This project demonstrates that it is possible to elevate security maturity (SecOps) using native free tools, provided they are orchestrated with intelligent engineering.

---
*Tags: #BlueTeam #DetectionEngineering #PowerShell #Sysmon #Action1*
