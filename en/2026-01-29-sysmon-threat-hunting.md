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
# Automated Installation and Configuration
$SysmonBinary = "Sysmon64.exe"
$ConfigFile = "sysmonconfig-export.xml"

if (Test-Path $SysmonBinary -and Test-Path $ConfigFile) {
    Write-Output "Applying high-fidelity configuration..."
    # -i: Installs/Updates configuration
    # -accepteula: Automatically accepts terms
    Start-Process -FilePath ".\$SysmonBinary" -ArgumentList "-accepteula -i $ConfigFile" -Wait
    Write-Output "Sysmon deployed successfully."
} else {
    Write-Error "Configuration files not found."
}
