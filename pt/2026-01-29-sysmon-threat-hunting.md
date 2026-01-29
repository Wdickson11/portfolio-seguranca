---
layout: post
title: "Amplificando a Visibilidade de Endpoint: Detecção de Ameaças com Sysmon"
date: 2026-01-29
categories: [Blue Team, Endpoint Security, Logging]
tags: [Sysmon, Threat Hunting, SOC, Windows]
description: "Uma análise técnica sobre como utilizar o System Monitor (Sysmon) para superar as limitações dos logs nativos do Windows e detectar comportamentos maliciosos avançados."
---

# 🕵️‍♂️ Amplificando a Visibilidade: Detecção de Ameaças com Sysmon

Em um ambiente corporativo moderno, especialmente em cenários de trabalho remoto (Home Office), a visibilidade do endpoint é a linha tênue entre um incidente contido e um vazamento de dados.

Os logs nativos do Windows (Event Viewer) são essenciais, mas muitas vezes insuficientes para responder às perguntas críticas de um SOC: *"Qual processo criou esta conexão de rede?"* ou *"O que exatamente aquele script PowerShell executou?"*.

Este projeto explora a implementação e análise do **Sysmon (System Monitor)** da Microsoft Sysinternals como ferramenta primária de telemetria para *Threat Hunting*.

---

## 🎯 Objetivo do Projeto

Demonstrar a capacidade de:
1.  Instalar e configurar o Sysmon para filtrar "ruído" e focar em eventos de segurança.
2.  Mapear atividades maliciosas comuns (Malware Droppers, C2 Connections, Lateral Movement).
3.  Correlacionar eventos para criar uma narrativa de ataque.

---

## 🛠️ Ferramentas e Configuração

* **Ferramenta:** Sysmon v15.0 (Microsoft Sysinternals)
* **Configuração Base:** [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) (Padrão de mercado para alta fidelidade e baixo ruído).
* **Ambiente de Lab:** Windows 10 Enterprise & TryHackMe Sandbox.
* **Deploy (Simulação):** Automação via RMM (Action1/PowerShell) para endpoints remotos.

---

## 🔍 A "Cegueira" dos Logs Nativos vs. Sysmon

O diferencial do Sysmon é a granularidade. Abaixo, detalho os **Event IDs** mais críticos que monitorei durante este estudo e por que eles são vitais para um analista de SOC.

### 1. Process Creation (Event ID 1) - O "Rastro Digital"
Diferente do Evento 4688 do Windows, o Sysmon ID 1 fornece o **Hash do Arquivo** (MD5/SHA256) e a **Linha de Comando** completa por padrão.

> **Cenário de Detecção:** Um usuário abre um PDF malicioso que executa um script oculto.
> * **Log Nativo:** Diz apenas que o Acrobat Reader abriu.
> * **Sysmon:** Mostra que `AcroRd32.exe` iniciou `cmd.exe` com o argumento `/c powershell.exe -enc <payload_base64>`.
> * **Minha Análise:** A relação *ParentProcess* (Pai) vs *Image* (Filho) é o indicador mais forte de anomalia. Word ou Excel não devem criar processos de linha de comando.

### 2. Network Connection (Event ID 3) - O "Farol" (Beacon)
Mapeia qual processo iniciou uma conexão TCP/UDP. Isso é crucial para detectar *Command & Control (C2)*.

> **Cenário de Detecção:** Um malware tenta se comunicar com um servidor na Rússia.
> * **Sysmon:** Registra que `svchost.exe` (falso) iniciou conexão para o IP `185.x.x.x` na porta 443.
> * **Valor para o SOC:** Permite correlacionar tráfego de rede diretamente ao executável infectado, algo que o Firewall de borda não consegue fazer sozinho em tráfego criptografado.

### 3. DNS Query (Event ID 22) - A "Impressão Digital"
Muitos malwares usam DGA (Domain Generation Algorithms) ou conectam-se a domínios recém-criados.

> **Cenário de Detecção:** Ransomware tentando baixar chaves de criptografia.
> * **Sysmon:** Registra a query para `fatura-urgente-pagamento[.]com`.
> * **Ação:** Bloqueio imediato do domínio e isolamento da máquina que originou a requisição.

---

## 🧪 Estudo de Caso Prático (Simulação)

Utilizando amostras de malware controladas (baseadas na metodologia do TryHackMe e *Real-World Attacks*), analisei a cadeia de execução de um ataque de **Mimikatz** (roubo de credenciais).

**Cadeia de Eventos Identificada no Sysmon:**

1.  **Event ID 1:** `powershell.exe` executado com privilégios elevados.
2.  **Event ID 10 (Process Access):** O PowerShell acessou a memória do processo `lsass.exe` (Local Security Authority Subsystem Service).
    * *Nota Técnica:* O `lsass.exe` é onde o Windows guarda senhas. Apenas processos de sistema deveriam tocá-lo.
3.  **Event ID 11 (File Create):** Criação de um arquivo `mimikatz.log` na pasta `C:\Temp`.

**Conclusão da Análise:**
A regra de detecção (Sigma ou YARA) deve focar no **Event ID 10**, alertando sempre que um processo não assinado pela Microsoft tentar ler a memória do `lsass.exe`.

---

## 🚀 Desafios de Implementação em Escala

Durante meus estudos, identifiquei que o maior desafio do Sysmon não é a instalação, mas a **gestão de logs**.

* **Volume de Dados:** O Sysmon é verboso. Sem o arquivo de configuração XML correto (excluindo browser, atualizações do Windows), ele pode saturar o disco local ou o SIEM.
* **Estratégia de Coleta:** Em ambientes híbridos, recomendo o uso de *Windows Event Forwarding (WEF)* ou agentes modernos (como Elastic Agent/Wazuh) para enviar esses logs para uma análise centralizada na nuvem.

---

## 💡 Conclusão

O Sysmon transforma endpoints de "caixas pretas" em sensores de alta fidelidade. Para um profissional de Segurança Defensiva, dominar a interpretação desses logs é fundamental para reduzir o **MTTD (Mean Time to Detect)**.

Este projeto reforçou minha capacidade de entender o comportamento interno do sistema operacional Windows e como traduzir ações de atacantes em alertas acionáveis.

---
*Tags: #BlueTeam #Sysmon #ThreatHunting #CyberSecurity #DigitalForensics*
