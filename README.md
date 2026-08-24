# AI-Powered Insider Threat & DLP Incident Response Pipeline

A security monitoring project that extends my Active Directory + Wazuh home lab with automated AI-assisted incident triage.

The pipeline detects suspicious endpoint activity using **Sysmon and Wazuh**, maps the detection to **MITRE ATT&CK**, and automatically sends the alert to a locally hosted **Llama 3.2:1b model through Ollama** for analysis.

## How It Works

```text
CLIENT01
   ↓
Sysmon
   ↓
Wazuh Agent
   ↓
Custom Detection Rule
   ↓
Python AI Triage
   ↓
Ollama / Llama 3.2:1b
   ↓
Severity + Assessment + Next Step
```


## Detection

The test simulates potential insider data-hiding behavior by creating an **NTFS Alternate Data Stream (ADS)** using PowerShell.

Sysmon records the activity as **Event ID 15**, which is detected by custom Wazuh rule `100051`.

- **Wazuh Rule:** `100051`
- **Sysmon Event:** `15`
- **MITRE ATT&CK:** `T1564.004 — NTFS File Attributes`

<img width="726" height="672" alt="Wazuh-Rule15-Detection" src="https://github.com/user-attachments/assets/ead1473f-dfb9-4811-9f2b-b5e54213a189" />


## AI-Assisted Triage

When rule `100051` fires, Wazuh automatically launches `custom-ai-triage.py`.

The script extracts the event context and sends it to a locally hosted **Llama 3.2:1b** model. The model returns:

```text
Severity
Assessment
Recommended Next Step
```

<img width="1498" height="308" alt="AI-Analysis-Event15-Test" src="https://github.com/user-attachments/assets/5aa097e9-215b-486b-9d47-33907fd17990" />


## Technologies

**Wazuh • Sysmon • Active Directory • Python • Ollama • Llama 3.2 • MITRE ATT&CK • VMware • Ubuntu**

## Repository Files

- `custom-ai-triage.py` — automated Wazuh → Ollama integration
- `local_rules.xml` — custom detection rules
- `ossec-conf.png` — Wazuh integration configuration

## Result

Successfully built and tested the following automated workflow:

**Endpoint Activity → Sysmon → Wazuh Detection → Custom Rule → Local AI Triage → Recommended Investigation**

This project gave me hands-on experience with **SIEM detection engineering, endpoint telemetry, Python security automation, MITRE ATT&CK mapping, and AI-assisted incident response**.

> All activity was performed in an isolated, authorized cybersecurity lab environment.
