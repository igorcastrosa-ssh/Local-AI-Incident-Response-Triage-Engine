# Local AI Incident Response Triage Engine (Wazuh + Ollama)

An event-driven, privacy-preserving SIEM triage engine that automatically enriches high-risk endpoint security alerts using a locally hosted LLM (Ollama). 

This project bridges the gap between threat detection and automated response by converting raw JSON alert payloads into concise, actionable risk summaries for SOC analysts without exposing sensitive telemetry to external cloud APIs.

---

## 🏗️ Architecture Flow

```mermaid
graph LR
    A[Client01: Sysmon Event 15] -->|Log Event| B[Wazuh Manager]
    B -->|Rule 100051 Trigger| C[wazuh-integratord]
    C -->|Executes Script| D[custom-ai-triage.py]
    D -->|Local API Call| E[Ollama LLM Engine]
    E -->|JSON Analysis| D
    D -->|Append Report| F[ai_triage.log]

```







Endpoint Event: Sysmon captures Event 15 (Alternate Data Stream creation) on a target host.

Rule Matching: Wazuh Manager processes the log and triggers custom Rule 100051.

Automated Dispatch: wazuh-integratord calls the custom Python integration script.

Local LLM Inference: The script parses alert context and queries a local Ollama model via REST API (http://localhost:11434/api/generate).

Triage Logging: Incident response analysis streams directly to /var/ossec/logs/ai_triage.log


Key Features:

Zero-Cloud Data Privacy: Operates 100% on-premise to ensure sensitive corporate hostnames, file paths, and logs never leave the internal network.

Low-Latency SOC Enrichment: Leverages lightweight local LLMs (llama3 / mistral) to evaluate threat context within seconds.

Standard-Library Python: Written without external Python library dependencies (requests, etc.) for seamless execution under unprivileged system users (wazuh).

AI Analysis:
<img width="1498" height="308" alt="AI-Analysis-Event15-Test" src="https://github.com/user-attachments/assets/02d3ab18-9078-4e03-90f6-25cbfe1aacda" />

