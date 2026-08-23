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









Endpoint Event: Sysmon captures Event 15 (Alternate Data Stream creation) on a target host.

Rule Matching: Wazuh Manager processes the log and triggers custom Rule 100051.

Automated Dispatch: wazuh-integratord calls the custom Python integration script.

Local LLM Inference: The script parses alert context and queries a local Ollama model via REST API (http://localhost:11434/api/generate).

Triage Logging: Incident response analysis streams directly to /var/ossec/logs/ai_triage.log
