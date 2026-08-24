#!/usr/bin/env python3

import sys
import json
import urllib.request
from datetime import datetime

LOG_FILE = "/var/ossec/logs/ai_triage.log"


def write_log(message):
    with open(LOG_FILE, "a") as log:
        log.write(message)


def load_alert(alert_file_path):
    try:
        with open(alert_file_path, "r") as f:
            raw_alert = f.read()

        if not raw_alert.strip():
            raise ValueError("Alert file is empty.")

        return json.loads(raw_alert)

    except Exception as e:
        write_log(
            f"\n[ERROR] Failed to read/parse alert file "
            f"({alert_file_path}): {str(e)}\n"
        )
        raise


def analyze_with_ollama(alert, hook_url):
    rule_id = alert.get("rule", {}).get("id", "N/A")
    rule_desc = alert.get("rule", {}).get("description", "N/A")

    win_data = alert.get("data", {}).get("win", {})
    system_data = win_data.get("system", {})
    event_data = win_data.get("eventdata", {})

    computer = system_data.get(
        "computer",
        alert.get("agent", {}).get("name", "CLIENT01")
    )

    event_id = system_data.get("eventID", "N/A")
    user = event_data.get("user", "N/A")
    image = event_data.get("image", "N/A")
    target_file = event_data.get("targetFilename", "N/A")

    prompt = (
        "You are a defensive SOC analyst reviewing synthetic telemetry "
        "from an authorized insider-threat and DLP cybersecurity lab.\n\n"

        "Evaluate the event using context, not Event ID alone.\n"
        "Consider these risk indicators:\n"
        "- Whether PowerShell or another scripting engine created the artifact\n"
        "- Whether an NTFS Alternate Data Stream is being used\n"
        "- Whether the file is located in a shared or user-accessible directory\n"
        "- Whether the user context is privileged or unusual\n"
        "- Whether the activity could represent data hiding, staging, or preparation for exfiltration\n\n"

        f"Host: {computer}\n"
        f"User: {user}\n"
        f"Wazuh Rule ID: {rule_id}\n"
        f"Rule Description: {rule_desc}\n"
        f"Sysmon Event ID: {event_id}\n"
        f"Process Image: {image}\n"
        f"Target File: {target_file}\n\n"

        "Important guidance:\n"
        "An Alternate Data Stream is not automatically malicious. "
        "However, creation of an ADS by PowerShell on a file in a shared or "
        "user-accessible directory should be treated as suspicious and investigated.\n\n"

        "Severity scoring rules:\n"
        "LOW = routine or likely benign activity with little suspicious context.\n"
        "MEDIUM = suspicious activity that requires investigation but has limited evidence of malicious intent.\n"
        "HIGH = multiple suspicious indicators consistent with data hiding, staging, or unauthorized activity.\n"
        "CRITICAL = strong evidence of active compromise, confirmed exfiltration, or severe impact.\n\n"

        "You MUST select exactly ONE severity rating.\n"
        "Do not list multiple severity options.\n"
        "Do not repeat the severity scale.\n\n"

        "Your entire response MUST contain exactly three lines in this format:\n"
        "Severity: HIGH\n"
        "Assessment: PowerShell created an alternate data stream in a user-accessible directory, indicating possible data hiding or staging.\n"
        "Next Step: Review related process, user, file, and network activity.\n\n"

        "The example above demonstrates formatting only. "
        "Choose the severity appropriate for the actual event."
    )

    payload = {
        "model": "llama3.2:1b",
        "prompt": prompt,
        "stream": False
    }

    request = urllib.request.Request(
        hook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        response_body = response.read().decode("utf-8")
        response_data = json.loads(response_body)

    llm_analysis = response_data.get(
        "response",
        "No response returned from Ollama."
    )

    return {
        "computer": computer,
        "user": user,
        "rule_id": rule_id,
        "rule_desc": rule_desc,
        "event_id": event_id,
        "image": image,
        "target_file": target_file,
        "analysis": llm_analysis
    }


def main():
    try:
        if len(sys.argv) < 2:
            write_log(
                "\n[AI TRIAGE ERROR]: No alert file path provided by Wazuh.\n"
            )
            sys.exit(1)

        alert_file_path = sys.argv[1]

        hook_url = (
            sys.argv[3]
            if len(sys.argv) > 3
            else "http://localhost:11434/api/generate"
        )

        alert = load_alert(alert_file_path)

        try:
            result = analyze_with_ollama(alert, hook_url)

        except Exception as e:
            write_log(
                f"\n[ERROR] Ollama request failed: {str(e)}\n"
            )
            sys.exit(1)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = (
            f"\n=== AI TRIAGE REPORT - {timestamp} ===\n"
            f"Host: {result['computer']}\n"
            f"User: {result['user']}\n"
            f"Rule ID: {result['rule_id']}\n"
            f"Event ID: {result['event_id']}\n"
            f"Rule: {result['rule_desc']}\n"
            f"Target: {result['target_file']}\n"
            f"Process: {result['image']}\n\n"
            f"AI Analysis:\n"
            f"{result['analysis']}\n"
            f"========================================\n"
        )

        write_log(report)

    except Exception as e:
        write_log(
            f"\n[AI TRIAGE FATAL ERROR]: {str(e)}\n"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
