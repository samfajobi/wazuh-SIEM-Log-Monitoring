# File Integrity Monitoring (FIM) on Windows Server using Wazuh

## Overview
File Integrity Monitoring (FIM) is a security capability used to detect **unauthorized changes to critical files and directories**. Attackers often modify system files, configuration files, or sensitive directories to maintain persistence, escalate privileges, or evade detection.

This project demonstrates how to **configure and monitor File Integrity Monitoring on a Windows Server using Wazuh**, analyze alerts in the Wazuh dashboard, and perform SOC-style investigation and documentation.

---

## Objectives
- Configure File Integrity Monitoring on a Windows Server
- Detect file creation, modification, deletion, and permission changes
- Monitor and analyze FIM alerts in Wazuh
- Correlate Wazuh alerts with Windows Security Event Logs
- Map detected activities to the MITRE ATT&CK framework
- Practice real-world SOC alert triage

---

## Lab Architecture

- **Wazuh Manager:** Ubuntu Server
- **Wazuh Dashboard:** Web UI
- **Wazuh Agent:** Windows Server

```

[Windows Server + Wazuh Agent] → [Wazuh Manager] → [Wazuh Dashboard]

```

---