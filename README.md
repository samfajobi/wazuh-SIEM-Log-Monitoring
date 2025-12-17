# 🔐 Wazuh SIEM and Firewall Log Monitoring (SOC Home Lab)

## 📌 Overview

This project showcases a **Security Operations Center (SOC) home lab** built with **Wazuh SIEM** and integrated with a **network firewall (pfSense/OPNsense)** to monitor, detect, and analyze security events across both **endpoint and network layers**.

The lab centralizes security logs from endpoints, authentication services, and firewall devices, enabling effective **security monitoring, alert triage, and incident investigation**. Firewall logs are forwarded to Wazuh using syslog, allowing visibility into suspicious activities such as **unauthorized access attempts, port scanning, brute-force attacks, and network policy violations**.

Designed to mirror real-world enterprise SOC environments, this project demonstrates practical hands-on experience with **SIEM operations, firewall log analysis, event correlation, and defense-in-depth security monitoring**.

---


## 📌 Table of Contents
- [Overview](#overview)
- [Architecture Diagram](#architecture-diagram)
- [Lab Environment](#lab-environment)
- [Setup Guide](#setup-guide)
  - [Install Wazuh Server](#1-install-wazuh-server-ubuntu)
  - [Install Wazuh Agent on Windows 10](#2-install-wazuh-agent-on-windows-10)
  - [Install Wazuh Agent on Windows-server](#3-install-wazuh-agent-on-windows-server-2019)
  - [Install Wazuh Agent on Ubuntu](#4-install-wazuh-agent-on-ubuntu-server)
- [Attack Simulations](#attack-simulations)
- [Detection & Alerts](#detection--alerts)
- [What I Learned](#what-i-learned)
- [Repository Structure](#repository-structure)
- [Conclusion](#conclusion)

---

## 🧾 Overview
The purpose of this project is to build a production-style SOC lab environment using open-source tools.  
I deployed **Wazuh SIEM** on Ubuntu and installed agents on multiple operating systems to collect logs, detect threats, and simulate attacks using MITRE ATT&CK techniques.

This lab helps me practice:
- Endpoint detection & response
- Log analysis
- Incident detection & triage
- Linux auditd event monitoring
- Brute-force detection
- Threat hunting
- Windows & Linux security monitoring

---

## 🏗️ Architecture Diagram


