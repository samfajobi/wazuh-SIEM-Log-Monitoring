# Wazuh Server Setup Guide

This document explains how to install, configure, and run a Wazuh Server (Manager + API + Dashboard) on Ubuntu 22.04 for security monitoring in the SOC Home Lab.

## Prerequisites

- Ubuntu 20.04 or 22.04 server
- Minimum 4GB RAM, 2 CPUs
- Internet connection
- Root or sudo privilege

## Step 1 — Update System

```bash
sudo apt update && sudo apt upgrade -y
```

## Step 2 — Download and run the Wazuh installation assistant.

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
#### Incase you get an error `Command 'curl' not found`
#### Just install with `sudo apt install curl` and proceed


