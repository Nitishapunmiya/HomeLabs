# WAF-SOC Homelab: Web Attack Detection & Monitoring

A hands-on Web Application Firewall (WAF) and SOC monitoring lab built to simulate, detect, block, and investigate common web application attacks.

The project combines **ModSecurity + OWASP Core Rule Set (CRS)** with **Apache/DVWA** and **Splunk** to create an end-to-end security monitoring pipeline.

> **Attacker → WAF → Vulnerable Web Application → Security Logs → Splunk → Detection → Investigation**

---

## 🎯 Project Objective

The goal of this project was to build a realistic security lab where I could understand what happens when a web attack moves through an actual defensive stack.

Instead of only generating attacks, the project focuses on the complete lifecycle:

1. Simulate a web attack from an attacker machine.
2. Send the request toward the vulnerable application.
3. Inspect how the WAF processes the request.
4. Identify the OWASP CRS rule triggered.
5. Determine whether the request was blocked.
6. Forward the security logs to Splunk.
7. Create detection logic using SPL.
8. Investigate the attack using source IP, detection ID, attack type, URI, severity, and other fields.
9. Visualize the attacks through a SOC-style dashboard.

---

# 🏗️ Architecture

```text
                         ATTACK TRAFFIC
                              │
                              ▼
                    ┌──────────────────┐
                    │   Kali Linux     │
                    │         │
                    └────────┬─────────┘
                             │
                             │ HTTP
                             ▼
                    ┌──────────────────┐
                    │    ModSecurity   │
                    │       WAF        │
                    │                  │
                    │   OWASP CRS      │
                    └────────┬─────────┘
                             │
                    Allowed │
                             ▼
                    ┌──────────────────┐
                    │ Apache Web Server │
                    │                  │
                    │      DVWA        │
                    └────────┬─────────┘
                             │
                             │ Logs
                             ▼
                    ┌──────────────────┐
                    │      Splunk      │
                    │       SIEM       │
                    └──────────────────┘
                             │
                             ▼
                    Detection & Dashboard
