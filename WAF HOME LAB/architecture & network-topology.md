# Network Topology

## Overview

The WAF homelab was designed to simulate a small web application environment where HTTP requests pass through a Web Application Firewall before reaching an intentionally vulnerable application.

The lab consists of:

- A client/attacking machine used to generate web requests
- An kali server hosting Apache, DVWA and ModSecurity
- OWASP Core Rule Set (CRS) providing detection rules
- Splunk acting as the SIEM for log collection, detection and investigation

The overall flow is:

Client
↓
ModSecurity WAF
↓
Apache
↓
DVWA
↓
Security Logs
↓
Splunk


## Architecture

```text
                         HTTP REQUEST
                              │
                              ▼
                    ┌──────────────────┐
                    │  Client Machine  │
                    │                  │
                    │  Attack Testing  │
                    └────────┬─────────┘
                             │
                             │ HTTP
                             ▼
              ┌──────────────────────────────┐
              │       Ubuntu Web Server      │
              │                              │
              │       ModSecurity WAF        │
              │              │               │
              │       OWASP CRS Rules        │
              │              │               │
              │           Apache             │
              │              │               │
              │             DVWA             │
              └──────────────┬───────────────┘
                             │
                             │ Logs
                             ▼
                    ┌──────────────────┐
                    │      Splunk      │
                    │       SIEM       │
                    │                  │
                    │ Detection &      │
                    │ Investigation     │
                    └──────────────────┘
