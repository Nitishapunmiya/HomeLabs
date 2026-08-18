# Lab Environment Setup

## Overview

This project was built as a local cybersecurity homelab to study web application attacks, Web Application Firewall (WAF) detection and blocking, and SIEM-based security monitoring.

The lab was built using VirtualBox, with Kali Linux used to host the vulnerable web application and WAF components.

## Components

| Component | Role |
|---|---|
| Kali Linux | Web server, DVWA host and WAF |
| Apache | Web server |
| MariaDB | DVWA database |
| DVWA | Intentionally vulnerable web application |
| ModSecurity | Web Application Firewall |
| OWASP CRS | WAF detection rules |
| Splunk | SIEM, detection and investigation |
| VirtualBox | Virtualization platform |

## Kali Linux Environment

Kali Linux was used as the main machine for the web application environment.

The following components were configured on Kali:

- Apache
- PHP
- MariaDB
- DVWA
- ModSecurity
- OWASP Core Rule Set (CRS)

## Network Environment

The lab used a VirtualBox network to allow the client generating web requests to communicate with the Kali web server.

During testing, the Kali web server was observed at:

`192.168.56.102`

An example ModSecurity transaction showed:

`192.168.56.1  192.168.56.102 80`

This represents:

- **Source IP:** `192.168.56.1`
- **Source Port:** `52388`
- **Destination IP:** `192.168.56.102`
- **Destination Port:** `80`

The web application was accessed over HTTP on port 80.

## Web Application

Damn Vulnerable Web Application (DVWA) was used as the intentionally vulnerable web application.

DVWA provided controlled modules for testing common web application attacks.

The three attacks investigated in this project were:

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection

## WAF Environment

After confirming that DVWA was working, ModSecurity was integrated with Apache.

OWASP CRS was then configured to provide detection rules for common web attacks.

The WAF was used to inspect incoming HTTP requests and determine whether requests should be allowed or blocked.

## Logging and SIEM

After the WAF was working, its security logs were integrated with Splunk.

The main logs investigated during the project included:

- ModSecurity audit logs
- Apache error logs

These logs contained information such as:

- Source IP
- Requested URI
- HTTP request
- ModSecurity rule ID
- Attack category
- Severity
- Matched data
- Anomaly score
- Blocking action

The logs were then used to build Splunk detections and dashboards.

## Project Build Process

The environment was developed incrementally:

1. Created the virtual lab in VirtualBox.
2. Configured the Kali Linux machine and networking.
3. Set up Apache, PHP and MariaDB.
4. Installed and configured DVWA.
5. Verified that DVWA was accessible.
6. Installed ModSecurity.
7. Configured OWASP CRS.
8. Configured ModSecurity logging.
9. Integrated the relevant logs with Splunk.
10. Generated controlled web attacks.
11. Investigated the resulting WAF events.
12. Created Splunk detection searches.
13. Built dashboards for monitoring blocked requests and individual attack types.

## Initial Baseline

A working DVWA environment was established before attack testing began.

This baseline was important because it allowed normal requests to be compared with malicious requests later in the project.

For example:

`/DVWA/vulnerabilities/sqli/index.php?id=2`

is a normal request and is not automatically a SQL Injection attack.

## Objective

The purpose of building the environment was to create an end-to-end security monitoring lab rather than simply demonstrate vulnerabilities.

The project was used to understand:

- How a WAF processes web requests
- How OWASP CRS identifies malicious patterns
- How ModSecurity records security events
- How blocked requests appear in logs
- How WAF logs can be analyzed in Splunk
- How detection rules can be created from raw security events
- How security dashboards can help investigate web attacks
