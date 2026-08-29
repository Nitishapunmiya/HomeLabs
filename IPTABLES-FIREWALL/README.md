# Mini Firewall + Splunk SOC Lab

A hands-on cybersecurity home lab demonstrating **Linux firewall configuration, network traffic filtering, firewall logging, connection tracking, and centralized security monitoring using Splunk**.

The project uses Kali Linux as the protected system, WSL Ubuntu for controlled traffic generation, and Splunk Enterprise for centralized log collection and investigation.

---

## Project Overview

The lab was built to understand how a Linux host-based firewall can:

* Control incoming network traffic
* Allow required services
* Block unwanted traffic
* Protect services such as SSH
* Generate firewall security logs
* Track network connections
* Forward security logs to a SIEM
* Support investigation of network activity

The main technologies used were:

**Kali Linux · iptables · rsyslog · conntrack · Splunk Universal Forwarder · Splunk Enterprise · Nmap · Netcat · curl · SSH**

---

## Lab Architecture

The lab consists of:

| Component                  | Role                           |
| -------------------------- | ------------------------------ |
| WSL Ubuntu                 | Traffic generation and testing |
| Kali Linux                 | Protected host and firewall    |
| Windows Host               | Splunk Enterprise              |
| iptables                   | Firewall                       |
| rsyslog                    | System logging                 |
| conntrack                  | Connection tracking            |
| Splunk Universal Forwarder | Log forwarding                 |
| Splunk Enterprise          | SIEM                           |

The basic security workflow is:

```text
Traffic
   ↓
Kali Linux
   ↓
iptables
   ↓
Firewall Decision
   ↓
kern.log
   ↓
Splunk Universal Forwarder
   ↓
Splunk Enterprise
   ↓
Investigation
```

For the complete architecture, see:

➡️ **[architecture.md](Architecture.md)**

---

## Implementation

The implementation covers:

* Network configuration
* Connectivity verification
* iptables configuration
* Port-based filtering
* SSH protection
* Firewall rule ordering
* Rule persistence
* Firewall logging
* rsyslog and `kern.log`
* Connection tracking with `conntrack`
* Splunk Universal Forwarder
* Splunk receiving configuration
* Firewall log forwarding
* Nmap reconnaissance
* Netcat and curl testing
* Troubleshooting
* Validation and results

For the complete technical implementation, commands, configuration details, troubleshooting, and results, see:

➡️ **[implementation.md](implementation.md)**

---

## Evidence

Screenshots and evidence from the lab are stored in:

```text
screenshots/
```

The evidence includes:

* Network configuration
* iptables rules
* Firewall packet counters
* Firewall log events
* conntrack output
* Splunk events
* Nmap results

---

## Skills Demonstrated

* Linux
* Networking
* TCP/IP
* iptables
* Firewall Administration
* SSH
* rsyslog
* Linux Logging
* conntrack
* Network Troubleshooting
* Nmap
* Netcat
* Splunk
* Splunk Universal Forwarder
* SIEM
* Security Log Analysis

---

## Project Scope

This project focuses on:

**Firewall Prevention → Logging → Collection → Investigation**

Automated behavioral detection and automated IP blocking are not part of the current implementation.

---

## Future Improvements

Potential future improvements include:

* Behavioral port-scan detection
* Splunk detection searches
* Firewall activity dashboards
* IDS integration
* Automated suspicious-IP blocking
* Automated incident response
* SIEM alerting

---

## Documentation

* **[Architecture]** — High-level project architecture and component relationships
* **[Implementation]** — Detailed configuration, testing, troubleshooting, and results

---

## Disclaimer

All network scanning and firewall testing in this project was performed in a controlled lab environment on systems used for the project.
