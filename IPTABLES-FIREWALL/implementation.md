# Mini Firewall + Splunk SOC Lab — Implementation

> **Note:** IP addresses shown in this documentation are representative private lab addresses and are used for documentation purposes. They are not the exact addresses of the current lab environment.

---

## 1. Lab Environment

The lab was built using the following components:

| Component                  | Role                           |
| -------------------------- | ------------------------------ |
| Kali Linux VM              | Protected host and firewall    |
| WSL Ubuntu                 | Traffic generation and testing |
| Windows Host               | Splunk Enterprise              |
| iptables                   | Host-based firewall            |
| rsyslog                    | System logging                 |
| conntrack                  | Network connection tracking    |
| Splunk Universal Forwarder | Log collection and forwarding  |
| Splunk Enterprise          | SIEM and log analysis          |
| Netcat                     | TCP connectivity testing       |
| curl                       | HTTP connectivity testing      |
| Nmap                       | Network reconnaissance         |
| SSH                        | Remote administration/testing  |

---

# 2. Network Configuration

Kali Linux was configured with two network interfaces.

### NAT Interface

The NAT interface was used to provide Kali with external network connectivity.

The interface and routing information were inspected using:

```bash
ip addr
```

and:

```bash
ip route
```

These commands were used to identify the available interfaces, assigned addresses, and routing paths.

### Host-Only Interface

The Host-Only network was used for controlled communication between the lab systems.

Representative addresses used in this documentation:

```text
WSL Ubuntu    → 192.168.56.10
Kali Linux    → 192.168.56.20
```

The Host-Only network allowed traffic to be generated from WSL toward the Kali firewall without depending on external network connectivity.

---

# 3. Connectivity Verification

Before configuring firewall restrictions, connectivity between the lab systems was tested.

The purpose was to establish a baseline and make sure that a later connection failure could be distinguished between:

* Network configuration problems
* Routing problems
* Service availability problems
* Firewall filtering

Basic tools used during testing included:

```bash
ping
curl
nc
```

The routing table and active interfaces were also checked during troubleshooting.

---

# 4. Inspecting Existing iptables Rules

The existing firewall configuration was inspected using:

```bash
sudo iptables -L -n -v --line-numbers
```

### Command breakdown

| Option           | Purpose                                                     |
| ---------------- | ----------------------------------------------------------- |
| `-L`             | Lists firewall rules                                        |
| `-n`             | Displays addresses and ports numerically                    |
| `-v`             | Shows additional information including packet/byte counters |
| `--line-numbers` | Displays rule numbers                                       |

The packet and byte counters were particularly useful during testing because they provided evidence that traffic was matching a particular rule.

---

# 5. Understanding iptables Chains

The project focused on the three main iptables chains:

### INPUT

Controls traffic entering the Kali host.

### OUTPUT

Controls traffic originating from Kali.

### FORWARD

Controls traffic passing through Kali when the machine is acting as a router.

The primary focus of this project was the `INPUT` chain because Kali was being used as the protected host.

---

# 6. Test HTTP Service

A temporary HTTP service was created on TCP port:

```text
8080
```

This provided a known service that could be used to test firewall behavior.

The purpose was to compare the behavior of the service before and after applying firewall restrictions.

---

# 7. Blocking TCP/8080

A rule was created to block incoming TCP traffic destined for port `8080`:

```bash
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### Rule breakdown

```text
-A INPUT
```

Adds the rule to the `INPUT` chain.

```text
-p tcp
```

Matches TCP traffic.

```text
--dport 8080
```

Matches traffic destined for TCP port `8080`.

```text
-j DROP
```

Drops matching packets.

The rule provided a controlled test case for validating firewall filtering.

---

# 8. Testing the Blocked Port

TCP connectivity to the test port was tested from the traffic-generation environment using Netcat:

```bash
nc -vz 192.168.56.20 8080
```

The expected behavior was that the connection would not successfully reach the service because the firewall was configured to drop the traffic.

The firewall counters were then inspected:

```bash
sudo iptables -L -n -v --line-numbers
```

An increase in the relevant packet counter indicated that traffic was matching the configured firewall rule.

---

# 9. HTTP Testing with curl

HTTP connectivity was also tested using:

```bash
curl http://192.168.56.20
```

`curl` was useful for testing application-level HTTP connectivity, while Netcat was used for direct TCP connectivity testing.

Using multiple testing methods helped distinguish between network-level and application-level issues.

---

# 10. SSH Configuration and Testing

SSH was enabled on Kali for remote administration and firewall testing.

SSH operates over:

```text
TCP/22
```

A connection from the testing environment was performed using:

```bash
ssh <username>@192.168.56.20
```

SSH was intentionally kept available during firewall configuration because accidentally blocking the administration channel can make remote access unavailable.

---

# 11. SSH Repeated-Connection Protection

The lab also explored using iptables to restrict repeated SSH connection attempts.

The objective was to understand how firewall rules can be used beyond simple port-based blocking.

Repeated connection attempts were generated from the controlled testing environment and the resulting firewall behavior was observed.

This provided practical exposure to the concept of firewall-based connection-rate control.

---

# 12. Rule Ordering

iptables processes rules sequentially.

Therefore, rule order can affect the final decision applied to a packet.

For example:

```text
ACCEPT rule
     ↓
DROP rule
```

can produce a different result from:

```text
DROP rule
     ↓
ACCEPT rule
```

The configured rules were therefore inspected using:

```bash
sudo iptables -L -n -v --line-numbers
```

The rule numbers and packet counters helped identify which rules were actually handling the traffic.

---

# 13. Firewall Rule Persistence

During the project, it was observed that iptables rules configured directly in the running system do not automatically survive a reboot unless persistence is configured.

The firewall configuration was therefore saved and configured for persistence.

This is an important operational consideration because a firewall that loses its security policy after a restart can leave a system with an unintended security posture.

---

# 14. Firewall Logging

After configuring traffic filtering, firewall logging was implemented.

The iptables `LOG` target was used to generate log messages for blocked traffic.

A custom prefix was used:

```text
IPTABLES-BLOCK
```

This made firewall events easier to locate in the system logs.

A logged firewall event can contain information such as:

```text
SRC=192.168.56.10
DST=192.168.56.20
PROTO=TCP
DPT=8080
```

These fields provide useful information during security investigation.

---

# 15. Understanding Firewall Log Fields

Common iptables log fields include:

| Field   | Meaning                    |
| ------- | -------------------------- |
| `SRC`   | Source IP address          |
| `DST`   | Destination IP address     |
| `PROTO` | Network protocol           |
| `SPT`   | Source port                |
| `DPT`   | Destination port           |
| `IN`    | Incoming network interface |
| `OUT`   | Outgoing network interface |
| `LEN`   | Packet length              |
| `TTL`   | IP time-to-live            |

For example:

```text
SRC=192.168.56.10
DST=192.168.56.20
DPT=8080
```

indicates that the source system attempted to communicate with the Kali host on destination port `8080`.

---

# 16. rsyslog

The `rsyslog` service was verified as part of the firewall logging pipeline.

The purpose was to ensure that kernel-generated firewall messages could be handled by the Linux logging system.

The logging relationship was:

```text
iptables
   ↓
Kernel logging
   ↓
rsyslog
   ↓
kern.log
```

---

# 17. Verifying Firewall Events in kern.log

Firewall events were observed in:

```text
/var/log/kern.log
```

The custom prefix was used to locate firewall events:

```bash
sudo grep "IPTABLES-BLOCK" /var/log/kern.log
```

This allowed the firewall events to be separated from other kernel messages.

A successful test produced entries containing information such as the source IP, destination IP, protocol, and destination port.

---

# 18. Troubleshooting Firewall Logging

During the lab, there were situations where generated traffic did not immediately appear in `kern.log`.

The troubleshooting process involved checking the complete path rather than assuming that the logging configuration was the problem.

The following were checked:

* Source and destination IP addresses
* Network interfaces
* Routing table
* Listening services
* iptables rules
* Rule ordering
* Packet counters
* Logging rules
* rsyslog
* `kern.log`

This was an important troubleshooting lesson because a missing log event can originate from several different layers.

---

# 19. Connection Tracking with conntrack

The Linux connection-tracking subsystem was used to inspect network sessions.

The current connection-tracking table was viewed using:

```bash
sudo conntrack -L
```

Live connection events were monitored using:

```bash
sudo conntrack -E
```

This provided visibility into network connections independently of application-level tools.

---

# 20. TCP Connection States

Connection tracking was used to understand TCP connection states.

States observed during testing included:

```text
SYN_SENT
SYN_RECV
ESTABLISHED
FIN_WAIT
LAST_ACK
TIME_WAIT
```

A successful TCP connection generally progresses through the TCP handshake before reaching:

```text
ESTABLISHED
```

Connection tracking therefore provided a lower-level view of what was happening when commands such as SSH, curl, and Netcat were used.

---

# 21. Splunk Universal Forwarder

The Splunk Universal Forwarder was installed and configured on Kali.

Its purpose was to collect the firewall-related kernel log and forward the events to Splunk Enterprise.

The monitored log file was:

```text
/var/log/kern.log
```

The Universal Forwarder service was verified during the integration process.

---

# 22. Splunk Enterprise Receiving

Splunk Enterprise was configured to receive forwarded events using:

```text
TCP/9997
```

The Universal Forwarder communicated with the Splunk Enterprise instance through this receiving port.

The receiving configuration allowed the firewall events generated on Kali to be collected centrally.

---

# 23. Verifying Forwarder Connectivity

The network connection associated with the Splunk Forwarder was inspected using connection tracking.

Representative documentation addresses:

```text
Kali
192.168.56.20

Splunk Enterprise
192.168.56.10

Port
9997/TCP
```

An `ESTABLISHED` TCP connection provided evidence that a TCP session existed between the forwarding system and the Splunk receiving service.

---

# 24. Splunk Index Configuration

The forwarded firewall events were configured to be available in:

```text
index=main
```

This allowed the events to be searched centrally in Splunk Enterprise.

The basic investigation path was:

```text
kern.log
   ↓
Universal Forwarder
   ↓
TCP/9997
   ↓
Splunk Enterprise
   ↓
index=main
```

---

# 25. Generating Fresh Firewall Events

To validate the complete logging pipeline, new traffic was generated against a firewall-controlled port.

For example:

```bash
nc -vz 192.168.56.20 8080
```

The resulting event could then be followed through:

1. iptables
2. Firewall packet counters
3. `kern.log`
4. Splunk Universal Forwarder
5. Splunk Enterprise

This demonstrated how a network event can become a SIEM investigation record.

---

# 26. Nmap Testing

Nmap was used to perform controlled reconnaissance against the Kali host.

Example:

```bash
nmap 192.168.56.20
```

The scan demonstrated different port states, including:

```text
open
closed
filtered
```

### Open

A service is reachable and accepting connections.

### Closed

The host is reachable, but no service is listening on the port.

### Filtered

Nmap cannot determine the port state because traffic is being filtered or otherwise prevented from reaching the service.

The scan helped demonstrate the observable effect of firewall filtering.

---

# 27. Observed Nmap Results

During testing, the Kali host produced results showing a mixture of open, closed, and filtered ports.

Examples included:

```text
21/tcp    filtered
22/tcp    closed
23/tcp    filtered
25/tcp    filtered
53/tcp    filtered
80/tcp    open
443/tcp   filtered
445/tcp   filtered
8080/tcp  filtered
```

These results were useful for understanding the difference between a port being closed and a port being actively filtered by the firewall.

---

# 28. Packet and Byte Counters

iptables packet and byte counters were used as an additional validation mechanism.

Command:

```bash
sudo iptables -L -n -v --line-numbers
```

When traffic was generated against a matching rule, the corresponding counters could be inspected to determine whether packets had reached that rule.

This provided evidence that was independent of the client-side connection result.

---

# 29. Troubleshooting Lessons

The project involved troubleshooting several networking and firewall-related issues.

### Network vs Firewall Problems

A failed `ping`, `curl`, or TCP connection does not automatically mean that iptables is blocking the traffic.

The following must also be considered:

* Incorrect IP address
* Incorrect interface
* Routing problems
* Service not listening
* Network isolation
* Firewall rules

### WSL Networking

WSL has its own virtual networking and routing behavior.

Changing the WSL default gateway is not a suitable permanent solution simply to make the security lab work, because it can affect normal WSL connectivity.

The lab therefore treated WSL networking separately from the Kali firewall configuration.

### Firewall Troubleshooting

When traffic did not behave as expected, rule ordering, counters, network configuration, and service availability were checked instead of changing firewall rules blindly.

---

# 30. Validation Approach

The firewall was validated using multiple sources of evidence rather than relying on only one command.

For a blocked connection, the investigation could follow:

```text
Connection Attempt
      ↓
iptables
      ↓
Packet Counter
      ↓
Firewall Log
      ↓
kern.log
      ↓
Splunk
```

This approach made it possible to determine whether the problem was occurring at the network, firewall, logging, or SIEM stage.

---

# 31. Results

The completed lab demonstrated:

* Configuration of a Linux host-based firewall
* Understanding of iptables chains
* Port-based traffic filtering
* TCP/8080 blocking
* SSH configuration and testing
* Protection against repeated SSH connection attempts
* Firewall rule persistence
* Firewall logging using the `LOG` target
* Custom `IPTABLES-BLOCK` logging
* Firewall events in `kern.log`
* rsyslog-based system logging
* Connection tracking using `conntrack`
* TCP connection-state analysis
* Splunk Universal Forwarder configuration
* Splunk receiving on TCP/9997
* Firewall log forwarding to Splunk
* Firewall events in `index=main`
* Controlled Nmap reconnaissance
* Network testing using Netcat and curl
* Packet and byte counter analysis
* Troubleshooting of network and firewall issues

---

# 32. What I Learned

### Firewall Administration

I gained practical experience configuring and troubleshooting Linux firewall rules and understanding how rule ordering affects traffic decisions.

### Network Troubleshooting

The lab demonstrated that connectivity problems need to be investigated across multiple layers instead of immediately assuming that the firewall is responsible.

### Security Logging

I learned how firewall actions can generate security telemetry and how those events move through the Linux logging system.

### Connection Tracking

Using `conntrack` provided a deeper understanding of network sessions and TCP connection states.

### SIEM Integration

The Splunk integration demonstrated how security logs generated by a host-based control can be collected centrally for investigation.

### SOC Perspective

The project connected four important security activities:

**Prevention → Logging → Collection → Investigation**

---

# 33. Current Limitations

The current implementation does not include:

* Automated port-scan detection
* Automated suspicious-IP blocking
* Automated incident response
* IDS/IPS integration
* Advanced behavioral correlation
* Automated SOC alerting

These are considered future improvements rather than completed features.

---

# 34. Future Improvements

Potential future enhancements include:

* Behavioral port-scan detection
* Detection of repeated connection attempts
* Advanced Splunk detection searches
* Firewall activity dashboards
* IDS integration using Suricata
* Automated suspicious-IP blocking
* Automated incident response
* SIEM alerting and escalation

---

# 35. Project Summary

This project provided hands-on experience with a complete host-based firewall and security logging workflow.

The lab combined:

**iptables** for traffic enforcement,
**rsyslog/kern.log** for security event logging,
**conntrack** for network visibility, and
**Splunk** for centralized log collection and investigation.

Testing with SSH, Netcat, curl, and Nmap provided practical validation of the firewall configuration and demonstrated how network activity can be observed from both the firewall and SIEM perspectives.
