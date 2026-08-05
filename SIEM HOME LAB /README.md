# SIEM Home Lab — Complete Build Documentation

## 1. Project Overview

The goal of this project was to build a **small SOC/SIEM home lab** where I could:

* Generate security activity/attacks in a controlled environment.
* Collect Linux security logs.
* Forward those logs to a SIEM.
* Search and investigate the logs.
* Eventually create detections and alerts.
* Understand the complete SOC workflow from **attack → log → SIEM → detection → investigation**.

The final lab uses:

* **Ubuntu WSL** → attacker / activity generation
* **Kali Linux VM** → victim and log source
* **Splunk Universal Forwarder** → log forwarding from Kali
* **Windows Host** → Splunk Enterprise SIEM
* **TCP 9997** → communication between the Forwarder and Splunk
* **rsyslog** → creates traditional Linux log files
* **auth.log / syslog** → logs monitored by Splunk

---

# 2. Final Architecture

The final architecture is:

```text
                 ATTACK / ACTIVITY
                       │
                       ▼
              ┌─────────────────┐
              │   Ubuntu WSL    │
              │    Attacker     │
              └────────┬────────┘
                       │
                       │ SSH / Other Activity
                       ▼
              ┌─────────────────┐
              │   Kali Linux    │
              │     Victim      │
              │                 │
              │ /var/log/       │
              │  auth.log       │
              │  syslog         │
              └────────┬────────┘
                       │
                       │ Splunk Universal
                       │ Forwarder 10.4.2
                       │
                       │ TCP 9997
                       ▼
              ┌─────────────────┐
              │ Windows Host    │
              │                 │
              │ Splunk          │
              │ Enterprise      │
              │                 │
              │ SIEM            │
              └────────┬────────┘
                       │
                       ▼
              Search / Detection /
              Investigation / Alerts
```

---

# 3. Why We Chose This Architecture

Initially, there were several possible SIEM options such as Wazuh, Splunk and Microsoft Sentinel.

The main practical problem was the laptop's limited resources. Running a complete SIEM stack and multiple virtual machines locally could consume significant RAM.

Therefore, the lab was designed to distribute the workload:

```text
Kali VM
   ↓
Only generates activity and collects logs

Windows Host
   ↓
Runs Splunk Enterprise

Ubuntu WSL
   ↓
Generates controlled activity/attacks
```

This avoided unnecessarily running another heavy SIEM server inside a VM.

---

# 4. Initial Problem: How Would the Machines Communicate?

One of the first challenges was networking.

The lab contained:

* Windows host
* Kali VM
* Ubuntu WSL

Initially, there was confusion because Windows could communicate with Kali, but Kali could not successfully ping Windows.

The concern was that **Windows Defender Firewall was blocking traffic**.

This was important because the Splunk Forwarder needed to communicate from Kali to Windows.

---

# 5. VirtualBox Networking

Kali was eventually configured using a **Bridged Adapter**.

This allowed Kali and Windows to exist on the same LAN.

The resulting architecture became approximately:

```text
Windows
192.168.1.75
      │
      │ Same LAN
      │
Kali
192.168.1.x
```

The exact IP addresses can change because the network uses DHCP.

---

# 6. Installing Splunk Enterprise on Windows

The next step was installing **Splunk Enterprise** on the Windows host.

After installation, Splunk was accessed through:

```text
http://localhost:8000
```

This confirmed that the Splunk Enterprise web interface was working.

At this point:

```text
Windows
   │
   └── Splunk Enterprise
```

was operational.

---

# 7. Configuring Splunk to Receive Data

The Universal Forwarder needs a receiving port on the Splunk server.

Splunk was configured to receive data on:

```text
TCP 9997
```

The receiving configuration was enabled through:

```text
Settings
→ Forwarding and receiving
→ Configure receiving
→ Add new
→ 9997
```

This established the destination for the Kali Forwarder.

---

# 8. Windows Firewall Problem

Even though Splunk was configured to listen on port 9997, Windows Firewall could still block incoming connections.

Therefore, we created an inbound Windows Firewall rule allowing:

```text
Protocol: TCP
Port: 9997
Direction: Inbound
Action: Allow
```

The rule was created with PowerShell:

```powershell
New-NetFirewallRule -DisplayName "Splunk Receiving 9997" -Direction Inbound -Protocol TCP -LocalPort 9997 -Action Allow
```

We initially tried to check whether the rule existed:

```powershell
Get-NetFirewallRule -DisplayName "Splunk Receiving 9997"
```

Windows returned:

```text
No MSFT_NetFirewallRule objects found
```

This simply meant that the rule had not yet been created.

We then created it successfully.

---

# 9. Testing TCP Connectivity

Instead of relying only on `ping`, we tested the actual Splunk port.

From Kali:

```bash
nc -vnz 192.168.1.75 9997
```

The result was:

```text
(UNKNOWN) [192.168.1.75] 9997 (?) open
```

This was a major milestone.

It proved:

```text
Kali
  │
  │ TCP 9997
  ▼
Windows Splunk
```

was reachable.

### Why `nc` was important

`nc` means Netcat.

The command:

```bash
nc -vnz 192.168.1.75 9997
```

means:

* `-v` → verbose
* `-n` → don't perform DNS lookup
* `-z` → check the port without sending data

The result `open` confirmed that TCP 9997 was accessible.

---

# 10. Installing Splunk Universal Forwarder on Kali

The Splunk Universal Forwarder `.deb` package was downloaded and transferred into Kali.

The Forwarder was installed on Kali.

The installed version was:

```text
Splunk Universal Forwarder 10.4.2
```

The installation location was:

```text
/opt/splunkforwarder
```


---

# 11. Connecting the Universal Forwarder to Splunk

The Forwarder was configured to send data to the Windows Splunk server:

```bash
sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.1.75:9997
```

Initially, checking the configuration produced:

```text
Active forwards:
        None

Configured but inactive forwards:
        192.168.1.75:9997
```

This meant:

> The destination was configured, but the Forwarder was not currently connected.

---

# 12. Starting the Universal Forwarder

The Forwarder was started:

```bash
sudo /opt/splunkforwarder/bin/splunk start
```

After starting it, we checked:

```bash
sudo /opt/splunkforwarder/bin/splunk list forward-server
```

Eventually the output became:

```text
Active forwards:
        192.168.1.75:9997

Configured but inactive forwards:
        None
```

This was another major milestone.

It confirmed:

```text
Kali Universal Forwarder
          │
          │ Connected
          ▼
Windows Splunk :9997
```

---

# 13. First Log Collection Problem

We initially tried to monitor:

```text
/var/log/auth.log
```

using:

```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log
```

However, Splunk returned:

```text
Parameter name: Path must be a file or directory.
```

The problem was that:

```text
/var/log/auth.log
```

did not exist on the Kali installation.

We then checked Kali's logging system.

---

# 14. Understanding `journalctl`

We ran:

```bash
sudo journalctl -n 10
```

and received entries such as:

```text
pam_unix(sudo:session): session opened
pam_unix(sudo:session): session closed
CRON
sudo
```

This showed that Kali was actively generating logs through **systemd-journald**.

The important distinction was:

```text
journald
    ↓
stores systemd journal events

journalctl
    ↓
command used to read those events
```

So the logs existed, but traditional files such as:

```text
/var/log/auth.log
/var/log/syslog
```

were not available.

---

# 15. Checking `/var/log/syslog`

We checked:

```bash
ls -l /var/log/syslog
```

and received:

```text
No such file or directory
```

We also checked the `rsyslog` service:

```bash
systemctl status rsyslog
```

The result was:

```text
Unit rsyslog.service could not be found.
```

This explained why the traditional log files were missing.

---

# 16. Installing rsyslog

To make the SIEM lab simpler and to generate traditional log files that the Universal Forwarder could monitor, we installed `rsyslog`.

First:

```bash
sudo apt update
```

Then:

```bash
sudo apt install rsyslog -y
```

The service was enabled and started:

```bash
sudo systemctl enable --now rsyslog
```

After this, the traditional logs became available:

```text
/var/log/auth.logok goo
/var/log/syslog
```

This solved the log-file problem.

---

# 17. Configuring the Forwarder to Monitor Logs

We then added the authentication log:

```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log
```

And the system log:

```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/syslog
```

The Universal Forwarder was then restarted:

```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

We verified the monitored files with:

```bash
sudo /opt/splunkforwarder/bin/splunk list monitor
```

The expected monitored files were:

```text
/var/log/auth.log
/var/log/syslog
```

---

# 18. First Successful Log Ingestion

We opened Splunk Enterprise on Windows:

```text
http://localhost:8000
```

Then opened:

```text
Search & Reporting
```

and searched:

```spl
index=*
```

Kali events appeared in Splunk.

This confirmed the entire pipeline was working:

```text
Kali log
   ↓
auth.log / syslog
   ↓
Splunk Universal Forwarder
   ↓
TCP 9997
   ↓
Windows
   ↓
Splunk Enterprise
   ↓
Search
```

---

# 19. Attacks performed 

SSH Brute Force Attack detected
Windows persistence using sceduled task
windows priviledge escalation

# 20. Dynamic IP Challenge

One remaining infrastructure issue was the use of DHCP.

The Windows host currently had an IP such as:

```text
192.168.1.75
```

The Forwarder was configured with:

```text
192.168.1.75:9997
```

Because the network uses dynamic addressing, Windows could potentially receive another IP later.

For example:

```text
Today:
192.168.1.75

Later:
192.168.1.82
```

If that happens, the Forwarder would continue trying to connect to the old IP.

The Forwarder configuration itself is persistent, so it does not need to be recreated every time Kali starts.

If the Windows IP changes, the forwarding destination needs to be updated.

For example:

```bash
sudo /opt/splunkforwarder/bin/splunk remove forward-server OLD_IP:9997
```

Then:

```bash
sudo /opt/splunkforwarder/bin/splunk add forward-server NEW_IP:9997
```

The current lab intentionally keeps dynamic addressing rather than using a static IP or hostname.

---

# 21. Important Commands Learned

During the build, several Linux commands became important.

## `journalctl`

Used to view systemd journal logs.

```bash
sudo journalctl -n 10
```

Last 10 journal entries.

```bash
journalctl -f
```

Follow logs in real time.

```bash
journalctl -u ssh
```

View logs related to SSH.

---

## `rsyslog`

A Linux logging service that processes/routes syslog-style events.

In this lab it helped create:

```text
/var/log/auth.log
/var/log/syslog
```

which the Splunk Forwarder could monitor.

---

## `nc`

Netcat.

Used to test network connectivity to a specific TCP port.

```bash
nc -vnz 192.168.1.75 9997
```

Result:

```text
9997 open
```

confirmed that the Splunk receiving port was reachable.

---

## `systemctl`

Used to manage services.

Examples:

```bash
systemctl status rsyslog
```

```bash
sudo systemctl start ssh
```

```bash
sudo systemctl restart rsyslog
```

```bash
sudo systemctl enable --now rsyslog
```

---

## `ip addr`

Used to find network interfaces and IP addresses:

```bash
ip addr
```

---

## `ip route`

Used to view routing information:

```bash
ip route
```

---

## `ping`

Used for basic ICMP connectivity testing:

```bash
ping 192.168.1.75
```

However, a failed ping does not necessarily mean a host is unreachable because firewalls can block ICMP.

---

## `ss`

Used to view listening ports and network connections:

```bash
ss -tulnp
```

---

## `tail`

Useful for monitoring logs:

```bash
tail -f /var/log/auth.log
```

This displays new authentication events as they are written.

---

## `grep`

Used to search logs:

```bash
grep "Failed password" /var/log/auth.log
```

or:

```bash
grep "Accepted" /var/log/auth.log
```

---

## `find`

Used to locate files:

```bash
sudo find /var/log -type f
```

---

## `chown`

Changes file ownership.

The Splunk warning included:

```bash
chown -R splunkfwd:splunkfwd /opt/splunkforwarder
```

---

# 22. What We Have Achieved

At this point, the lab has successfully demonstrated:

### Infrastructure

* Kali Linux VM
* Windows host
* Ubuntu WSL
* Bridged networking
* Windows Firewall configuration
* TCP connectivity testing

### SIEM

* Splunk Enterprise installed on Windows
* Splunk receiving configured on TCP 9997
* Windows Firewall allowing TCP 9997
* Splunk Universal Forwarder 10.4.2 installed on Kali
* Forwarder connected to Splunk

### Logging

* systemd journal investigation
* rsyslog installation
* `/var/log/auth.log`
* `/var/log/syslog`
* Forwarder monitoring
* Successful log ingestion

### Security event validation

* SSH connection from Ubuntu to Kali
* Successful SSH authentication
* Authentication event visible in Splunk

---

# 24. Current Working State

The current lab is:

```text
┌──────────────────────┐
│      Ubuntu WSL      │
│                      │
│  Attacker / Activity │
└──────────┬───────────┘
           │
           │ SSH / attacks
           ▼
┌──────────────────────┐
│      Kali Linux      │
│                      │
│      Victim          │
│                      │
│  rsyslog             │
│      ↓               │
│  auth.log            │
│  syslog              │
│      ↓               │
│  Universal Forwarder │
│       10.4.2         │
└──────────┬───────────┘
           │
           │ TCP 9997
           ▼
┌──────────────────────┐
│    Windows Host      │
│                      │
│  Splunk Enterprise   │
│                      │
│  Search & Reporting  │
└──────────────────────┘
```

The core SIEM ingestion pipeline is **working successfully**.

---

# 24. What Comes Next

The infrastructure phase is essentially complete.

The next phase is **SOC detection and investigation**.

We can now start generating controlled security events.

The planned progression is:

```text
PHASE 1
Infrastructure
        ↓
PHASE 2
Log Collection
        ↓
PHASE 3
Attack Simulation
        ↓
PHASE 4
Detection Engineering
        ↓
PHASE 5
Alerts
        ↓
PHASE 6
Investigation
        ↓
PHASE 7
MITRE ATT&CK Mapping
        ↓
PHASE 8
Dashboards
        ↓
PHASE 9
Incident Response
```

The first scenario is **SSH brute-force detection**.

The planned flow is:

```text
Ubuntu WSL
     │
     │ Multiple failed SSH attempts
     ▼
Kali
     │
     ▼
/var/log/auth.log
     │
     ▼
Splunk Forwarder
     │
     ▼
Windows Splunk
     │
     ▼
SPL Detection
     │
     ▼
Alert
     │
     ▼
SOC Investigation
```

A normal successful SSH login has already been verified with:

```spl
index=* "Accepted password"
```

The next step is therefore to generate controlled **failed SSH authentication events**, identify the resulting log pattern, create an SPL detection for repeated failures, and turn it into a SIEM alert.

---

# 25. Overall Learning Outcome

This lab started as a simple question:

> "How can I build a SIEM home lab?"

It evolved into a complete practical pipeline where I learned:

```text
Networking
    ↓
Virtual Machines
    ↓
Firewall
    ↓
TCP ports
    ↓
Linux logging
    ↓
journald
    ↓
rsyslog
    ↓
Log files
    ↓
Splunk Universal Forwarder
    ↓
Splunk Enterprise
    ↓
Log ingestion
    ↓
Searching
    ↓
Security event investigation
```

The most important lesson was that a SIEM is **not just a dashboard**.

A working SIEM requires:

```text
DATA SOURCE
     ↓
LOG GENERATION
     ↓
LOG COLLECTION
     ↓
LOG TRANSPORT
     ↓
LOG INGESTION
     ↓
NORMALIZATION / SEARCH
     ↓
DETECTION
     ↓
ALERT
     ↓
INVESTIGATION
     ↓
RESPONSE
```

The home lab has now successfully completed the **log generation → collection → transport → ingestion → search** portion.

The next goal is to complete the **detection → alert → investigation → response** portion.

