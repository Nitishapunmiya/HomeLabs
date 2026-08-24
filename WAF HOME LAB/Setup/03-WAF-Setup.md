# 03 — Web Application Firewall (WAF) Setup

## 1. Overview

This stage of the home lab focuses on deploying and configuring a **Web Application Firewall (WAF)** in front of the DVWA web application.

The lab uses **ModSecurity** integrated with **Apache2**, together with the **OWASP Core Rule Set (CRS)** to detect and block common web application attacks.

The purpose of this setup is to:

* Inspect incoming HTTP requests
* Detect malicious web traffic
* Detect common web attacks using OWASP CRS
* Block malicious requests
* Generate security logs
* Investigate WAF alerts during attack simulations
* Forward relevant logs to the SIEM for further analysis

---

## 2. Lab Architecture

The WAF is deployed on the Ubuntu server hosting DVWA.

```text
                    ATTACKER
                 
                       |
                       |
                 HTTP Requests
                       |
                       v
              +------------------+
              |     kali      |
              |                  |
              |     Apache2      |
              |        |         |
              |        v         |
              |  ModSecurity WAF |
              |        |         |
              |        v         |
              |   OWASP CRS      |
              |        |         |
              |        v         |
              |      DVWA        |
              |                  |
              +------------------+
                       |
                       v
                    Logs
                       |
                       v
              SIEM / Splunk
```

### Components

| Component             | Role                             |
| --------------------- | -------------------------------- |
| kali                  | Web server / WAF machine         |
| Apache2               | Web server                       |
| DVWA                  | Vulnerable web application       |
| ModSecurity           | WAF engine                       |
| OWASP CRS             | Attack detection rules           |
| Apache logs           | Web server logging               |
| ModSecurity audit log | WAF security logging             |
| Splunk                | Log collection and investigation |

---

# 3. Why ModSecurity?

**ModSecurity** is an open-source Web Application Firewall engine that can be integrated with Apache.

Instead of allowing every HTTP request to reach DVWA directly, ModSecurity inspects the request first.

For example:

```text
attacker
  |
  | Malicious HTTP Request
  v
Apache
  |
  v
ModSecurity
  |
  v
OWASP CRS
  |
  +---- Malicious ---> Block + Log
  |
  +---- Normal ------> DVWA
```

This makes ModSecurity the security inspection layer between the attacker and the web application.

---

# 4. Why OWASP Core Rule Set?

ModSecurity provides the WAF engine, while the **OWASP Core Rule Set (CRS)** provides a large collection of detection rules.

The CRS is designed to detect common web application attacks such as:

* SQL Injection
* Cross-Site Scripting (XSS)
* Command Injection
* Local File Inclusion
* Remote File Inclusion
* HTTP protocol violations
* Request anomalies
* Other common application-layer attacks

In this lab, the CRS rules are used to detect attacks against DVWA.

---

# 5. Install ModSecurity

On the Ubuntu DVWA server, update the package repository:

```bash
sudo apt update
```

Install ModSecurity for Apache:

```bash
sudo apt install libapache2-mod-security2 -y
```

---

# 6. Enable ModSecurity in Apache

Enable the Apache ModSecurity module:

```bash
sudo a2enmod security2
```

Restart Apache:

```bash
sudo systemctl restart apache2
```

Verify that the module is loaded:

```bash
apache2ctl -M | grep security
```

Expected output:

```text
security2_module (shared)
```

This confirms that ModSecurity has been loaded into Apache.

---

# 7. ModSecurity Configuration

The main ModSecurity configuration directory is:

```text
/etc/modsecurity/
```

Important configuration files include:

```text
/etc/modsecurity/modsecurity.conf
/etc/modsecurity/modsecurity.conf-recommended
```

If the main configuration file does not exist, create it from the recommended configuration:

```bash
sudo cp /etc/modsecurity/modsecurity.conf-recommended \
/etc/modsecurity/modsecurity.conf
```

---

# 8. Configure ModSecurity Engine

Open the ModSecurity configuration:

```bash
sudo nano /etc/modsecurity/modsecurity.conf
```

Locate:

```apache
SecRuleEngine DetectionOnly
```

For active WAF protection, configure:

```apache
SecRuleEngine On
```

### ModSecurity Modes

`DetectionOnly`:

```apache
SecRuleEngine DetectionOnly
```

In this mode, ModSecurity evaluates requests and generates detection information without actively blocking them.

`On`:

```apache
SecRuleEngine On
```

In this mode, ModSecurity can actively enforce the configured security rules and block malicious requests.

For the attack simulation stage of this lab, the WAF is configured for active protection.

---

# 9. Install OWASP Core Rule Set

Install the OWASP CRS package:

```bash
sudo apt install modsecurity-crs -y
```

The CRS installation is located under:

```text
/usr/share/modsecurity-crs/
```

The CRS rules are available under:

```text
/usr/share/modsecurity-crs/rules/
```

Verify the installation:

```bash
ls /usr/share/modsecurity-crs/
```

Check the rule directory:

```bash
ls /usr/share/modsecurity-crs/rules/
```

The installation contains multiple CRS rule files responsible for detecting different categories of malicious activity.

---

# 10. CRS Configuration

The CRS setup configuration is located at:

```text
/usr/share/modsecurity-crs/crs-setup.conf
```

The individual CRS rules are located at:

```text
/usr/share/modsecurity-crs/rules/
```

The Apache ModSecurity configuration loads the CRS setup and rules so that incoming requests can be inspected against them.

A typical CRS structure is:

```text
/usr/share/modsecurity-crs/
│
├── crs-setup.conf
│
└── rules/
    ├── REQUEST-901-INITIALIZATION.conf
    ├── REQUEST-920-PROTOCOL-ENFORCEMENT.conf
    ├── REQUEST-941-APPLICATION-ATTACK-XSS.conf
    ├── REQUEST-942-APPLICATION-ATTACK-SQLI.conf
    └── ...
```

The exact files present depend on the installed CRS version.

---

# 11. ModSecurity Data Directory

ModSecurity requires a directory for runtime data.

Create the directory:

```bash
sudo mkdir -p /var/cache/modsecurity
```

The ModSecurity configuration uses:

```apache
SecDataDir /var/cache/modsecurity
```

This directory is separate from the WAF audit logs.

---

# 12. Configure WAF Audit Logging

Logging is an important part of this lab because the objective is not only to block attacks but also to investigate them.

The ModSecurity audit log was configured at:

```text
/var/log/apache2/modsec_audit.log
```

The relevant configuration used in the lab is:

```apache
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABDEFHIJZ
SecAuditLogType Serial
SecAuditLog /var/log/apache2/modsec_audit.log
```

### Configuration Explanation

#### Audit Engine

```apache
SecAuditEngine RelevantOnly
```

Records transactions considered relevant to the configured audit conditions.

#### Relevant HTTP Status Codes

```apache
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
```

Controls which HTTP response statuses are considered relevant for audit logging.

#### Audit Log Parts

```apache
SecAuditLogParts ABDEFHIJZ
```

Controls which sections of the transaction are stored in the audit log.

#### Audit Log Type

```apache
SecAuditLogType Serial
```

Uses a serial audit log.

#### Audit Log Location

```apache
SecAuditLog /var/log/apache2/modsec_audit.log
```

Stores the ModSecurity audit information in:

```text
/var/log/apache2/modsec_audit.log
```

---

# 13. Verify the ModSecurity Audit Log

Check whether the audit log exists:

```bash
sudo ls -lh /var/log/apache2/modsec_audit.log
```

The file should be created once ModSecurity begins generating relevant audit events.

To monitor the log in real time:

```bash
sudo tail -f /var/log/apache2/modsec_audit.log
```

This is particularly useful while performing attack simulations from Kali.

---

# 14. Apache Logs

The WAF investigation uses both Apache and ModSecurity logs.

### Apache Error Log

```text
/var/log/apache2/error.log
```

View it using:

```bash
sudo tail -f /var/log/apache2/error.log
```

This log can contain Apache and module-related messages.

### ModSecurity Audit Log

```text
/var/log/apache2/modsec_audit.log
```

View it using:

```bash
sudo tail -f /var/log/apache2/modsec_audit.log
```

This is the primary WAF audit log used during the attack investigation.

---

# 15. Apache Configuration Validation

After modifying Apache or ModSecurity configuration, validate the configuration before restarting Apache:

```bash
sudo apache2ctl configtest
```

Expected result:

```text
Syntax OK
```

If the configuration is valid, restart Apache:

```bash
sudo systemctl restart apache2
```

Check Apache status:

```bash
sudo systemctl status apache2
```

---

# 16. Verify ModSecurity

Confirm that Apache has loaded the ModSecurity module:

```bash
apache2ctl -M | grep security
```

Expected:

```text
security2_module (shared)
```

Validate the Apache configuration:

```bash
sudo apache2ctl configtest
```

Expected:

```text
Syntax OK
```

At this point, Apache should be running with ModSecurity enabled.

---

# 17. WAF Request Processing

When a request is sent from Kali to DVWA, it follows this process:

```text
              attacker
                  |
                  |
            HTTP Request
                  |
                  v
              Apache2
                  |
                  v
           ModSecurity
                  |
                  v
            OWASP CRS
                  |
                  v
          Rule Evaluation
                  |
          +-------+-------+
          |               |
       Normal          Suspicious
          |               |
          v               v
        DVWA        Rule Matches
                          |
                          v
                    Anomaly Score
                          |
                          v
                    Enforcement
                          |
                          v
                    Block / Log
```

The important point is that **DVWA is not the first component processing the request**.

The request is inspected by the WAF before being allowed to continue to the application.

---

# 18. Anomaly Scoring

OWASP CRS uses an anomaly-scoring approach.

A request can trigger one or multiple detection rules.

Conceptually:

```text
HTTP Request
     |
     v
+----------------+
| OWASP CRS      |
| Rule Matching  |
+----------------+
     |
     +---- Rule Match 1
     |
     +---- Rule Match 2
     |
     +---- Rule Match 3
              |
              v
       Anomaly Score
              |
              v
       Blocking Decision
```

This allows the CRS to evaluate the overall suspicious nature of a request rather than relying only on a single detection rule.

---

# 19. Testing Normal Traffic

Before testing attacks, verify that normal traffic is still reaching DVWA.

From Kali, access the DVWA application normally through the configured web server address.

The expected behavior is:

```text
Kali
  |
  v
Apache
  |
  v
ModSecurity
  |
  v
OWASP CRS
  |
  v
DVWA
```

Normal requests should not be unnecessarily blocked.

---

# 20. Testing Malicious Traffic

After confirming that normal traffic works, controlled attacks can be performed from the Kali attacker machine.

The attack simulations for this project include:

```text
SQL Injection
XSS
Command Injection
```

During each attack, multiple logs can be monitored.

### Terminal 1 — Apache Error Log

```bash
sudo tail -f /var/log/apache2/error.log
```

### Terminal 2 — ModSecurity Audit Log

```bash
sudo tail -f /var/log/apache2/modsec_audit.log
```

### Terminal 3 — Attack Execution

The attack is generated from the Kali Linux machine.

This allows the request, WAF detection, blocking behavior, and resulting logs to be observed together.

---

# 21. Example Investigation Flow

The investigation workflow used in this project is:

```text
1. Generate attack 
          |
          v
2. Request reaches Apache
          |
          v
3. ModSecurity inspects request
          |
          v
4. OWASP CRS evaluates request
          |
          v
5. Security rule is triggered
          |
          v
6. WAF takes configured action
          |
          v
7. Event is logged
          |
          v
8. Logs are collected
          |
          v
9. Splunk investigation
          |
          v
10. Detection / Dashboard
```

This transforms the lab from simply demonstrating a WAF into a **security monitoring and investigation workflow**.

---

# 22. Important Configuration and Log Locations

| Purpose                               | Location                                        |
| ------------------------------------- | ----------------------------------------------- |
| ModSecurity configuration             | `/etc/modsecurity/`                             |
| Main ModSecurity configuration        | `/etc/modsecurity/modsecurity.conf`             |
| ModSecurity recommended configuration | `/etc/modsecurity/modsecurity.conf-recommended` |
| ModSecurity runtime data              | `/var/cache/modsecurity/`                       |
| OWASP CRS                             | `/usr/share/modsecurity-crs/`                   |
| CRS setup                             | `/usr/share/modsecurity-crs/crs-setup.conf`     |
| CRS rules                             | `/usr/share/modsecurity-crs/rules/`             |
| Apache error log                      | `/var/log/apache2/error.log`                    |
| ModSecurity audit log                 | `/var/log/apache2/modsec_audit.log`             |

---

# 23. Troubleshooting

## Apache Does Not Start

Run:

```bash
sudo apache2ctl configtest
```

If there is a configuration error, Apache will report it.

Check the Apache error log:

```bash
sudo tail -f /var/log/apache2/error.log
```

---

## ModSecurity Module Not Loaded

Run:

```bash
apache2ctl -M | grep security
```

If no output is returned, enable the module:

```bash
sudo a2enmod security2
```

Then restart Apache:

```bash
sudo systemctl restart apache2
```

---

## CRS Rules Not Found

Check:

```bash
ls /usr/share/modsecurity-crs/
```

Then:

```bash
ls /usr/share/modsecurity-crs/rules/
```

If the CRS package is missing:

```bash
sudo apt install modsecurity-crs -y
```

---

## Audit Log Not Appearing

Check the configured log path:

```bash
sudo ls -lh /var/log/apache2/modsec_audit.log
```

Check the ModSecurity configuration:

```bash
sudo grep -E "SecAudit|SecRuleEngine|SecDataDir" /etc/modsecurity/modsecurity.conf
```

Validate Apache:

```bash
sudo apache2ctl configtest
```

Then restart:

```bash
sudo systemctl restart apache2
```

---

# 24. WAF Verification Checklist

Before moving to the attack simulation stage, verify the following:

* [ ] Ubuntu web server is running
* [ ] Apache2 is running
* [ ] DVWA is accessible
* [ ] ModSecurity is installed
* [ ] `security2_module` is loaded
* [ ] `SecRuleEngine` is configured for active protection
* [ ] OWASP CRS is installed
* [ ] CRS rule directory exists
* [ ] `/var/cache/modsecurity/` exists
* [ ] ModSecurity audit logging is configured
* [ ] `/var/log/apache2/modsec_audit.log` exists
* [ ] Apache configuration returns `Syntax OK`
* [ ] Normal requests reach DVWA
* [ ] WAF events can be observed in the logs

---


---

# 25. Outcome

The WAF layer has now been integrated into the DVWA home lab.


This setup provides the foundation for the next stage of the project, where controlled web attacks are performed from Kali and the resulting **ModSecurity detections, WAF logs, and SIEM events** are investigated.

## Next Stage

The next documentation file covers the attack simulations performed against DVWA, beginning with:

```text
SQL Injection
```

The attack documentation will correlate:

```text
Attack
  ↓
HTTP Request
  ↓
ModSecurity
  ↓
OWASP CRS Rule
  ↓
WAF Detection / Blocking
  ↓
ModSecurity Audit Log
  ↓
Splunk
  ↓
Investigation
```
