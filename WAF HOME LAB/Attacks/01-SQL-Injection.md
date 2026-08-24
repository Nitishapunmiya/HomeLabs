# 01 — SQL Injection Attack Simulation

## 1. Overview

This stage demonstrates a controlled **SQL Injection (SQLi)** attack against the DVWA application running behind the ModSecurity Web Application Firewall.

The attack is performed from the **windows machine** against the **DVWA application hosted on Ubuntu**.




```

---

# 2. Lab Environment

| Component                  | Role                          |
| -------------------------- | ----------------------------- |
| kali                       | Web server + WAF              |
| Apache2                    | Web server                    |
| DVWA                       | Vulnerable web application    |
| ModSecurity                | Web Application Firewall      |
| OWASP CRS                  | Attack detection rules        |
| Splunk Universal Forwarder | Log forwarding                |
| Splunk                     | SIEM / investigation platform |

---

# 3. Attack Objective

The objective of this simulation is to determine whether the WAF can identify and respond to a SQL Injection attempt against DVWA.

The investigation focuses on:

* The attacker source
* The targeted DVWA endpoint
* The SQL Injection payload
* ModSecurity inspection
* OWASP CRS rule matching
* WAF response
* ModSecurity audit logging
* Splunk ingestion
* Security investigation

---

# 4. What is SQL Injection?

SQL Injection is a web application attack in which an attacker attempts to manipulate an application's database query by supplying specially crafted input.

A vulnerable application may construct a database query using user-controlled input.

Conceptually:

```text
User Input
    |
    v
Application
    |
    v
SQL Query
    |
    v
Database
```

If the application does not properly validate or parameterize the input, attacker-controlled data may alter the intended SQL query.

In this lab, DVWA intentionally contains vulnerable functionality so that SQL Injection can be safely demonstrated.

---

# 5. Attack Flow

The attack flow in this lab is:

```text
Kali Linux
     |
     | Malicious SQL Input
     v
DVWA Endpoint
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
     +--------> SQLi Detection
     |
     v
WAF Decision
     |
     +--------> Block
     |
     +--------> Log
     |
     v
Splunk
```

---

# 6. Pre-Attack Verification

Before performing the attack, verify that the DVWA application is accessible.

From windows, open the DVWA URL in a browser.


Also verify that ModSecurity is running on kali:

```bash
apache2ctl -M | grep security
```

Expected:

```text
security2_module (shared)
```

Verify the Apache configuration:

```bash
sudo apache2ctl configtest
```

Expected:

```text
Syntax OK
```

---

# 7. Monitor the WAF Logs

Before generating the attack, open a terminal on the Ubuntu WAF server.

Monitor the ModSecurity audit log:

```bash
sudo tail -f /var/log/apache2/modsec_audit.log
```

Also monitor the Apache error log if required:

```bash
sudo tail -f /var/log/apache2/error.log
```

Keeping the log open during the attack makes it possible to correlate the attack request with the WAF event.

---

# 8. Perform the SQL Injection Test

Navigate to the SQL Injection functionality in DVWA.

The exact URL depends on the DVWA installation and configuration.

The SQL Injection functionality is available under the DVWA vulnerabilities section.

Use a controlled SQL Injection test input against the vulnerable parameter.

For example, a basic SQL Injection test may use an input containing SQL syntax such as:

```text
' OR '1'='1
```

The purpose of this test is not to compromise a real system.

It is to generate controlled malicious traffic against the intentionally vulnerable DVWA application and observe how the WAF responds.

> **Important:** Perform this test only against the lab environment you control.

---

# 9. Observe the Application Response

After submitting the test input, observe the response from DVWA.

Depending on the current ModSecurity and CRS configuration, the request may be:

```text
Allowed
```

or:

```text
Blocked
```

The important part of this exercise is to determine what the WAF actually detected and what action it took.

Do not assume that every SQL Injection payload will produce the same response.

The result should be verified using:

* Browser response
* ModSecurity audit log
* Apache logs
* Splunk event

---

# 10. Inspect the ModSecurity Audit Log

On kali

```bash
sudo tail -f /var/log/apache2/modsec_audit.log
```

Alternatively, inspect the latest entries:

```bash
sudo tail -n 100 /var/log/apache2/modsec_audit.log
```

Search for SQL-related information:

```bash
sudo grep -i "sql" /var/log/apache2/modsec_audit.log
```

You can also search for ModSecurity-related entries:

```bash
sudo grep -i "modsecurity" /var/log/apache2/modsec_audit.log
```

The exact output depends on the request and the CRS version installed in the lab.

---

# 11. Information to Extract From the WAF Event

A ModSecurity event should be examined for the following information:

| Information        | Purpose                                    |
| ------------------ | ------------------------------------------ |
| Timestamp          | When the attack occurred                   |
| Source IP          | Where the request originated               |
| HTTP Method        | GET / POST etc.                            |
| Request URI        | Targeted application endpoint              |
| Request Parameters | Input supplied by attacker                 |
| Rule ID            | CRS rule that matched                      |
| Rule Message       | Why the request was considered suspicious  |
| Severity           | Importance of the detection                |
| Anomaly Score      | Overall suspicious score                   |
| HTTP Status        | Result of the request                      |
| Action             | Whether the request was allowed or blocked |

The exact field names and structure depend on how the audit log is parsed.

---

# 12. Identify the CRS Rule

OWASP CRS contains rules specifically designed to detect SQL Injection.

SQL Injection-related rules are located in the CRS application attack SQLi rule file:

```text
/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
```

Check the installed file:

```bash
ls /usr/share/modsecurity-crs/rules/ | grep 942
```

The exact rule ID triggered by the test should be obtained from the actual ModSecurity event.

Do **not** assume that one specific rule ID is always triggered.

The investigation should record the rule that actually appeared in the WAF log.

---

# 13. Determine the WAF Action

The next step is to determine what ModSecurity did with the request.

Possible outcomes include:

```text
Detection
```

or:

```text
Block / Reject
```

The result should be confirmed from the actual ModSecurity event and HTTP response.

The investigation question is:

> Did the WAF only detect the SQL Injection attempt, or did it actively prevent the request from reaching the application?

---

# 14. Verify the Event in Splunk

Once the Universal Forwarder has forwarded the WAF log, open:

```text
Splunk → Search & Reporting
```

Start with a search for the WAF audit log:

```spl
index=* source="/var/log/apache2/modsec_audit.log"
```

If the source path is different in your Splunk configuration, use the actual `source` shown by the event.

---

# 15. Search for SQL Injection Activity

A useful initial search is:

```spl
index=* source="/var/log/apache2/modsec_audit.log"
("SQL" OR "SQLi")
```

Another search can look for SQL Injection CRS rule references:

```spl
index=* source="/var/log/apache2/modsec_audit.log"
"942"
```

These searches are starting points.

The actual event should always be inspected before concluding that a specific rule detected the attack.

---

# 16. Identify the Attacker

Once the SQL Injection event is located in Splunk, identify the source IP.

Depending on field extraction, this may appear as:

```text
src_ip
```

or another field containing the client address.

If the field is not automatically extracted, inspect the raw event.

The investigation question is:

```text
Who generated the malicious request?
```

---

# 17. Identify the Target

Determine the DVWA endpoint targeted by the attacker.

Look for fields such as:

```text
uri
path
url
request
```

The target should be recorded in the investigation.

For example:

```text
Target:
DVWA SQL Injection endpoint
```

Use the actual URI observed in the event rather than inserting a guessed value.

---

# 18. Identify the Attack Payload

Inspect the raw ModSecurity event for the input submitted to the application.

The payload is important because it provides evidence of the attacker's intent.

For this controlled test, the payload contains SQL Injection syntax.

The investigation should record:

```text
Attack Type:
SQL Injection

Payload:
[Observed payload from the WAF event]
```

Do not rely only on the browser URL. The raw WAF event should be used as the authoritative evidence.

---

# 19. Identify the Detection Rule

Find the rule information inside the ModSecurity event.

Record:

```text
Rule ID:
[Actual rule ID from event]

Rule Message:
[Actual message from event]

Severity:
[Actual severity from event]
```

This information demonstrates that the WAF did not simply return an error; it identified the request using a security rule.

---

# 20. Identify the Anomaly Score

OWASP CRS uses anomaly scoring to evaluate suspicious activity.

Inspect the WAF event for anomaly-score information.

Conceptually:

```text
SQL Injection Request
        |
        v
CRS Rule Match
        |
        v
Anomaly Score
        |
        v
Blocking Threshold
        |
        v
WAF Decision
```

Record the actual score from the event if it is available.

---

# 21. Determine the HTTP Response

Check the response status associated with the event.

The response can help determine what happened after the WAF evaluated the request.

For example:

```text
HTTP 200
HTTP 403
```

may indicate very different outcomes.

Do not assume a `403` or `200` response without checking the actual event.

Record:

```text
HTTP Status:
[Observed status]
```

---

# 22. Splunk Investigation Query — Source IP

Once the correct source-IP field has been identified, events from the attacker can be investigated using:

```spl
index=* source="/var/log/apache2/modsec_audit.log"
| stats count by src_ip
| sort - count
```

If `src_ip` is not available as an extracted field, use the field identified from the actual event.

---

# 23. Splunk Investigation Query — Events Over Time

To visualize WAF activity over time:

```spl
index=* source="/var/log/apache2/modsec_audit.log"
| timechart count
```

This helps determine whether the SQL Injection attempt was:

* A single event
* Part of repeated activity
* Part of a larger attack sequence

---

# 24. Splunk Investigation Query — Top Targeted URIs

If the URI is extracted:

```spl
index=* source="/var/log/apache2/modsec_audit.log"
| stats count by uri
| sort - count
| head 10
```

This helps identify which application endpoints are being targeted most frequently.

---

# 25. Splunk Investigation Query — SQL Injection Events

A basic SQL Injection search:

```spl
index=* source="/var/log/apache2/modsec_audit.log"
("SQL" OR "SQLi")
```

If the actual CRS rule ID has been identified, the search can be made more precise.

For example:

```spl
index=* source="/var/log/apache2/modsec_audit.log"
"ACTUAL_RULE_ID"
```

Replace `ACTUAL_RULE_ID` with the rule ID observed in the real WAF event.

---

# 26. Correlate the Attack

The SQL Injection event should be correlated using multiple pieces of evidence.

This produces a complete picture of the attack.

---

# 27. SOC Investigation Perspective

From a SOC analyst perspective, the event can be investigated using the following questions:

### What happened?

A SQL Injection attempt was made against the DVWA application.

### Who performed it?

Identify the source IP from the WAF event.

### What was targeted?

Identify the DVWA endpoint and parameter.

### How was it detected?

ModSecurity inspected the request and OWASP CRS matched the malicious input.

### Which rule detected it?

Identify the actual CRS rule ID from the event.

### Was it blocked?

Confirm the WAF action and HTTP response.

### Was there repeated activity?

Search Splunk for additional events from the same source IP.

### Was there evidence of successful exploitation?

Correlate the WAF event with the application and server logs.

---


# 28. Result

The SQL Injection simulation demonstrates the complete WAF monitoring pipeline.

The request generated from windows was inspected by the web application security stack:

The resulting WAF event was then made available for centralized analysis through:



# 29. Key Learning Outcomes

This exercise demonstrates:

* How SQL Injection appears at the HTTP layer
* How ModSecurity inspects web requests
* How OWASP CRS detects SQL Injection patterns
* How WAF decisions are logged
* How WAF logs are forwarded to a SIEM
* How Splunk can be used to investigate WAF events
* How to identify attack source and target
* How to correlate timestamps and security events
* How a SOC analyst can investigate a web attack

---
