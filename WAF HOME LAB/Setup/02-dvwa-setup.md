# DVWA Setup

## Overview

Damn Vulnerable Web Application (DVWA) was used as the intentionally vulnerable web application for the WAF homelab.

The purpose of using DVWA was to create a controlled environment where common web attacks could be performed and then analyzed through ModSecurity, OWASP CRS, and Splunk.

DVWA was hosted on the Kali Linux machine.

## Web Application Stack

The DVWA environment used:

- Apache
- PHP
- MariaDB
- DVWA

Apache was used to serve the application, PHP was used to execute the application code, and MariaDB was used as the database backend.

## Apache Configuration

Apache was installed and configured on the Kali Linux machine to host DVWA.

After installation, Apache was started and tested to verify that the web server was functioning correctly.

The application was made available through the Kali machine's internal network address.

The web server used HTTP port `80`.

## PHP Configuration

DVWA requires PHP to execute its server-side application code.

PHP was installed and configured to work with Apache.

The PHP environment was tested by accessing DVWA and verifying that PHP pages were being processed correctly instead of being returned as plain text.

## MariaDB Configuration

MariaDB was configured as the database server for DVWA.

A database and corresponding database user were configured for the DVWA application.

The database connection was then configured in DVWA so that the application could communicate with MariaDB.

## DVWA Installation

After Apache, PHP, and MariaDB were configured, DVWA was installed on the Kali web server.

The DVWA application was placed in the Apache web directory and accessed through the browser.

The DVWA setup page was then used to initialize the application database.

## Database Initialization

The DVWA setup page was used to create and initialize the required database tables.

Once the database setup completed successfully, the DVWA application could be accessed normally.

This confirmed that the Apache, PHP, MariaDB, and DVWA components were working together.

## Verifying the Application

Before configuring the WAF, DVWA was tested to establish a working baseline.

The following were verified:

- Apache was running.
- DVWA was accessible through the browser.
- PHP was executing correctly.
- MariaDB was connected to DVWA.
- DVWA vulnerability modules were accessible.
- Normal HTTP requests reached the application.

Establishing this baseline was important because it allowed normal application traffic to be compared with malicious requests after the WAF was introduced.

## DVWA Vulnerability Modules

DVWA contains several intentionally vulnerable modules.

For this project, the following three modules were used for attack testing:

### SQL Injection

The SQL Injection module was used to test whether malicious SQL syntax in request parameters could be detected and blocked by ModSecurity and OWASP CRS.

A normal request such as:

`/DVWA/vulnerabilities/sqli/index.php?id=2`

was also tested.

A normal numeric value such as `2` is not automatically a SQL Injection attack.

### Cross-Site Scripting (XSS)

The XSS functionality in DVWA was used to generate malicious script input and observe how the WAF handled the request.

### Command Injection

The Command Injection functionality was used to test whether command-execution patterns could be detected by the WAF.

## Establishing the Baseline

The application was tested normally before attack testing began.

This was important because the project was focused on detecting malicious traffic rather than simply generating traffic.

For example, accessing a DVWA page with a normal parameter allowed us to confirm that the application was functioning before ModSecurity was introduced.

## Result

At the end of the DVWA setup stage:

- Kali Linux was hosting the application.
- Apache was serving DVWA.
- PHP was processing the application.
- MariaDB was providing the database backend.
- DVWA was accessible.
- The vulnerability modules were available for testing.
- A normal application baseline had been established.

The environment was then ready for the next stage: installing and configuring ModSecurity and the OWASP Core Rule Set as the WAF layer.
