# SSH Brute-Force Detection — Splunk Home Lab

I built a small home lab to simulate an SSH brute-force attack against a Linux
target and investigate it in Splunk — attack → logs → SIEM → detection.

---

## Lab Architecture

```
WSL (Ubuntu)   ← attacker
        |
        | nmap recon + repeated SSH login attempts 
        ↓
Kali Linux                  ← victim / SSH target
        |
        | authentication events
        ↓
Splunk Enterprise (Windows host)                 ← SIEM
        |
        ↓
SPL search / investigation
```

I only had 4 GB of RAM to work with, so instead of running two full VMs I
used WSL on my Windows laptop as the attacker and a single Kali Linux VM as
the victim. Splunk Enterprise ran on the Windows host itself.

> **Note:** the attacker shell (WSL) and the Splunk instance both run on the
> same physical laptop  — the "attacker" and "SIEM" are
> logically separate but physically the same machine in this lab.

**Target:** `192.168.1.202` (Kali Linux)
**Attacker source IP seen in logs:** `192.168.1.173`

---

## Step 1: Reconnaissance

Before attempting authentication, I ran an `nmap` service scan against the
target to confirm SSH was open and identify the service version.

```bash
nmap -sV 192.168.1.202
```

**Result:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 5 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This confirmed port 22 was open and running OpenSSH 10.0p2 on Debian
(Kali's underlying base), giving a clear target for the SSH attempts.

---

## Step 2: SSH Authentication Attempts

From the WSL shell, I ran repeated `ssh kali@192.168.1.202` connections:

```
root@LAPTOP/# ssh kali@192.168.1.202
kali@192.168.1.202's password:
Permission denied, please try again.
kali@192.168.1.202's password:
Permission denied, please try again.
kali@192.168.1.202's password:
kali@192.168.1.202: Permission denied (publickey,password).
```

This pattern (three password prompts, then rejection) repeated for two
separate connection attempts, and a third connection eventually succeeded:

```



Each SSH client invocation defaults to 3 password attempts before dropping
the connection — visible directly in the terminal output above and
confirmed later in Splunk (see the per-port breakdown below).

---

## Detection in Splunk

### Query 1 — Failed password attempts

```spl
index=* event="Failed password"
| table timestamp, src_ip, event, port
```

**Result:** 6 events, time range 7/30/26 8:30 PM – 7/31/26 9:27 PM (search
window; actual event timestamps below), all from `src_ip=192.168.1.173`.

| Timestamp | src_ip | event | port |
|---|---|---|---|
| 2026-07-31T11:37:23.764083-04:00 | 192.168.1.173 | Failed password | 64114 |
| 2026-07-31T11:37:29.725047-04:00 | 192.168.1.173 | Failed password | 64114 |
| 2026-07-31T11:37:35.897993-04:00 | 192.168.1.173 | Failed password | 64114 |
| 2026-07-31T11:39:27.485299-04:00 | 192.168.1.173 | Failed password | 64090 |
| 2026-07-31T11:39:33.142668-04:00 | 192.168.1.173 | Failed password | 64090 |
| 2026-07-31T11:39:37.503949-04:00 | 192.168.1.173 | Failed password | 64090 |

### Query 2 — Accepted password events

```spl
index=* event="Accepted password"
| table timestamp, src_ip, event, port
```

**Result:** 2 events, same source IP.

| Timestamp | src_ip | event | port |
|---|---|---|---|
| 2026-07-31T11:36:59.522383-04:00 | 192.168.1.173 | Accepted password | 64080 |
| 2026-07-31T11:39:53.905106-04:00 | 192.168.1.173 | Accepted password | 64154 |

> **To verify / not shown in screenshots:** the exact method used to extract
> the `event`, `src_ip`, and `port` fields (e.g. a `rex` in-search extraction
> vs. a `props.conf`/`transforms.conf` field extraction) isn't captured here
> — worth documenting separately if you want the full pipeline shown.

### Correlating failed vs. accepted

Splunk's own `_source_port` (`port`) field makes it possible to line up
each SSH connection attempt end-to-end:

| Port | Outcome | Attempts | Notes |
|---|---|---|---|
| 64080 | Accepted | 1 | Correct password on first try |
| 64114 | Failed only | 3 | All 3 attempts rejected, connection dropped |
| 64090 | Failed only | 3 | All 3 attempts rejected, connection dropped |
| 64154 | Accepted | 1 | Correct password on first try |

Each source port corresponds to a distinct SSH connection. Two connections
(64114, 64090) failed all three password attempts and were dropped; two
other connections (64080, 64154) authenticated successfully on the first
attempt. This is exactly the kind of pivot a SOC analyst uses in practice —
group by source port (or session ID) to reconstruct what happened within
each individual connection, rather than just counting failures in
isolation.

---

## MITRE ATT&CK Mapping

| Technique | ID | Notes |
|---|---|---|
| Network Service Discovery | T1046 | `nmap -sV` recon against the target before the attack |
| Brute Force | T1110 | Repeated SSH authentication attempts |
| Password Guessing | T1110.001 | Attempts used direct password guesses rather than a credential-stuffing list |

---

## Not Yet Captured (to add once screenshots are available)

- Splunk Universal Forwarder installation/configuration on Kali
- Splunk receiver (port 9997) configuration on the Windows host
- A dashboard visualizing this activity (failed/accepted over time, by port, etc.)
- A saved alert with a failed-attempt threshold
- Username-targeting analysis (all observed attempts used the `kali` account)
- Confirmation of how many total password attempts were scripted vs. manual

---

## Key Takeaways

- SIEMs don't detect the attack directly — they detect the **artifacts** an
  attack leaves behind (in this case, `Failed password` / `Accepted
  password` events).
- Grouping by a connection identifier (source port, in this case) turns a
  flat list of auth events into a reconstructed session timeline.
- Confirming whether failed attempts were followed by a successful login is
  the single most important pivot in a brute-force investigation — a
  string of failures that ends in `Accepted` means the account may be
  compromised, not just probed.

---


