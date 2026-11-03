"""
PhishTrace - Email header analysis + threat-intel enrichment + risk scoring.

Usage:
    python phishtrace.py                  # emails/ folder scan karega
    python phishtrace.py path/to/folder   # koi bhi folder
    python phishtrace.py --offline        # koi API/network call nahi (sirf header analysis)
"""
import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import time
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

import requests

try:
    import whois
except ImportError:
    whois = None

# ---------------- Settings ----------------
CACHE_FILE = Path("cache.json")
SKIP_NAMES = {"cmds"}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_IN_TEXT = re.compile(r"[a-z0-9-]+\.(?:com|net|org|in|io|co|info|biz|xyz|ru|cn)\b", re.I)

RISKY_EXT = {".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".iso", ".img",
             ".lnk", ".html", ".htm", ".zip", ".rar", ".7z", ".docm",
             ".xlsm", ".jar", ".ps1", ".hta"}

CLOUD_WORDS = ["microsoft", "amazon", "google", "digitalocean", "ovh",
               "hetzner", "linode", "azure", "cloudflare", "oracle"]

FREE_DOMAINS = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
                "onmicrosoft.com", "live.com", "proton.me", "protonmail.com"}

URGENT_WORDS = ["urgent", "verify", "suspended", "suspend", "action required",
                "immediately", "confirm your", "unusual activity", "locked",
                "password expire", "final notice", "claim", "winner"]

SUSPICIOUS_AT = 3
PHISHING_AT = 6


# ---------------- .env + cache ----------------
def load_env(path=".env"):
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env()
VT_KEY = os.getenv("VT_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

cache = json.loads(CACHE_FILE.read_text(encoding="utf-8")) if CACHE_FILE.exists() else {}


def save_cache():
    CACHE_FILE.write_text(json.dumps(cache, indent=1), encoding="utf-8")


# ---------------- Header parsing ----------------
def domain_of(addr):
    _, a = parseaddr(addr or "")
    return a.split("@")[-1].lower().strip(">") if "@" in a else ""


def public_ips(received_list):
    """Received chain neeche se upar (neeche wali entry = original origin)."""
    ips = []
    for h in reversed(received_list):
        for ip in IP_RE.findall(h):
            try:
                if ipaddress.ip_address(ip).is_global and ip not in ips:
                    ips.append(ip)
            except ValueError:
                pass
    return ips


def auth_result(text, key):
    m = re.search(rf"\b{key}=(\w+)", text or "", re.I)
    return m.group(1).lower() if m else "missing"


def attachment_info(msg):
    names, hashes, risky = [], [], 0
    for part in msg.walk():
        fname = part.get_filename()
        if not fname:
            continue
        names.append(fname)
        try:
            payload = part.get_payload(decode=True) or b""
            hashes.append(hashlib.sha256(payload).hexdigest())
        except Exception:
            pass
        low = fname.lower()
        pieces = low.split(".")
        if Path(low).suffix in RISKY_EXT or (
                len(pieces) > 2 and "." + pieces[-1] in RISKY_EXT):
            risky = 1
    return names, hashes, risky


def parse_email(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    if not any(msg.get(h) for h in ("From", "Received", "Subject", "Message-ID")):
        return None  # email nahi hai

    received = [str(r) for r in msg.get_all("Received", [])]
    auth = str(msg.get("Authentication-Results", ""))
    recv_spf = str(msg.get("Received-SPF", ""))
    ips = public_ips(received)
    att_names, att_hashes, att_risky = attachment_info(msg)

    from_raw = str(msg.get("From", ""))
    display_name, _ = parseaddr(from_raw)
    from_d = domain_of(from_raw)
    rp_d = domain_of(str(msg.get("Return-Path", "")))
    reply_d = domain_of(str(msg.get("Reply-To", "")))

    spf = auth_result(auth, "spf")
    if spf == "missing" and recv_spf.strip():
        spf = recv_spf.split()[0].lower()

    # Display-name spoofing: naam me koi domain likha, jo asli sender domain se alag hai
    spoof = 0
    for d in DOMAIN_IN_TEXT.findall(display_name or ""):
        if d.lower() not in from_d:
            spoof = 1

    subject = str(msg.get("Subject", ""))
    urgent = int(any(w in subject.lower() for w in URGENT_WORDS))

    return {
        "file": path.name,
        "from": from_raw,
        "from_domain": from_d,
        "return_path_domain": rp_d,
        "reply_to_domain": reply_d,
        "subject": subject,
        "message_id": str(msg.get("Message-ID", "")),
        "spf": spf,
        "dkim": auth_result(auth, "dkim"),
        "dmarc": auth_result(auth, "dmarc"),
        "hop_count": len(received),
        "origin_ip": ips[0] if ips else "",
        "all_ips": ";".join(ips),
        "from_returnpath_mismatch": int(bool(from_d and rp_d and from_d != rp_d)),
        "from_replyto_mismatch": int(bool(from_d and reply_d and from_d != reply_d)),
        "display_name_spoof": spoof,
        "urgent_subject": urgent,
        "x_mailer": str(msg.get("X-Mailer", "")),
        "attachment_count": len(att_names),
        "attachment_names": ";".join(att_names),
        "attachment_sha256": ";".join(att_hashes),
        "has_risky_attachment": att_risky,
    }


# ---------------- Threat-intel enrichment ----------------
_last_vt_call = 0.0


def vt_get(path):
    """VirusTotal free tier = 4 requests/min, isliye har call ke beech ~16 sec."""
    global _last_vt_call
    wait = 16 - (time.time() - _last_vt_call)
    if wait > 0:
        time.sleep(wait)
    r = requests.get(f"https://www.virustotal.com/api/v3/{path}",
                     headers={"x-apikey": VT_KEY}, timeout=20)
    _last_vt_call = time.time()
    return r


def registered_domain(domain):
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def ip_intel(ip, offline):
    key = f"ip:{ip}"
    if isinstance(cache.get(key), dict):
        return cache[key]
    data = {"country": "", "org": "", "abuse_score": "", "abuse_reports": "", "vt_malicious": ""}
    if offline:
        return data

    try:
        j = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10).json()
        data["country"] = j.get("country", "")
        data["org"] = j.get("org", "")
    except Exception as e:
        print("   ipinfo error:", e)

    if ABUSEIPDB_KEY:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                             headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                             params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
            d = r.json()["data"]
            data["abuse_score"] = d.get("abuseConfidenceScore", 0)
            data["abuse_reports"] = d.get("totalReports", 0)
        except Exception as e:
            print("   abuseipdb error:", e)

    if VT_KEY:
        try:
            r = vt_get(f"ip_addresses/{ip}")
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            data["vt_malicious"] = stats.get("malicious", 0)
        except Exception as e:
            print("   virustotal ip error:", e)

    cache[key] = data
    save_cache()
    return data


def domain_intel(domain, offline):
    """Domain age (WHOIS) + VirusTotal domain reputation."""
    out = {"age_days": "", "vt_malicious": ""}
    if not domain:
        return out
    reg = registered_domain(domain)
    if reg in FREE_DOMAINS:
        out["age_days"] = "free_domain"
        return out

    key = f"dom:{reg}"
    if isinstance(cache.get(key), dict):
        return cache[key]
    if offline:
        return out

    if whois is not None:
        try:
            created = whois.whois(reg).creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                out["age_days"] = (datetime.now() - created.replace(tzinfo=None)).days
        except Exception:
            pass

    if VT_KEY:
        try:
            r = vt_get(f"domains/{reg}")
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            out["vt_malicious"] = stats.get("malicious", 0)
        except Exception as e:
            print("   virustotal domain error:", e)

    cache[key] = out
    save_cache()
    return out


def hash_intel(sha256, offline):
    key = f"hash:{sha256}"
    if key in cache:
        return cache[key]
    if offline or not VT_KEY:
        return "not_checked"
    result = "error"
    try:
        r = vt_get(f"files/{sha256}")
        if r.status_code == 404:
            result = "not_found"
        else:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            result = f"malicious={stats.get('malicious', 0)}"
    except Exception as e:
        print("   virustotal hash error:", e)
    cache[key] = result
    save_cache()
    return result


def enrich(row, offline):
    ip = ip_intel(row["origin_ip"], offline) if row["origin_ip"] else {}
    row["ip_country"] = ip.get("country", "")
    row["ip_org"] = ip.get("org", "")
    row["ip_is_cloud"] = int(any(w in row["ip_org"].lower() for w in CLOUD_WORDS))
    row["ip_abuse_score"] = ip.get("abuse_score", "")
    row["ip_abuse_reports"] = ip.get("abuse_reports", "")
    row["ip_vt_malicious"] = ip.get("vt_malicious", "")

    d = domain_intel(row["from_domain"], offline)
    row["from_domain_age_days"] = d.get("age_days", "")
    row["from_domain_vt_malicious"] = d.get("vt_malicious", "")

    hashes = [h for h in row["attachment_sha256"].split(";") if h]
    row["attachment_vt"] = ";".join(hash_intel(h, offline) for h in hashes)
    return row


# ---------------- Scoring ----------------
def num(v):
    try:
        return float(v)
    except (ValueError, TypeError):
        return None


def score_email(r):
    score, why = 0, []

    def add(points, reason):
        nonlocal score
        score += points
        why.append(f"{reason} (+{points})")

    spf, dkim, dmarc = r["spf"], r["dkim"], r["dmarc"]

    # --- Authentication ---
    if spf in ("fail", "softfail"):
        add(3, "SPF fail")
    elif spf in ("none", "temperror", "permerror"):
        add(1, "SPF none/error")
    if dkim == "fail":
        add(2, "DKIM fail")
    elif dkim == "none":
        add(1, "DKIM none")
    if dmarc in ("none", "permerror", "fail"):
        add(2, "DMARC none/fail")

    # --- Sender identity ---
    if r["from_domain_age_days"] == "free_domain":
        add(2, "Free/shared-tenant sender domain")
    age = num(r["from_domain_age_days"])
    if age is not None:
        if age < 30:
            add(3, "Very new domain (<30 days)")
        elif age < 90:
            add(2, "New domain (<90 days)")
    if r["from_replyto_mismatch"] == 1:
        add(1, "From/Reply-To mismatch")
    if r["display_name_spoof"] == 1:
        add(2, "Display-name spoofing")
    if r["urgent_subject"] == 1:
        add(1, "Urgency keywords in subject")

    # --- Infrastructure ---
    if r["ip_is_cloud"] == 1 and spf in ("fail", "softfail"):
        add(1, "Cloud IP + SPF fail")

    # --- Attachments ---
    if r["has_risky_attachment"] == 1:
        add(3, "Risky attachment type")
    for part in str(r["attachment_vt"]).split(";"):
        if part.startswith("malicious="):
            n = num(part.split("=")[1])
            if n and n > 0:
                add(5, "Attachment hash flagged malicious on VirusTotal")
                break

    # --- Threat intel (API keys ke saath) ---
    ab = num(r["ip_abuse_score"])
    if ab is not None:
        if ab >= 25:
            add(3, f"AbuseIPDB confidence {int(ab)}%")
        elif ab > 0:
            add(1, f"AbuseIPDB confidence {int(ab)}%")
    vt_ip = num(r["ip_vt_malicious"])
    if vt_ip and vt_ip > 0:
        add(3, f"Sender IP flagged by {int(vt_ip)} VirusTotal engines")
    vt_dom = num(r["from_domain_vt_malicious"])
    if vt_dom and vt_dom > 0:
        add(3, f"Sender domain flagged by {int(vt_dom)} VirusTotal engines")

    return score, why


def verdict(score):
    if score >= PHISHING_AT:
        return "PHISHING"
    if score >= SUSPICIOUS_AT:
        return "SUSPICIOUS"
    return "LEGIT"


# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description="PhishTrace - email header analysis & scoring")
    ap.add_argument("folder", nargs="?", default="emails", help="emails ka folder (default: emails)")
    ap.add_argument("--output", default="results.csv")
    ap.add_argument("--offline", action="store_true", help="koi API/network call nahi")
    args = ap.parse_args()

    folder = Path(args.folder)
    if not folder.exists():
        print(f"Folder nahi mila: {folder.resolve()}")
        return

    print("VirusTotal key :", "ON" if VT_KEY else "OFF")
    print("AbuseIPDB key  :", "ON" if ABUSEIPDB_KEY else "OFF")
    print("Mode           :", "OFFLINE" if args.offline else "ONLINE", "\n")

    files = [f for f in sorted(folder.rglob("*")) if f.is_file() and f.name not in SKIP_NAMES]
    rows, skipped = [], 0

    for i, f in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {f.name}")
        try:
            row = parse_email(f)
        except Exception as e:
            print("   FAILED:", e)
            continue
        if row is None:
            skipped += 1
            print("   SKIPPED (email nahi hai)")
            continue

        row = enrich(row, args.offline)
        s, why = score_email(row)
        row["score"] = s
        row["verdict"] = verdict(s)
        row["reasons"] = "; ".join(why)
        rows.append(row)
        print(f"   -> {row['verdict']} (score {s})")

    if not rows:
        print("Koi email parse nahi hui. Folder check karo.")
        return

    first = ["file", "verdict", "score", "reasons"]
    cols = first + [c for c in rows[0].keys() if c not in first]
    with open(args.output, "w", newline="", encoding="utf-8-sig") as out:
        w = csv.DictWriter(out, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    counts = {"LEGIT": 0, "SUSPICIOUS": 0, "PHISHING": 0}
    for r in rows:
        counts[r["verdict"]] += 1

    print("\n================ SUMMARY ================")
    print(f"Emails analysed : {len(rows)}   (skipped: {skipped})")
    for k, v in counts.items():
        print(f"{k:<11}: {v}")
    print(f"Report saved    : {args.output}")
    print("\nTop risky emails:")
    for r in sorted(rows, key=lambda x: x["score"], reverse=True)[:5]:
        print(f"  {r['score']:>2}  {r['verdict']:<10} {r['file'][:35]}")
        print(f"      {r['reasons'] or 'no red flags'}")


if __name__ == "__main__":
    main()
