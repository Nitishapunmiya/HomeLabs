# PhishTrace

PhishTrace is a Python tool that analyses raw `.eml` email files for phishing indicators. It extracts email headers, enriches the sender's IP, domain and attachment hashes with threat-intelligence sources, and produces an explainable risk score (Legit / Suspicious / Phishing) with the reasons behind it.

No labels are needed. Point it at any folder of emails and it returns a verdict for each one.

## How it works

```
emails/*.eml  ->  1. Header extraction  ->  2. Threat-intel enrichment  ->  3. Risk scoring  ->  results.csv
```

1. **Header extraction**: From, Return-Path, Reply-To, Message-ID, SPF/DKIM/DMARC results, Received chain (origin IP read bottom-up), attachment names and SHA-256 hashes.
2. **Enrichment**:
   - IP: country, ASN/organisation, cloud-provider check (ipinfo), abuse score (AbuseIPDB), reputation (VirusTotal)
   - Domain: age (WHOIS), reputation (VirusTotal)
   - Attachments: SHA-256 hash lookup on VirusTotal (the file is never opened or uploaded)
3. **Scoring**: every red flag adds points and the reason is recorded.

## Scoring

| Signal | Points |
|---|---|
| SPF fail / softfail | +3 |
| SPF none / error | +1 |
| DKIM fail | +2 |
| DKIM none | +1 |
| DMARC none / fail / permerror | +2 |
| Free or shared-tenant sender domain (gmail, onmicrosoft...) | +2 |
| Sender domain younger than 30 days | +3 |
| Sender domain younger than 90 days | +2 |
| From vs Reply-To domain mismatch | +1 |
| Display-name spoofing | +2 |
| Urgency keywords in subject | +1 |
| Cloud-provider IP with SPF fail | +1 |
| Risky attachment type (.exe, .js, .iso, .zip...) | +3 |
| Attachment hash flagged on VirusTotal | +5 |
| AbuseIPDB confidence >= 25% | +3 |
| AbuseIPDB confidence 1-24% | +1 |
| Sender IP flagged on VirusTotal | +3 |
| Sender domain flagged on VirusTotal | +3 |

**Verdict:** 0-2 = LEGIT, 3-5 = SUSPICIOUS, 6+ = PHISHING

## Installation

```bash
git clone https://github.com/[your-username]/PhishTrace.git
cd PhishTrace
pip install -r requirements.txt
```

### API keys (optional)

PhishTrace works without any keys (header analysis, ipinfo, WHOIS). For VirusTotal and AbuseIPDB enrichment, copy `.env.example` to `.env` and add your free keys:

```
VT_KEY=your_virustotal_key_here
ABUSEIPDB_KEY=your_abuseipdb_key_here
```

## Usage

```bash
python phishtrace.py                  # analyse the emails/ folder
python phishtrace.py path/to/folder   # analyse any folder
python phishtrace.py --offline        # header analysis only, no network calls
```

Output is saved to `results.csv` (verdict, score, reasons, and all extracted fields). Results are cached in `cache.json` so repeated IPs and domains are not queried again.

## Sample output

<img width="1495" height="631" alt="readme" src="https://github.com/user-attachments/assets/91d5cd5c-1964-4442-b1bb-1ee1886ae0b0" />

## Findings


- Phishing samples I looked at often came from Google or Microsoft infrastructure, so IP reputation alone showed them as clean.
- Missing or failing SPF/DMARC and free-tenant sender domains were the strongest signals.
- DKIM pass does not mean an email is trustworthy, since attackers can send from properly signed accounts.

## Limitations

- Scoring is rule-based and the weights are hand-tuned, not machine-learned.
- Header-only analysis can miss phishing sent from properly authenticated infrastructure. Body and URL analysis is the next step.
- Legitimate bulk mail (newsletters, mailing lists) can trigger false positives.
- Free API tiers are rate limited (VirusTotal: 4 requests/minute), so large batches are slow.
- Tested on a small sample set only. Not a production detector.

## Future work

- URL and body extraction with reputation checks
- Display-name and lookalike-domain detection
- Evaluation on a larger labelled dataset
- HTML report output

## Safety

Phishing emails can contain live links and malicious attachments. PhishTrace only parses headers and computes attachment hashes, it never opens attachments. Run it on untrusted samples inside a VM if possible.

## Disclaimer

For educational and research use.
