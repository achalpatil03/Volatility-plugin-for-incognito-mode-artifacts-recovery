# Volatility-plugin-for-incognito-mode-artifacts-recovery
A Volatility3 plugin for Windows memory forensics that detects active Chrome Incognito sessions and extracts browsing artifacts directly from RAM dumps — without touching the disk.

Compatibility: Windows 10 only.
Volatility3 requires kernel symbol tables (ISF files) to parse Windows memory. These symbol packs do not currently exist for Windows 11, so this plugin will not work on Windows 11 memory dumps.

What It Does
Chrome Incognito leaves no history, cookies, or cache on disk — but everything is still present in RAM while the session is active. This plugin:

Detects the incognito session by scanning the Chrome browser process heap for OTR (Off-The-Record) profile markers (OTRProfile, off_the_record, kIncognito, etc.)
Identifies incognito renderer processes by differentiating them from normal tab renderers (incognito renderers have no --profile-directory flag)
Extracts artifacts from the memory of those renderer processes
Extracted Artifacts
Type	Examples
URLs	Visited pages, navigation history
Search Queries	Google, Bing search terms
Form Fields	Login fields, phone numbers, submitted data
Credentials	Passwords, API keys, Bearer tokens, JWTs
OAuth Tokens	Google OAuth, GitHub PAT, AWS keys, Slack tokens
Cookies	Session cookies, auth cookies
Exfiltration	Telegram bot exfil, Discord webhooks, cloud uploads, WebSocket C2
Phishing	BlobPhish pages, AiTM/Evilginx2 proxy domains, inline data URIs
IP Recon	Shodan, VirusTotal, ipinfo lookups
Installation
Install Volatility3
Clone or download this plugin
Place the files inside your Volatility3 directory:

volatility3/

        └── incognito_scanner/
            ├── __init__.py
            ├── artifact.py
            └── plugin.py

Usage
Basic scan:


python vol.py -f memory.mem windows.incognito_scanner
With IOC keyword matching:


python vol.py -f memory.mem windows.incognito_scanner --keywords "bitcoin,wallet,onion"
With threat intelligence enrichment (VirusTotal + AbuseIPDB):


python vol.py -f memory.mem windows.incognito_scanner --enrich --vt-key YOUR_VT_KEY --aipdb-key YOUR_AIPDB_KEY
Disable timeline reconstruction:


python vol.py -f memory.mem windows.incognito_scanner --timeline false
Output
The plugin automatically exports three report files to the current directory on every run:

incognito_<timestamp>.json — machine-readable full report
incognito_<timestamp>.csv — spreadsheet-compatible
incognito_<timestamp>.html — styled forensic report with threat intel badges
Results are also printed to the terminal as a prioritized table (credentials and active exfiltration channels first).

Options
Flag	Description
--keywords	Comma-separated keywords/IOCs to match against all artifacts
--timeline	Enable/disable timeline reconstruction (default: enabled)
--enrich	Query threat intel APIs for extracted URLs and IPs
--vt-key	VirusTotal API key (free tier: 500 lookups/day)
--pt-key	PhishTank application key (optional)
--aipdb-key	AbuseIPDB API key (free tier: 1000 checks/day)
Requirements
Python 3.8+
Volatility3
A Windows 10 memory dump (.mem, .vmem, .raw)
For VMware dumps: include the .vmss file alongside the .vmem
Limitations
Windows 11 is not supported — Volatility3 symbol tables do not yet cover Windows 11 kernel builds
Chrome must have been running in Incognito mode at the time the dump was taken — closed tabs will not appear
If the Chrome heap was paged out to disk at dump time, OTR marker detection may fall back to process tree analysis
