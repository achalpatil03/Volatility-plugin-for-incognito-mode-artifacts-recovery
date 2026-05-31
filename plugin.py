import base64
import csv
import datetime
import hashlib
import html
import json
import logging
import os
import re
import time
import urllib.parse
import urllib.request
from typing import Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows.incognito_scanner.artifact import Artifact

vollog = logging.getLogger(__name__)


class IncognitoScanner(interfaces.plugins.PluginInterface):

    _required_framework_version = (2, 0, 0)

    # OTR markers written to browser heap when incognito is active
    INCOGNITO_MARKERS = [
        b"OTRProfile",
        b"IncognitoProfile",
        b"off_the_record",
        b"is_off_the_record",
        b"kIncognito",
        b"INCOGNITO_AND_GUEST",
        b"CreateOffTheRecordProfile",
        b"kOTRProfileID",
    ]

    # Profile path strings found in normal tab renderers — absent in incognito
    NORMAL_MARKERS = [
        b"\\Default\\History",
        b"\\Default\\Cookies",
        b"User Data\\Default",
        b"--profile-directory",
    ]

    # Heap strings unique to GPU/network/crashpad/audio processes — used to exclude them
    _NON_RENDERER_MARKERS = [
        b"GpuChannel", b"CommandBufferStub", b"D3D11Device",
        b"GpuMemoryBuffer", b"SkiaRenderer", b"VulkanDevice",
        b"NetworkServiceImpl", b"URLLoaderFactory",
        b"CookieManager", b"--utility-sub-type=network",
        b"CrashpadClient", b"ExceptionHandlerServer", b"crashpad_handler",
        b"WASAPIAudioStream", b"AudioOutputDevice", b"AudioService",
        b"StorageServiceImpl", b"LevelDBServiceImpl",
    ]

    NOISE_DOMAINS = {
        "google-analytics.com", "googletagmanager.com", "doubleclick.net",
        "googlesyndication.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
        "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
        "amazon-adsystem.com", "criteo.com", "outbrain.com", "taboola.com",
        "sentry.io", "mixpanel.com", "segment.io", "newrelic.com",
        "update.googleapis.com", "safebrowsing.googleapis.com",
        "clients2.google.com", "ssl.gstatic.com", "ocsp.digicert.com",
        "crl.microsoft.com", "ctldl.windowsupdate.com", "microsoft.com",
        "windowsupdate.com", "fontfabrik.com", "digicert.com",
        "verisign.com", "symantec.com",
        # Chrome background services
        "accountcapabilities-pa.googleapis.com", "optimizationguide-pa.googleapis.com",
        "content-autofill.googleapis.com", "csp.withgoogle.com",
        "beacons.gcp.gvt2.com", "gvt1.com", "gvt2.com",
        "pki.goog", "ocsp.pki.goog",
        "accounts.google.com",
        "googleapis.com", "people.googleapis.com",
        "googlevideo.com",
        "yt3.ggpht.com", "i.ytimg.com", "ytimg.com",
        "gstatic.com",
        "is1-ssl.mzstatic.com", "is2-ssl.mzstatic.com", "is3-ssl.mzstatic.com",
        "mzstatic.com",
        "googleadservices.com", "googleads.g.doubleclick.net",
        "arc.msn.com", "assets.msn.com",
        "ecs.office.com", "config.office.com",
        "clients2.google.com", "clients4.google.com",
        "w3.org", "www.w3.org",
        "w3-reporting-nel.reddit.com",
    }

    URL_REGEX    = re.compile(rb"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{10,400}")
    SEARCH_REGEX = re.compile(rb"[?&](?:q|query|search)=([^&\s\x00\r\n]{3,200})", re.I)
    FORM_REGEX   = re.compile(
        rb"(?:username|email|login|password|token|api_key|secret|wallet|"
        rb"phone|mobile|mobilenumber|phonenumber|contact|otp|userid|user_id)"
        rb"=([^&\s\r\n\x00]{1,200})", re.I
    )
    # JSON login body format used by apps like Flipkart, Amazon
    PHONE_JSON_REGEX = re.compile(
        rb'"(?:mobileNumber|mobile|phone|phoneNumber|contact|loginId|userId)"'
        rb'\s*:\s*"(\+?[0-9]{7,15})"',
        re.I
    )
    COOKIE_REGEX = re.compile(rb"(?:Set-Cookie|Cookie):\s*([^\r\n\x00]{10,400})", re.I)

    CREDENTIALS = [
        (re.compile(rb"(?:password|passwd|pwd)=([^&\s\r\n\x00]{8,100})", re.I), "PASSWORD"),
        (re.compile(rb"(?:api[_-]?key|apikey)=([A-Za-z0-9_\-]{16,})", re.I),   "API_KEY"),
        (re.compile(rb"Bearer\s+([A-Za-z0-9_\-\.]{20,})", re.I),                "BEARER_TOKEN"),
    ]

    # JWT: three base64url segments separated by dots
    JWT_REGEX = re.compile(rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

    # Known OAuth / API token prefixes
    OAUTH_PATTERNS = [
        (re.compile(rb"ya29\.[A-Za-z0-9_\-]{60,}"),          "GOOGLE_OAUTH"),
        (re.compile(rb"ghp_[A-Za-z0-9]{36}"),                 "GITHUB_PAT"),
        (re.compile(rb"gho_[A-Za-z0-9]{36}"),                 "GITHUB_OAUTH"),
        (re.compile(rb"xoxb-[0-9]+-[A-Za-z0-9\-]+"),         "SLACK_BOT_TOKEN"),
        (re.compile(rb"xoxp-[0-9]+-[A-Za-z0-9\-]+"),         "SLACK_USER_TOKEN"),
        (re.compile(rb"AKIA[A-Z0-9]{16}"),                    "AWS_ACCESS_KEY"),
        (re.compile(rb"sk-[A-Za-z0-9]{48}"),                  "OPENAI_KEY"),
        (re.compile(rb"(?:access_token|id_token)=[A-Za-z0-9_\-\.]{40,}", re.I), "ACCESS_TOKEN"),
    ]

    # Exfiltration channel patterns
    PASTE_SITES   = re.compile(
        rb"https?://(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.com|"
        rb"dpaste\.org|rentry\.co|privatebin\.net)/[^\s\x00\r\n]{3,80}", re.I
    )
    LARGE_B64_URL = re.compile(
        rb"https?://[^\s\x00]*[?&][a-zA-Z_\-]{1,20}=([A-Za-z0-9+/]{80,}={0,2})"
    )
    # Upload/exfil endpoint paths including common phishing kit panel names
    UPLOAD_ENDPOINT = re.compile(
        rb"https?://[^\s\x00]*/(?:upload|exfil|submit|send|collect|data|dump|"
        rb"res|tele|panel|gate|bot|log|grab|steal)"
        rb"(?:\.php)?[^\s\x00\r\n]{0,100}", re.I
    )

    # TLDs commonly abused by phishing kits (.zip/.mov weaponised in 2023-2024)
    PHISHING_TLDS = {
        "pw", "click", "work", "tk", "gq", "ml", "cf", "ga",
        "zip", "mov", "loan", "win", "download", "cricket", "party",
        "webcam", "faith", "review", "country", "accountant",
        "science", "stream", "gdn", "cyou", "cfd", "bond",
    }

    # BlobPhish: phishing pages loaded via createObjectURL(new Blob([atob(html)]))
    BLOB_URL_REGEX    = re.compile(rb"blob:https?://[^\s\x00\r\n]{10,200}")
    INLINE_DATA_REGEX = re.compile(
        rb"data:text/html(?:;charset=[a-z0-9\-]+)?;base64,[A-Za-z0-9+/]{80,}={0,2}",
        re.I
    )
    # JS strings present in V8 heap when a BlobPhish page is active
    BLOBPHISH_JS_MARKERS = [
        b"createObjectURL",
        b"new Blob(",
        b"atob(",
        b"revokeObjectURL",
    ]

    # AiTM/Evilginx2: proxy domain pattern and stolen session cookie indicators
    AITM_DOMAIN_REGEX = re.compile(
        rb"https?://login\.[a-z0-9\-]{4,30}\."
        rb"(?:xyz|cloud|live|online|site|app)[/\s\x00\r\n]",
        re.I
    )
    SECURE_COOKIE_REGEX = re.compile(
        rb"(?:__Secure-|__Host-)[A-Za-z0-9_\-\.]{3,60}=[^\s\r\n\x00;]{10,300}"
    )
    SESSION_ID_REGEX = re.compile(
        rb"SessionId\s*[=:]\s*[A-Za-z0-9_\.\-]{16,100}", re.I
    )

    # Phishing kit victim fingerprinting — kits call these to geo-filter victims
    IP_INTEL_APIS = re.compile(
        rb"(?:ipregistry\.co|ipify\.org|ipapi\.co|ip-api\.com|"
        rb"geolocation\.onetrust\.com|api\.ipgeolocation\.io)",
        re.I
    )
    # JS strings used by detectIncognito library to probe private browsing mode
    INCOGNITO_PROBE_MARKERS = [
        b"navigator.storage.estimate",
        b"requestFileSystem",
        b"webkitRequestFileSystem",
        b"window.indexedDB",
        b"detectIncognito",
    ]

    # IPv4 pattern reused inside other regexes
    _IPv4 = rb"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

    # IP lookup services — extracts the target IP from the URL path
    IP_LOOKUP_REGEX = re.compile(
        rb"https?://(?:www\.)?"
        rb"(?:ipinfo\.io"
        rb"|ip-api\.com/(?:json|php|csv|xml)"
        rb"|ipwhois\.app/json"
        rb"|ipgeolocation\.io/ip-location"
        rb"|virustotal\.com/gui/ip-address"
        rb"|shodan\.io/host"
        rb"|search\.censys\.io/hosts"
        rb"|abuseipdb\.com/check"
        rb"|whois\.com/whois"
        rb"|who\.is/whois-ip/ip"
        rb"|ipvoid\.com/ip-blacklist-check"
        rb"|bgp\.he\.net/ip"
        rb"|mxtoolbox\.com/SuperTool\.aspx\?action=blacklist%3a"
        rb"|threatcrowd\.org/ip\.php\?ip="
        rb"|otx\.alienvault\.com/indicator/ip"
        rb")"
        rb"[/=](" + _IPv4 + rb")",
        re.I
    )

    # Catches search queries like google.com/search?q=192.168.1.1
    IP_SEARCH_REGEX = re.compile(
        rb"[?&](?:q|query|search|s)=([^&\s\x00\r\n]{0,40}?"
        + _IPv4 +
        rb"[^&\s\x00\r\n]{0,40})",
        re.I
    )

    # Private/reserved ranges for classifying recon intent
    _PRIVATE_RANGES = [
        (re.compile(rb"^10\."),                                    "INTERNAL_RECON"),
        (re.compile(rb"^192\.168\."),                              "INTERNAL_RECON"),
        (re.compile(rb"^172\.(?:1[6-9]|2[0-9]|3[01])\."),        "INTERNAL_RECON"),
        (re.compile(rb"^127\."),                                   None),
        (re.compile(rb"^169\.254\."),                              None),
        (re.compile(rb"^(?:0|255)\."),                             None),
    ]

    # JSON body credentials from SPA login forms (React/Vue frontends)
    JSON_CRED_REGEX = re.compile(
        rb'"(?:email|username|login|user)"\s*:\s*"([^"\\]{3,100})"'
        rb'(?:[^}]{0,200})"(?:password|passwd|pwd|pass)"\s*:\s*"([^"\\]{3,100})"',
        re.I | re.DOTALL
    )

    HTTP_CONTEXT = [
        b"GET ", b"POST ", b"HTTP/1", b"HTTP/2",
        b"Host:", b"Cookie:", b"Authorization:", b"Referer:",
    ]

    DIRECT_NAV  = re.compile(rb"/(?:login|signin|auth|admin|dashboard|panel|wallet|payment|checkout)", re.I)
    DIRECT_IP   = re.compile(rb"https?://(?:\d{1,3}\.){3}\d{1,3}")
    C2_PATTERNS = re.compile(rb"/(?:gate|panel|bot|c2|cmd|task|beacon)\.php", re.I)
    DARKNET     = re.compile(rb"\.onion|\.i2p", re.I)
    NONSTD_PORT = re.compile(rb"https?://[^/\s]+:(?!80\b|443\b)\d{2,5}")

    # Telegram bot exfil: api.telegram.org/bot<token>/sendMessage
    TELEGRAM_EXFIL_REGEX = re.compile(
        rb"https?://api\.telegram\.org/bot[0-9]{8,12}:[A-Za-z0-9_\-]{35,}"
        rb"/send(?:Message|Document|Photo|Animation|Audio|Video)",
        re.I
    )
    # Standalone bot token in heap (config not yet turned into a request)
    TELEGRAM_TOKEN_REGEX = re.compile(
        rb"\bbot([0-9]{8,12}:[A-Za-z0-9_\-]{35,})"
    )

    # Discord webhook exfil used by infostealers like Raccoon, RedLine, Vidar
    DISCORD_WEBHOOK_REGEX = re.compile(
        rb"https?://(?:discord(?:app)?\.com|ptb\.discord\.com)"
        rb"/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,90}",
        re.I
    )

    # Cloud storage upload APIs abused for exfiltration (Drive, Dropbox, S3, OneDrive)
    CLOUD_UPLOAD_REGEX = re.compile(
        rb"https?://(?:"
        rb"(?:www\.)?googleapis\.com/upload/drive/v[0-9]/files|"
        rb"content\.dropboxapi\.com/2/files/upload|"
        rb"graph\.microsoft\.com/v1\.0/(?:me|users/[^/\s\x00]{1,60})/drive/[^\s\x00\r\n]{5,100}|"
        rb"[a-z0-9][\w.\-]{2,62}\.s3(?:[.\-][a-z0-9\-]+)*\.amazonaws\.com|"
        rb"[a-z0-9][a-z0-9\-]{1,61}\.blob\.core\.windows\.net"
        rb")",
        re.I
    )

    # WebSocket C2 channels — legitimate providers filtered via _WS_NOISE_HOSTS
    WEBSOCKET_REGEX = re.compile(
        rb"wss?://[a-zA-Z0-9\-._]{4,100}(?::\d{2,5})?(?:/[^\s\x00\r\n]{0,100})?",
        re.I
    )
    _WS_NOISE_HOSTS = frozenset([
        "googleapis.com", "microsoft.com", "slack.com", "pusher.com",
        "firebase.com", "firebaseio.com", "sockjs", "hotjar.com",
        "intercom.io", "zendesk.com", "cloudflare.com",
    ])

    # Content-Disposition attachment with sensitive file extensions
    SENSITIVE_FILE_DOWNLOAD_REGEX = re.compile(
        rb"Content-Disposition\s*:\s*attachment\s*;[^\r\n\x00]{0,80}"
        rb"filename\s*=\s*[\"']?([^\r\n\x00\"';]{3,150})",
        re.I
    )
    _SENSITIVE_EXTS = frozenset([
        b".docx", b".doc", b".xlsx", b".xls", b".pdf",
        b".zip", b".7z", b".gz", b".rar", b".tar",
        b".db", b".sqlite", b".sqlite3", b".kdbx",
        b".csv", b".pst", b".ost", b".mdb",
        b".sql", b".bak", b".dump",
        b".pem", b".key", b".p12", b".pfx", b".der", b".crt",
    ])

    # Base64 PNG/JPEG blob in heap — screenshot being exfiltrated
    SCREENSHOT_B64_REGEX = re.compile(
        rb"(?:iVBORw0KGgo[A-Za-z0-9+/]{200,}|/9j/4[A-Za-z0-9+/]{200,})"
    )

    LAUNCH_TICKS_RE = re.compile(r"--launch-time-ticks=(\d+)")

    # TI API endpoints
    _VT_URL    = "https://www.virustotal.com/api/v3/urls/{}"
    _PT_URL    = "https://checkurl.phishtank.com/checkurl/"
    _AIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

    # TI cache file — SHA256 keyed, TTL 7 days URLs / 3 days IPs
    _TI_CACHE_PATH = os.path.join(os.path.expanduser("~"), ".incognito_scanner_ti_cache.json")
    _TI_URL_TTL    = 7 * 86400   # seconds
    _TI_IP_TTL     = 3 * 86400

    _UUID_RE = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I
    )
    _DOTNET_TOKEN_PREFIXES = (
        '31bf3856', 'b77a5c56', 'b03f5f7f',
        '89845dcd', 'adb9793a',
    )

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="keywords",
                description="Comma-separated keywords or IOCs",
                optional=True,
                default=None,
            ),
            requirements.BooleanRequirement(
                name="timeline",
                description="Enable timeline reconstruction",
                optional=True,
                default=True,
            ),
            requirements.BooleanRequirement(
                name="enrich",
                description="Query VirusTotal, PhishTank and AbuseIPDB to flag extracted URLs/IPs",
                optional=True,
                default=False,
            ),
            requirements.StringRequirement(
                name="vt-key",
                description="VirusTotal API key (free tier: 500 lookups/day)",
                optional=True,
                default=None,
            ),
            requirements.StringRequirement(
                name="pt-key",
                description="PhishTank application key (optional — leave blank for anonymous queries)",
                optional=True,
                default=None,
            ),
            requirements.StringRequirement(
                name="aipdb-key",
                description="AbuseIPDB API key (free tier: 1000 checks/day)",
                optional=True,
                default=None,
            ),
        ]

    def _get_proc_name(self, proc) -> str:
        try:
            return proc.ImageFileName.cast(
                "string",
                max_length=proc.ImageFileName.vol.count,
                errors="replace"
            ).lower()
        except Exception:
            return ""

    def _get_cmdline(self, proc) -> str:
        try:
            peb = proc.get_peb()
            if not peb:
                return ""
            cmdline = peb.ProcessParameters.CommandLine.Buffer.dereference().cast(
                "string", encoding="utf-16-le", max_length=2048, errors="replace"
            )
            if not cmdline or len(cmdline.strip()) < 8:
                return ""
            return cmdline
        except Exception:
            return ""

    def _get_launch_ticks(self, cmdline: str) -> Optional[int]:
        """Extract Chrome's internal renderer creation timestamp for timeline ordering."""
        m = self.LAUNCH_TICKS_RE.search(cmdline)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                pass
        return None

    def _build_chrome_tree(self, kernel) -> Dict:
        """Build pid -> {proc, ppid, cmdline, name} for all chrome.exe processes."""
        tree = {}
        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=kernel.name,
        ):
            try:
                name = self._get_proc_name(proc)
                if "chrome.exe" not in name:
                    continue
                pid     = int(proc.UniqueProcessId)
                ppid    = int(proc.InheritedFromUniqueProcessId)
                cmdline = self._get_cmdline(proc)
                tree[pid] = {
                    "proc":    proc,
                    "ppid":    ppid,
                    "cmdline": cmdline,
                    "name":    name,
                }
            except Exception:
                continue
        return tree

    def _is_browser_process(self, cmdline: str) -> bool:
        """Browser process has no --type= flag; all child processes do."""
        if not cmdline:
            return False
        return "--type=" not in cmdline.lower()

    def _heap_has_markers(self, proc, markers: list, sample_size: int = 8 * 1024 * 1024) -> bool:
        """Scan anonymous VADs only — skips file-mapped DLLs that contain static strings."""
        try:
            layer = self.context.layers[proc.add_process_layer()]
            for vad in proc.get_vad_root().traverse():
                try:
                    try:
                        if vad.get_file_name():
                            continue
                    except Exception:
                        pass

                    size = vad.get_size()
                    if size < 0x1000 or size > 500 * 1024 * 1024:
                        continue
                    data = layer.read(
                        vad.get_start(),
                        min(size, sample_size),
                        pad=True
                    )
                    if any(m in data for m in markers):
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    def _find_incognito_browser(self, tree: Dict) -> Tuple[Optional[int], str]:
        """Find browser PID with OTR markers in heap; returns (pid, detection_method)."""
        browser_pids = [pid for pid, info in tree.items()
                        if self._is_browser_process(info["cmdline"])]
        renderer_pids = [pid for pid, info in tree.items()
                         if "--type=renderer" in info["cmdline"].lower()]

        vollog.info(f"Chrome browser processes (no --type=): {browser_pids}")
        vollog.info(f"Chrome renderer processes:             {renderer_pids}")
        vollog.info(f"Other chrome processes:                "
                    f"{[p for p in tree if p not in browser_pids and p not in renderer_pids]}")

        for pid in browser_pids:
            info = tree[pid]
            vollog.debug(f"Scanning browser PID {pid} heap for OTR markers ...")
            if self._heap_has_markers(info["proc"], self.INCOGNITO_MARKERS):
                vollog.info(f"[CONFIRMED via OTR heap] Incognito active — browser PID {pid}")
                return pid, "Ctrl+Shift+N (OTR Heap Markers)"

        # Fallback: check for --incognito flag in renderer cmdlines
        for pid in renderer_pids:
            cmdline = tree[pid]["cmdline"]
            if "--incognito" in cmdline.lower():
                ppid = tree[pid]["ppid"]
                vollog.info(f"[CONFIRMED via --incognito flag] renderer PID {pid}, browser PID={ppid}")
                if ppid in tree:
                    return ppid, "Command Line Flag (--incognito)"
                if browser_pids:
                    return browser_pids[0], "Command Line Flag (--incognito)"

        unknown_pids = [pid for pid, info in tree.items()
                        if not info["cmdline"] and pid not in browser_pids]
        vollog.info(f"Chrome processes with unreadable cmdlines: {unknown_pids}")

        if browser_pids and (renderer_pids or unknown_pids):
            vollog.info(
                f"OTR heap scan missed; using browser PID {browser_pids[0]} "
                f"with renderer classification fallback."
            )
            return browser_pids[0], "Process Tree Analysis (Heap Paged Out)"

        return None, ""

    def _get_incognito_renderers(self, tree: Dict, browser_pid: int) -> List[Dict]:
        """Return child renderers of the confirmed browser PID that lack normal profile markers."""
        incognito_renderers = []

        for pid, info in tree.items():
            cmdline = info["cmdline"]

            if cmdline and "--type=renderer" not in cmdline.lower():
                continue

            # Must be child of our confirmed incognito browser
            if info["ppid"] != browser_pid:
                continue

            # Normal renderers always have --profile-directory; incognito ones don't
            if cmdline and "--profile-directory" in cmdline.lower():
                vollog.info(f"  PID {pid} → NORMAL   (--profile-directory in cmdline)")
                continue

            # Fallback heap check when cmdline is unreadable (PEB paged out)
            if not cmdline:
                vollog.info(f"  PID {pid} → cmdline unreadable, falling back to heap check")
                if self._heap_has_markers(info["proc"], self._NON_RENDERER_MARKERS, sample_size=1 * 1024 * 1024):
                    vollog.info(f"  PID {pid} → SKIPPED  (non-renderer process markers in heap)")
                    continue
                if self._heap_has_markers(info["proc"], self.NORMAL_MARKERS, sample_size=2 * 1024 * 1024):
                    vollog.info(f"  PID {pid} → NORMAL   (profile path strings in heap)")
                    continue

            # Extract launch ticks for timeline ordering
            ticks = self._get_launch_ticks(cmdline)
            vollog.info(f"  PID {pid} → INCOGNITO (launch_ticks={ticks})")

            incognito_renderers.append({
                "proc":         info["proc"],
                "pid":          pid,
                "launch_ticks": ticks,
            })

        return incognito_renderers

    def _read_vads(self, proc, max_bytes: int = 150 * 1024 * 1024) -> Iterator[Tuple[int, bytes]]:
        pid = int(proc.UniqueProcessId)
        try:
            layer_name = proc.add_process_layer()
            layer = self.context.layers[layer_name]
        except Exception as e:
            vollog.warning(f"_read_vads PID {pid}: add_process_layer failed: {e}")
            return

        BLOCK      = 1 * 1024 * 1024
        total_read = 0
        for vad in proc.get_vad_root().traverse():
            if total_read >= max_bytes:
                vollog.debug(f"_read_vads PID {pid}: per-process limit {max_bytes//1024//1024}MB reached")
                break
            try:
                size = vad.get_size()
                if size < 0x1000 or size > 64 * 1024 * 1024:
                    continue

                # Skip DLLs/exes — only scan heap regions
                try:
                    fname = vad.get_file_name() or ""
                    if fname and any(ext in fname.lower() for ext in (".dll", ".exe", ".sys", ".mui", ".pdb")):
                        continue
                except Exception:
                    pass

                start     = vad.get_start()
                offset    = start
                remaining = size

                while remaining > 0:
                    to_read = min(BLOCK, remaining)
                    try:
                        chunk = layer.read(offset, to_read, pad=True)
                        if chunk:
                            # Skip mostly-null chunks (paged-out memory)
                            null_count = chunk.count(b'\x00')
                            if null_count > len(chunk) * 0.80:
                                offset    += to_read
                                remaining -= to_read
                                continue
                            total_read += to_read
                            yield offset, chunk
                    except Exception:
                        break
                    offset    += to_read
                    remaining -= to_read

            except Exception:
                continue

    def _is_string_dense(self, data: bytes) -> bool:
        if not data:
            return False
        sample    = data[:8192]
        printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
        return (printable / len(sample)) > 0.15

    def _has_http_context(self, data: bytes, match_start: int) -> bool:
        window = data[max(0, match_start - 512): min(len(data), match_start + 512)]
        return any(ctx in window for ctx in self.HTTP_CONTEXT)

    _KNOWN_TLDS = {
        "com","net","org","edu","gov","io","co","uk","us","de","fr","jp",
        "ru","cn","br","au","ca","in","it","es","nl","se","no","fi","dk",
        "pl","cz","ro","hu","sk","lt","lv","ee","ua","by","kz","ge","am",
        "az","info","biz","app","dev","ai","tv","me","mobi","name","online",
        "site","web","tech","store","shop","blog","news","live","cloud",
        "xyz","top","win","pro","vip","club","onion","i2p","mil","int",
    }

    def _validate_url(self, url: str) -> bool:
        try:
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                return False
            host = p.netloc.split(":")[0]
            if not host or len(host) > 253 or "." not in host:
                return False
            if any(c in host for c in (" ", "\\", "\x00", "\r", "\n")):
                return False
            tld = host.split(".")[-1].lower()
            if tld not in self._KNOWN_TLDS:
                return False
            if host[-1] in ("-", "."):
                return False
            if p.path and host in p.path:
                return False
            if not all(32 <= ord(c) <= 126 for c in host):
                return False
            if p.path:
                path = p.path
                if re.match(r'^/[a-zA-Z0-9]{0,3}$', path):
                    return False
                if path.startswith("/@") or path.startswith("/@@"):
                    return False
                if re.match(r'^/api-?$', path, re.I):
                    return False
                if host in ("www.youtube.com", "youtube.com") and path == "/watch" and not p.query:
                    return False

                # Background service / analytics paths with no forensic value
                _NOISE_PATHS = (
                    "/ajax/browser_error_reports/",
                    "/browser/error_reports/",
                    "/pagead/interaction/",
                    "/pagead/viewthroughconversion/",
                    "/generate_204", "/gen_204",
                    "/favicon.ico", "/robots.txt", "/crossdomain.xml",
                    "/.well-known/", "/domainreliability/upload",
                    "/svc/shreddit/events",
                    "/get_midroll_info", "/aboutthisad", "/s/player/",
                    "/get/videoqualityreport", "/accounts/OAuthLogin",
                    "/intl/en/policies/",
                    "/api-2.0/", "/api/v1/", "/api/v2/", "/api/v3/",
                    "/v1/location", "/v1/user", "/v2/user",
                )
                if any(path.startswith(noise) for noise in _NOISE_PATHS):
                    return False
            return True
        except Exception:
            return False

    # Filter Google Ads redirect URLs (not user navigation)
    _AD_TRACKING = re.compile(
        r'[?&](?:gc_id|gclid|gclsrc|label=video_click|ctype=\d)', re.I
    )

    def _is_noise_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            host   = parsed.netloc.lower().split(":")[0]
            parts  = host.split(".")
            for i in range(len(parts) - 1):
                if ".".join(parts[i:]) in self.NOISE_DOMAINS:
                    return True
            if self._AD_TRACKING.search(url):
                return True
            return False
        except Exception:
            return False

    def _classify_url(self, url_bytes: bytes) -> Tuple[str, str]:
        if self.DARKNET.search(url_bytes):
            return "DARKNET",        "HIGH"
        if self.DIRECT_IP.search(url_bytes):
            return "DIRECT_IP",      "HIGH"
        if self.C2_PATTERNS.search(url_bytes):
            return "C2_INFRA",       "HIGH"
        if self.NONSTD_PORT.search(url_bytes):
            return "NONSTD_PORT",    "HIGH"
        # Check TLD and scheme
        try:
            url_str = url_bytes.decode(errors="ignore")
            parsed  = urlparse(url_str)
            host    = parsed.netloc.split(":")[0].lower()
            tld     = host.split(".")[-1] if "." in host else ""
            if tld in self.PHISHING_TLDS:
                return "PHISHING_DOMAIN", "HIGH"
            # Plain HTTP on a public host is suspicious in an HTTPS-era web
            if parsed.scheme == "http":
                return "PLAIN_HTTP",     "HIGH"
        except Exception:
            pass
        if self.DIRECT_NAV.search(url_bytes):
            return "ADMIN_AUTH",     "HIGH"
        return "NAVIGATION", "MEDIUM"

    # ------------------------------------------------------------
    # EXTRACTORS
    # ------------------------------------------------------------

    def _extract_urls(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        results, seen = [], set()

        for m in self.URL_REGEX.finditer(data):
            try:
                url = m.group().decode(errors="ignore").rstrip(".,;\"')")
                if url in seen:
                    continue
                if not self._validate_url(url):
                    continue
                if self._is_noise_url(url):
                    continue
                seen.add(url)
                cat, conf = self._classify_url(m.group())
                # HTTP context nearby boosts confidence but isn't required
                if not self._has_http_context(data, m.start()):
                    conf = "MEDIUM" if conf == "HIGH" else "LOW"
                results.append(Artifact(
                    artifact_type="URL",
                    value=url,
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": cat, "confidence": conf}
                ))
            except Exception:
                continue

        return results

    # YouTube video ID is always exactly 11 chars from the set [A-Za-z0-9_-]
    _YT_THUMB_RE = re.compile(rb"ytimg\.com/vi/([A-Za-z0-9_\-]{11})/")

    def _extract_yt_watch_urls(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        """Reconstruct YouTube watch URLs from thumbnail CDN requests in heap."""
        results, seen = [], set()
        for m in self._YT_THUMB_RE.finditer(data):
            try:
                vid_id = m.group(1).decode(errors="ignore")
                watch_url = f"https://www.youtube.com/watch?v={vid_id}"
                if watch_url in seen:
                    continue
                seen.add(watch_url)
                results.append(Artifact(
                    artifact_type="URL",
                    value=watch_url,
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": "NAVIGATION", "confidence": "MEDIUM"},
                ))
            except Exception:
                continue
        return results

    def _extract_search(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        results, seen = [], set()

        for m in self.SEARCH_REGEX.finditer(data):
            try:
                query = unquote(
                    m.group(1).decode(errors="ignore").replace("+", " ")
                ).strip()
                if query in seen or len(query) < 2:
                    continue
                if sum(1 for c in query if c.isprintable()) / len(query) < 0.85:
                    continue
                seen.add(query)
                results.append(Artifact(
                    artifact_type="SEARCH",
                    value=query,
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": "USER_INTENT", "confidence": "HIGH"}
                ))
            except Exception:
                continue

        return results

    # System/placeholder values to filter out of form results
    _FORM_NOISE_VALUES = {
        "local", "system", "network service", "nt authority", "anonymous",
        "administrator", "nobody", "guest", "null", "undefined", "none",
        "true", "false", "yes", "no", "on", "off", "default", "example",
        "test", "debug", "admin", "user", "demo", "sample",
    }

    def _extract_forms(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        results, seen = [], set()

        for m in self.FORM_REGEX.finditer(data):
            try:
                raw_value = m.group(1).decode(errors="ignore").strip()

                if len(raw_value) < 6:
                    continue
                if raw_value.isdigit():
                    continue
                if raw_value.startswith("?") or set(raw_value) <= set("?*+.,;: "):
                    continue
                raw_value = raw_value.rstrip(".,;")
                if raw_value.lower() in self._FORM_NOISE_VALUES:
                    continue

                # Skip token=X inside URL query strings (not a real form field)
                match_start = m.start()
                if match_start > 0 and data[match_start - 1:match_start] in (b'&', b'?'):
                    continue

                if not all(32 <= ord(c) <= 126 for c in raw_value):
                    continue

                full_key_lower = m.group(0).lower()

                # Filter .NET public key tokens (hex-only values under token=)
                if b"token=" in full_key_lower and re.fullmatch(r'[0-9a-fA-F]+', raw_value):
                    continue

                if b"token=" in full_key_lower:
                    val_lower = raw_value.lower()
                    if any(val_lower.startswith(p) for p in self._DOTNET_TOKEN_PREFIXES):
                        continue

                if ";dc_lat=" in raw_value or ";dc_rdid=" in raw_value:
                    continue

                # Need at least 4 unique chars to avoid heap padding garbage
                if len(set(raw_value)) < 4:
                    continue

                alnum_ratio = sum(1 for c in raw_value if c.isalnum()) / len(raw_value)
                if alnum_ratio < 0.6:
                    continue

                full_match = m.group(0).decode(errors="ignore").strip()
                if full_match in seen:
                    continue
                seen.add(full_match)

                full_key = m.group(0).lower()
                cat  = "PASSWORD"  if b"pass"  in full_key or b"token" in full_key else "FORM_FIELD"
                conf = "HIGH"      if b"pass"  in full_key or b"token" in full_key else "MEDIUM"
                results.append(Artifact(
                    artifact_type="FORM",
                    value=full_match,
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": cat, "confidence": conf}
                ))
            except Exception:
                continue

        return results

    def _extract_cookies(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        results, seen = [], set()
        skip_prefixes = ("_ga=", "_gid=", "_fbp=", "__utm", "_gat=")

        for m in self.COOKIE_REGEX.finditer(data):
            try:
                cookie = m.group(1).decode(errors="ignore").strip()
                if cookie in seen or len(cookie) < 10:
                    continue
                if any(cookie.lower().startswith(p) for p in skip_prefixes):
                    continue
                seen.add(cookie)
                is_session = any(
                    x in cookie.lower()
                    for x in ["session", "token", "auth", "jwt", "sid="]
                )
                results.append(Artifact(
                    artifact_type="COOKIE",
                    value=cookie[:200],
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={
                        "category":   "SESSION_COOKIE" if is_session else "COOKIE",
                        "confidence": "HIGH"            if is_session else "LOW",
                    }
                ))
            except Exception:
                continue

        return results

    def _extract_credentials(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        results, seen = [], set()

        for pattern, label in self.CREDENTIALS:
            for m in pattern.finditer(data):
                try:
                    val = m.group().decode(errors="ignore").strip()
                    if val in seen:
                        continue
                    seen.add(val)
                    results.append(Artifact(
                        artifact_type="CREDENTIAL",
                        value=val[:200],
                        pid=pid,
                        offset=base + m.start(),
                        source="vad",
                        extra={"category": label, "confidence": "HIGH"}
                    ))
                except Exception:
                    continue

        return results

    def _extract_jwt_tokens(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        results, seen = [], set()
        for m in self.JWT_REGEX.finditer(data):
            try:
                token = m.group().decode(errors="ignore")
                if token in seen:
                    continue
                seen.add(token)
                parts = token.split(".")
                try:
                    pad     = parts[1] + "=="
                    payload = json.loads(base64.b64decode(pad).decode(errors="ignore"))
                    # Extract all meaningful identity fields from payload
                    identity_keys = ["sub", "email", "username", "mobile", "phone",
                                     "uid", "user_id", "userId", "accountId",
                                     "name", "iss", "aud", "exp"]
                    claims = {k: payload[k] for k in identity_keys if k in payload}
                    claims_str = " ".join(f"{k}={v}" for k, v in claims.items())
                    detail  = f"JWT {claims_str} | {token[:80]}"
                except Exception:
                    detail = f"JWT (raw) | {token[:100]}"
                results.append(Artifact(
                    artifact_type="CREDENTIAL",
                    value=detail,
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": "JWT_TOKEN", "confidence": "HIGH"},
                ))
            except Exception:
                continue
        return results

    def _extract_oauth_tokens(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        results, seen = [], set()
        for pattern, label in self.OAUTH_PATTERNS:
            for m in pattern.finditer(data):
                try:
                    token = m.group().decode(errors="ignore")
                    if token in seen:
                        continue
                    seen.add(token)
                    results.append(Artifact(
                        artifact_type="CREDENTIAL",
                        value=token[:200],
                        pid=pid,
                        offset=base + m.start(),
                        source="vad",
                        extra={"category": label, "confidence": "HIGH"},
                    ))
                except Exception:
                    continue
        return results


    def _extract_exfiltration(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        results, seen = [], set()
        for pattern, cat, conf in [
            (self.PASTE_SITES,    "PASTE_SITE",   "HIGH"),
            (self.LARGE_B64_URL,  "B64_EXFIL",    "MEDIUM"),
            (self.UPLOAD_ENDPOINT,"UPLOAD_ENDPOINT","MEDIUM"),
        ]:
            for m in pattern.finditer(data):
                try:
                    url = m.group().decode(errors="ignore")
                    if url in seen:
                        continue
                    if self._is_noise_url(url):
                        continue
                    if not self._validate_url(url):
                        continue
                    seen.add(url)
                    results.append(Artifact(
                        artifact_type="URL",
                        value=url[:300],
                        pid=pid,
                        offset=base + m.start(),
                        source="vad",
                        extra={"category": cat, "confidence": conf},
                    ))
                except Exception:
                    continue
        return results

    def _extract_blobphish(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        """Detect BlobPhish pages (createObjectURL + atob pattern) and inline data URIs."""
        results, seen = [], set()

        js_hits = [m for m in self.BLOBPHISH_JS_MARKERS if m in data]
        if len(js_hits) >= 2:
            val = f"BLOBPHISH_JS markers found: {[m.decode() for m in js_hits]}"
            if val not in seen:
                seen.add(val)
                results.append(Artifact(
                    artifact_type="PHISHING",
                    value=val,
                    pid=pid,
                    offset=base,
                    source="vad",
                    extra={"category": "BLOBPHISH_JS", "confidence": "HIGH"},
                ))

        for pattern, cat in [
            (self.BLOB_URL_REGEX,    "BLOBPHISH_URL"),
            (self.INLINE_DATA_REGEX, "INLINE_HTML_PHISH"),
        ]:
            for m in pattern.finditer(data):
                try:
                    val = m.group().decode(errors="ignore")
                    if val in seen:
                        continue
                    seen.add(val)
                    results.append(Artifact(
                        artifact_type="PHISHING",
                        value=val[:300],
                        pid=pid,
                        offset=base + m.start(),
                        source="vad",
                        extra={"category": cat, "confidence": "HIGH"},
                    ))
                except Exception:
                    continue
        return results

    def _extract_aitm_indicators(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        """Detect AiTM/Evilginx2 proxy domains, stolen SessionId strings, and phishing kit IP fingerprinting."""
        results, seen = [], set()

        for m in self.AITM_DOMAIN_REGEX.finditer(data):
            try:
                val = m.group().decode(errors="ignore").strip()
                if val not in seen:
                    seen.add(val)
                    results.append(Artifact(
                        artifact_type="PHISHING",
                        value=val[:300],
                        pid=pid,
                        offset=base + m.start(),
                        source="vad",
                        extra={"category": "AITM_PROXY_DOMAIN", "confidence": "HIGH"},
                    ))
            except Exception:
                continue

        # UUID session IDs get MEDIUM confidence; non-UUID get HIGH
        for m in self.SESSION_ID_REGEX.finditer(data):
            try:
                val = m.group().decode(errors="ignore").strip()
                if val not in seen:
                    seen.add(val)
                    sid_value = val.split("=", 1)[-1].strip() if "=" in val else val
                    conf = "MEDIUM" if self._UUID_RE.match(sid_value) else "HIGH"
                    results.append(Artifact(
                        artifact_type="CREDENTIAL",
                        value=val[:200],
                        pid=pid,
                        offset=base + m.start(),
                        source="vad",
                        extra={"category": "AITM_SESSION_ID", "confidence": conf},
                    ))
            except Exception:
                continue

        for m in self.IP_INTEL_APIS.finditer(data):
            try:
                val = m.group().decode(errors="ignore")
                if val not in seen:
                    seen.add(val)
                    results.append(Artifact(
                        artifact_type="PHISHING",
                        value=f"IP_INTEL_API: {val}",
                        pid=pid,
                        offset=base + m.start(),
                        source="vad",
                        extra={"category": "PHISHKIT_FINGERPRINT", "confidence": "MEDIUM"},
                    ))
            except Exception:
                continue

        return results

    def _extract_incognito_probe(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        """Detect pages running detectIncognito JS (2+ probe markers in same heap chunk)."""
        hits = [m for m in self.INCOGNITO_PROBE_MARKERS if m in data]
        if len(hits) < 2:
            return []
        val = f"INCOGNITO_PROBE markers: {[m.decode() for m in hits]}"
        return [Artifact(
            artifact_type="PHISHING",
            value=val,
            pid=int(pid),
            offset=base,
            source="vad",
            extra={"category": "INCOGNITO_PROBE_JS", "confidence": "MEDIUM"},
        )]

    def _classify_recon_ip(self, ip_bytes: bytes) -> str:
        """Return recon category for an IP, or None to skip."""
        for pattern, label in self._PRIVATE_RANGES:
            if pattern.match(ip_bytes):
                return label  # None means skip (loopback/reserved)
        return "EXTERNAL_RECON"

    def _extract_ip_recon(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        """Detect IP lookups via dedicated services (ipinfo, shodan) and search queries containing IPs."""
        results, seen = [], set()

        for m in self.IP_LOOKUP_REGEX.finditer(data):
            try:
                full_url = m.group(0).decode(errors="ignore")
                target_ip = m.group(1)                          # captured IP bytes
                category  = self._classify_recon_ip(target_ip)
                if category is None:
                    continue                                     # skip loopback/reserved
                target_str = target_ip.decode(errors="ignore")
                # derive service name from URL
                service = full_url.split("/")[2].lstrip("www.")
                val = f"IP_RECON target={target_str} via {service}"
                if val in seen:
                    continue
                seen.add(val)
                results.append(Artifact(
                    artifact_type="RECON",
                    value=val,
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": category, "confidence": "HIGH",
                           "target_ip": target_str, "service": service},
                ))
            except Exception:
                continue

        # Also catch search queries like "google.com/search?q=192.168.1.1"
        for m in self.IP_SEARCH_REGEX.finditer(data):
            try:
                query = unquote(m.group(1).decode(errors="ignore").replace("+", " ")).strip()
                # extract the IP portion for classification
                ip_match = re.search(self._IPv4, m.group(1))
                if not ip_match:
                    continue
                category = self._classify_recon_ip(ip_match.group(0))
                if category is None:
                    continue
                val = f"IP_SEARCH query={query}"
                if val in seen:
                    continue
                seen.add(val)
                results.append(Artifact(
                    artifact_type="RECON",
                    value=val,
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": category, "confidence": "MEDIUM",
                           "target_ip": ip_match.group(0).decode(errors="ignore")},
                ))
            except Exception:
                continue

        return results

    def _extract_aitm_cookies(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        """Detect stolen OAuth session cookies (__Secure-/__Host- prefixed) in heap."""
        results, seen = [], set()
        for m in self.SECURE_COOKIE_REGEX.finditer(data):
            try:
                cookie = m.group().decode(errors="ignore")
                if cookie in seen:
                    continue
                seen.add(cookie)
                results.append(Artifact(
                    artifact_type="COOKIE",
                    value=cookie[:300],
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": "AITM_SESSION_COOKIE", "confidence": "HIGH"},
                ))
            except Exception:
                continue
        return results

    def _extract_json_credentials(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        """Catch JSON credential bodies from React/Vue phishing kit login forms."""
        results, seen = [], set()
        for m in self.JSON_CRED_REGEX.finditer(data):
            try:
                username = m.group(1).decode(errors="ignore").strip()
                password = m.group(2).decode(errors="ignore").strip()
                val = f"JSON_CRED user={username} pass={password}"
                if val in seen:
                    continue
                seen.add(val)
                results.append(Artifact(
                    artifact_type="CREDENTIAL",
                    value=val[:300],
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": "JSON_CREDENTIAL", "confidence": "HIGH"},
                ))
            except Exception:
                continue
        return results

    def _extract_phone_login(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        """Extract phone/mobile numbers submitted via JSON login forms (Flipkart, Amazon etc.)"""
        results, seen = [], set()
        for m in self.PHONE_JSON_REGEX.finditer(data):
            try:
                number = m.group(1).decode(errors="ignore").strip()
                if number in seen:
                    continue
                seen.add(number)
                results.append(Artifact(
                    artifact_type="FORM",
                    value=f"phone={number}",
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": "PHONE_LOGIN", "confidence": "HIGH"},
                ))
            except Exception:
                continue
        return results

    def _extract_data_exfil(self, data: bytes, pid: int, base: int) -> List[Artifact]:
        """Detect Telegram/Discord exfil, cloud uploads, WebSocket C2, and file downloads."""
        results, seen = [], set()

        for m in self.TELEGRAM_EXFIL_REGEX.finditer(data):
            try:
                val = m.group().decode(errors="ignore")
                if val not in seen:
                    seen.add(val)
                    results.append(Artifact(
                        artifact_type="EXFILTRATION",
                        value=val[:300],
                        pid=pid,
                        offset=base + m.start(),
                        source="vad",
                        extra={"category": "TELEGRAM_EXFIL", "confidence": "HIGH"},
                    ))
            except Exception:
                continue

        # Standalone bot token (kit config not yet turned into a request URL)
        tg_already = any(r.extra.get("category") == "TELEGRAM_EXFIL" for r in results)
        if not tg_already:
            for m in self.TELEGRAM_TOKEN_REGEX.finditer(data):
                try:
                    token = m.group(1).decode(errors="ignore")
                    val = f"TELEGRAM_BOT_TOKEN: {token}"
                    if val not in seen:
                        seen.add(val)
                        results.append(Artifact(
                            artifact_type="EXFILTRATION",
                            value=val[:200],
                            pid=pid,
                            offset=base + m.start(),
                            source="vad",
                            extra={"category": "TELEGRAM_EXFIL", "confidence": "MEDIUM"},
                        ))
                except Exception:
                    continue

        for m in self.DISCORD_WEBHOOK_REGEX.finditer(data):
            try:
                val = m.group().decode(errors="ignore")
                if val not in seen:
                    seen.add(val)
                    results.append(Artifact(
                        artifact_type="EXFILTRATION",
                        value=val[:300],
                        pid=pid,
                        offset=base + m.start(),
                        source="vad",
                        extra={"category": "DISCORD_EXFIL", "confidence": "HIGH"},
                    ))
            except Exception:
                continue

        for m in self.CLOUD_UPLOAD_REGEX.finditer(data):
            try:
                val = m.group().decode(errors="ignore")
                if val in seen:
                    continue
                seen.add(val)
                raw = m.group()
                if b"googleapis" in raw:
                    cat = "GDRIVE_UPLOAD"
                elif b"dropbox" in raw:
                    cat = "DROPBOX_UPLOAD"
                elif b"microsoft" in raw or b"windows.net" in raw:
                    cat = "ONEDRIVE_UPLOAD"
                elif b"amazonaws" in raw:
                    cat = "S3_UPLOAD"
                else:
                    cat = "CLOUD_UPLOAD"
                results.append(Artifact(
                    artifact_type="EXFILTRATION",
                    value=f"{cat}: {val[:250]}",
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": cat, "confidence": "MEDIUM"},
                ))
            except Exception:
                continue

        for m in self.WEBSOCKET_REGEX.finditer(data):
            try:
                val = m.group().decode(errors="ignore")
                if val in seen or len(val) < 10:
                    continue
                host = val.split("/")[2] if val.count("/") >= 2 else val[6:]
                host = host.split(":")[0].lower()
                if any(n in host for n in self._WS_NOISE_HOSTS):
                    continue
                seen.add(val)
                # Non-standard port = higher chance of C2 beacon
                conf = "HIGH" if re.search(rb":\d{4,5}/", m.group()) else "MEDIUM"
                results.append(Artifact(
                    artifact_type="EXFILTRATION",
                    value=f"WEBSOCKET: {val[:250]}",
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": "WEBSOCKET_C2", "confidence": conf},
                ))
            except Exception:
                continue

        for m in self.SENSITIVE_FILE_DOWNLOAD_REGEX.finditer(data):
            try:
                filename = m.group(1).decode(errors="ignore").strip()
                fname_b = filename.lower().encode()
                if not any(fname_b.endswith(ext) for ext in self._SENSITIVE_EXTS):
                    continue
                val = f"FILE_DOWNLOAD: {filename}"
                if val in seen:
                    continue
                seen.add(val)
                results.append(Artifact(
                    artifact_type="EXFILTRATION",
                    value=val[:300],
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": "SENSITIVE_FILE_DL", "confidence": "HIGH"},
                ))
            except Exception:
                continue

        for m in self.SCREENSHOT_B64_REGEX.finditer(data):
            try:
                preview = m.group()[:60].decode(errors="ignore")
                val = f"SCREENSHOT_B64: {preview}..."
                if val in seen:
                    continue
                seen.add(val)
                results.append(Artifact(
                    artifact_type="EXFILTRATION",
                    value=val[:200],
                    pid=pid,
                    offset=base + m.start(),
                    source="vad",
                    extra={"category": "SCREENSHOT_EXFIL", "confidence": "MEDIUM"},
                ))
            except Exception:
                continue

        return results

    def _load_ti_cache(self) -> Dict:
        try:
            if os.path.exists(self._TI_CACHE_PATH):
                with open(self._TI_CACHE_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_ti_cache(self, cache: Dict) -> None:
        try:
            with open(self._TI_CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(cache, f, separators=(",", ":"))
        except Exception:
            pass

    def _cache_get(self, cache: Dict, indicator: str, ttl: int) -> Optional[Dict]:
        key = hashlib.sha256(indicator.encode()).hexdigest()
        entry = cache.get(key)
        if entry and (time.time() - entry.get("ts", 0)) < ttl:
            return entry.get("data")
        return None

    def _cache_set(self, cache: Dict, indicator: str, data: Dict) -> None:
        key = hashlib.sha256(indicator.encode()).hexdigest()
        cache[key] = {"ts": time.time(), "data": data, "ind": indicator[:120]}

    def _check_virustotal(self, url: str, api_key: str) -> Optional[Dict]:
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            req = urllib.request.Request(
                self._VT_URL.format(url_id),
                headers={"x-apikey": api_key, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            stats = (data.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {})
            if not stats:
                return None
            malicious  = int(stats.get("malicious",  0))
            suspicious = int(stats.get("suspicious", 0))
            return {
                "malicious":  malicious,
                "suspicious": suspicious,
                "verdict": (
                    "MALICIOUS"  if malicious  > 0 else
                    "SUSPICIOUS" if suspicious > 0 else
                    "CLEAN"
                ),
            }
        except Exception as e:
            vollog.debug(f"VirusTotal check failed for {url[:60]}: {e}")
            return None

    def _check_phishtank(self, url: str, api_key: str = "") -> Optional[bool]:
        try:
            post_data = {"url": url, "format": "json"}
            if api_key:
                post_data["app_key"] = api_key
            req = urllib.request.Request(
                self._PT_URL,
                data=urllib.parse.urlencode(post_data).encode(),
                headers={"User-Agent": "phishtank/IncognitoScanner"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            results = data.get("results", {})
            return bool(results.get("in_database") and results.get("valid"))
        except Exception as e:
            vollog.debug(f"PhishTank check failed for {url[:60]}: {e}")
            return None

    def _check_abuseipdb(self, ip: str, api_key: str) -> Optional[Dict]:
        try:
            params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
            req = urllib.request.Request(
                f"{self._AIPDB_URL}?{params}",
                headers={"Key": api_key, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            d = data.get("data", {})
            if not d:
                return None
            score   = int(d.get("abuseConfidenceScore", 0))
            reports = int(d.get("totalReports", 0))
            return {
                "abuse_score":   score,
                "total_reports": reports,
                "country":       d.get("countryCode", ""),
                "isp":           d.get("isp", ""),
                "verdict": (
                    "MALICIOUS"  if score > 80 else
                    "SUSPICIOUS" if score > 25 else
                    "CLEAN"
                ),
            }
        except Exception as e:
            vollog.debug(f"AbuseIPDB check failed for {ip}: {e}")
            return None

    def _enrich_artifacts(
        self,
        artifacts: List[Artifact],
        vt_key: Optional[str],
        pt_key: Optional[str],
        aipdb_key: Optional[str],
    ) -> None:
        cache = self._load_ti_cache()
        checked_urls: Set = set()
        checked_ips:  Set = set()
        vt_live = pt_live = ip_live = 0
        vt_hit  = pt_hit  = ip_hit  = 0
        dirty   = False   # track whether cache needs saving

        for a in artifacts:
            if a.extra.get("confidence") == "LOW":
                continue

            if a.artifact_type == "PHISHING":
                raw_url = a.value
                if ": http" in raw_url:
                    raw_url = raw_url[raw_url.index(": http") + 2:]
                url = raw_url[:2000]
                if url in checked_urls:
                    continue
                checked_urls.add(url)
                ti: Dict = {}

                # VirusTotal
                if vt_key:
                    cached = self._cache_get(cache, f"vt:{url}", self._TI_URL_TTL)
                    if cached is not None:
                        vt_hit += 1
                        result = cached
                    else:
                        result = self._check_virustotal(url, vt_key)
                        if result:
                            self._cache_set(cache, f"vt:{url}", result)
                            dirty = True
                        vt_live += 1
                        time.sleep(15)  # respect VT free tier limit
                    if result:
                        ti["virustotal"] = result
                        if result.get("verdict") != "CLEAN":
                            a.extra["confidence"] = "HIGH"

                # PhishTank
                if pt_key is not None:
                    cached = self._cache_get(cache, f"pt:{url}", self._TI_URL_TTL)
                    if cached is not None:
                        pt_hit += 1
                        is_phish = cached.get("confirmed_phish")
                    else:
                        is_phish = self._check_phishtank(url, pt_key)
                        if is_phish is not None:
                            self._cache_set(cache, f"pt:{url}", {"confirmed_phish": is_phish})
                            dirty = True
                        pt_live += 1
                        time.sleep(2)
                    if is_phish is True:
                        ti["phishtank"] = {"confirmed_phish": True}
                        a.extra["confidence"] = "HIGH"
                        a.extra["category"]   = "PHISHING_DOMAIN"
                    elif is_phish is False:
                        ti["phishtank"] = {"confirmed_phish": False}

                if ti:
                    a.extra["threat_intel"] = ti

            elif a.artifact_type == "RECON" and aipdb_key:
                ip = a.extra.get("target_ip", "")
                if not ip or ip in checked_ips:
                    continue
                checked_ips.add(ip)

                cached = self._cache_get(cache, f"aipdb:{ip}", self._TI_IP_TTL)
                if cached is not None:
                    ip_hit += 1
                    result = cached
                else:
                    result = self._check_abuseipdb(ip, aipdb_key)
                    if result:
                        self._cache_set(cache, f"aipdb:{ip}", result)
                        dirty = True
                    ip_live += 1
                    time.sleep(1)

                if result:
                    a.extra["threat_intel"] = {"abuseipdb": result}
                    if result.get("verdict") != "CLEAN":
                        a.extra["confidence"] = "HIGH"

        if dirty:
            self._save_ti_cache(cache)

        vollog.info(
            f"Threat intel enrichment complete — "
            f"VT: {vt_live} live / {vt_hit} cached  |  "
            f"PhishTank: {pt_live} live / {pt_hit} cached  |  "
            f"AbuseIPDB: {ip_live} live / {ip_hit} cached"
        )

    def _write_json(self, artifacts: List[Artifact], path: str) -> None:
        rows = []
        for a in artifacts:
            rows.append({
                "type":       a.artifact_type,
                "category":   a.extra.get("category", ""),
                "confidence": a.extra.get("confidence", ""),
                "value":      a.value,
                "pid":        a.pid,
                "offset":     hex(a.offset) if isinstance(a.offset, int) else str(a.offset),
            })
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"total": len(rows), "artifacts": rows}, f, indent=2)
        vollog.info(f"JSON report written: {path}")

    def _write_csv(self, artifacts: List[Artifact], path: str) -> None:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Type", "Category", "Confidence", "Value", "PID", "Offset"])
            for a in artifacts:
                w.writerow([
                    a.artifact_type,
                    a.extra.get("category", ""),
                    a.extra.get("confidence", ""),
                    a.value,
                    a.pid,
                    hex(a.offset) if isinstance(a.offset, int) else str(a.offset),
                ])
        vollog.info(f"CSV report written: {path}")

    def _write_html(self, artifacts: List[Artifact], path: str,
                    detection_method: str = "") -> None:

        non_tl   = [a for a in artifacts if a.artifact_type != "TIMELINE"]
        creds    = [a for a in non_tl if a.artifact_type == "CREDENTIAL"]
        exfil    = [a for a in non_tl if a.artifact_type == "EXFILTRATION"]
        phishing = [a for a in non_tl if a.artifact_type == "PHISHING"
                    or a.extra.get("category") in (
                        "PHISHING_DOMAIN", "AITM_SESSION_COOKIE",
                        "BLOBPHISH_URL", "INLINE_HTML_PHISH", "PLAIN_HTTP")]
        recon    = [a for a in non_tl if a.artifact_type == "RECON"]
        ioc_hits = [a for a in non_tl if a.artifact_type == "IOC_HIT"]
        urls     = [a for a in non_tl if a.artifact_type == "URL" and a not in phishing]
        searches = [a for a in non_tl if a.artifact_type == "SEARCH"]
        forms    = [a for a in non_tl if a.artifact_type == "FORM"]
        timeline = [a for a in artifacts if a.artifact_type == "TIMELINE"]
        detection_display = html.escape(detection_method) if detection_method else "Session Active at Dump Time"

        def ti_badges(a):
            ti = a.extra.get("threat_intel", {})
            if not ti:
                return ""
            parts = []
            vt = ti.get("virustotal", {})
            if vt:
                v = vt.get("verdict", "")
                color = {"MALICIOUS": "#ff2222", "SUSPICIOUS": "#ff8800", "CLEAN": "#448844"}.get(v, "#555")
                mal = vt.get("malicious", 0)
                sus = vt.get("suspicious", 0)
                parts.append(
                    f"<span style='background:{color};color:#fff;font-size:.7em;"
                    f"padding:1px 6px;border-radius:3px;margin-left:4px'>"
                    f"VT {v} ({mal}M/{sus}S)</span>"
                )
            pt = ti.get("phishtank", {})
            if pt:
                confirmed = pt.get("confirmed_phish", False)
                color = "#ff2222" if confirmed else "#448844"
                label = "PhishTank PHISH" if confirmed else "PhishTank CLEAN"
                parts.append(
                    f"<span style='background:{color};color:#fff;font-size:.7em;"
                    f"padding:1px 6px;border-radius:3px;margin-left:4px'>{label}</span>"
                )
            ab = ti.get("abuseipdb", {})
            if ab:
                v = ab.get("verdict", "")
                color = {"MALICIOUS": "#ff2222", "SUSPICIOUS": "#ff8800", "CLEAN": "#448844"}.get(v, "#555")
                parts.append(
                    f"<span style='background:{color};color:#fff;font-size:.7em;"
                    f"padding:1px 6px;border-radius:3px;margin-left:4px'>"
                    f"AbuseIPDB {v}</span>"
                )
            return "".join(parts)

        def row(a):
            cat = html.escape(a.extra.get("category", ""))
            val = html.escape(a.value[:300])
            off = hex(a.offset) if isinstance(a.offset, int) else str(a.offset)
            return (f"<tr><td><code style='font-size:.8em'>{cat}</code></td>"
                    f"<td style='word-break:break-all'>{val}{ti_badges(a)}</td>"
                    f"<td style='color:#aaa'>{a.pid}</td>"
                    f"<td style='color:#666;font-size:.8em'>{off}</td></tr>")

        def section(icon, title, items):
            if not items:
                return ""
            rows_html = [row(a) for a in items]
            return (
                f"<div class='section'>"
                f"<h2>{icon} {html.escape(title)}"
                f"&nbsp;<span style='color:#888;font-size:.8em;font-weight:400'>"
                f"{len(items)} artifact{'s' if len(items)!=1 else ''}</span></h2>"
                f"<table><thead><tr>"
                f"<th>Category</th><th>Value</th><th>PID</th><th>Offset</th>"
                f"</tr></thead><tbody>{''.join(rows_html)}</tbody></table></div>"
            )

        tl_html = ""
        if timeline:
            tl_rows = [
                f"<div class='tl-row'>"
                f"<span class='tl-dot'></span>"
                f"<span class='tl-val'>{html.escape(a.value[:130])}</span>"
                f"<span class='tl-pid'>PID {a.pid}</span>"
                f"</div>"
                for a in timeline
            ]
            tl_html = (
                "<div class='section'><h2>&#x1F4CB; Activity Timeline</h2>"
                "<div class='tl-wrap'>" + "".join(tl_rows) + "</div></div>"
            )

        body = f"""<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<title>Incognito Scanner — Forensic Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#12131a;color:#dde1f0;
        padding:28px 32px;line-height:1.5}}
  h1{{font-size:1.6em;color:#e94560;margin-bottom:4px;letter-spacing:.5px}}
  .meta{{color:#888;font-size:.85em;margin-bottom:8px}}
  .detection-banner{{background:#1c1e2d;border:1px solid #2a2d3e;border-left:3px solid #e94560;
    border-radius:0 4px 4px 0;padding:8px 14px;margin-bottom:22px;font-size:.88em;color:#c8cfe8}}
  .detection-banner span{{color:#e94560;font-weight:600}}

  /* Summary bar */
  .stats{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:28px}}
  .stat{{background:#1c1e2d;border:1px solid #2a2d3e;border-radius:8px;
         padding:14px 20px;min-width:100px;text-align:center}}
  .stat-n{{font-size:1.9em;font-weight:700;color:#e94560}}
  .stat-l{{font-size:.75em;color:#aaa;margin-top:2px;text-transform:uppercase;
            letter-spacing:.5px}}

  /* Sections */
  .section{{margin-bottom:28px}}
  h2{{font-size:1em;font-weight:600;color:#c8cfe8;padding:10px 14px;
       background:#1c1e2d;border-left:3px solid #e94560;border-radius:0 4px 4px 0;
       margin-bottom:0;display:flex;align-items:center;gap:8px}}

  /* Tables */
  table{{width:100%;border-collapse:collapse;font-size:.82em;
         background:#161821;border:1px solid #2a2d3e;border-top:none}}
  thead tr{{background:#1c1e2d}}
  th{{padding:8px 10px;text-align:left;color:#a0a8c0;font-weight:600;
       border-bottom:1px solid #2a2d3e}}
  td{{padding:7px 10px;border-bottom:1px solid #1e2030;vertical-align:top}}
  tbody tr:hover{{background:#1c1e2d}}
  code{{font-family:monospace;color:#9ab;font-size:.9em}}

  /* Timeline */
  .tl-wrap{{background:#161821;border:1px solid #2a2d3e;border-top:none;
            padding:10px 14px}}
  .tl-row{{display:flex;align-items:baseline;gap:10px;padding:5px 0;
            border-bottom:1px solid #1e2030;font-size:.83em}}
  .tl-row:last-child{{border-bottom:none}}
  .tl-dot{{display:inline-block;width:8px;height:8px;border-radius:50%;
            background:#e94560;flex-shrink:0;margin-top:4px}}
  .tl-val{{flex:1;word-break:break-all;color:#d0d4e8}}
  .tl-pid{{color:#555;font-size:.85em;white-space:nowrap}}
</style>
</head><body>

<h1>&#x1F575; Chrome Incognito Forensic Report</h1>
<div class='meta'>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;&nbsp;|&nbsp;&nbsp; {len(non_tl)} artifacts extracted</div>
<div class='detection-banner'>Incognito Session Initiated Via: <span>{detection_display}</span></div>

<div class='stats'>
  <div class='stat'><div class='stat-n'>{len(non_tl)}</div><div class='stat-l'>Total</div></div>
<div class='stat'><div class='stat-n'>{len(creds)}</div><div class='stat-l'>Credentials</div></div>
  <div class='stat'><div class='stat-n' style='color:#ff4444'>{len(exfil)}</div><div class='stat-l'>Exfiltration</div></div>
  <div class='stat'><div class='stat-n'>{len(phishing)}</div><div class='stat-l'>Phishing</div></div>
  <div class='stat'><div class='stat-n'>{len(recon)}</div><div class='stat-l'>Recon</div></div>
  <div class='stat'><div class='stat-n'>{len(urls)}</div><div class='stat-l'>URLs</div></div>
  <div class='stat'><div class='stat-n'>{len(searches)}</div><div class='stat-l'>Searches</div></div>
  <div class='stat'><div class='stat-n'>{len(forms)}</div><div class='stat-l'>Forms</div></div>
</div>

{section("&#x1F510;", "Credentials & Tokens", creds)}
{section("&#x1F4E4;", "Data Exfiltration", exfil)}
{section("&#x26A0;&#xFE0F;", "Phishing Indicators", phishing)}
{section("&#x1F9ED;", "IP Reconnaissance", recon)}
{section("&#x1F6A8;", "IOC Matches", ioc_hits)}
{section("&#x1F50D;", "Search Queries", searches)}
{section("&#x1F310;", "Visited URLs", urls)}
{section("&#x1F4DD;", "Form Fields", forms)}
{tl_html}

</body></html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        vollog.info(f"HTML report written: {path}")

    def _apply_iocs(self, artifacts: List[Artifact], keywords: str) -> List[Artifact]:
        keyword_list = [k.strip().lower() for k in keywords.split(",") if k.strip()]
        hits = []
        for a in artifacts:
            for k in keyword_list:
                if k in a.value.lower():
                    hits.append(Artifact(
                        artifact_type="IOC_HIT",
                        value=a.value[:200],
                        pid=a.pid,
                        offset=a.offset,
                        source=a.source,
                        extra={
                            "category":   "IOC_MATCH",
                            "confidence": "HIGH",
                            "keyword":    k,
                            "matched":    a.artifact_type,
                        }
                    ))
        return hits

    def _build_timeline(self, artifacts: List[Artifact],
                        renderer_ticks: Dict[int, Optional[int]]) -> List[Artifact]:
        by_pid: Dict[int, List[Artifact]] = {}
        nav_types = {"URL", "SEARCH", "FORM", "CREDENTIAL"}

        for a in artifacts:
            if a.artifact_type in nav_types:
                by_pid.setdefault(a.pid, []).append(a)

        timeline = []

        sorted_pids = sorted(
            by_pid.keys(),
            key=lambda p: renderer_ticks.get(p) or 0
        )

        global_seq = 1
        for pid in sorted_pids:
            items = by_pid[pid]
            items.sort(key=lambda x: x.offset if isinstance(x.offset, int) else 0)
            ticks = renderer_ticks.get(pid)
            for a in items:
                timeline.append(Artifact(
                    artifact_type="TIMELINE",
                    value=f"[{global_seq}] {a.extra.get('category', a.artifact_type)}: {a.value[:80]}",
                    pid=pid,
                    offset=a.offset,
                    source=a.source,
                    extra={
                        "category":     "TIMELINE",
                        "confidence":   a.extra.get("confidence", ""),
                        "seq":          str(global_seq),
                        "orig_type":    a.artifact_type,
                        "launch_ticks": str(ticks) if ticks else "unknown",
                    }
                ))
                global_seq += 1

        return timeline

    def run(self):
        kernel           = self.context.modules[self.config["kernel"]]
        keywords         = self.config.get("keywords",  None)
        timeline_enabled = self.config.get("timeline",  True)
        enrich           = self.config.get("enrich",    False)
        vt_key           = self.config.get("vt-key",    None)
        pt_key           = self.config.get("pt-key",    None)
        aipdb_key        = self.config.get("aipdb-key", None)

        tree = self._build_chrome_tree(kernel)
        vollog.info(f"Total Chrome processes found: {len(tree)}")

        # Step 1: Confirm incognito session via OTR heap markers
        browser_pid, detection_method = self._find_incognito_browser(tree)

        if browser_pid is None:
            browser_count = sum(1 for info in tree.values() if self._is_browser_process(info["cmdline"]))
            vollog.warning(
                f"No OTR markers found. Chrome processes in dump: {len(tree)} total, "
                f"{browser_count} browser process(es). "
                "Either Chrome incognito was not open at dump time, heap was paged out, "
                "or the .vmss file is missing (copy it alongside the .vmem file)."
            )
            return renderers.TreeGrid(
                [("Type", str), ("Category", str), ("Confidence", str),
                 ("Value", str), ("PID", str), ("Offset", str)],
                iter([])
            )

        vollog.info(f"Browser process PID {browser_pid} confirmed incognito session")

        # Step 2: Collect incognito renderer children
        incognito_renderers = self._get_incognito_renderers(tree, browser_pid)
        vollog.info(f"Incognito renderer processes identified: {len(incognito_renderers)}")

        if not incognito_renderers:
            vollog.warning(
                "Browser confirmed incognito but no incognito renderers found. "
                "Incognito tabs may have been closed before dump was taken."
            )

        renderer_ticks: Dict[int, Optional[int]] = {
            r["pid"]: r["launch_ticks"] for r in incognito_renderers
        }

        all_artifacts: List[Artifact] = []

        # Step 3a: Scan browser process for high-signal artifacts only (not URLs)
        browser_proc = tree[browser_pid]["proc"]
        vollog.info(f"Scanning browser process PID {browser_pid} for credentials/tokens ...")
        for base, chunk in self._read_vads(browser_proc):
            if not self._is_string_dense(chunk):
                continue
            if b"eyJ" in chunk:
                all_artifacts.extend(self._extract_jwt_tokens(chunk, browser_pid, base))
            if b"ookie" in chunk:
                all_artifacts.extend(self._extract_cookies(chunk, browser_pid, base))

        # Step 3b: Full artifact extraction from each incognito renderer
        for renderer in incognito_renderers:
            proc = renderer["proc"]
            pid  = renderer["pid"]

            for base, chunk in self._read_vads(proc):
                if not self._is_string_dense(chunk):
                    continue

                if b"http" in chunk or b"ytimg" in chunk:
                    all_artifacts.extend(self._extract_urls(chunk, pid, base))
                    all_artifacts.extend(self._extract_yt_watch_urls(chunk, pid, base))
                    all_artifacts.extend(self._extract_search(chunk, pid, base))
                    all_artifacts.extend(self._extract_exfiltration(chunk, pid, base))

                if b"ookie" in chunk:
                    all_artifacts.extend(self._extract_cookies(chunk, pid, base))
                    all_artifacts.extend(self._extract_aitm_cookies(chunk, pid, base))

                if b"=" in chunk or b"mobile" in chunk.lower() or b"phone" in chunk.lower():
                    all_artifacts.extend(self._extract_forms(chunk, pid, base))
                    all_artifacts.extend(self._extract_credentials(chunk, pid, base))
                    all_artifacts.extend(self._extract_phone_login(chunk, pid, base))

                if b"eyJ" in chunk:
                    all_artifacts.extend(self._extract_jwt_tokens(chunk, pid, base))

                # BlobPhish detection
                if (b"blob:" in chunk or b"data:text" in chunk
                        or b"createObjectURL" in chunk or b"atob(" in chunk):
                    all_artifacts.extend(self._extract_blobphish(chunk, pid, base))

                # IP recon: only run if a lookup-service keyword is present
                if any(kw in chunk for kw in (
                        b"ipinfo", b"shodan", b"virustotal", b"ip-api",
                        b"abuseipdb", b"censys", b"ipwhois", b"whois.com")):
                    all_artifacts.extend(self._extract_ip_recon(chunk, pid, base))

                # AiTM indicators: Evilginx2 domains and SessionId strings
                if (b"SessionId" in chunk or b"session_id" in chunk
                        or b"login." in chunk or b"ipify" in chunk or b"ipregistry" in chunk):
                    all_artifacts.extend(self._extract_aitm_indicators(chunk, pid, base))

                # detectIncognito probe check
                if any(m in chunk for m in self.INCOGNITO_PROBE_MARKERS):
                    all_artifacts.extend(self._extract_incognito_probe(chunk, pid, base))

                # JSON credentials from SPA login forms
                if b'"password"' in chunk or b'"passwd"' in chunk:
                    all_artifacts.extend(self._extract_json_credentials(chunk, pid, base))

                # OAuth and API token extraction
                if any(kw in chunk for kw in (
                        b"ya29.", b"ghp_", b"gho_", b"AKIA", b"xoxb-",
                        b"xoxp-", b"sk-", b"access_token")):
                    all_artifacts.extend(self._extract_oauth_tokens(chunk, pid, base))

                # Exfiltration channels
                if any(kw in chunk for kw in (
                        b"telegram", b"discord", b"dropbox", b"amazonaws",
                        b"googleapis.com/upload", b"wss://", b"pastebin",
                        b"hastebin", b"ghostbin", b"dpaste", b"rentry")):
                    all_artifacts.extend(self._extract_data_exfil(chunk, pid, base))

        # Global deduplication
        deduped:     List[Artifact] = []
        seen_global: Set            = set()
        for a in all_artifacts:
            key = (a.artifact_type, a.value)
            if key not in seen_global:
                seen_global.add(key)
                deduped.append(a)

        # Threat intelligence enrichment (optional — requires --enrich flag + API keys)
        if enrich:
            if not any([vt_key, pt_key is not None, aipdb_key]):
                vollog.warning(
                    "--enrich set but no API keys provided. "
                    "Pass --vt-key, --pt-key, and/or --aipdb-key."
                )
            else:
                vollog.info(
                    f"Enriching artifacts with threat intel "
                    f"(VT={'yes' if vt_key else 'no'}, "
                    f"PhishTank={'yes' if pt_key is not None else 'no'}, "
                    f"AbuseIPDB={'yes' if aipdb_key else 'no'}) ..."
                )
                self._enrich_artifacts(deduped, vt_key, pt_key, aipdb_key)

        vollog.info(f"Total artifacts after dedup: {len(deduped)}")
        for atype in ("URL", "SEARCH", "FORM", "CREDENTIAL", "COOKIE"):
            count = sum(1 for a in deduped if a.artifact_type == atype)
            if count:
                vollog.info(f"  {atype}: {count}")

        # Priority sort — highest value artifacts first
        PRIORITY = {
            # Tier 0: active credential/token compromise
            "JWT_TOKEN":          0,
            "AWS_ACCESS_KEY":     0,
            "GOOGLE_OAUTH":       0,
            "GITHUB_PAT":         0,
            "OPENAI_KEY":         0,
            "SLACK_BOT_TOKEN":    0,
            "JSON_CREDENTIAL":    0,
            "AITM_SESSION_COOKIE":0,
            "CREDENTIAL":         0,
            "PASSWORD":           0,
            # Tier 1: active exfiltration channels (data leaving right now)
            "TELEGRAM_EXFIL":     1,
            "DISCORD_EXFIL":      1,
            "SCREENSHOT_EXFIL":   1,
            "SENSITIVE_FILE_DL":  1,
            # Tier 2: phishing infrastructure
            "BLOBPHISH_URL":         2,
            "BLOBPHISH_JS":          2,
            "INLINE_HTML_PHISH":     2,
            "PHISHING_DOMAIN":       2,
            "AITM_PROXY_DOMAIN":     2,
            "AITM_SESSION_ID":       2,
            # Tier 3: cloud exfil + C2 channels
            "GDRIVE_UPLOAD":      3,
            "DROPBOX_UPLOAD":     3,
            "ONEDRIVE_UPLOAD":    3,
            "S3_UPLOAD":          3,
            "CLOUD_UPLOAD":       3,
            "WEBSOCKET_C2":       3,
            "INCOGNITO_PROBE_JS": 3,
            "PHISHKIT_FINGERPRINT":3,
            # Tier 4: access tokens and API keys
            "ACCESS_TOKEN":       4,
            "BEARER_TOKEN":       4,
            "API_KEY":            4,
            # Tier 5: legacy exfiltration signals
            "PASTE_SITE":         5,
            "B64_EXFIL":          5,
            "C2_INFRA":           5,
            "DARKNET":            5,
            "DIRECT_IP":          6,
            "PLAIN_HTTP":         6,
            "ADMIN_AUTH":         6,
            "UPLOAD_ENDPOINT":    6,
            # Tier 6+: context
            "SESSION_COOKIE":     7,
            "USER_INTENT":        8,
            "NAVIGATION":         9,
            "COOKIE":             10,
            "FORM_FIELD":         11,
        }
        CONF_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        deduped.sort(
            key=lambda a: (
                PRIORITY.get(a.extra.get("category", ""), 99),
                CONF_ORDER.get(a.extra.get("confidence", ""), 3),
            )
        )

        # IOC matching
        ioc_hits: List[Artifact] = []
        if keywords:
            ioc_hits = self._apply_iocs(deduped, keywords)

        # Timeline using launch_ticks for ordering
        timeline: List[Artifact] = []
        if timeline_enabled:
            timeline = self._build_timeline(deduped, renderer_ticks)

        combined = deduped + ioc_hits + timeline

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        for fmt, writer, extra_args in [
            (f"incognito_{ts}.json", self._write_json, []),
            (f"incognito_{ts}.csv",  self._write_csv,  []),
            (f"incognito_{ts}.html", self._write_html, [detection_method]),
        ]:
            try:
                writer(combined, fmt, *extra_args)
            except Exception as _e:
                vollog.warning(f"Could not write {fmt}: {_e}")

        return renderers.TreeGrid(
            [
                ("Type",     str),
                ("Category", str),
                ("Value",    str),
                ("PID",      str),
                ("Offset",   str),
            ],
            ((0, a.to_row()) for a in combined),
        )