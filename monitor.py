import os
import html
import json
import time
import httpx
import ipaddress
import asyncio
from enum import Enum
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from jinja2 import Environment, FileSystemLoader
CLOUDFLARE_API_TOKEN = os.environ["CLOUDFLARE_API_TOKEN"]
ZONE_ID = os.environ["ZONE_ID"]
ACCOUNT_ID = os.environ["ACCOUNT_ID"]
TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
MERCHANT_ALERT_CHAT_ID = os.environ.get("MERCHANT_ALERT_CHAT_ID") or TELEGRAM_CHAT_ID
WATCH_IP_ALERT_CHAT_ID = os.environ.get("WATCH_IP_ALERT_CHAT_ID") or TELEGRAM_CHAT_ID
REFERER_ALERT_CHAT_ID = os.environ.get("REFERER_ALERT_CHAT_ID") or TELEGRAM_CHAT_ID
CLEANUP_ALERT_CHAT_ID = os.environ.get("CLEANUP_ALERT_CHAT_ID") or TELEGRAM_CHAT_ID
BLOCK_THRESHOLD = int(os.environ.get("BLOCK_THRESHOLD", "100"))
STATUS_499_THRESHOLD = int(os.environ.get("STATUS_499_THRESHOLD", "0"))
STATUS_499_HOSTS = [h.strip().lower() for h in os.environ.get("STATUS_499_HOSTS", "").split(",") if h.strip()]
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "120"))
ALERT_COOLDOWN = int(os.environ.get("ALERT_COOLDOWN", "600"))
WATCH_IPS = [ip.strip() for ip in os.environ.get("WATCH_IPS", "").split(",") if ip.strip()]
ALLOWED_REFERER_DOMAINS = [d.strip().lower() for d in os.environ.get("ALLOWED_REFERER_DOMAINS", "").split(",") if d.strip()]
REFERER_HOSTS = [h.strip().lower() for h in os.environ.get("REFERER_HOSTS", "").split(",") if h.strip()]  # Chỉ quét referer trên các host này; rỗng = quét tất cả host
REFERER_SCAN_TIME = os.environ.get("REFERER_SCAN_TIME", "17:00")  # Giờ VN, format HH:MM, quét 1 lần/ngày
MERCHANT_IP_LISTS = [name.strip() for name in os.environ.get("MERCHANT_IP_LISTS", "").split(",") if name.strip()]
BLOCK_IP_LIST = os.environ.get("BLOCK_IP_LIST", "block_ips")

def parse_merchant_list_hosts(raw: str) -> dict[str, set[str]]:
    # Format: "<list_name>:<host1>|<host2>,<list_name2>:<host3>"
    result: dict[str, set[str]] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        name, hosts_str = entry.split(":", 1)
        name = name.strip()
        hosts = {h.strip().lower() for h in hosts_str.split("|") if h.strip()}
        if name and hosts:
            result[name] = hosts
    return result

MERCHANT_LIST_ALLOWED_HOSTS: dict[str, set[str]] = parse_merchant_list_hosts(
    os.environ.get("MERCHANT_LIST_ALLOWED_HOSTS", "")
)
MERCHANT_CACHE_REFRESH_INTERVAL = int(os.environ.get("MERCHANT_CACHE_REFRESH_INTERVAL", "300"))
ALLOWED_BLOCK_USERS = [u.strip() for u in os.environ.get("ALLOWED_BLOCK_USERS", "").split(",") if u.strip()]
BLOCK_MODES = ("auto", "manual")
BLOCK_MODE = os.environ.get("BLOCK_MODE", "auto").strip().lower()  # Chế độ khi khởi động; đổi lúc chạy bằng lệnh /auto, /manual
if BLOCK_MODE not in BLOCK_MODES:
    print(f"BLOCK_MODE '{BLOCK_MODE}' không hợp lệ (auto|manual) → dùng 'auto'")
    BLOCK_MODE = "auto"
AUTO_BLOCK_COMMENT = "devops-auto-block"  # Comment ghi vào Cloudflare List khi auto block
# IP trong BLOCK_IP_LIST đã block đủ N ngày (mốc tuổi tối thiểu) → xét xoá nếu không còn gọi đến
# gần đây (dùng Traffic, httpRequestsAdaptiveGroups — không bị giới hạn span 1 ngày / dữ liệu tối đa
# 3 ngày như Events; đã verify thực tế qua API); <=0 = tắt.
BLOCK_CLEANUP_LOOKBACK_DAYS = int(os.environ.get("BLOCK_CLEANUP_LOOKBACK_DAYS", "7"))
BLOCK_CLEANUP_TIME = os.environ.get("BLOCK_CLEANUP_TIME", "03:00")  # Giờ VN, format HH:MM, dọn 1 lần/ngày
# Telegram giới hạn tối đa ~100 "entity" định dạng (bold, code...) mỗi tin — quá số này thì phần dư
# mất định dạng <code> (Telegram tự coi là link thường). Mỗi IP là 1 entity <code>, header dùng 2
# entity <b> → chừa biên an toàn, không cấu hình qua env vì đây cũng là giới hạn kỹ thuật của Telegram.
CLEANUP_IPS_PER_MESSAGE = 90

# Báo cáo (không tự xoá) IP whitelist merchant sandbox không còn gọi domain sandbox gần đây — list này
# còn được quản lý qua Terragrunt/git nên bot không tự xoá, chỉ báo để xoá đúng qua quy trình Terraform.
SANDBOX_WHITELIST_LIST = os.environ.get("SANDBOX_WHITELIST_LIST", "merchant_ips_to_sandbox_api")
SANDBOX_WHITELIST_HOSTS = [h.strip().lower() for h in os.environ.get("SANDBOX_WHITELIST_HOSTS", "").split(",") if h.strip()]
SANDBOX_WHITELIST_LOOKBACK_DAYS = int(os.environ.get("SANDBOX_WHITELIST_LOOKBACK_DAYS", "30"))
SANDBOX_WHITELIST_SCAN_TIME = os.environ.get("SANDBOX_WHITELIST_SCAN_TIME", "09:00")  # Giờ VN, format HH:MM
SANDBOX_WHITELIST_ALERT_CHAT_ID = os.environ.get("SANDBOX_WHITELIST_ALERT_CHAT_ID") or TELEGRAM_CHAT_ID
SANDBOX_WHITELIST_IPS_PER_MESSAGE = 90  # Giới hạn entity Telegram, giống CLEANUP_IPS_PER_MESSAGE

VN_TZ = timezone(timedelta(hours=7))
CF_API_BASE = "https://api.cloudflare.com/client/v4"
GRAPHQL_URL = f"{CF_API_BASE}/graphql"
CF_HEADERS = {"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}"}
LISTS_URL = f"{CF_API_BASE}/accounts/{ACCOUNT_ID}/rules/lists"
TELEGRAM_API_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
BASE_DASHBOARD_URL = f"https://dash.cloudflare.com/{ACCOUNT_ID}/g-pay.vn/security/analytics/events"
TRAFFIC_DASHBOARD_URL = f"https://dash.cloudflare.com/{ACCOUNT_ID}/g-pay.vn/analytics/traffic"

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    trim_blocks=True,
    lstrip_blocks=True,
    autoescape=False,
)

def render_template(name: str, **context) -> str:
    return jinja_env.get_template(name).render(**context).rstrip("\n")

COUNTRY_NAMES: dict[str, str] = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AR": "Argentina",
    "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan", "BH": "Bahrain",
    "BD": "Bangladesh", "BY": "Belarus", "BE": "Belgium", "BR": "Brazil",
    "BN": "Brunei", "BG": "Bulgaria", "KH": "Cambodia", "CA": "Canada",
    "CL": "Chile", "CN": "China", "CO": "Colombia", "HR": "Croatia",
    "CY": "Cyprus", "CZ": "Czech Republic", "DK": "Denmark", "EG": "Egypt",
    "EE": "Estonia", "FI": "Finland", "FR": "France", "GE": "Georgia",
    "DE": "Germany", "GH": "Ghana", "GR": "Greece", "HK": "Hong Kong",
    "HU": "Hungary", "IN": "India", "ID": "Indonesia", "IR": "Iran",
    "IQ": "Iraq", "IE": "Ireland", "IL": "Israel", "IT": "Italy",
    "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya",
    "KP": "North Korea", "KR": "South Korea", "KW": "Kuwait", "KG": "Kyrgyzstan",
    "LA": "Laos", "LV": "Latvia", "LB": "Lebanon", "LT": "Lithuania",
    "LU": "Luxembourg", "MO": "Macau", "MY": "Malaysia", "MV": "Maldives",
    "MT": "Malta", "MX": "Mexico", "MD": "Moldova", "MN": "Mongolia",
    "MA": "Morocco", "MM": "Myanmar", "NP": "Nepal", "NL": "Netherlands",
    "NZ": "New Zealand", "NG": "Nigeria", "NO": "Norway", "OM": "Oman",
    "PK": "Pakistan", "PS": "Palestine", "PA": "Panama", "PH": "Philippines",
    "PL": "Poland", "PT": "Portugal", "QA": "Qatar", "RO": "Romania",
    "RU": "Russia", "SA": "Saudi Arabia", "SN": "Senegal", "RS": "Serbia",
    "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia", "ZA": "South Africa",
    "ES": "Spain", "LK": "Sri Lanka", "SE": "Sweden", "CH": "Switzerland",
    "TW": "Taiwan", "TJ": "Tajikistan", "TZ": "Tanzania", "TH": "Thailand",
    "TN": "Tunisia", "TR": "Turkey", "TM": "Turkmenistan", "UA": "Ukraine",
    "AE": "UAE", "GB": "United Kingdom", "US": "United States",
    "UZ": "Uzbekistan", "VN": "Vietnam", "YE": "Yemen", "ZW": "Zimbabwe",
    "T1": "Tor Network", "XX": "Unknown",
}

def country_name(code: str) -> str:
    if not code:
        return "Unknown"
    return COUNTRY_NAMES.get(code.upper(), code)


def is_allowed_referer(host: str) -> bool:
    host = host.split(":")[0].lower().rstrip(".")
    return any(host == domain or host.endswith(f".{domain}") for domain in ALLOWED_REFERER_DOMAINS)


class Severity(str, Enum):
    INFO     = "INFO"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"

SEVERITY_ORDER = [Severity.INFO, Severity.WARNING, Severity.CRITICAL]

SEVERITY_LABEL = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.WARNING:  "🟡 WARNING",
    Severity.INFO:     "⚪ INFO",
}

SOURCE_SEVERITY: dict[str, tuple[Severity, str]] = {
    "l7ddos":          (Severity.CRITICAL, "DDoS Layer 7"),
    "firewallManaged": (Severity.CRITICAL, "Cloudflare Managed WAF"),
    "bic":             (Severity.CRITICAL, "Bot Intelligence"),
    "hot":             (Severity.CRITICAL, "Hotlink Protection"),
    "ratelimit":       (Severity.INFO,     "Rate Limiting"),
    "firewallCustom":  (Severity.INFO,     "Custom Rules"),
}

def classify_source(source: str) -> tuple[Severity, str]:
    entry = SOURCE_SEVERITY.get(source or "")
    if entry:
        return entry
    return Severity.WARNING, f"Unknown source: {source}"


GROUPED_QUERY = """
query ($zoneTag: String!, $start: String!, $end: String!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      totalBlocked: firewallEventsAdaptiveGroups(
        limit: 1
        filter: { datetime_geq: $start, datetime_leq: $end, action: "block", source_neq: "firewallCustom" }
      ) {
        count
      }
      topAttackerIPs: firewallEventsAdaptiveGroups(
        limit: 100
        filter: { datetime_geq: $start, datetime_leq: $end, action: "block", source_neq: "firewallCustom" }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          clientIP
        }
      }
      httpRequestsAdaptiveGroups(
        limit: 1
        filter: { datetime_geq: $start, datetime_leq: $end }
      ) {
        sum { visits }
      }
    }
  }
}
"""

# Chi tiết (path, UA, ASN, severity) cho 1 IP cụ thể — gọi riêng cho các IP đã xác định cần xử lý,
# group theo clientIP thật (không như topAttackerIPs ở trên) nên không bị path/UA làm vỡ vụn thứ hạng
ATTACKER_IP_DETAIL_QUERY = """
query ($zoneTag: String!, $start: String!, $end: String!, $ip: String!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      events: firewallEventsAdaptiveGroups(
        limit: 10
        filter: { datetime_geq: $start, datetime_leq: $end, action: "block", source_neq: "firewallCustom", clientIP: $ip }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          clientAsn
          clientASNDescription
          clientCountryName
          clientRequestHTTPHost
          userAgent
          clientRequestPath
          source
        }
      }
    }
  }
}
"""

STATUS_499_QUERY = """
query ($zoneTag: String!, $start: String!, $end: String!, $host: String!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      total499: httpRequestsAdaptiveGroups(
        limit: 1
        filter: { datetime_geq: $start, datetime_leq: $end, edgeResponseStatus: 499, clientRequestHTTPHost: $host }
      ) {
        count
      }
      top499: httpRequestsAdaptiveGroups(
        limit: 5
        filter: { datetime_geq: $start, datetime_leq: $end, edgeResponseStatus: 499, clientRequestHTTPHost: $host }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          clientRequestPath
          clientCountryName
        }
      }
    }
  }
}
"""

# Kiểm tra IP nào trong danh sách vẫn còn gọi đến gần đây (bất kể có khớp đúng rule block hay không —
# đã nằm trong BLOCK_IP_LIST tức là đã xác định vi phạm, chỉ cần biết còn "gọi" hay im hẳn) trước khi
# dọn khỏi list. Dùng httpRequestsAdaptiveGroups (Traffic) thay vì firewallEventsAdaptiveGroups (Events)
# vì Traffic không bị giới hạn span 1 ngày / dữ liệu tối đa 3 ngày như Events (đã verify thực tế qua API,
# Traffic query được nguyên BLOCK_CLEANUP_LOOKBACK_DAYS ngày trong 1 lần, không cần chia theo từng ngày).
RECENT_TRAFFIC_ACTIVITY_QUERY = """
query ($zoneTag: String!, $start: String!, $end: String!, $ips: [String!]) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      recentHits: httpRequestsAdaptiveGroups(
        limit: 200
        filter: { datetime_geq: $start, datetime_leq: $end, clientIP_in: $ips }
      ) {
        dimensions {
          clientIP
        }
      }
    }
  }
}
"""

# Giống RECENT_TRAFFIC_ACTIVITY_QUERY nhưng lọc thêm theo host — dùng cho báo cáo IP whitelist
# sandbox không còn gọi đúng domain sandbox gần đây (không phải "còn gọi bất kỳ đâu")
RECENT_TRAFFIC_ACTIVITY_BY_HOST_QUERY = """
query ($zoneTag: String!, $start: String!, $end: String!, $ips: [String!], $hosts: [String!]) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      recentHits: httpRequestsAdaptiveGroups(
        limit: 200
        filter: { datetime_geq: $start, datetime_leq: $end, clientIP_in: $ips, clientRequestHTTPHost_in: $hosts }
      ) {
        dimensions {
          clientIP
        }
      }
    }
  }
}
"""

# Query lấy tất cả blocked events để check merchant IPs và watch IPs
BLOCKED_EVENTS_QUERY = """
query ($zoneTag: String!, $start: String!, $end: String!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      firewallEventsAdaptive(
        limit: 100
        filter: {
          datetime_geq: $start
          datetime_leq: $end
          action: "block"
          source_neq: "firewallCustom"
        }
        orderBy: [datetime_DESC]
      ) {
        clientIP
        clientAsn
        clientASNDescription
        clientCountryName
        clientRequestHTTPHost
        clientRequestHTTPMethodName
        clientRequestHTTPProtocol
        clientRequestPath
        clientRequestQuery
        clientRefererHost
        edgeResponseStatus
        userAgent
        rayName
        source
        datetime
      }
    }
  }
}
"""

def with_referer_host_filter(query: str) -> str:
    # REFERER_HOSTS rỗng = không lọc host (quét tất cả).
    # Hosts lấy từ config (không phải input người dùng); json.dumps escape đúng chuẩn chuỗi GraphQL
    if not REFERER_HOSTS:
        return query.replace("__HOST_FILTER__", "")
    return query.replace("__HOST_FILTER__", f", clientRequestHTTPHost_in: {json.dumps(REFERER_HOSTS)}")


# Quét toàn bộ traffic (không chỉ traffic đã bị Cloudflare block) theo referer,
# vì domain lạ dẫn traffic vào không nhất thiết bị WAF chặn.
# __HOST_FILTER__ được thay bằng with_referer_host_filter() để giới hạn theo REFERER_HOSTS (rỗng = không giới hạn).
REFERER_QUERY = """
query ($zoneTag: String!, $start: String!, $end: String!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      referers: httpRequestsAdaptiveGroups(
        limit: 100
        filter: { datetime_geq: $start, datetime_leq: $end__HOST_FILTER__ }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          clientRefererHost
          clientRequestHTTPHost
        }
      }
    }
  }
}
"""

# Query riêng lấy top path + top IP cho 1 referer cụ thể — chỉ gọi cho các referer đã xác định là đáng ngờ
REFERER_DETAIL_QUERY = """
query ($zoneTag: String!, $start: String!, $end: String!, $referer: String!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      paths: httpRequestsAdaptiveGroups(
        limit: 5
        filter: { datetime_geq: $start, datetime_leq: $end, clientRefererHost: $referer__HOST_FILTER__ }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          clientRequestPath
        }
      }
      ips: httpRequestsAdaptiveGroups(
        limit: 5
        filter: { datetime_geq: $start, datetime_leq: $end, clientRefererHost: $referer__HOST_FILTER__ }
        orderBy: [count_DESC]
      ) {
        count
        dimensions {
          clientIP
          clientCountryName
        }
      }
    }
  }
}
"""

last_alert_time: dict[str, datetime] = {}
merchant_ips: set[str] = set()
merchant_ip_hosts: dict[str, set[str]] = {}
merchant_ip_names: dict[str, set[str]] = {}
merchant_cache_updated_at: datetime | None = None
list_name_to_id: dict[str, str] = {}
last_poll_window_end: datetime | None = None
# Lịch sử số lần bị block của từng IP trong 24h gần nhất — bắt kiểu tấn công chậm/lặp lại
# (vd 1 IP chỉ bắn vài request mỗi giờ, không đời nào đạt BLOCK_THRESHOLD trong 1 cửa sổ poll)
daily_block_history: dict[str, list[tuple[datetime, int]]] = {}
# Hardcode (không qua env/Helm) vì đây là ngưỡng tinh chỉnh ít khi đổi — đổi thì sửa code + deploy lại
DAILY_BLOCK_THRESHOLD = 20
block_mode: str = BLOCK_MODE  # Lưu in-memory, restart quay về BLOCK_MODE
started_at = datetime.now(timezone.utc)
bot_username: str = ""

MODE_LABEL = {
    "auto":   "🤖 AUTO (tự động block)",
    "manual": "✋ MANUAL (bấm nút để block)",
}


def get_time_range(window_seconds: int | None = None):
    global last_poll_window_end
    now = datetime.now(timezone.utc)
    if window_seconds is not None:
        start = now - timedelta(seconds=window_seconds)
        return start.strftime("%Y-%m-%dT%H:%M:%SZ"), now.strftime("%Y-%m-%dT%H:%M:%SZ")
    # poll_loop (không truyền window_seconds): cửa sổ liền mạch — lấy đúng điểm kết thúc lần
    # poll trước làm điểm bắt đầu lần này, không tính lại now()-POLL_INTERVAL mỗi lần (tránh hở
    # vài giây không được quét do thời gian xử lý giữa các lần poll).
    start = last_poll_window_end or (now - timedelta(seconds=POLL_INTERVAL))
    last_poll_window_end = now
    return start.strftime("%Y-%m-%dT%H:%M:%SZ"), now.strftime("%Y-%m-%dT%H:%M:%SZ")

def poll_window_label() -> str:
    if POLL_INTERVAL % 60 == 0:
        return f"{POLL_INTERVAL // 60}m"
    return f"{POLL_INTERVAL}s"

def should_alert(key: str) -> bool:
    now = datetime.now(timezone.utc)
    last = last_alert_time.get(key)
    if last is not None and (now - last).total_seconds() < ALERT_COOLDOWN:
        return False
    last_alert_time[key] = now
    return True

async def query_cloudflare(client: httpx.AsyncClient, query: str, variables: dict, label: str) -> dict | None:
    try:
        resp = await client.post(
            GRAPHQL_URL,
            headers=CF_HEADERS,
            json={"query": query, "variables": variables},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        print(f"HTTP error ({label}) {e.response.status_code}: {e.response.text}")
        return None
    except Exception as e:
        print(f"Error querying Cloudflare ({label}): {e}")
        return None

def list_items_url(list_id: str) -> str:
    return f"{LISTS_URL}/{list_id}/items"

def list_bulk_operation_url(operation_id: str) -> str:
    return f"{LISTS_URL}/bulk_operations/{operation_id}"

async def refresh_list_catalog(client: httpx.AsyncClient) -> None:
    global list_name_to_id
    try:
        resp = await client.get(LISTS_URL, headers=CF_HEADERS, timeout=30)
        resp.raise_for_status()
        list_name_to_id = {item["name"]: item["id"] for item in resp.json().get("result", [])}
    except Exception as e:
        print(f"Error fetching Cloudflare IP list catalog: {e}")

async def get_list_id(client: httpx.AsyncClient, name: str) -> str | None:
    if name not in list_name_to_id:
        await refresh_list_catalog(client)
    return list_name_to_id.get(name)

async def fetch_list_items(client: httpx.AsyncClient, list_id: str) -> list[dict]:
    items: list[dict] = []
    cursor = None
    while True:
        params = {"per_page": 100}
        if cursor:
            params["cursor"] = cursor
        resp = await client.get(list_items_url(list_id), headers=CF_HEADERS, params=params, timeout=30)
        resp.raise_for_status()
        body = resp.json()
        items.extend(body.get("result", []))
        cursor = body.get("result_info", {}).get("cursors", {}).get("after")
        if not cursor:
            break
    return items

async def refresh_merchant_cache(client: httpx.AsyncClient) -> None:
    global merchant_ips, merchant_ip_hosts, merchant_ip_names, merchant_cache_updated_at
    ip_hosts: dict[str, set[str]] = {}
    ip_names: dict[str, set[str]] = {}
    for name in MERCHANT_IP_LISTS:
        list_id = await get_list_id(client, name)
        if not list_id:
            print(f"Merchant IP list '{name}' not found on Cloudflare")
            continue
        allowed_hosts = MERCHANT_LIST_ALLOWED_HOSTS.get(name, set())
        if not allowed_hosts:
            print(f"Merchant IP list '{name}': chưa cấu hình allowed host trong MERCHANT_LIST_ALLOWED_HOSTS")
        try:
            items = await fetch_list_items(client, list_id)
        except Exception as e:
            print(f"Error fetching merchant list '{name}': {e}")
            continue
        for item in items:
            ip = (item.get("ip") or "").split("/")[0]
            if not ip:
                continue
            ip_hosts.setdefault(ip, set()).update(allowed_hosts)
            comment = (item.get("comment") or "").strip()
            if comment:
                ip_names.setdefault(ip, set()).add(comment)
    merchant_ip_hosts = ip_hosts
    merchant_ip_names = ip_names
    merchant_ips = set(ip_hosts.keys())
    merchant_cache_updated_at = datetime.now(timezone.utc)
    print(f"Merchant IP cache refreshed: {len(merchant_ips)} IPs from {MERCHANT_IP_LISTS}")

async def ensure_merchant_cache(client: httpx.AsyncClient) -> None:
    if not MERCHANT_IP_LISTS:
        return
    stale = (
        merchant_cache_updated_at is None
        or (datetime.now(timezone.utc) - merchant_cache_updated_at).total_seconds() > MERCHANT_CACHE_REFRESH_INTERVAL
    )
    if stale:
        await refresh_merchant_cache(client)

def is_merchant_ip(ip: str) -> bool:
    return bool(ip) and ip in merchant_ips

def merchant_status_line(ip: str) -> str:
    if not ip:
        return ""
    if not is_merchant_ip(ip):
        return "⚠️ <b>KHÔNG CÓ TRONG DANH SÁCH MERCHANT</b>"
    names = sorted(merchant_ip_names.get(ip, set()))
    declared = sorted(merchant_ip_hosts.get(ip, set()))
    line = "🏪 <b>MERCHANT IP</b>"
    if names:
        line += f" ({', '.join(names)})"
    if declared:
        line += f" (domain khai báo: {', '.join(declared)})"
    return line

async def wait_list_operation(client: httpx.AsyncClient, operation_id: str) -> tuple[bool | None, str]:
    """Poll bulk operation của Cloudflare List. True/False = completed/failed; None = hết 40s chưa confirm."""
    for _ in range(20):
        await asyncio.sleep(2)
        try:
            op_resp = await client.get(list_bulk_operation_url(operation_id), headers=CF_HEADERS, timeout=30)
            op_resp.raise_for_status()
            result = op_resp.json().get("result", {})
        except Exception as e:
            return False, str(e)
        if result.get("status") == "completed":
            return True, "OK"
        if result.get("status") == "failed":
            return False, result.get("error") or "Cloudflare operation failed"
    return None, "Timeout"

async def add_ips_to_block_list(client: httpx.AsyncClient, ips: list[str], comment: str) -> tuple[bool, str]:
    # Gửi tất cả IP trong 1 bulk operation → chỉ chờ Cloudflare confirm 1 lần
    list_id = await get_list_id(client, BLOCK_IP_LIST)
    if not list_id:
        return False, f"Không tìm thấy list '{BLOCK_IP_LIST}' trên Cloudflare"
    try:
        resp = await client.post(
            list_items_url(list_id),
            headers=CF_HEADERS,
            json=[{"ip": ip, "comment": comment} for ip in ips],
            timeout=30,
        )
        resp.raise_for_status()
        operation_id = resp.json()["result"]["operation_id"]
    except Exception as e:
        return False, str(e)
    ok, info = await wait_list_operation(client, operation_id)
    if ok is None:
        print(f"[BLOCK TIMEOUT] IP {', '.join(ips)} — Cloudflare không confirm sau 40s, nhưng có thể đã block thật")
        return False, "Timeout chờ Cloudflare xử lý (IP có thể đã được block)"
    return ok, info

async def add_ip_to_block_list(client: httpx.AsyncClient, ip: str, username: str = "unknown") -> tuple[bool, str]:
    return await add_ips_to_block_list(client, [ip], block_comment(username))

def block_comment(name: str) -> str:
    return f"{name} - {datetime.now(VN_TZ):%d/%m/%Y %H:%M}"

def ip_in_list_item(ip: str, item_ip: str) -> bool:
    # Item trong list có thể là IP đơn hoặc CIDR (vd IPv6 /64)
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(item_ip, strict=False)
    except ValueError:
        return False

async def remove_ip_from_block_list(client: httpx.AsyncClient, ip: str) -> tuple[bool, str]:
    list_id = await get_list_id(client, BLOCK_IP_LIST)
    if not list_id:
        return False, f"Không tìm thấy list '{BLOCK_IP_LIST}' trên Cloudflare"
    try:
        resp = await client.get(
            list_items_url(list_id), headers=CF_HEADERS, params={"search": ip, "per_page": 100}, timeout=30
        )
        resp.raise_for_status()
        item_ids = [item["id"] for item in resp.json().get("result", []) if ip_in_list_item(ip, item.get("ip", ""))]
        if not item_ids:
            return True, "IP không có trong list"
        # httpx .delete() không nhận body → dùng .request()
        resp = await client.request(
            "DELETE",
            list_items_url(list_id),
            headers=CF_HEADERS,
            json={"items": [{"id": item_id} for item_id in item_ids]},
            timeout=30,
        )
        resp.raise_for_status()
        operation_id = resp.json()["result"]["operation_id"]
    except Exception as e:
        return False, str(e)
    ok, info = await wait_list_operation(client, operation_id)
    if ok is None:
        print(f"[UNBLOCK TIMEOUT] IP {ip} — Cloudflare không confirm sau 40s, nhưng có thể đã unblock thật")
        return False, "Timeout chờ Cloudflare xử lý (IP có thể đã được unblock)"
    return ok, info

def auto_block_candidates(ips: list[str]) -> list[str]:
    # Không auto block merchant IP và WATCH_IPS (WATCH_IPS vẫn có nút Block thủ công)
    return [ip for ip in dict.fromkeys(ips) if ip and ip != "unknown" and not is_merchant_ip(ip) and ip not in WATCH_IPS]

async def auto_block_ips(client: httpx.AsyncClient, ips: list[str]) -> tuple[dict[str, str], set[str]]:
    """Trả về (dòng trạng thái theo IP để hiện trong alert, tập IP đã block thành công)."""
    lines: dict[str, str] = {}
    blocked: set[str] = set()
    to_block = auto_block_candidates(ips)
    if not to_block:
        return lines, blocked
    print(f"[AUTO BLOCK] {', '.join(to_block)}...")
    ok, info = await add_ips_to_block_list(client, to_block, block_comment(AUTO_BLOCK_COMMENT))
    for ip in to_block:
        if ok:
            lines[ip] = "🔒 <b>Đã tự động block</b>"
            blocked.add(ip)
        else:
            lines[ip] = f"❌ Auto block lỗi: {html.escape(info)}"
    if ok:
        print(f"[AUTO BLOCK OK] {', '.join(to_block)}")
    else:
        print(f"[AUTO BLOCK FAILED] {', '.join(to_block)}: {info}")
    return lines, blocked


async def remove_items_from_block_list(client: httpx.AsyncClient, list_id: str, item_ids: list[str]) -> tuple[bool, str]:
    try:
        resp = await client.request(
            "DELETE",
            list_items_url(list_id),
            headers=CF_HEADERS,
            json={"items": [{"id": item_id} for item_id in item_ids]},
            timeout=30,
        )
        resp.raise_for_status()
        operation_id = resp.json()["result"]["operation_id"]
    except Exception as e:
        return False, str(e)
    ok, info = await wait_list_operation(client, operation_id)
    if ok is None:
        print(f"[CLEANUP TIMEOUT] Cloudflare không confirm xoá {len(item_ids)} IP sau 40s, nhưng có thể đã xoá thật")
        return False, "Timeout chờ Cloudflare xử lý"
    return ok, info


async def ips_with_recent_traffic(client: httpx.AsyncClient, ips: list[str], start: str, end: str) -> set[str]:
    data = await query_cloudflare(
        client, RECENT_TRAFFIC_ACTIVITY_QUERY, {"zoneTag": ZONE_ID, "start": start, "end": end, "ips": ips}, "cleanup-recent-traffic"
    )
    if data is None:
        return set(ips)  # Lỗi query → an toàn, coi như vẫn active, không xoá nhầm
    errors = data.get("errors")
    if errors:
        print(f"GraphQL errors (cleanup-recent-traffic): {errors}")
        return set(ips)  # Lỗi (vd quota) → an toàn, coi như vẫn active, không xoá nhầm
    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return set(ips)
    groups = zones[0].get("recentHits", [])
    return {(g.get("dimensions") or {}).get("clientIP", "") for g in groups}

async def collect_still_active_ips(client: httpx.AsyncClient, ips: list[str], lookback_days: int) -> set[str]:
    """IP nào còn gọi đến trong lookback_days ngày gần nhất (bất kể có khớp đúng rule block hay không —
    đã nằm trong BLOCK_IP_LIST tức đã xác định vi phạm, chỉ cần biết còn "gọi" hay đã im hẳn)."""
    start = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    still_active: set[str] = set()
    batch_size = 100
    for i in range(0, len(ips), batch_size):
        batch = ips[i:i + batch_size]
        still_active |= await ips_with_recent_traffic(client, batch, start, end)
    return still_active


async def cleanup_expired_blocks(client: httpx.AsyncClient):
    """Dọn IP trong BLOCK_IP_LIST đã bị block đủ BLOCK_CLEANUP_LOOKBACK_DAYS ngày (tính từ created_on,
    mốc tuổi tối thiểu) VÀ không còn gọi đến trong đúng khoảng đó — tránh tràn quota IP Lists.
    Cần đủ tuổi mới xét, để tránh IP vừa mới block vài giờ bị coi nhầm là "đã im hơi lặng tiếng"."""
    if BLOCK_CLEANUP_LOOKBACK_DAYS <= 0:
        return
    list_id = await get_list_id(client, BLOCK_IP_LIST)
    if not list_id:
        print(f"[CLEANUP] Không tìm thấy list '{BLOCK_IP_LIST}'")
        return
    items = await fetch_list_items(client, list_id)
    age_cutoff = datetime.now(timezone.utc) - timedelta(days=BLOCK_CLEANUP_LOOKBACK_DAYS)

    candidates: list[tuple[str, str]] = []  # (item_id, ip)
    for item in items:
        ip = (item.get("ip") or "").split("/")[0]
        created_on = item.get("created_on")
        if not ip or not created_on:
            continue
        try:
            created_dt = datetime.fromisoformat(created_on.replace("Z", "+00:00"))
        except ValueError:
            continue
        if created_dt <= age_cutoff:
            candidates.append((item["id"], ip))

    if not candidates:
        print(f"[CLEANUP] Không có IP nào đã block đủ {BLOCK_CLEANUP_LOOKBACK_DAYS} ngày để xét xoá")
        return

    print(f"[CLEANUP] {len(candidates)} IP đã block đủ {BLOCK_CLEANUP_LOOKBACK_DAYS} ngày, kiểm tra hoạt động {BLOCK_CLEANUP_LOOKBACK_DAYS} ngày gần đây...")
    candidate_ips = [ip for _, ip in candidates]
    still_active = await collect_still_active_ips(client, candidate_ips, BLOCK_CLEANUP_LOOKBACK_DAYS)

    to_remove = [(item_id, ip) for item_id, ip in candidates if ip not in still_active]
    if not to_remove:
        print(f"[CLEANUP] {len(candidates)} IP đủ tuổi nhưng vẫn còn hoạt động trong {BLOCK_CLEANUP_LOOKBACK_DAYS} ngày gần đây → giữ nguyên")
        return

    item_ids = [item_id for item_id, _ in to_remove]
    removed_ips = [ip for _, ip in to_remove]
    ok, info = await remove_items_from_block_list(client, list_id, item_ids)
    if not ok:
        print(f"[CLEANUP FAILED] {info}")
        return
    print(f"[CLEANUP OK] Đã gỡ {len(removed_ips)} IP không còn hoạt động: {', '.join(removed_ips)}")
    await send_cleanup_digest(client, removed_ips)


async def send_cleanup_digest(client: httpx.AsyncClient, removed_ips: list[str]):
    # Chia theo CLEANUP_IPS_PER_MESSAGE (không phải theo ký tự) để không vượt giới hạn entity của Telegram
    chunks = [removed_ips[i:i + CLEANUP_IPS_PER_MESSAGE] for i in range(0, len(removed_ips), CLEANUP_IPS_PER_MESSAGE)]
    total_pages = len(chunks)
    for i, chunk in enumerate(chunks, 1):
        page_label = f" ({i}/{total_pages})" if total_pages > 1 else ""
        message = format_cleanup_alert(chunk, len(removed_ips), page_label)
        await send_telegram(client, message, chat_id=CLEANUP_ALERT_CHAT_ID)
        if total_pages > 1:
            await asyncio.sleep(0.3)


async def ips_with_recent_traffic_to_hosts(client: httpx.AsyncClient, ips: list[str], hosts: list[str], start: str, end: str) -> set[str]:
    data = await query_cloudflare(
        client, RECENT_TRAFFIC_ACTIVITY_BY_HOST_QUERY,
        {"zoneTag": ZONE_ID, "start": start, "end": end, "ips": ips, "hosts": hosts},
        "sandbox-whitelist-recent-traffic",
    )
    if data is None:
        return set(ips)  # Lỗi query → an toàn, coi như vẫn active
    errors = data.get("errors")
    if errors:
        print(f"GraphQL errors (sandbox-whitelist-recent-traffic): {errors}")
        return set(ips)
    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return set(ips)
    groups = zones[0].get("recentHits", [])
    return {(g.get("dimensions") or {}).get("clientIP", "") for g in groups}


async def collect_ips_active_on_hosts(client: httpx.AsyncClient, ips: list[str], hosts: list[str], lookback_days: int) -> set[str]:
    start = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    still_active: set[str] = set()
    batch_size = 100
    for i in range(0, len(ips), batch_size):
        batch = ips[i:i + batch_size]
        still_active |= await ips_with_recent_traffic_to_hosts(client, batch, hosts, start, end)
    return still_active


async def check_sandbox_whitelist_staleness(client: httpx.AsyncClient):
    """Báo cáo (KHÔNG tự xoá — list quản lý qua Terragrunt/git, bot xoá trực tiếp sẽ bị Terraform
    apply lại) IP trong SANDBOX_WHITELIST_LIST đã whitelist đủ SANDBOX_WHITELIST_LOOKBACK_DAYS ngày
    (mốc tuổi tối thiểu) mà không gọi domain sandbox (SANDBOX_WHITELIST_HOSTS) nào trong đúng khoảng đó.
    Cần đủ tuổi mới xét, để tránh IP vừa whitelist vài hôm (merchant chưa kịp gọi thử) bị báo nhầm."""
    if SANDBOX_WHITELIST_LOOKBACK_DAYS <= 0 or not SANDBOX_WHITELIST_HOSTS:
        return
    list_id = await get_list_id(client, SANDBOX_WHITELIST_LIST)
    if not list_id:
        print(f"[SANDBOX WHITELIST] Không tìm thấy list '{SANDBOX_WHITELIST_LIST}'")
        return
    items = await fetch_list_items(client, list_id)
    age_cutoff = datetime.now(timezone.utc) - timedelta(days=SANDBOX_WHITELIST_LOOKBACK_DAYS)

    candidates: list[tuple[str, str]] = []  # (ip, comment)
    for item in items:
        ip = (item.get("ip") or "").split("/")[0]
        created_on = item.get("created_on")
        if not ip or not created_on:
            continue
        try:
            created_dt = datetime.fromisoformat(created_on.replace("Z", "+00:00"))
        except ValueError:
            continue
        if created_dt <= age_cutoff:
            candidates.append((ip, item.get("comment") or ""))

    if not candidates:
        print(f"[SANDBOX WHITELIST] Không có IP nào whitelist đủ {SANDBOX_WHITELIST_LOOKBACK_DAYS} ngày để xét")
        return

    print(f"[SANDBOX WHITELIST] {len(candidates)} IP đã whitelist đủ {SANDBOX_WHITELIST_LOOKBACK_DAYS} ngày, kiểm tra còn gọi domain sandbox không...")
    candidate_ips = [ip for ip, _ in candidates]
    still_active = await collect_ips_active_on_hosts(client, candidate_ips, SANDBOX_WHITELIST_HOSTS, SANDBOX_WHITELIST_LOOKBACK_DAYS)

    stale = [(ip, comment) for ip, comment in candidates if ip not in still_active]
    if not stale:
        print(f"[SANDBOX WHITELIST] {len(candidates)} IP đủ tuổi nhưng vẫn còn gọi domain sandbox → không báo cáo")
        return

    print(f"[SANDBOX WHITELIST] {len(stale)} IP không còn gọi domain sandbox: {', '.join(ip for ip, _ in stale)}")
    await send_sandbox_whitelist_digest(client, stale)


def format_sandbox_whitelist_alert(items: list[tuple[str, str]], total_count: int, page_label: str = "") -> str:
    return render_template(
        "sandbox_whitelist.html",
        time_display=datetime.now(VN_TZ).strftime("%H:%M %d/%m/%Y"),
        list_name=SANDBOX_WHITELIST_LIST,
        lookback_days=SANDBOX_WHITELIST_LOOKBACK_DAYS,
        count=total_count,
        page_label=page_label,
        items=items,
    )


async def send_sandbox_whitelist_digest(client: httpx.AsyncClient, stale: list[tuple[str, str]]):
    chunks = [stale[i:i + SANDBOX_WHITELIST_IPS_PER_MESSAGE] for i in range(0, len(stale), SANDBOX_WHITELIST_IPS_PER_MESSAGE)]
    total_pages = len(chunks)
    for i, chunk in enumerate(chunks, 1):
        page_label = f" ({i}/{total_pages})" if total_pages > 1 else ""
        message = format_sandbox_whitelist_alert(chunk, len(stale), page_label)
        await send_telegram(client, message, chat_id=SANDBOX_WHITELIST_ALERT_CHAT_ID)
        if total_pages > 1:
            await asyncio.sleep(0.3)


TELEGRAM_MAX_LEN = 4096

def split_message(message: str) -> list[str]:
    # Chia theo từng dòng (mỗi dòng trong code luôn tự đóng tag HTML trong chính nó,
    # không có tag nào mở ở dòng này rồi đóng ở dòng khác) để không bao giờ để lại tag hở.
    if len(message) <= TELEGRAM_MAX_LEN:
        return [message]
    chunks: list[str] = []
    current = ""
    for line in message.split("\n"):
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > TELEGRAM_MAX_LEN:
            if current:
                chunks.append(current)
            current = line[:TELEGRAM_MAX_LEN]  # 1 dòng đơn lẻ dài hơn cả giới hạn — trường hợp cực hiếm
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks

async def send_telegram(client: httpx.AsyncClient, message: str, keyboard: list[list[dict]] | None = None, chat_id: str | None = None):
    chunks = split_message(message)
    total = len(chunks)
    for i, chunk in enumerate(chunks, 1):
        text = chunk if total == 1 else f"{chunk}\n\n({i}/{total})"
        payload = {
            "chat_id": chat_id or TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if keyboard and i == total:
            payload["reply_markup"] = {"inline_keyboard": keyboard}
        try:
            resp = await client.post(f"{TELEGRAM_API_BASE}/sendMessage", json=payload, timeout=10)
            print(f"Telegram response: {resp.status_code} ({i}/{total})")
        except Exception as e:
            print(f"Error sending Telegram: {e}")

async def answer_callback_query(client: httpx.AsyncClient, callback_id: str, text: str = "", show_alert: bool = False):
    try:
        await client.post(
            f"{TELEGRAM_API_BASE}/answerCallbackQuery",
            json={"callback_query_id": callback_id, "text": text, "show_alert": show_alert},
            timeout=10,
        )
    except Exception as e:
        print(f"Error answering callback query: {e}")

async def edit_message_reply_markup(client: httpx.AsyncClient, chat_id, message_id, keyboard: list[list[dict]]):
    try:
        await client.post(
            f"{TELEGRAM_API_BASE}/editMessageReplyMarkup",
            json={"chat_id": chat_id, "message_id": message_id, "reply_markup": {"inline_keyboard": keyboard}},
            timeout=10,
        )
    except Exception as e:
        print(f"Error editing message markup: {e}")

def block_button(ip: str) -> dict:
    return {"text": f"🚫 Block {ip}", "callback_data": f"block:{ip}"}

def unblock_button(ip: str) -> dict:
    return {"text": f"🔓 Unblock {ip}", "callback_data": f"unblock:{ip}"}

def toggle_button(text: str, next_action: str, ip: str) -> dict:
    # Nút vừa hiện trạng thái (text) vừa bấm được luôn — callback_data trỏ tới hành động tiếp theo
    # (đảo chiều khi thành công, thử lại đúng hành động vừa lỗi khi thất bại)
    return {"text": text, "callback_data": f"{next_action}:{ip}"}

def build_block_keyboard(ips: list[str], blocked: set[str] | None = None) -> list[list[dict]] | None:
    # IP đã block → nút Unblock; chưa block → nút Block; merchant IP → không có nút
    blocked = blocked or set()
    rows = []
    seen = set()
    for ip in ips:
        if not ip or ip in seen or is_merchant_ip(ip):
            continue
        seen.add(ip)
        rows.append([unblock_button(ip) if ip in blocked else block_button(ip)])
    return rows or None

def replace_ip_rows(rows: list[list[dict]], ip: str, replacement: list[list[dict]]) -> list[list[dict]]:
    # Gộp TOÀN BỘ hàng thuộc về IP này (nút action hiện tại + mọi dòng trạng thái cũ từ các lần
    # Block/Unblock trước đó) thành đúng `replacement` — tránh dồn thành 1 đống dòng khi bấm qua lại.
    suffix = f":{ip}"
    new_rows = []
    inserted = False
    for row in rows:
        if any((btn.get("callback_data") or "").endswith(suffix) for btn in row):
            if not inserted:
                new_rows.extend(replacement)
                inserted = True
        else:
            new_rows.append(row)
    return new_rows


def format_ddos_alert(
    classified: list,
    total_blocked: int,
    total_visits: int,
    worst_severity: Severity,
    block_lines: dict[str, str] | None = None,
    only_ips: list[str] | None = None,
) -> str:
    time_display = datetime.now(VN_TZ).strftime("%H:%M %d/%m/%Y")

    def ip_events_url(ip: str) -> str:
        return f"{BASE_DASHBOARD_URL}?ip={quote(ip, safe='')}&action=block"

    ip_groups: dict[str, dict] = {}
    for severity, reason, e in classified:
        d = e["dimensions"]
        ip = d.get("clientIP", "unknown")
        if ip not in ip_groups:
            ip_groups[ip] = {
                "severity": severity,
                "reason": reason,
                "count": 0,
                "country": country_name(d.get("clientCountryName", "")),
                "isp": d.get("clientASNDescription", ""),
                "asn": d.get("clientAsn", ""),
                "host": d.get("clientRequestHTTPHost", ""),
                "ua": (d.get("userAgent") or "")[:30],
                "paths": [],
            }
        ip_groups[ip]["count"] += e["count"]
        path = (d.get("clientRequestPath") or "/")[:50]
        ip_groups[ip]["paths"].append((path, e["count"]))

    ips_context = [
        {
            "ip": ip,
            "count": info["count"],
            "severity_label": SEVERITY_LABEL[info["severity"]],
            "country": info["country"],
            "isp": info["isp"],
            "asn": info["asn"],
            "host": info["host"],
            "ua": info["ua"],
            "reason": info["reason"],
            "merchant_line": merchant_status_line(ip),
            "block_line": (block_lines or {}).get(ip, ""),
            "paths": info["paths"],
            "events_url": ip_events_url(ip),
        }
        for ip, info in list(ip_groups.items())[:5]
        if only_ips is None or ip in only_ips
    ]

    return render_template(
        "attack.html",
        severity_label=SEVERITY_LABEL[worst_severity],
        time_display=time_display,
        poll_window=poll_window_label(),
        total_visits_fmt=f"{total_visits:,}",
        total_blocked_fmt=f"{total_blocked:,}",
        ips=ips_context,
    )


def format_watch_ip_alert(event: dict, ip: str) -> str:
    time_display = datetime.now(VN_TZ).strftime("%H:%M %d/%m/%Y")
    source = event.get("source", "")
    severity, reason = classify_source(source)

    return render_template(
        "merchant.html",
        severity_label=SEVERITY_LABEL[severity],
        time_display=time_display,
        ip=ip,
        reason=reason,
        merchant_line=merchant_status_line(ip),
        host=event.get("clientRequestHTTPHost", ""),
        path=event.get("clientRequestPath", ""),
        method=event.get("clientRequestHTTPMethodName", ""),
        protocol=event.get("clientRequestHTTPProtocol", ""),
        query=(event.get("clientRequestQuery") or "")[:60],
        status=event.get("edgeResponseStatus", ""),
        referer=event.get("clientRefererHost", ""),
        country=country_name(event.get("clientCountryName", "")),
        asn=event.get("clientAsn", ""),
        isp=event.get("clientASNDescription", ""),
        ua=(event.get("userAgent") or "")[:40],
        ray=event.get("rayName", ""),
        dashboard_url=f"{BASE_DASHBOARD_URL}?ip={ip}&action=block",
    )


def common_path_prefix(paths: list[str]) -> str:
    """Prefix chung của các path, cắt về đúng ranh giới '/' gần nhất (không cắt giữa 1 đoạn)."""
    if len(paths) < 2:
        return ""
    prefix = os.path.commonprefix(paths)
    if "/" not in prefix:
        return ""
    return prefix[: prefix.rindex("/") + 1]


def format_suspicious_referer_entry(referer: str, info: dict) -> str:
    hosts = sorted((info.get("hosts") or {}).items(), key=lambda x: -x[1])[:3]

    ips = []
    for ip_g in (info.get("ips") or [])[:5]:
        d = ip_g.get("dimensions") or {}
        ips.append((d.get("clientIP", "unknown"), ip_g.get("count", 0), country_name(d.get("clientCountryName", ""))))

    entries = [
        ((p.get("dimensions") or {}).get("clientRequestPath") or "/", p.get("count", 0))
        for p in (info.get("paths") or [])[:5]
    ]
    prefix = common_path_prefix([path for path, _ in entries]) if entries else ""
    display_paths = [(path[len(prefix):], count) for path, count in entries] if prefix else entries

    return render_template(
        "referer_entry.html",
        referer=referer,
        count_fmt=f"{info['count']:,}",
        hosts=hosts,
        ips=ips,
        prefix=prefix,
        display_paths=display_paths,
    )


def build_referer_digest_pages(ranked: list[tuple[str, dict]], scan_window: str) -> list[tuple[str, list[str]]]:
    """Gói các domain thành từng trang (mỗi trang <= giới hạn Telegram), không cắt domain nào giữa chừng.
    Trả về list (nội dung tin, danh sách referer trong tin đó) để gọi nơi khác build nút Block theo đúng trang."""
    time_display = datetime.now(VN_TZ).strftime("%H:%M %d/%m/%Y")
    dashboard_url = f"{TRAFFIC_DASHBOARD_URL}?time-window=1440"
    total = sum(info["count"] for _, info in ranked)
    footer = render_template("referer_footer.html", dashboard_url=dashboard_url)

    def full_header(page_label: str) -> str:
        return render_template(
            "referer_header.html",
            is_continuation=False,
            page_label=page_label,
            time_display=time_display,
            scan_window=scan_window,
            domain_count=len(ranked),
            total_fmt=f"{total:,}",
        )

    def continuation_header(page_label: str) -> str:
        return render_template("referer_header.html", is_continuation=True, page_label=page_label)

    # Đóng gói theo budget xấu nhất (header đầy đủ) để luôn an toàn — trang tiếp theo
    # dùng header ngắn hơn nên thực tế sẽ còn dư chút chỗ, không sao.
    budget = TELEGRAM_MAX_LEN - len(full_header(" (9/9)")) - len(footer) - 10

    pages: list[list[tuple[str, dict]]] = [[]]
    page_len = 0
    for referer, info in ranked:
        entry = format_suspicious_referer_entry(referer, info)
        added = len(entry) + 2
        if page_len + added > budget and pages[-1]:
            pages.append([])
            page_len = 0
        pages[-1].append((referer, info))
        page_len += added

    total_pages = len(pages)
    result = []
    for i, page in enumerate(pages, 1):
        label = f" ({i}/{total_pages})" if total_pages > 1 else ""
        body = "\n\n".join(format_suspicious_referer_entry(r, info) for r, info in page)
        head = full_header(label) if i == 1 else continuation_header(label)
        text = f"{head}\n\n{body}\n\n{footer}"
        result.append((text, [r for r, _ in page]))
    return result


async def check_watch_ips_and_merchants(client: httpx.AsyncClient, start: str, end: str):
    """
    Query 1 lần tất cả blocked events, rồi filter:
    - WATCH_IPS (hardcode trong values) → alert Watch IP
    - merchant_ips (từ Cloudflare list) → alert Merchant IP Blocked
    """
    # Tập hợp IP cần watch
    watch_set = set(WATCH_IPS)
    all_watch = watch_set | merchant_ips

    if not all_watch:
        return

    data = await query_cloudflare(
        client, BLOCKED_EVENTS_QUERY,
        {"zoneTag": ZONE_ID, "start": start, "end": end},
        "watch IPs & merchants"
    )
    if data is None:
        return
    errors = data.get("errors")
    if errors:
        print(f"GraphQL errors (watch): {errors}")
        return
    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return

    events = zones[0].get("firewallEventsAdaptive", [])

    # Group events theo IP
    ip_events: dict[str, list] = {}
    for event in events:
        ip = event.get("clientIP", "")
        if ip in all_watch:
            ip_events.setdefault(ip, []).append(event)

    if not ip_events:
        print(f"Watch IPs & merchants: no blocked events")
        return

    for ip, evts in ip_events.items():
        is_watch = ip in watch_set
        declared_hosts = merchant_ip_hosts.get(ip, set())
        matched = [e for e in evts if (e.get("clientRequestHTTPHost") or "").lower() in declared_hosts]

        # Merchant IP bị block khi gọi host NGOÀI whitelist → không phải lỗi tích hợp, bỏ qua
        # (trừ khi IP nằm trong WATCH_IPS thì vẫn theo dõi)
        if is_merchant_ip(ip) and declared_hosts and not matched and not is_watch:
            print(f"Merchant IP {ip}: bị block ở host ngoài whitelist {sorted(declared_hosts)} → bỏ qua")
            continue

        alert_key = f"watch:{ip}"
        if not should_alert(alert_key):
            print(f"Watch IP {ip}: alert suppressed (cooldown)")
            continue

        print(f"Watch IP {ip} blocked! {len(evts)} events")

        # Merchant alert chỉ khi bị block đúng host đã khai báo (hoặc list chưa cấu hình host)
        merchant_ok = is_merchant_ip(ip) and (bool(matched) or not declared_hosts)
        event_for_alert = matched[0] if matched else evts[0]

        if merchant_ok:
            message = format_watch_ip_alert(event_for_alert, ip)
        else:
            # Watch IP thường (hoặc merchant IP nhưng sai host + có trong WATCH_IPS)
            e = event_for_alert
            source = e.get("source", "")
            severity, reason = classify_source(source)
            message = render_template(
                "watch_ip.html",
                severity_label=SEVERITY_LABEL[severity],
                time_display=datetime.now(VN_TZ).strftime("%H:%M %d/%m/%Y"),
                ip=ip,
                count=len(evts),
                reason=reason,
                merchant_line=merchant_status_line(ip),
                host=e.get("clientRequestHTTPHost", ""),
                path=e.get("clientRequestPath", ""),
                method=e.get("clientRequestHTTPMethodName", ""),
                protocol=e.get("clientRequestHTTPProtocol", ""),
                status=e.get("edgeResponseStatus", ""),
                referer=e.get("clientRefererHost", ""),
                country=country_name(e.get("clientCountryName", "")),
                isp=e.get("clientASNDescription", ""),
                asn=e.get("clientAsn", ""),
                ua=(e.get("userAgent") or "")[:40],
                ray=e.get("rayName", ""),
                dashboard_url=f"{BASE_DASHBOARD_URL}?ip={ip}&action=block",
            )

        if merchant_ok:
            await send_telegram(client, message, keyboard=None, chat_id=MERCHANT_ALERT_CHAT_ID)
        else:
            await send_telegram(client, message, chat_id=WATCH_IP_ALERT_CHAT_ID)


async def fetch_referer_detail(client: httpx.AsyncClient, start: str, end: str, referer: str) -> tuple[list, list]:
    data = await query_cloudflare(
        client, with_referer_host_filter(REFERER_DETAIL_QUERY), {"zoneTag": ZONE_ID, "start": start, "end": end, "referer": referer}, f"referer-detail:{referer}"
    )
    if data is None:
        return [], []
    errors = data.get("errors")
    if errors:
        print(f"GraphQL errors (referer-detail {referer}): {errors}")
        return [], []
    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return [], []
    zone = zones[0]
    return zone.get("paths", []), zone.get("ips", [])


async def check_suspicious_referers(client: httpx.AsyncClient, start: str, end: str):
    if not ALLOWED_REFERER_DOMAINS:
        return
    # referer_scan_loop chạy độc lập với poll_loop nên tự đảm bảo cache merchant mới,
    # không dựa vào poll_loop đã chạy trước đó (tránh gắn nhầm nút Block cho IP merchant)
    await ensure_merchant_cache(client)
    data = await query_cloudflare(client, with_referer_host_filter(REFERER_QUERY), {"zoneTag": ZONE_ID, "start": start, "end": end}, "referer")
    if data is None:
        return
    errors = data.get("errors")
    if errors:
        print(f"GraphQL errors (referer): {errors}")
        return
    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return

    groups = zones[0].get("referers", [])
    suspicious: dict[str, dict] = {}
    for g in groups:
        d = g["dimensions"]
        referer = d.get("clientRefererHost", "")
        if not referer or is_allowed_referer(referer):
            continue
        host = d.get("clientRequestHTTPHost", "")
        entry = suspicious.setdefault(referer, {"count": 0, "hosts": {}})
        entry["count"] += g["count"]
        if host:
            entry["hosts"][host] = entry["hosts"].get(host, 0) + g["count"]

    if not suspicious:
        print("No suspicious referer detected")
        return

    ranked = sorted(suspicious.items(), key=lambda x: -x[1]["count"])
    referers = [referer for referer, _ in ranked]

    detail_results = await asyncio.gather(*(fetch_referer_detail(client, start, end, referer) for referer in referers))
    for referer, (paths, ips) in zip(referers, detail_results):
        suspicious[referer]["paths"] = paths
        suspicious[referer]["ips"] = ips

    print(f"Suspicious referers detected: {len(suspicious)} domains ({', '.join(referers)})")

    # Gộp nhiều domain/tin theo giới hạn ký tự Telegram, không cắt domain nào giữa chừng
    pages = build_referer_digest_pages(ranked, "24h")
    print(f"Referer digest: {len(pages)} tin nhắn cho {len(ranked)} domain")
    for text, _ in pages:
        await send_telegram(client, text, chat_id=REFERER_ALERT_CHAT_ID)
        if len(pages) > 1:
            await asyncio.sleep(0.3)


def seconds_until_next_daily_time(time_str: str) -> float:
    hour, minute = map(int, time_str.split(":"))
    now = datetime.now(VN_TZ)
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()

async def referer_scan_loop(client: httpx.AsyncClient):
    if not ALLOWED_REFERER_DOMAINS:
        print("Referer scan: chưa cấu hình ALLOWED_REFERER_DOMAINS — bỏ qua")
        return
    while True:
        sleep_seconds = seconds_until_next_daily_time(REFERER_SCAN_TIME)
        next_run = datetime.now(VN_TZ) + timedelta(seconds=sleep_seconds)
        print(f"Referer scan: chờ tới {next_run.strftime('%H:%M %d/%m/%Y')} (còn {sleep_seconds:.0f}s)")
        await asyncio.sleep(sleep_seconds)
        start, end = get_time_range(86400)
        print(f"[{datetime.now(VN_TZ).strftime('%H:%M:%S %d/%m/%Y')}] Referer scan {start} -> {end}")
        try:
            await check_suspicious_referers(client, start, end)
        except Exception as e:
            print(f"Error in referer scan: {e!r}")

async def cleanup_scan_loop(client: httpx.AsyncClient):
    if BLOCK_CLEANUP_LOOKBACK_DAYS <= 0:
        print("Block cleanup: BLOCK_CLEANUP_LOOKBACK_DAYS <= 0 — bỏ qua")
        return
    while True:
        sleep_seconds = seconds_until_next_daily_time(BLOCK_CLEANUP_TIME)
        next_run = datetime.now(VN_TZ) + timedelta(seconds=sleep_seconds)
        print(f"Block cleanup: chờ tới {next_run.strftime('%H:%M %d/%m/%Y')} (còn {sleep_seconds:.0f}s)")
        await asyncio.sleep(sleep_seconds)
        print(f"[{datetime.now(VN_TZ).strftime('%H:%M:%S %d/%m/%Y')}] Block cleanup scan")
        try:
            await cleanup_expired_blocks(client)
        except Exception as e:
            print(f"Error in block cleanup scan: {e!r}")

async def sandbox_whitelist_scan_loop(client: httpx.AsyncClient):
    if SANDBOX_WHITELIST_LOOKBACK_DAYS <= 0 or not SANDBOX_WHITELIST_HOSTS:
        print("Sandbox whitelist scan: chưa cấu hình SANDBOX_WHITELIST_HOSTS hoặc SANDBOX_WHITELIST_LOOKBACK_DAYS <= 0 — bỏ qua")
        return
    while True:
        sleep_seconds = seconds_until_next_daily_time(SANDBOX_WHITELIST_SCAN_TIME)
        next_run = datetime.now(VN_TZ) + timedelta(seconds=sleep_seconds)
        print(f"Sandbox whitelist scan: chờ tới {next_run.strftime('%H:%M %d/%m/%Y')} (còn {sleep_seconds:.0f}s)")
        await asyncio.sleep(sleep_seconds)
        print(f"[{datetime.now(VN_TZ).strftime('%H:%M:%S %d/%m/%Y')}] Sandbox whitelist scan")
        try:
            await check_sandbox_whitelist_staleness(client)
        except Exception as e:
            print(f"Error in sandbox whitelist scan: {e!r}")


def record_daily_block_counts(attacker_ip_groups: list[dict], now_utc: datetime) -> None:
    # Dọn record cũ hơn 24h cho MỌI IP đang theo dõi mỗi lần gọi, tránh dict phình to mãi theo thời gian
    cutoff = now_utc - timedelta(hours=24)
    for ip in list(daily_block_history.keys()):
        kept = [(ts, c) for ts, c in daily_block_history[ip] if ts > cutoff]
        if kept:
            daily_block_history[ip] = kept
        else:
            del daily_block_history[ip]
    for g in attacker_ip_groups:
        ip = (g.get("dimensions") or {}).get("clientIP", "")
        count = g.get("count", 0)
        if not ip or not count:
            continue
        daily_block_history.setdefault(ip, []).append((now_utc, count))

def slow_attacker_ips() -> list[str]:
    # IP nào bị block cộng dồn đủ DAILY_BLOCK_THRESHOLD trong 24h gần nhất — bắt kiểu tấn công
    # chậm/lặp lại mà từng cửa sổ poll riêng lẻ không bao giờ đủ BLOCK_THRESHOLD để lộ diện
    return [ip for ip, records in daily_block_history.items() if sum(c for _, c in records) >= DAILY_BLOCK_THRESHOLD]

async def fetch_attacker_ip_detail(client: httpx.AsyncClient, start: str, end: str, ip: str) -> list[dict]:
    data = await query_cloudflare(
        client, ATTACKER_IP_DETAIL_QUERY, {"zoneTag": ZONE_ID, "start": start, "end": end, "ip": ip}, f"attacker-detail:{ip}"
    )
    if data is None:
        return []
    errors = data.get("errors")
    if errors:
        print(f"GraphQL errors (attacker-detail {ip}): {errors}")
        return []
    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return []
    events = zones[0].get("events", [])
    for e in events:
        (e.get("dimensions") or {}).setdefault("clientIP", ip)  # detail query không group theo IP, tự gắn lại
    return events

async def check_ddos_threshold(client: httpx.AsyncClient, start: str, end: str):
    data = await query_cloudflare(client, GROUPED_QUERY, {"zoneTag": ZONE_ID, "start": start, "end": end}, "grouped")
    if data is None:
        return
    errors = data.get("errors")
    if errors:
        print(f"GraphQL errors (grouped): {errors}")
        return
    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return
    zone = zones[0]
    total_blocked_groups = zone.get("totalBlocked", [])
    attacker_ip_groups = zone.get("topAttackerIPs", [])  # group đúng theo clientIP, không bị path/UA làm vỡ vụn
    http_groups = zone.get("httpRequestsAdaptiveGroups", [])
    total_visits = 0
    if http_groups:
        total_visits = http_groups[0].get("sum", {}).get("visits", 0)
    total_blocked = sum(g["count"] for g in total_blocked_groups)
    print(f"Blocked (excl. custom rules): {total_blocked}, Threshold: {BLOCK_THRESHOLD}")

    # Luôn cộng dồn theo ngày cho MỌI IP bị block trong cửa sổ này, kể cả khi total_blocked
    # chưa đạt BLOCK_THRESHOLD — bắt kiểu tấn công chậm/lặp lại qua nhiều cửa sổ poll
    now_utc = datetime.now(timezone.utc)
    record_daily_block_counts(attacker_ip_groups, now_utc)

    # Nguồn 1: burst nhanh — top IP khi tổng blocked trong cửa sổ vượt threshold
    burst_ips = [g["dimensions"]["clientIP"] for g in attacker_ip_groups[:5] if (g.get("dimensions") or {}).get("clientIP")] \
        if total_blocked >= BLOCK_THRESHOLD else []
    # Nguồn 2: cộng dồn chậm — IP đạt DAILY_BLOCK_THRESHOLD trong 24h, dù chưa cửa sổ nào riêng lẻ đủ
    slow_ips = slow_attacker_ips()

    candidate_ips = list(dict.fromkeys(burst_ips + slow_ips))
    if not candidate_ips:
        print("No DDoS alert needed")
        return

    # Cooldown theo từng IP: IP mới (chưa alert trong ALERT_COOLDOWN) → alert ngay, chỉ gồm các IP mới
    new_ips = [ip for ip in candidate_ips if should_alert(f"ddos:{ip}")]
    if not new_ips:
        print("DDoS alert suppressed (cooldown, không có IP mới)")
        return

    detail_results = await asyncio.gather(*(fetch_attacker_ip_detail(client, start, end, ip) for ip in new_ips))
    classified = [
        (*classify_source(e["dimensions"].get("source", "")), e)
        for events in detail_results
        for e in events
    ]
    if not classified:
        print("DDoS alert suppressed (không lấy được chi tiết IP)")
        return
    worst_severity = max(
        (c[0] for c in classified),
        key=lambda s: SEVERITY_ORDER.index(s),
        default=Severity.INFO,
    )
    if worst_severity == Severity.INFO:
        print(f"{len(new_ips)} IP mới — toàn bộ Rate Limiting (INFO) → không alert")
        return
    print(f"ALERT! {total_blocked} blocked requests, {len(new_ips)} IP mới ({', '.join(new_ips)}), severity={worst_severity}")

    block_lines: dict[str, str] = {}
    blocked: set[str] = set()
    if block_mode == "auto":
        block_lines, blocked = await auto_block_ips(client, new_ips)
    message = format_ddos_alert(classified, total_blocked, total_visits, worst_severity, block_lines, new_ips)
    keyboard = build_block_keyboard(new_ips, blocked)
    await send_telegram(client, message, keyboard)


def build_499_dashboard_url(host: str = "", path: str = "") -> str:
    url = f"{TRAFFIC_DASHBOARD_URL}?status-code=499"
    if host:
        url += f"&host={quote(host, safe='')}"
    if path:
        url += f"&path={quote(path, safe='/')}"
    return url


def format_499_alert(host: str, total_499: int, top_groups: list) -> str:
    time_display = datetime.now(VN_TZ).strftime("%H:%M %d/%m/%Y")
    top = top_groups[0].get("dimensions") if top_groups else None
    top_path = (top or {}).get("clientRequestPath") or ""
    dashboard_url = build_499_dashboard_url(host, top_path)

    top_paths = []
    for g in top_groups[:5]:
        d = g.get("dimensions") or {}
        full_path = d.get("clientRequestPath") or "/"
        top_paths.append((
            build_499_dashboard_url(host, full_path),
            full_path[:50],
            g.get("count", 0),
            country_name(d.get("clientCountryName", "")),
        ))

    return render_template(
        "status499.html",
        host=host,
        time_display=time_display,
        poll_window=poll_window_label(),
        total_fmt=f"{total_499:,}",
        top_paths=top_paths,
        dashboard_url=dashboard_url,
    )


async def check_status_499_for_host(client: httpx.AsyncClient, start: str, end: str, host: str):
    data = await query_cloudflare(
        client, STATUS_499_QUERY, {"zoneTag": ZONE_ID, "start": start, "end": end, "host": host}, f"status499:{host}"
    )
    if data is None:
        return
    errors = data.get("errors")
    if errors:
        print(f"GraphQL errors (status499 {host}): {errors}")
        return
    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return
    zone = zones[0]
    total_groups = zone.get("total499", [])
    top_groups = zone.get("top499", [])
    total_499 = sum(g["count"] for g in total_groups)
    print(f"Status 499 [{host}]: {total_499}, Threshold: {STATUS_499_THRESHOLD}")
    if total_499 < STATUS_499_THRESHOLD:
        return
    print(f"ALERT! {host} có {total_499} requests với status 499")
    if should_alert(f"status499:{host}"):
        message = format_499_alert(host, total_499, top_groups)
        await send_telegram(client, message, chat_id=MERCHANT_ALERT_CHAT_ID)
    else:
        print(f"Status 499 [{host}] alert suppressed (cooldown)")


async def check_status_499(client: httpx.AsyncClient, start: str, end: str):
    if STATUS_499_THRESHOLD <= 0 or not STATUS_499_HOSTS:
        return
    await asyncio.gather(*(check_status_499_for_host(client, start, end, host) for host in STATUS_499_HOSTS))


def format_cleanup_alert(ips: list[str], total_count: int, page_label: str = "") -> str:
    return render_template(
        "cleanup.html",
        time_display=datetime.now(VN_TZ).strftime("%H:%M %d/%m/%Y"),
        count=total_count,
        lookback_days=BLOCK_CLEANUP_LOOKBACK_DAYS,
        page_label=page_label,
        ips=ips,
    )


async def handle_callback_query(client: httpx.AsyncClient, callback: dict):
    callback_id = callback["id"]
    data = callback.get("data", "")
    message = callback.get("message") or {}
    chat_id = message.get("chat", {}).get("id")
    message_id = message.get("message_id")
    from_user = callback.get("from", {})
    username = from_user.get("username") or from_user.get("first_name") or "?"
    action, _, ip = data.partition(":")
    if action not in ("block", "unblock") or not ip:
        await answer_callback_query(client, callback_id)
        return
    if not is_allowed_block_user(username):
        await answer_callback_query(
            client, callback_id,
            f"⛔ @{username} không có quyền {action} IP!",
            show_alert=True
        )
        print(f"User {username} không có quyền {action} IP {ip}")
        return
    if action == "block":
        await answer_callback_query(client, callback_id, f"Đang block {ip}...")
        print(f"[BLOCK] {username} đang block IP {ip}...")
        ok, info = await add_ip_to_block_list(client, ip, username)
        if ok:
            replacement = [[toggle_button(f"✅ Đã block bởi {username}", "unblock", ip)]]
        else:
            replacement = [[toggle_button(f"❌ Block lỗi ({username})", "block", ip)]]
    else:
        await answer_callback_query(client, callback_id, f"Đang unblock {ip}...")
        print(f"[UNBLOCK] {username} đang unblock IP {ip}...")
        ok, info = await remove_ip_from_block_list(client, ip)
        if ok:
            replacement = [[toggle_button(f"🔓 Đã unblock bởi {username}", "block", ip)]]
        else:
            replacement = [[toggle_button(f"❌ Unblock lỗi ({username})", "unblock", ip)]]
    if chat_id is not None and message_id is not None:
        markup = message.get("reply_markup") or {}
        rows = markup.get("inline_keyboard", [])
        await edit_message_reply_markup(client, chat_id, message_id, replace_ip_rows(rows, ip, replacement))
    if ok:
        print(f"[{action.upper()} OK] IP {ip} by {username}: {info}")
    else:
        print(f"[{action.upper()} FAILED] IP {ip} by {username}: {info}")
        if action == "block":
            await answer_callback_query(client, callback_id, f"❌ Lỗi block {ip}: {info}", show_alert=True)


def is_allowed_block_user(username: str) -> bool:
    return not ALLOWED_BLOCK_USERS or username in ALLOWED_BLOCK_USERS


async def handle_command(client: httpx.AsyncClient, msg: dict):
    global block_mode
    text = (msg.get("text") or "").strip()
    if not text.startswith("/"):
        return
    chat_id = msg.get("chat", {}).get("id")
    if str(chat_id) != str(TELEGRAM_CHAT_ID):
        return
    # Bỏ qua lệnh gửi lúc bot chưa chạy (Telegram giữ update tới 24h)
    if msg.get("date", 0) < started_at.timestamp():
        return
    command, _, target_bot = text.split()[0].lower().partition("@")
    if target_bot and bot_username and target_bot != bot_username.lower():
        return
    if command not in ("/auto", "/manual", "/mode"):
        return
    from_user = msg.get("from", {})
    username = from_user.get("username") or from_user.get("first_name") or "?"
    if command == "/mode":
        await send_telegram(client, f"Chế độ block hiện tại: <b>{MODE_LABEL[block_mode]}</b>", chat_id=chat_id)
        return
    if not is_allowed_block_user(username):
        print(f"User {username} không có quyền đổi chế độ block ({command})")
        await send_telegram(client, f"⛔ @{html.escape(username)} không có quyền đổi chế độ block!", chat_id=chat_id)
        return
    new_mode = command[1:]
    if new_mode == block_mode:
        await send_telegram(client, f"Đang ở chế độ <b>{MODE_LABEL[block_mode]}</b> rồi", chat_id=chat_id)
        return
    old_mode = block_mode
    block_mode = new_mode
    print(f"[MODE] {username} đổi chế độ block: {old_mode} → {new_mode}")
    await send_telegram(
        client,
        f"🔁 <b>{html.escape(username)}</b> đã chuyển chế độ block: {MODE_LABEL[old_mode]} → <b>{MODE_LABEL[new_mode]}</b>",
        chat_id=chat_id,
    )


async def telegram_callback_loop(client: httpx.AsyncClient):
    global bot_username
    try:
        await client.post(f"{TELEGRAM_API_BASE}/deleteWebhook", timeout=10)
    except Exception as e:
        print(f"Error deleting Telegram webhook: {e}")
    try:
        resp = await client.get(f"{TELEGRAM_API_BASE}/getMe", timeout=10)
        bot_username = resp.json().get("result", {}).get("username", "")
    except Exception as e:
        print(f"Error fetching bot info: {e}")
    offset = 0
    while True:
        try:
            resp = await client.get(
                f"{TELEGRAM_API_BASE}/getUpdates",
                params={"offset": offset, "timeout": 25, "allowed_updates": '["callback_query","message"]'},
                timeout=35,
            )
            resp.raise_for_status()
            updates = resp.json().get("result", [])
        except Exception as e:
            print(f"Error polling Telegram updates: {e}")
            await asyncio.sleep(5)
            continue
        for update in updates:
            offset = update["update_id"] + 1
            callback = update.get("callback_query")
            if callback:
                await handle_callback_query(client, callback)
            message = update.get("message")
            if message:
                await handle_command(client, message)


async def check_and_alert(client: httpx.AsyncClient):
    start, end = get_time_range()
    print(f"[{datetime.now(VN_TZ).strftime('%H:%M:%S %d/%m/%Y')}] Checking {start} -> {end}")
    await ensure_merchant_cache(client)
    results = await asyncio.gather(
        check_watch_ips_and_merchants(client, start, end),
        check_ddos_threshold(client, start, end),
        check_status_499(client, start, end),
        return_exceptions=True,
    )
    for result in results:
        if isinstance(result, Exception):
            print(f"Error in check: {result!r}")


async def poll_loop(client: httpx.AsyncClient):
    while True:
        await check_and_alert(client)
        await asyncio.sleep(POLL_INTERVAL)


def print_spiritual_meme():
    # Đọc thẳng file (không qua Jinja2) — nội dung tĩnh, không có biến nào cần render
    with open(os.path.join(TEMPLATE_DIR, "startup_banner.txt"), encoding="utf-8") as f:
        meme = f.read()
    # flush=True: chạy trong container (stdout không phải terminal) thì vẫn hiện
    # ngay theo từng dòng trong kubectl logs
    print("\n[SYSTEM] Khởi động tiến trình cầu nguyện...", flush=True)
    time.sleep(0.5)
    print(meme, flush=True)

    prayers = [
        "🔮 Đang kết nối vũ trụ...",
        "🙏 Xin tổ nghề độ không lỗi 500 Internal Server Error...",
        "🍀 Cầu mong RAM không tràn, CPU không nhảy....",
        "🚀 Deploy thành công! Bot gánh team!"
    ]
    for msg in prayers:
        print(f" {msg}", flush=True)
        time.sleep(0.8)


async def main():
    print_spiritual_meme()
    print(f"[{datetime.now(VN_TZ).strftime('%H:%M:%S %d/%m/%Y')}] Cloudflare monitor started, interval: {POLL_INTERVAL}s")
    if WATCH_IPS:
        print(f"Watch IPs (hardcode): {', '.join(WATCH_IPS)}")
        print(f"Watch IP alert chat: {WATCH_IP_ALERT_CHAT_ID}")
    if MERCHANT_IP_LISTS:
        print(f"Merchant IP lists: {', '.join(MERCHANT_IP_LISTS)} (refresh every {MERCHANT_CACHE_REFRESH_INTERVAL}s)")
        print(f"Merchant alert chat: {MERCHANT_ALERT_CHAT_ID}")
    if ALLOWED_REFERER_DOMAINS:
        print(f"Allowed referer domains: {', '.join(ALLOWED_REFERER_DOMAINS)} (quét 1 lần/ngày lúc {REFERER_SCAN_TIME})")
        print(f"Referer hosts: {', '.join(REFERER_HOSTS) if REFERER_HOSTS else 'tất cả (REFERER_HOSTS rỗng)'}")
        print(f"Referer alert chat: {REFERER_ALERT_CHAT_ID}")
    else:
        print("Referer scan: chưa cấu hình ALLOWED_REFERER_DOMAINS — bỏ qua check suspicious referer")
    if ALLOWED_BLOCK_USERS:
        print(f"Allowed block users: {', '.join(ALLOWED_BLOCK_USERS)}")
    else:
        print("Allowed block users: tất cả (không giới hạn)")
    print(f"Block list: {BLOCK_IP_LIST}")
    print(f"Block mode: {block_mode} (đổi lúc chạy bằng /auto, /manual trong TELEGRAM_CHAT_ID)")
    if BLOCK_CLEANUP_LOOKBACK_DAYS > 0:
        print(f"Block cleanup: dọn IP im hơi lặng tiếng {BLOCK_CLEANUP_LOOKBACK_DAYS} ngày, 1 lần/ngày lúc {BLOCK_CLEANUP_TIME}")
        print(f"Cleanup alert chat: {CLEANUP_ALERT_CHAT_ID}")
    else:
        print("Block cleanup: tắt (BLOCK_CLEANUP_LOOKBACK_DAYS <= 0)")
    if SANDBOX_WHITELIST_LOOKBACK_DAYS > 0 and SANDBOX_WHITELIST_HOSTS:
        print(f"Sandbox whitelist scan: list '{SANDBOX_WHITELIST_LIST}', im {SANDBOX_WHITELIST_LOOKBACK_DAYS} ngày, 1 lần/ngày lúc {SANDBOX_WHITELIST_SCAN_TIME}")
        print(f"Sandbox whitelist alert chat: {SANDBOX_WHITELIST_ALERT_CHAT_ID}")
    else:
        print("Sandbox whitelist scan: tắt (chưa cấu hình SANDBOX_WHITELIST_HOSTS hoặc LOOKBACK_DAYS <= 0)")
    print("Severity: CRITICAL=l7ddos/firewallManaged | INFO=ratelimit | WARNING=unknown")
    if STATUS_499_THRESHOLD > 0 and STATUS_499_HOSTS:
        print(f"Status 499 threshold: {STATUS_499_THRESHOLD} reqs / {POLL_INTERVAL}s cho hosts: {', '.join(STATUS_499_HOSTS)}")
    else:
        print("Status 499 threshold: chưa cấu hình đủ (threshold hoặc hosts) — bỏ qua check 499")
    async with httpx.AsyncClient() as client:
        await asyncio.gather(
            poll_loop(client),
            telegram_callback_loop(client),
            referer_scan_loop(client),
            cleanup_scan_loop(client),
            sandbox_whitelist_scan_loop(client),
        )


if __name__ == "__main__":
    asyncio.run(main())