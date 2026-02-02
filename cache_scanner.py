import requests
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote
import json
import time
import random
import argparse
import sys

WARNING = """
WARNING: This tool is for authorized bug bounty testing only.
Use on targets you have permission for.
"""
print(WARNING)

def parse_args():
    parser = argparse.ArgumentParser(
        description="HTTP Cache Poisoning / Cache Deception / Cache Key Manipulation Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python cache.py --url https://example.com/page --continue
  python cache.py -f targets.txt -n 12 --delay 1.1 --output results.json
  python cache.py -u https://shop.com --suspect vuln.txt --cache-hits cached.txt
        """
    )

    # === Input (one of them required) ===
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', '-f', dest='input_file',
                             help='File with URLs (one per line)')
    input_group.add_argument('--url', '-u', dest='single_url',
                             help='Single URL to test')

    # === Scanning behavior ===
    parser.add_argument('--threads', '-n', type=int, default=5,
                        help='Number of concurrent targets (default: 5)')
    parser.add_argument('--delay', type=float, default=0.6,
                        help='Seconds between requests to same target (default: 0.6)')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Request timeout in seconds (default: 30)')
    parser.add_argument('--continue', dest='continue_on_success', action='store_true',
                        help='Keep testing after finding a suspect case')

    # === Output files ===
    parser.add_argument('--output', default='cache_scan_results.json', metavar='FILE',
                        help='JSON results file (default: cache_scan_results.json)')
    parser.add_argument('--cache-hits', default='cache_hits.txt', metavar='FILE',
                        help='File for URLs that appear cached (default: cache_hits.txt)')
    parser.add_argument('--suspect', default='suspect_urls.txt', metavar='FILE',
                        help='File for potentially vulnerable URLs (default: suspect_urls.txt)')

    # === Old flags kept for compatibility ===
    parser.add_argument('--headers-only', action='store_true',
                        help='Only test header-based poisoning')
    parser.add_argument('--params-only', action='store_true',
                        help='Only test query parameter poisoning')
    parser.add_argument('--user-agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                        help='User-Agent string')

    return parser.parse_args()

args = parse_args()

# ───────────────────────────────────────────────
#  Load URLs
# ───────────────────────────────────────────────
if args.single_url:
    urls = [args.single_url.strip()]
elif args.input_file:
    try:
        with open(args.input_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith(('#', '//'))]
        if not urls:
            print("[ERROR] Input file is empty.")
            sys.exit(1)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.input_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Cannot read file: {e}")
        sys.exit(1)
else:
    print("[ERROR] You must provide either --url or --file")
    sys.exit(1)

print(f"[*] Loaded {len(urls)} URL(s) to scan")

# ───────────────────────────────────────────────
#  You can add cache-related headers & logic
# ───────────────────────────────────────────────

cache_headers = [
    'X-Cache', 'CF-Cache-Status', 'Age', 'Via', 'X-Served-By',
    'X-Proxy-Cache', 'X-Akamai-Cache-Status', 'Server-Timing',
    'Fastly-Cache', 'CDN-Cache'
]

def get_cache_headers(resp):
    return {h: resp.headers.get(h, '') for h in cache_headers if h in resp.headers}

def get_cache_status(headers):
    if 'CF-Cache-Status' in headers:
        status = headers['CF-Cache-Status'].upper()
        if status in ['HIT', 'REVALIDATED', 'UPDATING']:
            return 'HIT'
        elif status in ['MISS', 'BYPASS', 'EXPIRED', 'DYNAMIC', 'BYPASS+MISS', 'BYPASS+HIT']:
            return 'MISS'

    if 'X-Cache' in headers:
        xc = headers['X-Cache'].upper()
        if any(x in xc for x in ['HIT', 'HIT FROM', 'CACHED']):
            return 'HIT'
        elif any(x in xc for x in ['MISS', 'MISS FROM', 'BYPASS', 'UNCACHEABLE']):
            return 'MISS'

    if 'X-Proxy-Cache' in headers:
        xpc = headers['X-Proxy-Cache'].upper()
        if 'HIT' in xpc:
            return 'HIT'
        elif any(x in xpc for x in ['MISS', 'BYPASS']):
            return 'MISS'

    if 'Age' in headers and headers['Age'].isdigit() and int(headers['Age']) > 0:
        return 'HIT'

    if 'X-Cacheable' in headers:
        if 'YES' in headers['X-Cacheable'].upper() or 'TRUE' in headers['X-Cacheable'].upper():
            return 'HIT'

    return 'UNKNOWN'

def detect_cdn(headers):
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    if 'cf-ray' in lower_headers or 'cf-cache-status' in lower_headers:
        return 'Cloudflare'
    if 'x-amz-cf-id' in lower_headers or ('server' in lower_headers and 'cloudfront' in lower_headers['server']):
        return 'CloudFront'
    if 'fastly-cache' in lower_headers or ('x-served-by' in lower_headers and 'fastly' in lower_headers['x-served-by']):
        return 'Fastly'
    if 'x-akamai-cache-status' in lower_headers or ('via' in lower_headers and 'akamai' in lower_headers['via']):
        return 'Akamai'
    if ('via' in lower_headers and 'varnish' in lower_headers['via']) or 'x-varnish' in lower_headers:
        return 'Varnish'
    return 'Unknown'

# ───────────────────────────────────────────────
#  You can add headers / params / variations
# ───────────────────────────────────────────────

user_agent = args.user_agent
headers_base = {'User-Agent': user_agent}

headers_to_test = [
    'X-Forwarded-Host',
    'X-Host',
    'X-Original-URL',
    'X-Rewrite-URL',
    'X-Forwarded-Proto',
    'Forwarded',
    'X-HTTP-Method-Override'
]

params_to_test = [
    'cb',
    'cachebuster',
    'utm_source',
    'test',
    'debug',
    'lang',
    'format',
    'callback'
]

from urllib.parse import urljoin, quote

variations = [
    # Generic syntax / normalization tricks
    ('trailing_slash_add', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/')),
    ('trailing_slash_remove', lambda p: urljoin(p.geturl(), p.path.rstrip('/'))),
    ('double_slash', lambda p: p._replace(path=p.path.replace('/', '//', 1)).geturl()),
    ('encoded_slash', lambda p: p._replace(path=quote(p.path, safe='')).geturl()),
    ('upper_path', lambda p: p._replace(path=p.path.upper()).geturl()),
    ('path_param_semicolon', lambda p: urljoin(p.geturl(), p.path + ';test=1')),
    ('append_many_slashes', lambda p: p._replace(path=p.path + '///').geturl()),

    # Common file extensions / backups
    ('append_js', lambda p: p._replace(path=p.path.rstrip('/') + '.js').geturl()),
    ('append_css', lambda p: p._replace(path=p.path.rstrip('/') + '.css').geturl()),
    ('append_json', lambda p: p._replace(path=p.path.rstrip('/') + '.json').geturl()),
    ('append_png', lambda p: p._replace(path=p.path.rstrip('/') + '.png').geturl()),
    ('append_ico', lambda p: p._replace(path=p.path.rstrip('/') + '.ico').geturl()),
    ('append_avif', lambda p: p._replace(path=p.path.rstrip('/') + '.avif').geturl()),
    ('append_webp', lambda p: p._replace(path=p.path.rstrip('/') + '.webp').geturl()),
    ('append_bak', lambda p: p._replace(path=p.path.rstrip('/') + '.bak').geturl()),
    ('append_old', lambda p: p._replace(path=p.path.rstrip('/') + '.old').geturl()),
    ('append_backup', lambda p: p._replace(path=p.path.rstrip('/') + '.backup').geturl()),
    ('append_backup_json', lambda p: p._replace(path=p.path.rstrip('/') + '/backup.json').geturl()),
    ('append_config_yaml', lambda p: p._replace(path=p.path.rstrip('/') + '/config.yaml').geturl()),
    ('append_env', lambda p: p._replace(path=p.path.rstrip('/') + '/.env').geturl()),
    ('append_git', lambda p: p._replace(path=p.path.rstrip('/') + '/.git').geturl()),
    ('append_sitemap_xml', lambda p: p._replace(path=p.path.rstrip('/') + '/sitemap.xml').geturl()),
    ('append_robots_txt', lambda p: p._replace(path=p.path.rstrip('/') + '/robots.txt').geturl()),
    ('append_test_php', lambda p: p._replace(path=p.path.rstrip('/') + '/test.php').geturl()),
    ('append_index_php', lambda p: p._replace(path=p.path.rstrip('/') + '/index.php').geturl()),
    ('append_db_dump', lambda p: p._replace(path=p.path.rstrip('/') + '/db_dump.sql').geturl()),
    ('append_manifest_json', lambda p: p._replace(path=p.path.rstrip('/') + '/manifest.json').geturl()),
    ('append_sw_js', lambda p: p._replace(path=p.path.rstrip('/') + '/sw.js').geturl()),
    ('append_favicon_ico', lambda p: p._replace(path=p.path.rstrip('/') + '/favicon.ico').geturl()),
    ('append_apple_touch_icon', lambda p: p._replace(path=p.path.rstrip('/') + '/apple-touch-icon.png').geturl()),

    # Common fake / internal paths
    ('append_admin', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/admin')),
    ('append_wp_admin', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/wp-admin')),
    ('append_page_data', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/page-data')),
    ('append_page_data_json', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/page-data.json')),
    ('append_dash_page_data', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/page-data/')),
    ('append_api', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/api')),
    ('append_login', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/login')),
    ('append_dashboard', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/dashboard')),
    ('append_profile', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/profile')),
    ('append_settings', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/settings')),
    ('append_logs', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/logs')),
    ('append_config', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/config')),
    ('append_debug', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/debug')),
    ('append_cache', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/cache')),
    ('append_static', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/static')),
    ('append_assets', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/assets')),
    ('append_images', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/images')),
    ('append_scripts', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/scripts')),
    ('append_styles', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/styles')),
    ('append_fonts', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/fonts')),
    ('append_vendor', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/vendor')),
    ('append_node_modules', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/node_modules')),

    # Fake / poisoned paths (your main interest)
    ('append_fake_css', lambda p: p._replace(path=p.path + '/fake.css').geturl()),
    ('append_fake_js', lambda p: p._replace(path=p.path + '/nonexistent.js').geturl()),
    ('append_style_css', lambda p: p._replace(path=p.path + '/style.css').geturl()),
    ('append_main_js', lambda p: p._replace(path=p.path + '/main.js').geturl()),
    ('append_index_html', lambda p: p._replace(path=p.path + '/index.html').geturl()),
    ('append_extra_dir', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/extra/')),
    ('append_page_bata', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/page-bata')),
    ('append_admin_poison_xxx', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/admin/poison_xxx')),
    ('append_page_bata_poison_query', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/page-bata?poison=xxx')),
    ('append_fakeadmin', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/fakeadmin/')),
    ('append_fakeadmin_poison_query', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/fakeadmin?poison=xxx')),
    ('append_poison_xxx', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/poison_xxx')),
    ('append_dotdot', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/../')),
    ('append_encoded_dotdot', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/%2e%2e/')),
    ('append_dotdot_poison', lambda p: urljoin(p.geturl(), p.path.rstrip('/') + '/../poison_xxx')),

    # Less common but useful
    ('append_admin_css', lambda p: p._replace(path=p.path.rstrip('/') + '/admin.css').geturl()),
    ('append_composer_json', lambda p: p._replace(path=p.path.rstrip('/') + '/composer.json').geturl()),
    ('append_package_json', lambda p: p._replace(path=p.path.rstrip('/') + '/package.json').geturl()),
]

additional_suffixes = [
    "#?",
    "%09",
    "%09%3b",
    "%09..",
    "%09;",
    "%20",
    "%23",
    "%23%3f",
    "%252f%252f",
    "%252f/",
    "%2e%2e",
    "%2e%2e/",
    "%2f",
    "%2f%20%23",
    "%2f%23",
    "%2f%2f",
    "%2f%3b%2f",
    "%2f%3b%2f%2f",
    "%2f%3f",
    "%2f%3f/",
    "%2f/",
    "%2f;?",
    "%2f?;",
    "%3b",
    "%3b%09",
    "%3b%2f%2e%2e",
    "%3b%2f%2e%2e%2f%2e%2e%2f%2f",
    "%3b%2f%2e.",
    "%3b%2f..",
    "%3b/%2e%2e/..%2f%2f",
    "%3b/%2e.",
    "%3b/%2f%2f../",
    "%3b/..",
    "%3b//%2f../",
    "%3f%23",
    "%3f%3f",
    "%3f.php",
    "..",
    "..%00/",
    "..%00/;",
    "..%00;/",
    "..%09",
    "..%0d/",
    "..%0d/;",
    "..%0d;/",
    "..%5c/",
    "..%ff/",
    "..%ff/;",
    "..%ff;/",
    "../",
    "..;%00/",
    "..;%0d/",
    "..;%ff/",
    "..;\\",
    "..;\\;",
    "..\\",
    "..\\;",
    ".html",
    ".json",
    "/",
    "/#",
    "/%20",
    "/%20#",
    "/%20%23",
    "/%23",
    "/%252e%252e%252f/",
    "/%252e%252e%253b/",
    "/%252e%252f/",
    "/%252e%253b/",
    "/%252e/",
    "/%252f",
    "/%2e%2e",
    "/%2e%2e%2f/",
    "/%2e%2e%3b/",
    "/%2e%2e/",
    "/%2e%2f/",
    "/%2e%3b/",
    "/%2e%3b//",
    "/%2e/",
    "/%2e//",
    "/%2f",
    "/%3b/",
    "/..",
    "/..%2f",
    "/..%2f..%2f",
    "/..%2f..%2f..%2f",
    "/../",
    "/../../",
    "/../../../",
    "/../../../",
    "/../../",
    "/../.././../",
    "/../../../",
    "/.././../",
    "/../.;/../",
    "/..//",
    "/..//../",
    "/..//../../",
    "/..//..;/",
    "/../;/",
    "/../;/../",
    "/..;%2f",
    "/..;%2f..;%2f",
    "/..;%2f..;%2f..;%2f",
    "/..;/",
    "/..;/../",
    "/..;/..;/",
    "/..;//",
    "/..;//../",
    "/..;//..;/",
    "/..;/;/",
    "/..;/;/..;/",
    "/./",
    "/.//",
    "/.;/",
    "/.;//",
    "//..",
    "//../../",
    "//..;",
    "//./",
    "//.;/",
    "///..",
    "///../",
    "///..//",
    "/;/",
    "/;/",
    "/;//",
    "/;?",
    "/;x",
    "/;x/",
    "/?",
    "/?;",
    "/x/../",
    "/x/..//",
    "/x/../;/",
    "/x/..;/",
    "/x/..;//",
    "/x/..;/;/",
    "/x//../",
    "/x//..;/",
    "/x/;/../",
    "/x/;/..;/",
    ";",
    ";%09",
    ";%09..",
    ";%09..;",
    ";%09;",
    ";%2F..",
    ";%2f%2e%2e",
    ";%2f%2e%2e%2f%2e%2e%2f%2f",
    ";%2f%2f/../",
    ";%2f..",
    ";%2f..%2f%2e%2e%2f%2f",
    ";%2f..%2f..%2f%2f",
    ";%2f..%2f/",
    ";%2f..%2f/..%2f",
    ";%2f..%2f/../",
    ";%2f../%2f..%2f",
    ";%2f../%2f../",
    ";%2f..//..%2f",
    ";%2f..//../",
    ";%2f..///",
    ";%2f..///;",
    ";%2f..//;/",
    ";%2f..//;/;",
    ";%2f../;//",
    ";%2f../;/;/",
    ";%2f../;/;/;",
    ";%2f..;///",
    ";%2f..;//;/",
    ";%2f..;/;//",
    ";%2f/%2f../",
    ";%2f//..%2f",
    ";%2f//../",
    ";%2f//..;/",
    ";%2f/;/../",
    ";%2f/;/..;/",
    ";%2f;//../",
    ";%2f;/;/..;/",
    ";/%2e%2e",
    ";/%2e%2e%2f%2f",
    ";/%2e%2e%2f/",
    ";/%2e%2e/",
    ";/%2e.",
    ";/%2f%2f../",
    ";/%2f/..%2f",
    ";/%2f/../",
    ";/.%2e",
    ";/.%2e/%2e%2e/%2f",
    ";/..",
    ";/..%2f",
    ";/..%2f%2f../",
    ";/..%2f..%2f",
    ";/..%2f/",
    ";/..%2f//",
    ";/../",
    ";/../%2f/",
    ";/../../",
    ";/../../",
    ";/.././../",
    ";/../.;/../",
    ";/../",
    ";/..//%2e%2e/",
    ";/..//%2f",
    ";/..//../",
    ";/..///",
    ";/../;/",
    ";/../;/../",
    ";/..;",
    ";/.;.",
    ";//%2f../",
    ";//..",
    ";//../../",
    ";///..",
    ";///../",
    ";///..//",
    ";?",
    ";x",
    ";x/",
    ";x;",
    "?",
    "?#",
    "?.php",
    "?;",
    "??",
    "///",
    "/%2f/",
    "//%2f",
    "%2f/%2f",
    "%2f%2f%2f",
    "%2f//",
]

def sanitize_name(s):
    table = str.maketrans({
        '%': 'pct', '/': 'slash', ';': 'semi', '.': 'dot',
        '#': 'hash', '?': 'q', '\\': 'backslash', ' ': 'space',
    })
    return s.translate(table)

# Append dynamic suffix variations (you already had this)
variations += [
    (f'append_{sanitize_name(s)}', lambda p, suff=s: p._replace(path=p.path + suff).geturl())
    for s in additional_suffixes
]

# ───────────────────────────────────────────────
#  Request helpers (mostly unchanged)
# ───────────────────────────────────────────────

def make_request(url, extra_headers=None, timeout=args.timeout, retries=3):
    h = headers_base.copy()
    if extra_headers:
        h.update(extra_headers)
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=h, timeout=timeout, allow_redirects=True)
            return resp
        except requests.exceptions.Timeout:
            print(f"\033[31m[TIMEOUT] {url} attempt {attempt+1}\033[0m")
            time.sleep(2 ** attempt)
        except Exception as e:
            print(f"\033[31m[ERROR] {url}: {e}\033[0m")
            return None
    print(f"\033[31m[REQUEST FAILED AFTER RETRIES] {url}\033[0m")
    return None

def body_hash(resp):
    if resp:
        return hashlib.sha256(resp.content).hexdigest()
    return ''

# ───────────────────────────────────────────────
#  Core test function — with --continue support
# ───────────────────────────────────────────────

def perform_test(url, test_type, key=None, variation_func=None):
    unique = f"poison_{random.randint(100000, 999999)}"
    parsed = urlparse(url)

    result = {
        'url': url,
        'test_type': test_type,
        'header_used': key if test_type == 'Headers' else '',
        'param_used': key if test_type == 'Params' else '',
        'variation_used': key if test_type == 'with-paths' else '',
        'poisoned_url': '',
        'unique_poison': unique,
        'extra_headers': {},
        'cache_status': '',
        'reflected': False,
        'hash_changed': False,
        'cdn': 'Unknown',
        'status_code': 0,
        'cache_headers': {}
    }

    extra_h = {}
    poisoned_url = url
    poisoned_desc = url

    if test_type == 'Headers':
        extra_h = {key: unique}
        poisoned_desc = f"{url} -H {key}:{unique}"
    elif test_type == 'Params':
        q = f"{key}={unique}"
        poisoned_url = url + ('&' if parsed.query else '?') + q
        poisoned_desc = poisoned_url
    elif test_type == 'with-paths':
        poisoned_base = variation_func(parsed)
        q = f"test={unique}"
        p_parsed = urlparse(poisoned_base)
        poisoned_url = poisoned_base + ('&' if p_parsed.query else '?') + q
        poisoned_desc = f"{url} {key.replace('append_', '/').replace('_', '-')}"

    result['poisoned_url'] = poisoned_url
    result['extra_headers'] = extra_h

    print(f"testing-{test_type} : {poisoned_desc} ...", end=' ')

    resp_base   = make_request(url)
    time.sleep(args.delay)
    if not resp_base:   print("request failed"); return result, False

    hash_base = body_hash(resp_base)
    cdn = detect_cdn(resp_base.headers)
    result['cdn'] = cdn

    resp_poison = make_request(poisoned_url, extra_h)
    time.sleep(args.delay)
    if not resp_poison: print("request failed"); return result, False

    resp_clean  = make_request(url)
    time.sleep(args.delay)
    if not resp_clean:  print("request failed"); return result, False

    hash_clean = body_hash(resp_clean)
    cache_headers_clean = get_cache_headers(resp_clean)
    cache_status_clean  = get_cache_status(cache_headers_clean)

    reflected   = unique in (resp_clean.text or '')
    hash_changed = hash_clean != hash_base

    result.update({
        'cache_status': cache_status_clean,
        'reflected': reflected,
        'hash_changed': hash_changed,
        'status_code': resp_clean.status_code,
        'cache_headers': cache_headers_clean
    })

    is_suspect = (reflected or hash_changed) and cache_status_clean in ('HIT', 'MISS')

    if is_suspect:
        print("bounty")
        print(f"\033[41mHere is your bounty: Cache poisoning hit using {test_type} {key}\033[0m")
        print(f"Poisoned URL/Path: {poisoned_url}")
        if extra_h:
            print(f"With headers: {extra_h}")
        print(f"Unique poison: {unique}")
        print("Steps to reproduce:")
        print(f"1. GET {url}")
        print(f"2. GET {poisoned_url}" + (f" with {extra_h}" if extra_h else ""))
        print(f"3. GET {url} again - check for change or reflection of {unique}")
    else:
        print("no-here")

    return result, is_suspect

# ───────────────────────────────────────────────
#  Default caching check (unchanged)
# ───────────────────────────────────────────────

def check_default_caching(url):
    print(f"testing-with-nothing : {url} ...", end=' ')
    resp1 = make_request(url)
    time.sleep(args.delay)
    if not resp1:
        print("request failed")
        return 'UNKNOWN', False

    resp2 = make_request(url)
    time.sleep(args.delay)
    if not resp2:
        print("request failed")
        return 'UNKNOWN', False

    cache_status2 = get_cache_status(get_cache_headers(resp2))
    is_hit = cache_status2 == 'HIT'

    if is_hit:
        print("hit (default cache)")
    else:
        print("no-here")

    return cache_status2, is_hit

# ───────────────────────────────────────────────
#  Process one URL — with --continue logic
# ───────────────────────────────────────────────

def process_url(url):
    print(f"\n[Starting analysis for URL: {url}]")
    print("=" * 80)

    results = []

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            print(f"\033[31m[INVALID URL] {url}\033[0m")
            return []
    except:
        print(f"\033[31m[INVALID URL] {url}\033[0m")
        return []

    default_cache, is_default_suspect = check_default_caching(url)
    if is_default_suspect:
        print(f"\033[41mDefault caching detected — worth checking poisoning manually.\033[0m")

    do_headers    = not args.params_only
    do_params     = not args.headers_only
    do_variations = not args.headers_only and not args.params_only

    stop_early = False

    if do_headers:
        for h in headers_to_test:
            if stop_early:
                break
            res, suspect = perform_test(url, 'Headers', key=h)
            results.append(res)
            if suspect and not args.continue_on_success:
                print(f"→ Suspect found & --continue not used → stopping this URL early.")
                stop_early = True

    if do_params and not stop_early:
        for p in params_to_test:
            if stop_early:
                break
            res, suspect = perform_test(url, 'Params', key=p)
            results.append(res)
            if suspect and not args.continue_on_success:
                print(f"→ Suspect found & --continue not used → stopping this URL early.")
                stop_early = True

    if do_variations and not stop_early:
        for v_name, v_func in variations:
            if stop_early:
                break
            res, suspect = perform_test(url, 'with-paths', key=v_name, variation_func=v_func)
            results.append(res)
            if suspect and not args.continue_on_success:
                print(f"→ Suspect found & --continue not used → stopping this URL early.")
                stop_early = True

    print(f"[Analysis complete for {url}]")
    print("=" * 80 + "\n")
    return results

# ───────────────────────────────────────────────
#  Main execution
# ───────────────────────────────────────────────

all_results    = []
cache_hits     = set()
cache_suspect  = set()

with ThreadPoolExecutor(max_workers=args.threads) as executor:
    futures = [executor.submit(process_url, u) for u in urls]
    for future in as_completed(futures):
        try:
            res_list = future.result()
            for res in res_list:
                all_results.append(res)
                u = res['url']
                if res.get('cache_status') == 'HIT':
                    cache_hits.add(u)
                if res.get('reflected') or res.get('hash_changed'):
                    if res.get('cache_status') in ('HIT', 'MISS'):
                        cache_suspect.add(u)
        except Exception as e:
            print(f"Worker failed: {e}")

# ───────────────────────────────────────────────
#  Save results
# ───────────────────────────────────────────────

print(f"\nSaving full results → {args.output}")
with open(args.output, 'w', encoding='utf-8') as f:
    json.dump(all_results, f, indent=2, ensure_ascii=False)

print(f"Saving cached URLs → {args.cache_hits}")
with open(args.cache_hits, 'w', encoding='utf-8') as f:
    for u in sorted(cache_hits):
        f.write(u + '\n')

print(f"Saving suspect URLs → {args.suspect}")
with open(args.suspect, 'w', encoding='utf-8') as f:
    f.write("Potentially vulnerable URLs (cache poisoning / deception possible):\n")
    f.write("-" * 70 + "\n")
    for u in sorted(cache_suspect):
        f.write(u + '\n')

print("\n" + "="*75)
print(f"Scan finished.")
print(f"  • URLs scanned:          {len(urls)}")
print(f"  • Cache hits found:      {len(cache_hits)}")
print(f"  • Potentially vulnerable: {len(cache_suspect)}")
print(f"  • Full JSON:             {args.output}")
print(f"  • Cache hits file:       {args.cache_hits}")
print(f"  • Suspect file:          {args.suspect}")
print("="*75)
