#!/usr/bin/env python3
"""
Cache Poisoning / Deception Scanner
Inspired by autopoisoner + output style like modern web cache tools
Supports batch from file + multithreading
"""

import argparse
import random
import time
import threading
import json
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Tuple, Optional

# ────────────────────────────────────────────────
#  Configuration
# ────────────────────────────────────────────────

CANARY_BASE = "poison"
TIMEOUT = 12
DELAY_BETWEEN = 0.6          # seconds between requests to same target

HEADERS_TO_TEST = [
    "X-Forwarded-Host", "X-Host", "X-Original-URL", "X-Rewrite-URL",
    "X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Original-Host",
    "Forwarded", "X-HTTP-Method-Override", "X-Amz-Website-Redirect-Location",
    "X-Forwarded-Prefix", "Host", "Referer", "Origin"
]

PARAMS_TO_TEST = [
    "cb", "cachebuster", "v", "_", "t", "test", "debug", "utm_source",
    "utm_medium", "lang", "format", "callback"
]

PATH_VARIATIONS = {
    "trailing-slash-add":    lambda p: p._replace(path=p.path.rstrip('/') + '/'),
    "trailing-slash-remove": lambda p: p._replace(path=p.path.rstrip('/')),
    "double-slash":          lambda p: p._replace(path='//' + p.path.lstrip('/')),
    "encoded-slash":         lambda p: p._replace(path=p.path.replace('/', '%2f')),
    "upper-path":            lambda p: p._replace(path=p.path.upper()),
    # You can add more: append_.css, /../test, etc.
}

# ────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────

def random_suffix() -> str:
    return f"{CANARY_BASE}_{random.randint(100000, 999999)}"


def make_request(url: str, headers: Optional[Dict] = None, timeout: int = TIMEOUT) -> Optional[requests.Response]:
    try:
        return requests.get(
            url,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=False
        )
    except (requests.RequestException, KeyboardInterrupt):
        return None


def get_cache_indicators(headers: Dict) -> Dict[str, Any]:
    indicators = {}
    for h in ["X-Cache", "X-Cache-Hits", "Age", "Cf-Cache-Status", "X-Cache-Status"]:
        if h.lower() in (k.lower() for k in headers):
            indicators[h] = headers.get(h) or headers.get(h.lower())
    return indicators


def looks_cached(headers: Dict) -> bool:
    cache_status = headers.get("Cf-Cache-Status", "").lower()
    if cache_status in ["hit", "hit-from-origin", "dynamic"]:
        return True
    if "age" in headers and int(headers.get("Age", 0)) > 0:
        return True
    if "x-cache" in (k.lower() for k in headers) and "hit" in headers.get("X-Cache", "").lower():
        return True
    return False


def body_fingerprint(resp: requests.Response) -> str:
    if not resp or not resp.text:
        return ""
    # Very simple hash — in production you might use xxhash or simhash
    return str(hash(resp.text[:8000]))


# ────────────────────────────────────────────────
#  Core test function
# ────────────────────────────────────────────────

def perform_test(url: str, test_type: str, key: str = "", variation_func=None) -> Tuple[Dict, bool]:
    result: Dict[str, Any] = {
        "url": url,
        "test_type": test_type,
        "key": key,
        "poisoned_url": url,
        "extra_headers": {},
        "cache_status": "UNKNOWN",
        "reflected": False,
        "hash_changed": False,
        "status_code": 0,
    }

    unique = random_suffix()
    poisoned_url = url
    poisoned_desc = url
    extra_h = {}

    parsed = urlparse(url)

    if test_type == "Headers":
        extra_h = {key: unique}
        poisoned_desc = f"{url} -H {key}:{unique}"
    elif test_type == "Params":
        q = f"{key}={unique}"
        sep = "&" if parsed.query else "?"
        poisoned_url = url + sep + q
        poisoned_desc = poisoned_url
    elif test_type == "with-paths" and variation_func:
        poisoned_parsed = variation_func(parsed)
        poisoned_base = poisoned_parsed.geturl()
        q = f"test={unique}"
        p_parsed = urlparse(poisoned_base)
        sep = "&" if p_parsed.query else "?"
        poisoned_url = poisoned_base + sep + q
        poisoned_desc = f"{url} {key.replace('_', '-')}"

    result["poisoned_url"] = poisoned_url
    result["extra_headers"] = extra_h

    print(f"testing-{test_type} : {poisoned_desc} ... ", end="", flush=True)

    # 1. Baseline
    resp_base = make_request(url)
    time.sleep(DELAY_BETWEEN)
    if not resp_base:
        print("request failed")
        return result, False

    hash_base = body_fingerprint(resp_base)

    # 2. Poisoned request
    resp_poison = make_request(poisoned_url, extra_h)
    time.sleep(DELAY_BETWEEN)
    if not resp_poison:
        print("request failed")
        return result, False

    # 3. Clean request after poison attempt
    resp_clean = make_request(url)
    time.sleep(DELAY_BETWEEN)
    if not resp_clean:
        print("request failed")
        return result, False

    hash_clean = body_fingerprint(resp_clean)
    cache_ind = get_cache_indicators(resp_clean.headers)
    cache_status = "HIT" if looks_cached(resp_clean.headers) else "MISS/UNKNOWN"

    reflected = unique in (resp_clean.text or "")
    hash_changed = hash_clean != hash_base

    result.update({
        "cache_status": cache_status,
        "reflected": reflected,
        "hash_changed": hash_changed,
        "status_code": resp_clean.status_code,
        "cache_headers": cache_ind
    })

    is_suspect = (reflected or hash_changed) and cache_status == "HIT"

    if is_suspect:
        print("bounty")
        print(f"\033[41mHere is your bounty: Cache poisoning hit using {test_type} {key}\033[0m")
        print(f"Poisoned URL/Path: {poisoned_url}")
        if extra_h:
            print(f"With headers: {extra_h}")
        print(f"Unique poison: {unique}")
        print("Steps to reproduce:")
        print(f"  1. GET {url}")
        print(f"  2. GET {poisoned_url}" + (f"   with {extra_h}" if extra_h else ""))
        print(f"  3. GET {url} again → reflection/change of {unique}")
    else:
        print("no-here")

    return result, is_suspect


def check_default_caching(url: str) -> Tuple[str, bool]:
    print(f"testing-with-nothing : {url} ... ", end="", flush=True)

    r1 = make_request(url)
    time.sleep(DELAY_BETWEEN)
    if not r1:
        print("request failed")
        return "UNKNOWN", False

    r2 = make_request(url)
    time.sleep(DELAY_BETWEEN)
    if not r2:
        print("request failed")
        return "UNKNOWN", False

    cached = looks_cached(r2.headers)
    status = "HIT" if cached else "MISS/UNKNOWN"

    if cached:
        print("hit (default cache)")
    else:
        print("no-here")

    return status, cached


def process_single_url(url: str, args) -> list:
    print(f"\n{'='*80}")
    print(f"[Starting analysis for URL: {url}]")
    print(f"{'='*80}\n")

    results = []

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            print(f"\033[31m[INVALID URL] {url}\033[0m")
            return results
    except Exception:
        print(f"\033[31m[INVALID URL] {url}\033[0m")
        return results

    # Check if the target even supports default caching
    _, default_cached = check_default_caching(url)
    # Note: we continue even if cached — goal is poisoning, not just caching

    # Headers
    for header in HEADERS_TO_TEST:
        res, suspect = perform_test(url, "Headers", key=header)
        results.append(res)
        if suspect and not args.continue_after_find:
            return results

    # Query parameters
    for param in PARAMS_TO_TEST:
        res, suspect = perform_test(url, "Params", key=param)
        results.append(res)
        if suspect and not args.continue_after_find:
            return results

    # Path variations
    for name, func in PATH_VARIATIONS.items():
        res, suspect = perform_test(url, "with-paths", key=name, variation_func=func)
        results.append(res)
        if suspect and not args.continue_after_find:
            return results

    print(f"\n[Analysis complete for {url}]")
    print(f"{'='*80}\n")

    return results


def main():
    parser = argparse.ArgumentParser(description="Web Cache Poisoning / Deception Scanner")
    parser.add_argument("--file", "-f", help="File with one URL per line")
    parser.add_argument("--url", "-u", help="Single URL to test")
    parser.add_argument("--threads", "-n", type=int, default=5, help="Number of concurrent targets")
    parser.add_argument("--delay", type=float, default=0.6, help="Delay between requests (seconds)")
    parser.add_argument("--output", "-o", default="cache_scan_results.json", help="JSON results file")
    parser.add_argument("--cache-hits", default="cache_hits.txt", help="List of URLs with cache hits")
    parser.add_argument("--suspect", default="suspect_urls.txt", help="Potentially poisoned URLs")
    parser.add_argument("--continue", dest="continue_after_find", action="store_true",
                        help="Continue testing even after finding a suspect case")
    args = parser.parse_args()

    global DELAY_BETWEEN
    DELAY_BETWEEN = args.delay

    urls = []
    if args.url:
        urls = [args.url.strip()]
    elif args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as e:
            print(f"Error reading file: {e}")
            return
    else:
        parser.print_help()
        return

    if not urls:
        print("No URLs provided.")
        return

    print(f"\nStarting scan of {len(urls)} URL(s) with {args.threads} threads ...\n")

    all_results = []
    cache_hits = set()
    suspects = set()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(process_single_url, u, args): u for u in urls}
        for future in as_completed(future_to_url):
            try:
                res_list = future.result()
                all_results.extend(res_list)
                for r in res_list:
                    if r.get("cache_status") == "HIT":
                        cache_hits.add(r["url"])
                    if r.get("reflected") or r.get("hash_changed"):
                        if r.get("cache_status") == "HIT":
                            suspects.add(r["url"])
            except Exception as exc:
                url = future_to_url[future]
                print(f"Thread for {url} generated an exception: {exc}")

    # Save results
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    with open(args.cache_hits, "w", encoding="utf-8") as f:
        for u in sorted(cache_hits):
            f.write(u + "\n")

    with open(args.suspect, "w", encoding="utf-8") as f:
        f.write("Potentially vulnerable to cache poisoning / deception:\n")
        for u in sorted(suspects):
            f.write(u + "\n")

    print(f"\nScan finished.")
    print(f"  Results:        {args.output}")
    print(f"  Cache hits:     {args.cache_hits} ({len(cache_hits)})")
    print(f"  Suspect URLs:   {args.suspect}   ({len(suspects)})")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
