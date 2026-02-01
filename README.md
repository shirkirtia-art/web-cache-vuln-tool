# Web Cache Vuln Tool

Lightweight **Python** tool for testing **web cache poisoning** and **cache deception** vulnerabilities.

It checks:
- Default caching behavior
- Header-based poisoning (X-Forwarded-Host, X-Host, Forwarded, etc.)
- Unkeyed / reflected parameter poisoning
- Path manipulation tricks (trailing slash, double slash, encoded slash, etc.)

Detects potential issues by looking for reflection of unique canaries, response body changes after poisoning attempts, and cache-hit indicators.

## Features

- Multithreaded scanning from a file of URLs
- Three main attack surfaces: Headers, Params, Path variations
- Simple cache-hit detection via repeated requests
- Colored "bounty" messages on suspected findings
- JSON + txt output for results, cache hits and suspect URLs

## Installation

1. Clone the repository:

```
git clone https://github.com/shirkirtia-art/web-cache-vuln-tool.git
cd web-cache-vuln-tool
```
2. Install dependencies (only requests is required):
```
pip install requests
# or
python -m pip install requests
```
Usage
Single URL
```
python cache_scanner.py -u https://example.com/style.css
```
Scan multiple URLs from file
Create targets.txt with one URL per line:
```
https://example.com/
https://example.com/assets/main.js
https://example.com/blog/post-123
```
Then run:
```
# Basic scan (default 5 threads)
python cache_scanner.py -f targets.txt

# Faster scanning
python cache_scanner.py -f targets.txt -n 12 --delay 0.4

# Safer / more polite scanning
python cache_scanner.py -f targets.txt --delay 1.8 -n 4 --continue

# Custom output filenames
python cache_scanner.py -f targets.txt \
  --continue \
  --output results-batch-2026.json \
  --cache-hits cached-2026.txt \
  --suspect suspects-2026.txt

```
Available options
```
--file,  -f FILE       File with URLs (one per line)
--url,   -u URL        Single URL to test

--threads, -n N        Number of concurrent targets (default: 5)
--delay SECONDS        Seconds between requests to the same target (default: 0.6)
--timeout SECONDS      Request timeout (default: 30)

--output FILE          JSON results file (default: cache_scan_results.json)
--cache-hits FILE      File for URLs that appear cached / HIT (default: cache_hits.txt)
--suspect FILE         File for potentially vulnerable URLs (default: suspect_urls.txt)

--continue             Keep testing after finding a suspect / bounty case

--headers-only         Only test header-based poisoning
--params-only          Only test query parameter poisoning

--user-agent STRING    Custom User-Agent header
```
Example Output
```
================================================================================
[Starting analysis for URL: https://example.com/community/redirect/tutorial-on-loops]
================================================================================

testing-with-nothing : https://example.com/community/redirect/tutorial-on-loops ... request failed
testing-Params : https://example.com/cdn-cgi/styles/cf.errors.css?format=poison_381137 ... no-here
testing-Headers : https://example.com/community/redirect/r-or-python -H X-Forwarded-Host:poison_390281 ... no-here
testing-Headers : https://example.com/cheat-sheet/data-knowledge -H X-HTTP-Method-Override:poison_293170 ... no-here
testing-Headers : https://example.com/cdn-cgi/bm/cv/result?req_id=xxx -H X-HTTP-Method-Override:poison_899196 ... request failed
testing-Params : https://example.com/cdn-cgi/styles/cf.errors.css?callback=poison_708446 ... no-here
...
testing-with-paths : https://example.com/cdn-cgi/styles/cf.errors.css trailing-slash-add ... no-here
...
```
When something suspicious is found:
```
testing-Headers : https://example.com/api/v1/data -H X-Forwarded-Host:poison_123456 ... bounty
Here is your bounty: Cache poisoning hit using Headers X-Forwarded-Host
Poisoned URL/Path: https://example.com/api/v1/data
With headers: {'X-Forwarded-Host': 'poison_123456'}
Unique poison: poison_123456
Steps to reproduce:
  1. GET https://example.com/api/v1/data
  2. GET https://example.com/api/v1/data with {'X-Forwarded-Host': 'poison_123456'}
  3. GET https://example.com/api/v1/data again → reflection/change of poison_123456
