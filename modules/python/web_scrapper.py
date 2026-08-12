#!/usr/bin/env python3
"""
web_scrapper.py — Web Scraping Module

Async-first • Playwright • selectolax • Sitemap • Classification
Communicates via JSON lines IPC (stdin → stdout).
"""

import asyncio
import json
import sys
import time
import re
import hashlib
import random
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

import aiohttp
from selectolax.parser import HTMLParser

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════════════════
# IPC Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def emit(msg: dict):
    print(json.dumps(msg), flush=True)

def log(level: str, message: str):
    emit({"type": "log", "level": level, "message": message})

def progress(percent: int, message: str = ""):
    emit({"type": "progress", "percent": percent, "message": message})

def finding(title: str, description: str, severity: str, evidence: str = "",
            tags: list = None, remediation: str = ""):
    emit({
        "type": "finding",
        "title": title,
        "description": description,
        "severity": severity,
        "evidence": evidence,
        "tags": tags or [],
        "remediation": remediation,
    })

def error(message: str):
    emit({"type": "error", "message": message})

def done(summary: str = ""):
    emit({"type": "done", "summary": summary})

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScraperConfig:
    target: str = ""
    run_id: str = "unknown"
    max_pages: int = 0
    max_depth: int = 0
    same_domain_only: bool = True
    use_browser: bool = False
    parse_sitemap: bool = True
    classify_content: bool = True
    delay: float = 0.5
    jitter: float = 0.3
    workers: int = 10
    timeout: int = 15
    headless: bool = True
    page_load_timeout: int = 15
    intercept_network: bool = True
    output_file: str = ""
    
    exclude_extensions: Set[str] = field(default_factory=lambda: {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.otf', '.mp4', '.mp3', '.avi',
        '.mov', '.flv', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.zip', '.tar', '.gz', '.exe', '.msi', '.dmg', '.apk',
        '.css', '.map', '.woff2',
    })
    
    @classmethod
    def from_context(cls, ctx: dict):
        opts = ctx.get("config", ctx.get("options", {}))
        timeout_secs = ctx.get("timeout_secs", opts.get("timeout", 15))
        return cls(
            target=ctx.get("target", ""),
            run_id=ctx.get("run_id", "unknown"),
            max_pages=opts.get("max_pages", 0),
            max_depth=opts.get("max_depth", 0),
            same_domain_only=opts.get("same_domain_only", True),
            use_browser=opts.get("use_browser", False),
            parse_sitemap=opts.get("parse_sitemap", True),
            classify_content=opts.get("classify_content", True),
            delay=opts.get("delay", 0.5),
            jitter=opts.get("jitter", 0.3),
            workers=opts.get("workers", 10),
            timeout=timeout_secs,
            headless=opts.get("headless", True),
            page_load_timeout=opts.get("page_load_timeout", 15),
            intercept_network=opts.get("intercept_network", True),
            output_file=opts.get("output_file", ""),
        )

# ═══════════════════════════════════════════════════════════════════════════════
# URL Canonicalization
# ═══════════════════════════════════════════════════════════════════════════════

class URLCanonicalizer:
    TRACKING_PARAMS = {
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
        'fbclid', 'gclid', 'gclsrc', 'dclid', 'gbraid', 'wbraid',
        'msclkid', 'mc_cid', 'mc_eid', '_ga', '_gl', '_hsenc', '_hsmi',
        'ref', 'source', 'ref_src', 'ref_url', 'trk', 'mkt_tok',
    }
    
    @staticmethod
    def canonicalize(url: str, source_url: str = "") -> Optional[str]:
        if not url or url.startswith('#') or url.startswith('javascript:') or url.startswith('mailto:') or url.startswith('tel:'):
            return None
        url = url.strip().split('#')[0]
        if not url:
            return None
        # Resolve relative URLs against source
        if source_url:
            url = urljoin(source_url, url)
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None
        if parsed.scheme not in ('http', 'https'):
            return None
        # Strip tracking params
        clean_qs = {k: v[0] for k, v in parse_qs(parsed.query).items()
                    if k not in URLCanonicalizer.TRACKING_PARAMS}
        new_query = '&'.join(f"{k}={v}" for k, v in sorted(clean_qs.items()))
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

# ═══════════════════════════════════════════════════════════════════════════════
# Content Classifier
# ═══════════════════════════════════════════════════════════════════════════════

class ContentClassifier:
    HTML_TAGS = {'html', 'head', 'meta', 'link', 'style', 'script', 'noscript', 'br', 'hr'}
    EMPTY_TAGS = {'img', 'input', 'area', 'base', 'col', 'embed', 'source', 'track', 'wbr'}
    HEADING_TAGS = {'h1', 'h2', 'h3', 'h4', 'h5', 'h6'}
    LIST_TAGS = {'ul', 'ol', 'li', 'dl', 'dt', 'dd'}
    TABLE_TAGS = {'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th', 'caption'}
    FORM_TAGS = {'form', 'fieldset', 'legend', 'label', 'button', 'select', 'option', 'optgroup', 'textarea', 'input'}
    
    @staticmethod
    def classify(html: str) -> dict:
        try:
            tree = HTMLParser(html)
            body = tree.css_first('body')
            if not body:
                return {"type": "unknown", "score": 0}
            text = body.text(strip=True, separator=' ')
            words = text.split()
            links = body.css('a[href]')
            forms = body.css('form')
            headings = body.css(ContentClassifier.HEADING_TAGS)
            tables = body.css(ContentClassifier.TABLE_TAGS)
            lists = body.css(ContentClassifier.LIST_TAGS)
            
            total_tags = len(list(tree.iter()))
            text_ratio = len(text) / max(total_tags, 1)
            
            if text_ratio > 20:
                return {"type": "text", "score": text_ratio}
            elif len(links) > 5:
                return {"type": "navigation", "score": len(links)}
            elif len(forms) > 0:
                return {"type": "form", "score": len(forms)}
            elif len(headings) > 3:
                return {"type": "content", "score": len(headings)}
            elif len(tables) > 0:
                return {"type": "data", "score": len(tables)}
            else:
                return {"type": "generic", "score": text_ratio}
        except Exception:
            return {"type": "unknown", "score": 0}

# ═══════════════════════════════════════════════════════════════════════════════
# Core Scraper
# ═══════════════════════════════════════════════════════════════════════════════

class WebScraper:
    def __init__(self, config: ScraperConfig):
        self.config = config
        self.seen_urls: Set[str] = set()
        self.visited: Set[str] = set()
        self.results: List[dict] = []
        self.domain = urlparse(config.target).netloc if config.target else ""
        
    async def fetch(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        try:
            async with session.get(url, timeout=self.config.timeout) as resp:
                if resp.status == 200:
                    return await resp.text()
                return None
        except Exception:
            return None
    
    async def discover_links(self, html: str, base_url: str) -> List[str]:
        try:
            tree = HTMLParser(html)
            links = []
            for a in tree.css('a[href]'):
                href = a.attributes.get('href', '')
                canonical = URLCanonicalizer.canonicalize(href, base_url)
                if canonical and canonical not in self.seen_urls:
                    self.seen_urls.add(canonical)
                    links.append(canonical)
            return links
        except Exception:
            return []
    
    async def run(self):
        if not self.config.target:
            error("No target specified")
            done("Scraping aborted: no target")
            return

        log("info", f"Starting scrape of {self.config.target}")
        progress(0, "Initializing")

        max_p = self.config.max_pages if self.config.max_pages > 0 else 100
        crawl_queue = deque([self.config.target])
        self.seen_urls.add(self.config.target)

        async with aiohttp.ClientSession() as session:
            while crawl_queue and len(self.visited) < max_p:
                url = crawl_queue.popleft()
                progress(
                    int(len(self.visited) / max_p * 100),
                    f"Scraping {url}"
                )
                log("info", f"Fetching: {url}")

                html = await self.fetch(session, url)
                if not html:
                    log("warn", f"No response from {url}")
                    continue

                self.visited.add(url)
                links = await self.discover_links(html, url)

                for link in links:
                    is_internal = urlparse(link).netloc == self.domain
                    tag = "internal-link" if is_internal else "external-link"
                    finding(
                        title=link,
                        description=f"{'Internal' if is_internal else 'External'} link found on {url}",
                        severity="info",
                        evidence=link,
                        tags=["recon", "web-scraper", tag],
                    )
                    # Only follow internal links
                    if is_internal and link not in self.seen_urls and len(crawl_queue) + len(self.visited) < max_p:
                        self.seen_urls.add(link)
                        crawl_queue.append(link)

                # Polite delay between requests
                await asyncio.sleep(self.config.delay)

        done(f"Scraped {len(self.visited)} pages, {len(self.seen_urls)} unique URLs found")
        log("info", f"Completed scraping of {self.config.target}")

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    try:
        raw = sys.stdin.readline()
        if not raw:
            done("No input received")
            return
        ctx = json.loads(raw.strip())
    except (json.JSONDecodeError, Exception):
        done("Malformed input, aborting")
        return
    
    config = ScraperConfig.from_context(ctx)
    scraper = WebScraper(config)
    await scraper.run()

if __name__ == "__main__":
    asyncio.run(main())