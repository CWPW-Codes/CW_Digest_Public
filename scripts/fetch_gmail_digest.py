#!/usr/bin/env python3
"""CW Digest Gmail ingestion and in-place HTML sync for newsletter-digest.html."""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from email.utils import parseaddr
from html import escape as html_escape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import parse_qs, urlparse

HTTP_SCHEMES = {"http", "https"}
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

REDIRECT_QUERY_KEYS = (
    "url",
    "u",
    "redirect",
    "target",
    "dest",
    "destination",
    "to",
    "q",
)

MANAGEMENT_KEYWORDS = (
    "unsubscribe",
    "manage",
    "preferences",
    "preference center",
    "email settings",
    "optout",
    "opt-out",
    "privacy",
    "view in browser",
    "webversion",
)

ALL_SOURCES = ("politico", "substack", "stephen_bush", "newsletters")

DEFAULT_SOURCE_QUERIES = {
    "politico": "(from:(politico.eu OR politico.com OR politicoemail.com) OR subject:(Playbook OR Politico)) newer_than:14d",
    "substack": (
        "(from:(substack.com OR substackmail.com OR everyone@labourtogether.co.uk) "
        "OR list:substack.com OR subject:\"on Substack\" OR \" via Everyone\") "
        "newer_than:60d -subject:\"Inside Politics\""
    ),
    "stephen_bush": "subject:\"Inside Politics\" newer_than:120d",
    "newsletters": (
        "(category:updates OR category:primary) newer_than:14d "
        "(newsletter OR digest OR briefing OR analysis OR playbook OR substack OR unsubscribe)"
    ),
}

SOURCE_LABELS = {
    "politico": "POLITICO",
    "substack": "SUBSTACK",
    "stephen_bush": "STEPHEN BUSH",
    "newsletter": "NEWSLETTER",
    "alert": "BREAKING",
}

SUBSTACK_DOMAINS = ("substack.com", "substackmail.com")
POLITICO_DOMAINS = ("politico.eu", "politico.com", "politicoemail.com")
FT_DOMAINS = ("ft.com",)
NEWSLETTER_PROVIDER_DOMAINS = (
    "substack.com",
    "substackmail.com",
    "beehiiv.com",
    "buttondown.email",
    "mailchi.mp",
    "mailchimpapp.net",
    "tinyletter.com",
    "convertkit-mail.com",
    "ck.page",
    "ghost.io",
)
NEWS_ORG_DOMAIN_HINTS = (
    "politico.com",
    "politico.eu",
    "ft.com",
    "economist.com",
    "newstatesman.co.uk",
    "spectator.co.uk",
    "thetimes.co.uk",
    "telegraph.co.uk",
    "theguardian.com",
    "guardian.co.uk",
    "bbc.co.uk",
    "bbc.com",
    "semafor.com",
    "bloomberg.com",
    "axios.com",
    "foreignpolicy.com",
    "foreignaffairs.com",
    "atlantic.com",
)
NEWSLETTER_HINT_HEADERS = (
    "list-id",
    "list-unsubscribe",
    "list-unsubscribe-post",
    "precedence",
    "x-newsletter",
    "x-mailing-list",
)
NEWSLETTER_SUBJECT_TERMS = (
    "newsletter",
    "digest",
    "playbook",
    "inside politics",
    "must-read",
    "breaking",
    "briefing",
    "morning",
    "evening",
    "daily",
    "weekly",
)
EVENT_SUBJECT_TERMS = (
    "event",
    "events",
    "webinar",
    "register",
    "registration",
    "rsvp",
    "invitation",
)

EXCLUDED_NEWSLETTER_TERMS = (
    "paper2audio",
    "invoice",
    "receipt",
    "order",
    "shipment",
    "delivery",
    "verification code",
    "password reset",
    "security alert",
    "promo",
    "discount",
    "sale",
    "black friday",
    "cyber monday",
    "trial",
    "webinar",
    "register now",
    "registration",
    "event invite",
    "join us in",
    "rsvp",
    "bacs transfer",
    "timesheet",
    "payroll",
)

NEWS_RELEVANCE_TERMS = (
    "newsletter",
    "digest",
    "briefing",
    "analysis",
    "comment",
    "opinion",
    "politics",
    "policy",
    "government",
    "parliament",
    "election",
    "economy",
    "business",
    "markets",
    "uk",
    "britain",
    "westminster",
    "europe",
    "foreign",
    "ai",
    "tech",
    "science",
    "innovation",
    "industry",
    "climate",
    "energy",
    "health",
)

NEWS_BRAND_TERMS = (
    "politico",
    "financial times",
    "ft",
    "economist",
    "new statesman",
    "spectator",
    "the guardian",
    "guardian",
    "telegraph",
    "the times",
    "bloomberg",
    "axios",
    "semafor",
    "foreign policy",
    "foreign affairs",
    "bbc",
    "inside politics",
    "playbook",
)

SUMMARY_BOILERPLATE_TERMS = (
    "presented by",
    "view this post on the web",
    "view this post",
    "view in browser",
    "read in app",
    "if you are having trouble",
    "manage preferences",
    "unsubscribe",
    "this email was sent to",
    "advertisement",
    "sponsored",
)

SUMMARY_SIGNAL_TERMS = (
    "ai",
    "election",
    "policy",
    "government",
    "labour",
    "conservative",
    "reform",
    "economy",
    "inflation",
    "tax",
    "budget",
    "growth",
    "trade",
    "uk",
    "europe",
    "china",
    "russia",
    "us",
    "nhs",
    "energy",
    "climate",
    "technology",
    "digital",
)

TOPIC_KEYWORDS: dict[str, tuple[str, ...]] = {
    "Elections": ("election", "by-election", "poll", "vote", "mayor"),
    "Labour": ("labour", "starmer", "rayner", "reeves", "mcsweeney"),
    "Conservatives": ("conservative", "tory", "badenoch", "sunak"),
    "Reform": ("reform",),
    "NHS": ("nhs", "health", "hospital", "doctor"),
    "Economy": ("economy", "growth", "inflation", "tax", "budget", "treasury"),
    "Housing": ("housing", "rent", "planning", "home"),
    "Immigration": ("immigration", "asylum", "borders", "migrant"),
    "AI": ("ai", "artificial intelligence", "machine learning"),
    "Tech": ("tech", "digital", "datacentre", "software", "startup"),
    "Foreign Policy": ("ukraine", "russia", "china", "eu", "trump", "diplomat", "foreign"),
}

DAY_KEYS = (
    (5, "sat", "Saturday"),
    (6, "sun", "Sunday"),
    (0, "mon", "Monday"),
    (1, "tue", "Tuesday"),
    (2, "wed", "Wednesday"),
    (3, "thu", "Thursday"),
    (4, "fri", "Friday"),
)
WEEKDAY_TO_KEY = {weekday: key for weekday, key, _name in DAY_KEYS}
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DEFAULT_CREDENTIALS_FILE = PROJECT_ROOT / "config" / "google_oauth_client.json"
DEFAULT_TOKEN_FILE = Path.home() / ".config" / "cw-digest" / "gmail_token.json"
DEFAULT_HTML_FILE = PROJECT_ROOT / "newsletter-digest.html"
DEFAULT_ENV_FILE = PROJECT_ROOT / ".env"
DEFAULT_SUMMARY_CACHE_FILE = PROJECT_ROOT / "data" / "ai_summary_cache.json"
DEFAULT_ARCHIVE_FILE = PROJECT_ROOT / "data" / "archive_weeks.json"
DEFAULT_WEEKS_DIR = PROJECT_ROOT / "data" / "weeks"
SUMMARY_STYLE_VERSION = "briefing-v1"


@dataclass(frozen=True)
class CandidateLink:
    url: str
    anchor_text: str
    channel: str


class _AnchorParser(HTMLParser):
    """Extract links and anchor text in appearance order."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[CandidateLink] = []
        self._href: str | None = None
        self._text_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        if self._href:
            self._flush_link()

        href = None
        for key, value in attrs:
            if key.lower() == "href":
                href = value
                break
        if href:
            self._href = href
            self._text_chunks = []

    def handle_data(self, data: str) -> None:
        if self._href:
            self._text_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href:
            self._flush_link()

    def close(self) -> None:
        if self._href:
            self._flush_link()
        super().close()

    def _flush_link(self) -> None:
        if not self._href:
            return
        anchor_text = " ".join(chunk.strip() for chunk in self._text_chunks if chunk.strip())
        self.links.append(
            CandidateLink(
                url=self._href.strip(),
                anchor_text=anchor_text.strip(),
                channel="html",
            )
        )
        self._href = None
        self._text_chunks = []


_URL_RE = re.compile(r"https?://[^\s<>'\"()\\]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", re.IGNORECASE)
_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")


def _strip_url_punctuation(url: str) -> str:
    while url and url[-1] in ".,;:!?)]}'\"":
        url = url[:-1]
    return url


def _normalize_http_url(url: str | None) -> str | None:
    if not url:
        return None
    candidate = _strip_url_punctuation(html.unescape(url.strip()))
    candidate = candidate.strip("\"'")
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in HTTP_SCHEMES:
        return None
    if not parsed.netloc:
        return None
    return parsed.geturl()


def _unwrap_redirect(url: str) -> str:
    """Unwrap common redirect wrappers once."""
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    for key in REDIRECT_QUERY_KEYS:
        values = query.get(key)
        if not values:
            continue
        maybe_url = _normalize_http_url(values[0])
        if maybe_url:
            return maybe_url

    host = parsed.netloc.lower()
    if host.endswith("google.com") and parsed.path == "/url":
        q_values = query.get("q")
        if q_values:
            maybe_url = _normalize_http_url(q_values[0])
            if maybe_url:
                return maybe_url

    return url


def extract_candidate_links(html_body: str | None, text_body: str | None) -> list[CandidateLink]:
    candidates: list[CandidateLink] = []

    if html_body:
        parser = _AnchorParser()
        parser.feed(html_body)
        parser.close()
        candidates.extend(parser.links)

    if text_body:
        for match in _URL_RE.finditer(text_body):
            candidates.append(
                CandidateLink(
                    url=match.group(0),
                    anchor_text="",
                    channel="text",
                )
            )

    resolved: list[CandidateLink] = []
    seen: set[str] = set()
    for candidate in candidates:
        unwrapped = _unwrap_redirect(candidate.url)
        normalized = _normalize_http_url(unwrapped)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        resolved.append(
            CandidateLink(
                url=normalized,
                anchor_text=candidate.anchor_text,
                channel=candidate.channel,
            )
        )
    return resolved


def _is_management_or_tracking_link(candidate: CandidateLink) -> bool:
    combined = f"{candidate.url} {candidate.anchor_text}".lower()
    return any(keyword in combined for keyword in MANAGEMENT_KEYWORDS)


def _is_asset_url(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico")):
        return True
    host = parsed.netloc.lower()
    if host.endswith("politico.eu") and path.startswith("/wp-content/"):
        return True
    return False


def _is_preferred_source_url(source: str, url: str) -> bool:
    source_key = (source or "").strip().lower()
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()

    if source_key in {"politico", "alert"}:
        if not (host.endswith("politico.eu") or host.endswith("politico.com")):
            return False
        return "/article/" in path or "/news/" in path or "/newsletter/" in path

    if source_key == "substack":
        return host.endswith("substack.com") and "/p/" in path

    if source_key == "stephen_bush":
        if host.endswith("newsletters.ft.com"):
            return path.startswith("/c/")
        if host.endswith("ft.com"):
            return "/content/" in path or "/inside-politics" in path
        if host.endswith("labourtogether.co.uk"):
            return "inside-politics" in path
        return False

    return True


def _score_link(source: str, url: str) -> int:
    source_key = (source or "").strip().lower()
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()

    score = 0
    if path and path != "/":
        score += 10
    if len([part for part in path.split("/") if part]) >= 2:
        score += 4
    if path in {"", "/"}:
        score -= 8
    if _is_asset_url(url):
        score -= 250

    if source_key in {"politico", "alert"}:
        if host.endswith("politico.eu") or host.endswith("politico.com"):
            score += 120
        if "/article/" in path or "/news/" in path or "/newsletter/" in path:
            score += 12
    elif source_key == "substack":
        if host.endswith("substack.com"):
            score += 75
        if "/p/" in path:
            score += 100
    elif source_key == "stephen_bush":
        if host.endswith("ft.com"):
            score += 120
        if "/content/" in path:
            score += 20
        if host.endswith("newsletters.ft.com") and path.startswith("/c/"):
            score += 95
        if host.endswith("labourtogether.co.uk"):
            score += 35

    return score


def choose_article_url(source: str, links: Iterable[CandidateLink]) -> str | None:
    filtered = [
        candidate
        for candidate in links
        if not _is_management_or_tracking_link(candidate) and not _is_asset_url(candidate.url)
    ]
    if not filtered:
        return None

    preferred = [candidate for candidate in filtered if _is_preferred_source_url(source, candidate.url)]
    if preferred:
        pool = preferred
    elif (source or "").strip().lower() in {"politico", "alert", "substack", "stephen_bush"}:
        # For known sources, prefer Gmail fallback over weak generic links.
        return None
    else:
        pool = filtered

    scored = sorted(
        enumerate(pool),
        key=lambda row: (-_score_link(source, row[1].url), row[0]),
    )
    best_score = _score_link(source, scored[0][1].url)
    if best_score <= 0:
        return None
    return scored[0][1].url


def resolve_open_links(
    *,
    source: str,
    gmail_link: str | None,
    html_body: str | None,
    text_body: str | None,
) -> dict[str, str | None]:
    links = extract_candidate_links(html_body=html_body, text_body=text_body)
    article_url = choose_article_url(source, links)
    gmail_url = _normalize_http_url(gmail_link)

    if gmail_url:
        open_url = gmail_url
        open_url_type = "gmail"
    elif article_url:
        open_url = article_url
        open_url_type = "article"
    else:
        open_url = None
        open_url_type = "none"

    return {
        "article_url": article_url,
        "gmail_link": gmail_url,
        "open_url": open_url,
        "open_url_type": open_url_type,
    }


def _collapse_whitespace(value: str | None) -> str:
    if not value:
        return ""
    cleaned = _ZERO_WIDTH_RE.sub(" ", value)
    cleaned = cleaned.replace("\xa0", " ")
    cleaned = _CONTROL_RE.sub(" ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def _truncate_text(value: str, limit: int) -> str:
    cleaned = value.strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit].rstrip()


def _to_plain_text(value: str | None) -> str:
    if not value:
        return ""
    text = value
    for _ in range(3):
        unescaped = html.unescape(text)
        if unescaped == text:
            break
        text = unescaped
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\[\s*\]", " ", text)
    return _collapse_whitespace(text)


def _summary_line_cleanup(value: str) -> str:
    line = _collapse_whitespace(value)
    line = line.replace("…", " ")
    line = line.replace("...", " ")
    line = line.replace("|", " ")
    line = re.sub(r"[-_=]{3,}", " ", line)
    line = re.sub(r"\(\s*\)", " ", line)
    if not line.startswith("**"):
        line = line.lstrip("-*•0123456789. ").strip()
    line = re.sub(r"\[[0-9]+\]", "", line)
    return line


def _trim_sentence(value: str, max_len: int = 320) -> str:
    cleaned = _collapse_whitespace(value)
    if len(cleaned) <= max_len:
        return cleaned

    window = cleaned[: max_len + 1]
    for boundary in (".", "?", "!", ";", ":", ","):
        idx = window.rfind(boundary)
        if idx >= int(max_len * 0.55):
            return cleaned[: idx + 1].strip()

    last_space = window.rfind(" ")
    if last_space >= int(max_len * 0.55):
        return window[:last_space].strip()
    return window.strip()


def _split_sentences(value: str) -> list[str]:
    collapsed = _collapse_whitespace(value)
    if not collapsed:
        return []
    parts = re.split(r"(?<=[.!?])\s+", collapsed)
    lines: list[str] = []
    for part in parts:
        line = _summary_line_cleanup(part)
        if line:
            lines.append(line)
    return lines


def _normalize_summary_text(summary_text: str | None, *, max_lines: int = 5, max_line_len: int = 450) -> str:
    raw = (summary_text or "").replace("\r\n", "\n").replace("\r", "\n")
    if not raw.strip():
        return ""

    lines: list[str] = []
    for chunk in raw.split("\n"):
        line = _summary_line_cleanup(chunk)
        if not line:
            continue
        if any(term in line.lower() for term in SUMMARY_BOILERPLATE_TERMS):
            continue
        lines.append(_trim_sentence(line, max_line_len))

    if not lines:
        collapsed = _collapse_whitespace(raw)
        return _trim_sentence(collapsed, max_line_len)

    unique_lines: list[str] = []
    seen: set[str] = set()
    for line in lines:
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        unique_lines.append(line)
        if len(unique_lines) >= max_lines:
            break

    if len(unique_lines) == 1 and max_lines > 1:
        expanded = [_trim_sentence(line, max_line_len) for line in _split_sentences(unique_lines[0])]
        if len(expanded) > 1:
            unique_lines = expanded[:max_lines]

    return "\n\n".join(unique_lines)


def _strip_urls(value: str) -> str:
    return _collapse_whitespace(_URL_RE.sub(" ", value))


def _title_for_summary(title: str | None) -> str:
    cleaned = _collapse_whitespace(title)
    cleaned = re.sub(r"^(re|fwd)\s*:\s*", "", cleaned, flags=re.IGNORECASE)
    return _truncate_text(cleaned or "Digest update", 130)


def _sentence_candidates(text: str) -> list[str]:
    collapsed = _strip_urls(text)
    collapsed = collapsed.replace("•", ". ").replace(";", ". ")
    chunks = re.split(r"(?<=[.!?])\s+|\n+", collapsed)
    candidates: list[str] = []
    for chunk in chunks:
        sentence = _summary_line_cleanup(chunk)
        if not sentence:
            continue
        if len(sentence) < 30:
            continue
        if any(term in sentence.lower() for term in SUMMARY_BOILERPLATE_TERMS):
            continue
        candidates.append(sentence)
    return candidates


def _sentence_score(sentence: str) -> int:
    lower = sentence.lower()
    score = 0
    if re.search(r"\d", sentence):
        score += 8
    if "%" in sentence or "£" in sentence:
        score += 5
    if re.search(r"\b[A-Z]{2,}\b", sentence):
        score += 2
    if ":" in sentence:
        score += 2
    if any(term in lower for term in SUMMARY_SIGNAL_TERMS):
        score += 4
    score += min(len(sentence) // 55, 4)
    return score


def _select_punchy_lines(text: str, max_lines: int = 2) -> list[str]:
    candidates = _sentence_candidates(text)
    if not candidates:
        cleaned = _strip_urls(text)
        if not cleaned:
            return []
        return [_trim_sentence(cleaned, 280)]

    scored = [
        (idx, sentence, _sentence_score(sentence))
        for idx, sentence in enumerate(candidates)
    ]
    chosen = sorted(scored, key=lambda row: (-row[2], row[0]))[: max_lines + 1]
    chosen.sort(key=lambda row: row[0])

    lines: list[str] = []
    seen: set[str] = set()
    for _idx, sentence, _score in chosen:
        normalized = sentence.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        lines.append(_trim_sentence(sentence, 320))
        if len(lines) >= max_lines:
            break
    return lines


def _build_summary(title: str, snippet: str | None, text_body: str | None) -> str:
    source_text = _to_plain_text(text_body) or _to_plain_text(snippet)
    title_line = _title_for_summary(title)
    if not source_text:
        return _normalize_summary_text(title_line, max_lines=1, max_line_len=130)

    body_lines = _select_punchy_lines(source_text, max_lines=3)
    title_lower = title_line.lower()
    filtered_lines = [
        line
        for line in body_lines
        if line.lower() not in title_lower and title_lower not in line.lower()
    ]
    if not filtered_lines:
        filtered_lines = body_lines
    if not filtered_lines:
        for sentence in _split_sentences(source_text):
            if sentence.lower() == title_lower:
                continue
            if any(term in sentence.lower() for term in SUMMARY_BOILERPLATE_TERMS):
                continue
            filtered_lines = [_trim_sentence(sentence, 320)]
            break
    if not filtered_lines:
        fallback_snippet = _trim_sentence(_to_plain_text(snippet), 240)
        if fallback_snippet and fallback_snippet.lower() != title_lower:
            filtered_lines = [fallback_snippet]

    lines = [title_line, *filtered_lines[:2]]
    return _normalize_summary_text("\n\n".join(lines), max_lines=5, max_line_len=450)


def _render_bold_paragraph(para: str) -> str:
    """Convert **bold text** markers to <strong> tags, escaping the rest."""
    parts = re.split(r"(\*\*.+?\*\*)", para)
    html_parts: list[str] = []
    for part in parts:
        if part.startswith("**") and part.endswith("**"):
            html_parts.append(f"<strong>{html_escape(part[2:-2])}</strong>")
        else:
            html_parts.append(html_escape(part))
    return "".join(html_parts)


def _to_summary_html(summary_text: str) -> str:
    normalized = _normalize_summary_text(summary_text)
    if not normalized:
        return "<p></p>"
    lines = [line for line in normalized.split("\n\n") if line.strip()]
    if not lines:
        return "<p></p>"

    has_bold = any("**" in line for line in lines)

    if has_bold:
        return "".join(f"<p>{_render_bold_paragraph(line)}</p>" for line in lines)

    # Legacy/heuristic fallback: headline + bullet list
    if len(lines) == 1:
        expanded = [_trim_sentence(line, 450) for line in _split_sentences(lines[0])]
        if len(expanded) > 1:
            lines = expanded[:5]

    headline = html_escape(lines[0])
    if len(lines) == 1:
        return f"<p><strong>{headline}</strong></p>"

    bullet_items = "".join(f"<li>{html_escape(line)}</li>" for line in lines[1:])
    return f"<p><strong>{headline}</strong></p><ul>{bullet_items}</ul>"


def _default_query_for_source(source: str) -> str:
    return DEFAULT_SOURCE_QUERIES.get((source or "").strip().lower(), "newer_than:14d")


def _read_optional_file(path: str | None) -> str | None:
    if not path:
        return None
    return Path(path).read_text(encoding="utf-8")


def _load_dotenv_file(path: Path) -> int:
    if not path.exists():
        return 0

    loaded = 0
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        if (
            len(value) >= 2
            and ((value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'"))
        ):
            value = value[1:-1]

        if key not in os.environ:
            os.environ[key] = value
            loaded += 1
    return loaded


def _summary_content_hash(title: str, text: str) -> str:
    digest_source = f"{title}\n{text}".encode("utf-8", errors="replace")
    return hashlib.sha256(digest_source).hexdigest()


def _load_summary_cache(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "entries": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {"version": 1, "entries": {}}

    if not isinstance(data, dict):
        return {"version": 1, "entries": {}}
    entries = data.get("entries")
    if not isinstance(entries, dict):
        data["entries"] = {}
    data.setdefault("version", 1)
    return data


def _save_summary_cache(path: Path, cache_doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache_doc, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def _get_cached_ai_summary(
    *,
    entries: dict[str, Any] | None,
    message_id: str,
    content_hash: str,
    model: str,
) -> str | None:
    if entries is None:
        return None
    record = entries.get(message_id)
    if not isinstance(record, dict):
        return None
    if record.get("content_hash") != content_hash:
        return None
    if record.get("model") != model:
        return None
    if record.get("style_version") != SUMMARY_STYLE_VERSION:
        return None
    summary = record.get("summary")
    if not summary or not isinstance(summary, str):
        return None
    if "..." in summary or "…" in summary:
        return None
    return _normalize_summary_text(summary) or None


def _set_cached_ai_summary(
    *,
    entries: dict[str, Any] | None,
    message_id: str,
    content_hash: str,
    model: str,
    summary: str,
) -> None:
    if entries is None:
        return
    entries[message_id] = {
        "summary": summary,
        "content_hash": content_hash,
        "model": model,
        "style_version": SUMMARY_STYLE_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _decode_base64url(data: str | None) -> str | None:
    if not data:
        return None
    padding = "=" * (-len(data) % 4)
    try:
        raw = base64.urlsafe_b64decode(data + padding)
    except Exception:
        return None
    return raw.decode("utf-8", errors="replace")


def _extract_header(headers: list[dict[str, Any]], name: str) -> str:
    target = name.lower()
    for header in headers:
        if str(header.get("name", "")).lower() == target:
            return str(header.get("value", ""))
    return ""


def _headers_lower_map(headers: list[dict[str, Any]]) -> dict[str, str]:
    mapped: dict[str, str] = {}
    for header in headers:
        key = str(header.get("name", "")).strip().lower()
        if not key:
            continue
        mapped[key] = str(header.get("value", ""))
    return mapped


def _email_domain(email_value: str | None) -> str:
    if not email_value or "@" not in email_value:
        return ""
    return email_value.rsplit("@", 1)[-1].lower()


def _endswith_any(value: str, suffixes: tuple[str, ...]) -> bool:
    return any(value.endswith(suffix) for suffix in suffixes)


def _extract_domains_from_values(values: Iterable[str]) -> set[str]:
    domains: set[str] = set()
    for value in values:
        if not value:
            continue
        for domain in _DOMAIN_RE.findall(value.lower()):
            domains.add(domain.strip("."))
    return domains


def _looks_like_newsletter_message(
    headers: list[dict[str, Any]],
    *,
    from_email: str | None,
    subject: str | None,
) -> bool:
    subject_lower = (subject or "").lower()
    if subject_lower.startswith("re:") or subject_lower.startswith("fwd:"):
        return False

    email_domain = _email_domain(from_email)
    header_map = _headers_lower_map(headers)
    from_blob = f"{from_email or ''} {header_map.get('from', '')}".lower()
    list_id = header_map.get("list-id", "").lower()
    list_unsubscribe = header_map.get("list-unsubscribe", "").lower()
    sender = header_map.get("sender", "").lower()
    reply_to = header_map.get("reply-to", "").lower()
    relevance_blob = f"{subject_lower} {from_blob} {list_id} {list_unsubscribe}"

    domains = _extract_domains_from_values(
        [email_domain, from_blob, list_id, list_unsubscribe, sender, reply_to]
    )
    has_known_source_domain = any(
        _endswith_any(domain, SUBSTACK_DOMAINS + POLITICO_DOMAINS + FT_DOMAINS)
        for domain in domains
    )
    has_news_org_domain = any(_endswith_any(domain, NEWS_ORG_DOMAIN_HINTS) for domain in domains)
    has_provider_domain = any(_endswith_any(domain, NEWSLETTER_PROVIDER_DOMAINS) for domain in domains)

    if any(term in relevance_blob for term in EXCLUDED_NEWSLETTER_TERMS):
        return False

    if has_known_source_domain:
        return True

    event_like_subject = any(term in subject_lower for term in EVENT_SUBJECT_TERMS)
    if event_like_subject and not has_news_org_domain:
        return False

    has_brand_term = any(term in relevance_blob for term in NEWS_BRAND_TERMS)
    has_relevance = has_brand_term or any(term in relevance_blob for term in NEWS_RELEVANCE_TERMS)

    if any(term in subject_lower for term in NEWSLETTER_SUBJECT_TERMS):
        if has_relevance or has_news_org_domain:
            return True

    has_newsletter_headers = any(name in header_map for name in NEWSLETTER_HINT_HEADERS)
    precedence = header_map.get("precedence", "").lower()
    is_bulk = precedence in {"bulk", "list", "junk"}
    if has_newsletter_headers or is_bulk:
        return has_relevance or has_news_org_domain

    if has_provider_domain and has_relevance:
        return True

    return has_news_org_domain and has_relevance


def _walk_payload_parts(payload: dict[str, Any]) -> Iterable[dict[str, Any]]:
    yield payload
    for part in payload.get("parts", []) or []:
        yield from _walk_payload_parts(part)


def _extract_message_bodies(payload: dict[str, Any]) -> tuple[str | None, str | None]:
    html_chunks: list[str] = []
    text_chunks: list[str] = []

    for part in _walk_payload_parts(payload):
        mime_type = str(part.get("mimeType", "")).lower()
        data = ((part.get("body") or {}).get("data"))
        decoded = _decode_base64url(data)
        if not decoded:
            continue
        if mime_type == "text/html":
            html_chunks.append(decoded)
        elif mime_type == "text/plain":
            text_chunks.append(decoded)

    html_body = "\n".join(html_chunks).strip() or None
    text_body = "\n".join(text_chunks).strip() or None
    return html_body, text_body


def _to_received_iso(internal_date_ms: str | None) -> str | None:
    if not internal_date_ms:
        return None
    try:
        ts_ms = int(internal_date_ms)
    except ValueError:
        return None
    if ts_ms <= 0:
        return None
    dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).astimezone()
    return dt.isoformat()


def _iso_to_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _gmail_message_link(message_id: str, account_index: int = 0) -> str:
    return f"https://mail.google.com/mail/u/{account_index}/#all/{message_id}"


def _oauth_client_config(client_id: str, client_secret: str | None = None) -> dict[str, Any]:
    return {
        "installed": {
            "client_id": client_id,
            "client_secret": client_secret or "",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",  # nosec B105
            "redirect_uris": ["http://localhost"],
        }
    }


def _load_gmail_service(
    credentials_file: Path,
    token_file: Path,
    *,
    client_id: str | None = None,
    client_secret: str | None = None,
):
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
    except ImportError as exc:
        raise RuntimeError(
            "Missing Google API dependencies. Install with: "
            "python3 -m pip install google-api-python-client google-auth google-auth-oauthlib"
        ) from exc

    creds = None
    if token_file.exists():
        creds = Credentials.from_authorized_user_file(str(token_file), GMAIL_SCOPES)

    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())

    if not creds or not creds.valid:
        if client_id:
            flow = InstalledAppFlow.from_client_config(
                _oauth_client_config(client_id=client_id, client_secret=client_secret),
                GMAIL_SCOPES,
            )
        else:
            if not credentials_file.exists():
                raise RuntimeError(
                    "Missing OAuth client file. Expected at "
                    f"{credentials_file}. Download Desktop OAuth credentials from Google Cloud "
                    "and save to this path, or pass --client-id."
                )
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), GMAIL_SCOPES)
        creds = flow.run_local_server(port=0)

    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(creds.to_json(), encoding="utf-8")

    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def _looks_like_substack_message(
    *,
    subject: str,
    from_email: str | None,
    headers: list[dict[str, Any]],
) -> bool:
    email_domain = _email_domain(from_email)
    if _endswith_any(email_domain, SUBSTACK_DOMAINS):
        return True

    lower = subject.lower()
    if " on substack" in lower:
        return True

    header_map = _headers_lower_map(headers)
    blob = " ".join(
        [
            header_map.get("from", ""),
            header_map.get("sender", ""),
            header_map.get("list-id", ""),
            header_map.get("list-unsubscribe", ""),
        ]
    ).lower()
    if " via everyone" in blob and "inside politics" not in lower:
        return True
    return "substack" in blob


def _looks_like_stephen_bush_message(
    *,
    subject: str,
    from_email: str | None,
    headers: list[dict[str, Any]],
) -> bool:
    lower = subject.lower()
    if "inside politics" not in lower and "stephen bush" not in lower:
        return False

    email_domain = _email_domain(from_email)
    header_map = _headers_lower_map(headers)
    from_blob = " ".join(
        [
            from_email or "",
            header_map.get("from", ""),
            header_map.get("sender", ""),
        ]
    ).lower()

    if "stephen bush" in from_blob:
        return True
    if "via everyone" in from_blob and "inside politics" in lower:
        return True
    if email_domain == "labourtogether.co.uk" and "inside politics" in lower:
        return True
    return False


def _classify_ui_source(
    *,
    base_source: str,
    subject: str,
    from_email: str | None,
    headers: list[dict[str, Any]],
) -> tuple[str, str] | None:
    lower = subject.lower()
    email_domain = _email_domain(from_email)

    if base_source == "politico":
        if "must-read" in lower:
            return "alert", "MUST-READ"
        if "breaking" in lower or "alert" in lower:
            return "alert", "BREAKING"
        return "politico", SOURCE_LABELS["politico"]

    if base_source == "substack":
        if _looks_like_stephen_bush_message(subject=subject, from_email=from_email, headers=headers):
            return "stephen_bush", SOURCE_LABELS["stephen_bush"]
        return "substack", SOURCE_LABELS["substack"]

    if base_source == "newsletters":
        if _endswith_any(email_domain, POLITICO_DOMAINS):
            if "must-read" in lower:
                return "alert", "MUST-READ"
            if "breaking" in lower or "alert" in lower:
                return "alert", "BREAKING"
            return "politico", SOURCE_LABELS["politico"]

        if _looks_like_stephen_bush_message(subject=subject, from_email=from_email, headers=headers):
            return "stephen_bush", SOURCE_LABELS["stephen_bush"]

        if _looks_like_substack_message(subject=subject, from_email=from_email, headers=headers):
            return "substack", SOURCE_LABELS["substack"]

        if _looks_like_newsletter_message(headers, from_email=from_email, subject=subject):
            return "newsletter", SOURCE_LABELS["newsletter"]
        return None

    return base_source, SOURCE_LABELS.get(base_source, base_source.upper())


def _quick_ai_summary(
    *,
    title: str,
    text: str,
    api_key: str,
    model: str,
    timeout_seconds: int = 25,
) -> str | None:
    cleaned = _collapse_whitespace(text)
    if not cleaned:
        return None

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You write compressed UK politics briefing summaries. Follow these rules strictly:\n"
                    "\n"
                    "FORMAT: Return one or more paragraphs separated by blank lines. "
                    "Each paragraph starts with a bold topline in **double asterisks**, followed by 1-2 detail sentences.\n"
                    "\n"
                    "Example:\n"
                    "**Chancellor shelves council tax revaluation until after 2029.** "
                    "Treasury sources confirm the review will not feature in the autumn statement. "
                    "Local authorities had lobbied for reform since 2021.\n"
                    "\n"
                    "**Starmer faces backbench revolt on planning bill.** "
                    "At least 35 Labour MPs have signalled opposition to green belt release provisions.\n"
                    "\n"
                    "RULES:\n"
                    "1. Lead with the politically significant, not chronological order.\n"
                    "2. Bold topline per paragraph: a tight factual claim, not a teaser or question.\n"
                    "3. Compress ruthlessly: a 3000-word source becomes 4-6 sentences total.\n"
                    "4. Use specific names, numbers, outcomes. '£10bn Blyth datacentre' not 'a major investment'.\n"
                    "5. Separate distinct stories into separate paragraphs with bolded toplines.\n"
                    "6. Breaking news or single-story pieces: one short paragraph only.\n"
                    "7. Neutral declarative language. No editorialising, no 'interestingly', no 'it remains to be seen'.\n"
                    "8. Include the 'so what' where non-obvious. State why it matters.\n"
                    "9. For data/policy pieces: lead with the key finding, then 1-2 supporting data points with figures.\n"
                    "\n"
                    "No ellipses. No bullet points. No labels like 'Point 1'. British English. "
                    "Plain text with **bold** markers only."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Title: {title}\n"
                    f"Content: {cleaned[:6000]}\n"
                    "Write the briefing summary now."
                ),
            },
        ],
        "temperature": 0.25,
        "max_tokens": 500,
    }

    request = urlrequest.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urlrequest.urlopen(request, timeout=timeout_seconds) as response:  # nosec B310
            data = json.loads(response.read().decode("utf-8"))
    except (urlerror.URLError, urlerror.HTTPError, TimeoutError, ValueError):
        return None

    choices = data.get("choices") or []
    if not choices:
        return None
    message = choices[0].get("message") or {}
    content = message.get("content")
    if not content or not isinstance(content, str):
        return None
    # Parse AI response: split on blank lines into paragraphs
    raw_paragraphs = re.split(r"\n\s*\n", content.strip())
    parsed_lines: list[str] = []
    for para in raw_paragraphs:
        line = _collapse_whitespace(para)
        if not line:
            continue
        # Strip legacy labels if AI falls back to old format
        line = re.sub(
            r"^(headline|point\s*[0-9]+|line\s*[0-9]+)\s*[:\-]\s*",
            "", line, flags=re.IGNORECASE,
        )
        if line:
            parsed_lines.append(line)

    # Fallback: if no **markers** and fewer than 2 paragraphs, try sentence splitting
    if len(parsed_lines) < 2 and not any("**" in line for line in parsed_lines):
        parsed_lines = _split_sentences(content)

    # If still only 1 line and no bold markers, pad with heuristic lines
    if len(parsed_lines) == 1 and "**" not in parsed_lines[0]:
        extras = _select_punchy_lines(cleaned, max_lines=2)
        for extra in extras:
            if extra.lower() == parsed_lines[0].lower():
                continue
            parsed_lines.append(extra)
            if len(parsed_lines) >= 3:
                break

    summary = _normalize_summary_text("\n\n".join(parsed_lines[:5]), max_lines=5, max_line_len=450)
    return summary or None


def _extract_topics(subject: str, summary_text: str) -> list[str]:
    blob = f"{subject} {summary_text}".lower()
    topics: list[str] = []
    for topic, terms in TOPIC_KEYWORDS.items():
        if any(re.search(r'\b' + re.escape(term) + r'\b', blob) for term in terms):
            topics.append(topic)
    if not topics:
        return ["General"]
    return topics[:5]


def _scan_limit_for_source(source: str, max_results: int) -> int:
    source_key = (source or "").strip().lower()
    if source_key == "newsletters":
        return min(max(max_results * 12, 120), 500)
    return min(max(max_results * 4, max_results), 200)


def _list_message_refs(service: Any, *, query: str, max_results: int, source: str) -> list[dict[str, Any]]:
    scan_limit = _scan_limit_for_source(source, max_results)
    batch_size = min(100, max(max_results * 2, 25))
    refs: list[dict[str, Any]] = []
    page_token: str | None = None

    while len(refs) < scan_limit:
        page_size = min(batch_size, scan_limit - len(refs))
        list_kwargs: dict[str, Any] = {
            "userId": "me",
            "q": query,
            "maxResults": page_size,
        }
        if page_token:
            list_kwargs["pageToken"] = page_token
        request = service.users().messages().list(**list_kwargs)
        response = request.execute()
        page_refs = response.get("messages", []) or []
        if not page_refs:
            break
        refs.extend(page_refs)
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    return refs


def fetch_from_gmail(
    *,
    source: str,
    query: str,
    max_results: int,
    credentials_file: Path,
    token_file: Path,
    account_index: int,
    include_bodies: bool,
    client_id: str | None,
    client_secret: str | None,
    ai_summaries: bool,
    ai_model: str,
    openai_api_key: str | None,
    summary_cache_entries: dict[str, Any] | None,
    summary_cache_stats: dict[str, int] | None,
) -> list[dict[str, Any]]:
    service = _load_gmail_service(
        credentials_file=credentials_file,
        token_file=token_file,
        client_id=client_id,
        client_secret=client_secret,
    )
    message_refs = _list_message_refs(service, query=query, max_results=max_results, source=source)

    items: list[dict[str, Any]] = []
    for message_ref in message_refs:
        message_id = str(message_ref.get("id", ""))
        if not message_id:
            continue

        message = (
            service.users()
            .messages()
            .get(userId="me", id=message_id, format="full")
            .execute()
        )

        payload = message.get("payload", {}) or {}
        headers = payload.get("headers", []) or []
        html_body, text_body = _extract_message_bodies(payload)

        from_header = _extract_header(headers, "From")
        from_name, from_email = parseaddr(from_header)
        display_from = from_name or from_email or from_header or "Unknown sender"

        subject = _extract_header(headers, "Subject") or "(No subject)"
        classified = _classify_ui_source(
            base_source=source,
            subject=subject,
            from_email=from_email,
            headers=headers,
        )
        if not classified:
            continue
        ui_source, ui_label = classified
        gmail_link = _gmail_message_link(message_id=message_id, account_index=account_index)

        resolved = resolve_open_links(
            source=ui_source,
            gmail_link=gmail_link,
            html_body=html_body,
            text_body=text_body,
        )

        summary_text = _build_summary(subject, message.get("snippet"), text_body)
        if ai_summaries and openai_api_key:
            ai_text_source = _to_plain_text(text_body) or _to_plain_text(message.get("snippet"))
            content_hash = _summary_content_hash(subject, ai_text_source)
            cached_summary = _get_cached_ai_summary(
                entries=summary_cache_entries,
                message_id=message_id,
                content_hash=content_hash,
                model=ai_model,
            )
            if cached_summary:
                summary_text = cached_summary
                if summary_cache_stats is not None:
                    summary_cache_stats["hits"] = summary_cache_stats.get("hits", 0) + 1
            else:
                if summary_cache_stats is not None:
                    summary_cache_stats["misses"] = summary_cache_stats.get("misses", 0) + 1
                ai_summary = _quick_ai_summary(
                    title=subject,
                    text=ai_text_source,
                    api_key=openai_api_key,
                    model=ai_model,
                )
                if ai_summary:
                    summary_text = ai_summary
                    _set_cached_ai_summary(
                        entries=summary_cache_entries,
                        message_id=message_id,
                        content_hash=content_hash,
                        model=ai_model,
                        summary=ai_summary,
                    )
                    if summary_cache_stats is not None:
                        summary_cache_stats["writes"] = summary_cache_stats.get("writes", 0) + 1
        item: dict[str, Any] = {
            "id": f"gmail:{message_id}",
            "source": ui_source,
            "source_label": ui_label,
            "message_id": message_id,
            "thread_id": message.get("threadId"),
            "from": display_from,
            "from_email": from_email,
            "title": subject,
            "received_at": _to_received_iso(message.get("internalDate")),
            "summary_text": summary_text,
            "summary_html": _to_summary_html(summary_text),
            "topics": _extract_topics(subject, summary_text),
            **resolved,
        }

        if include_bodies:
            item["html_body"] = html_body
            item["text_body"] = text_body

        items.append(item)
        if len(items) >= max_results:
            break

    return items


def enrich_digest_item(
    item: dict[str, object],
    *,
    html_body: str | None,
    text_body: str | None,
) -> dict[str, object]:
    """Populate article_url/open_url/open_url_type for a digest item."""
    source = str(item.get("source", "") or "")
    existing_article = _normalize_http_url(str(item.get("article_url", "") or ""))
    existing_gmail = _normalize_http_url(str(item.get("gmail_link", "") or ""))

    resolved = resolve_open_links(
        source=source,
        gmail_link=existing_gmail,
        html_body=html_body,
        text_body=text_body,
    )

    article_url = existing_article or resolved["article_url"]
    gmail_link = existing_gmail or resolved["gmail_link"]
    if gmail_link:
        open_url = gmail_link
        open_url_type = "gmail"
    elif article_url:
        open_url = article_url
        open_url_type = "article"
    else:
        open_url = None
        open_url_type = "none"

    enriched = dict(item)
    enriched["article_url"] = article_url
    enriched["gmail_link"] = gmail_link
    enriched["open_url"] = open_url
    enriched["open_url_type"] = open_url_type
    return enriched


def _sources_for(source_arg: str) -> list[str]:
    source_key = source_arg.strip().lower()
    if source_key == "all":
        return list(ALL_SOURCES)
    return [source_key]


def _week_start_for(day_value: date) -> date:
    # Python weekday: Monday=0 ... Sunday=6; we use Saturday-start weeks.
    days_since_sat = (day_value.weekday() - 5) % 7
    return day_value - timedelta(days=days_since_sat)


def _format_short_date(day_value: date) -> str:
    return f"{day_value.day} {day_value.strftime('%b')}"


def _format_full_date(day_value: date) -> str:
    return f"{day_value.strftime('%A')} {day_value.day} {day_value.strftime('%B %Y')}"


def _week_label(week_start: date) -> str:
    return f"W/C {week_start.day} {week_start.strftime('%b %Y')}"


def _week_id(week_start: date) -> str:
    return week_start.isoformat()


def _build_week_days(week_start: date) -> list[dict[str, Any]]:
    days: list[dict[str, Any]] = []
    for offset, (_weekday, key, name) in enumerate(DAY_KEYS):
        current = week_start + timedelta(days=offset)
        days.append(
            {
                "key": key,
                "name": name,
                "date": _format_short_date(current),
                "dateFull": _format_full_date(current),
                "items": [],
            }
        )
    return days


def _dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    sorted_items = sorted(
        items,
        key=lambda item: item.get("received_at") or "",
        reverse=True,
    )
    for item in sorted_items:
        message_id = str(item.get("message_id") or item.get("id") or "")
        if not message_id:
            continue
        if message_id in unique:
            continue
        unique[message_id] = item
    return list(unique.values())


def build_digest_data(items: list[dict[str, Any]], *, now: datetime | None = None) -> tuple[dict[str, Any], str, str]:
    now_dt = now or datetime.now().astimezone()
    week_start = _week_start_for(now_dt.date())
    week_end = week_start + timedelta(days=6)

    days = _build_week_days(week_start)
    days_by_key = {day["key"]: day for day in days}

    for item in _dedupe_items(items):
        received_dt = _iso_to_dt(item.get("received_at"))
        if not received_dt:
            continue
        received_date = received_dt.date()
        if received_date < week_start or received_date > week_end:
            continue

        day_key = WEEKDAY_TO_KEY.get(received_date.weekday())
        if not day_key:
            continue

        summary_html = str(item.get("summary_html") or "")
        if not summary_html:
            summary_html = _to_summary_html(str(item.get("summary_text") or ""))

        digest_item = {
            "source": item.get("source") or "politico",
            "sourceLabel": item.get("source_label") or SOURCE_LABELS.get(str(item.get("source") or "politico"), "SOURCE"),
            "from": item.get("from") or "Unknown sender",
            "time": received_dt.strftime("%H:%M"),
            "title": item.get("title") or "(No subject)",
            "summary": summary_html,
            "topics": item.get("topics") or ["General"],
            "article_url": item.get("article_url") or "",
            "gmail_link": item.get("gmail_link") or "",
            "open_url": item.get("open_url") or "",
            "open_url_type": item.get("open_url_type") or "none",
        }
        days_by_key[day_key]["items"].append(digest_item)

    for day in days:
        day["items"].sort(key=lambda item: item.get("time") or "", reverse=True)

    return {"days": days}, _week_label(week_start), _week_id(week_start)


def _json_for_inline_script(payload: dict[str, Any]) -> str:
    """Render JSON safely for direct embedding inside an inline <script> block."""
    raw = json.dumps(payload, ensure_ascii=False, indent=2)
    return (
        raw.replace("<", "\\u003C")
        .replace(">", "\\u003E")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def sync_html_with_data(html_path: Path, data: dict[str, Any], week_label: str) -> None:
    html = html_path.read_text(encoding="utf-8")

    start = html.find("const DATA =")
    if start == -1:
        raise RuntimeError("Could not locate `const DATA =` block in HTML.")

    marker = "// Determine today's tab"
    end = html.find(marker, start)
    if end == -1:
        raise RuntimeError("Could not locate end of DATA block in HTML.")

    data_json = _json_for_inline_script(data)
    replacement = f"const DATA = {data_json};\n\n"
    html = html[:start] + replacement + html[end:]

    html = re.sub(
        r'(<div class="week-label">)(.*?)(</div>)',
        lambda m: f"{m.group(1)}{week_label}{m.group(3)}",
        html,
        count=1,
    )

    html_path.write_text(html, encoding="utf-8")


def _day_counts(data: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for day in data.get("days", []):
        counts[str(day.get("key"))] = len(day.get("items", []))
    return counts


def _load_archive(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "weeks": []}

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {"version": 1, "weeks": []}

    if not isinstance(payload, dict):
        return {"version": 1, "weeks": []}

    weeks = payload.get("weeks")
    if not isinstance(weeks, list):
        payload["weeks"] = []
    payload.setdefault("version", 1)
    return payload


def _save_archive(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def _save_week_snapshot(weeks_dir: Path, week_id: str, entry: dict[str, Any]) -> Path:
    weeks_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = weeks_dir / f"{week_id}.json"
    snapshot_path.write_text(json.dumps(entry, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return snapshot_path


def update_archive(
    *,
    archive_file: Path,
    weeks_dir: Path,
    week_id: str,
    week_label: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    now_iso = datetime.now(timezone.utc).isoformat()
    archive = _load_archive(archive_file)
    weeks = archive.get("weeks")
    if not isinstance(weeks, list):
        weeks = []
        archive["weeks"] = weeks

    entry = {
        "week_id": week_id,
        "week_label": week_label,
        "updated_at": now_iso,
        "days": data.get("days", []),
    }

    replaced = False
    for idx, current in enumerate(weeks):
        if isinstance(current, dict) and str(current.get("week_id")) == week_id:
            weeks[idx] = entry
            replaced = True
            break
    if not replaced:
        weeks.append(entry)

    weeks.sort(key=lambda row: str(row.get("week_id") or ""), reverse=True)
    archive["updated_at"] = now_iso
    _save_archive(archive_file, archive)
    snapshot_path = _save_week_snapshot(weeks_dir, week_id, entry)

    return {
        "archive_file": str(archive_file),
        "week_snapshot": str(snapshot_path),
        "week_count": len(weeks),
        "week_id": week_id,
    }


def fetch_items_for_sources(
    *,
    source_arg: str,
    query_override: str | None,
    max_results: int,
    credentials_file: Path,
    token_file: Path,
    account_index: int,
    include_bodies: bool,
    client_id: str | None,
    client_secret: str | None,
    ai_summaries: bool,
    ai_model: str,
    openai_api_key: str | None,
    summary_cache_entries: dict[str, Any] | None,
    summary_cache_stats: dict[str, int] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    sources = _sources_for(source_arg)
    all_items: list[dict[str, Any]] = []
    source_meta: list[dict[str, str]] = []

    for source in sources:
        query = query_override or _default_query_for_source(source)
        source_meta.append({"source": source, "query": query})
        source_items = fetch_from_gmail(
            source=source,
            query=query,
            max_results=max_results,
            credentials_file=credentials_file,
            token_file=token_file,
            account_index=account_index,
            include_bodies=include_bodies,
            client_id=client_id,
            client_secret=client_secret,
            ai_summaries=ai_summaries,
            ai_model=ai_model,
            openai_api_key=openai_api_key,
            summary_cache_entries=summary_cache_entries,
            summary_cache_stats=summary_cache_stats,
        )
        all_items.extend(source_items)

    return _dedupe_items(all_items), source_meta


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync CW Digest HTML from Gmail newsletters")
    parser.add_argument(
        "--source",
        default="all",
        choices=["all", *ALL_SOURCES],
        help="Which source to fetch (default: all).",
    )
    parser.add_argument("--gmail-link", default=None, help="Gmail permalink fallback for manual mode")
    parser.add_argument("--html-file", default=None, help="Path to HTML body file (manual mode)")
    parser.add_argument("--text-file", default=None, help="Path to plain-text body file (manual mode)")
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Force manual mode (resolve links from --html-file/--text-file).",
    )
    parser.add_argument(
        "--sync-html",
        action="store_true",
        help="Write fetched digest data back into newsletter-digest.html.",
    )
    parser.add_argument(
        "--html-output",
        default=str(DEFAULT_HTML_FILE),
        help="HTML file to update when --sync-html is used.",
    )
    parser.add_argument("--query", default=None, help="Gmail query override for auto-fetch mode")
    parser.add_argument("--max-results", type=int, default=25, help="Messages to fetch per source")
    parser.add_argument(
        "--credentials-file",
        default=None,
        help=(
            "Path to Google OAuth client JSON "
            "(fallback: CW_DIGEST_OAUTH_CLIENT_FILE env, then default config path)."
        ),
    )
    parser.add_argument(
        "--token-file",
        default=None,
        help=(
            "Path to cached OAuth token JSON "
            "(fallback: CW_DIGEST_GMAIL_TOKEN_FILE env, then default token path)."
        ),
    )
    parser.add_argument(
        "--gmail-account-index",
        type=int,
        default=0,
        help="Gmail account index used in generated Gmail links",
    )
    parser.add_argument(
        "--include-bodies",
        action="store_true",
        help="Include extracted html/text bodies in auto-fetch output",
    )
    parser.add_argument(
        "--client-id",
        default=None,
        help=(
            "OAuth client_id for Desktop app "
            "(fallback: GOOGLE_OAUTH_CLIENT_ID env; alternative to credentials file)."
        ),
    )
    parser.add_argument(
        "--client-secret",
        default=None,
        help="OAuth client_secret for Desktop app (fallback: GOOGLE_OAUTH_CLIENT_SECRET env).",
    )
    parser.add_argument(
        "--ai-summaries",
        action="store_true",
        help="Use OpenAI to generate quick summaries per item.",
    )
    parser.add_argument(
        "--ai-model",
        default="gpt-4o-mini",
        help="OpenAI model for --ai-summaries.",
    )
    parser.add_argument(
        "--openai-api-key",
        default=None,
        help="OpenAI API key (fallbacks to OPENAI_API_KEY env var).",
    )
    parser.add_argument(
        "--summary-cache-file",
        default=str(DEFAULT_SUMMARY_CACHE_FILE),
        help="JSON cache file for AI summaries.",
    )
    parser.add_argument(
        "--archive-file",
        default=str(DEFAULT_ARCHIVE_FILE),
        help="JSON archive file for weekly snapshots.",
    )
    parser.add_argument(
        "--weeks-dir",
        default=str(DEFAULT_WEEKS_DIR),
        help="Directory containing per-week archive snapshots.",
    )
    parser.add_argument(
        "--no-archive",
        action="store_true",
        help="Skip writing archive snapshots during --sync-html.",
    )
    args = parser.parse_args()

    if args.max_results < 1:
        raise SystemExit("--max-results must be >= 1")

    _load_dotenv_file(DEFAULT_ENV_FILE)
    credentials_file_value = (
        args.credentials_file
        or os.getenv("CW_DIGEST_OAUTH_CLIENT_FILE")
        or str(DEFAULT_CREDENTIALS_FILE)
    )
    token_file_value = (
        args.token_file
        or os.getenv("CW_DIGEST_GMAIL_TOKEN_FILE")
        or str(DEFAULT_TOKEN_FILE)
    )
    client_id_value = args.client_id or os.getenv("GOOGLE_OAUTH_CLIENT_ID")
    client_secret_value = args.client_secret or os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
    openai_api_key = args.openai_api_key or os.getenv("OPENAI_API_KEY")
    if args.ai_summaries and not openai_api_key:
        raise SystemExit("AI summaries requested but no API key found. Set OPENAI_API_KEY or pass --openai-api-key.")

    summary_cache_file = Path(args.summary_cache_file).expanduser()
    archive_file = Path(args.archive_file).expanduser()
    weeks_dir = Path(args.weeks_dir).expanduser()
    summary_cache_doc: dict[str, Any] | None = None
    summary_cache_entries: dict[str, Any] | None = None
    summary_cache_stats: dict[str, int] | None = None
    if args.ai_summaries:
        summary_cache_doc = _load_summary_cache(summary_cache_file)
        summary_cache_entries = summary_cache_doc.get("entries")
        if not isinstance(summary_cache_entries, dict):
            summary_cache_entries = {}
            summary_cache_doc["entries"] = summary_cache_entries
        summary_cache_stats = {"hits": 0, "misses": 0, "writes": 0}

    auto_mode = not args.manual and not args.html_file and not args.text_file

    if auto_mode:
        try:
            items, source_meta = fetch_items_for_sources(
                source_arg=args.source,
                query_override=args.query,
                max_results=args.max_results,
                credentials_file=Path(credentials_file_value).expanduser(),
                token_file=Path(token_file_value).expanduser(),
                account_index=args.gmail_account_index,
                include_bodies=args.include_bodies,
                client_id=client_id_value,
                client_secret=client_secret_value,
                ai_summaries=args.ai_summaries,
                ai_model=args.ai_model,
                openai_api_key=openai_api_key,
                summary_cache_entries=summary_cache_entries,
                summary_cache_stats=summary_cache_stats,
            )
        except Exception as exc:
            print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
            raise SystemExit(1) from exc

        if args.ai_summaries and summary_cache_doc is not None:
            _save_summary_cache(summary_cache_file, summary_cache_doc)

        if args.sync_html:
            html_path = Path(args.html_output).expanduser()
            data, week_label, week_id = build_digest_data(items)
            sync_html_with_data(html_path=html_path, data=data, week_label=week_label)
            archive_meta = None
            if not args.no_archive:
                archive_meta = update_archive(
                    archive_file=archive_file,
                    weeks_dir=weeks_dir,
                    week_id=week_id,
                    week_label=week_label,
                    data=data,
                )
            print(
                json.dumps(
                    {
                        "updated_html": str(html_path),
                        "week_label": week_label,
                        "week_id": week_id,
                        "source": args.source,
                        "source_queries": source_meta,
                        "item_count": len(items),
                        "day_counts": _day_counts(data),
                        "ai_summary_cache": summary_cache_stats,
                        "ai_summary_cache_file": str(summary_cache_file) if args.ai_summaries else None,
                        "archive": archive_meta,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return

        if args.source != "all" and args.max_results == 1:
            if not items:
                print(
                    json.dumps(
                        {
                            "source": args.source,
                            "count": 0,
                            "items": [],
                            "message": "No matching Gmail messages found.",
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
                return
            print(json.dumps(items[0], indent=2, sort_keys=True))
            return

        print(
            json.dumps(
                {
                    "source": args.source,
                    "source_queries": source_meta,
                    "count": len(items),
                    "items": items,
                    "ai_summary_cache": summary_cache_stats,
                    "ai_summary_cache_file": str(summary_cache_file) if args.ai_summaries else None,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    resolved = resolve_open_links(
        source=args.source,
        gmail_link=args.gmail_link,
        html_body=_read_optional_file(args.html_file),
        text_body=_read_optional_file(args.text_file),
    )
    print(json.dumps(resolved, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
