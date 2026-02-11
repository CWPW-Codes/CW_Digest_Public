from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "fetch_gmail_digest.py"
)
SPEC = importlib.util.spec_from_file_location("fetch_gmail_digest", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_politico_article_is_selected_over_unsubscribe_link() -> None:
    html = """
    <html><body>
      <a href="https://www.politico.eu/article/labour-faces-pressure/">Read now</a>
      <a href="https://mailer.example.com/unsubscribe?id=99">Unsubscribe</a>
    </body></html>
    """

    resolved = MODULE.resolve_open_links(
        source="politico",
        gmail_link="https://mail.google.com/mail/u/0/#all/fmfcgz123",
        html_body=html,
        text_body=None,
    )

    assert resolved["article_url"] == "https://www.politico.eu/article/labour-faces-pressure/"
    assert resolved["open_url"] == "https://mail.google.com/mail/u/0/#all/fmfcgz123"
    assert resolved["open_url_type"] == "gmail"


def test_substack_redirect_is_unwrapped_and_selected() -> None:
    html = """
    <html><body>
      <a href="https://substack.com/redirect/abc?url=https%3A%2F%2Ffuture-north.substack.com%2Fp%2Fai-and-tech">Open post</a>
      <a href="https://future-north.substack.com/subscribe">Manage subscription</a>
    </body></html>
    """

    resolved = MODULE.resolve_open_links(
        source="substack",
        gmail_link="https://mail.google.com/mail/u/0/#all/fmfcgz124",
        html_body=html,
        text_body=None,
    )

    assert resolved["article_url"] == "https://future-north.substack.com/p/ai-and-tech"
    assert resolved["open_url"] == "https://mail.google.com/mail/u/0/#all/fmfcgz124"
    assert resolved["open_url_type"] == "gmail"


def test_stephen_bush_prefers_ft_link() -> None:
    html = """
    <html><body>
      <a href="https://www.ft.com/content/12345678-aaaa-bbbb-cccc-ddddeeeeffff">Column</a>
      <a href="https://www.example.com/inside-politics-roundup">Mirror</a>
      <a href="https://www.ft.com/preferences">Preferences</a>
    </body></html>
    """

    resolved = MODULE.resolve_open_links(
        source="stephen_bush",
        gmail_link="https://mail.google.com/mail/u/0/#all/fmfcgz125",
        html_body=html,
        text_body=None,
    )

    assert resolved["article_url"] == "https://www.ft.com/content/12345678-aaaa-bbbb-cccc-ddddeeeeffff"
    assert resolved["open_url"] == "https://mail.google.com/mail/u/0/#all/fmfcgz125"
    assert resolved["open_url_type"] == "gmail"


def test_stephen_bush_accepts_newsletters_ft_tracking_link() -> None:
    html = """
    <html><body>
      <a href="https://email.newsletters.ft.com/c/eJyM123abc">Open newsletter</a>
      <a href="https://www.example.com/unrelated">Elsewhere</a>
    </body></html>
    """

    resolved = MODULE.resolve_open_links(
        source="stephen_bush",
        gmail_link="https://mail.google.com/mail/u/0/#all/fmfcgz125",
        html_body=html,
        text_body=None,
    )

    assert resolved["article_url"] == "https://email.newsletters.ft.com/c/eJyM123abc"
    assert resolved["open_url"] == "https://mail.google.com/mail/u/0/#all/fmfcgz125"
    assert resolved["open_url_type"] == "gmail"


def test_fallback_to_gmail_when_no_article_link_exists() -> None:
    html = """
    <html><body>
      <a href="https://newsletter.example.com/unsubscribe?token=abc">Unsubscribe</a>
      <a href="https://newsletter.example.com/manage/preferences">Manage preferences</a>
    </body></html>
    """

    gmail_link = "https://mail.google.com/mail/u/0/#all/fmfcgz126"
    resolved = MODULE.resolve_open_links(
        source="politico",
        gmail_link=gmail_link,
        html_body=html,
        text_body=None,
    )

    assert resolved["article_url"] is None
    assert resolved["open_url"] == gmail_link
    assert resolved["open_url_type"] == "gmail"


def test_default_query_for_source_is_configured() -> None:
    query = MODULE._default_query_for_source("politico")
    assert "politico" in query.lower()
    assert "newer_than" in query.lower()
    substack_query = MODULE._default_query_for_source("substack")
    assert "substack" in substack_query.lower()
    assert "everyone@labourtogether.co.uk" in substack_query.lower()
    assert "on substack" in substack_query.lower()
    stephen_query = MODULE._default_query_for_source("stephen_bush")
    assert "inside politics" in stephen_query.lower()
    newsletters_query = MODULE._default_query_for_source("newsletters")
    assert "category:updates" in newsletters_query.lower()


def test_oauth_client_config_supports_client_id_only() -> None:
    cfg = MODULE._oauth_client_config("abc123.apps.googleusercontent.com")
    assert cfg["installed"]["client_id"] == "abc123.apps.googleusercontent.com"
    assert "auth_uri" in cfg["installed"]
    assert "token_uri" in cfg["installed"]


def test_newsletter_detection_from_list_headers() -> None:
    headers = [
        {"name": "From", "value": "Some List <alerts@example.org>"},
        {"name": "List-Unsubscribe", "value": "<mailto:unsubscribe@example.org>"},
    ]
    assert MODULE._looks_like_newsletter_message(
        headers,
        from_email="alerts@example.org",
        subject="Morning briefing",
    )


def test_newsletters_source_classifies_substack() -> None:
    headers = [{"name": "From", "value": "Some Substack <foo@substack.com>"}]
    classified = MODULE._classify_ui_source(
        base_source="newsletters",
        subject="New post",
        from_email="foo@substack.com",
        headers=headers,
    )
    assert classified == ("substack", "SUBSTACK")


def test_newsletters_source_classifies_substack_via_everyone() -> None:
    headers = [{"name": "From", "value": "'Noahpinion' via Everyone <everyone@labourtogether.co.uk>"}]
    classified = MODULE._classify_ui_source(
        base_source="newsletters",
        subject="The Fall of the Nerds",
        from_email="everyone@labourtogether.co.uk",
        headers=headers,
    )
    assert classified == ("substack", "SUBSTACK")


def test_substack_source_reclassifies_stephen_bush_mail() -> None:
    headers = [{"name": "From", "value": "'Stephen Bush' via Everyone <everyone@labourtogether.co.uk>"}]
    classified = MODULE._classify_ui_source(
        base_source="substack",
        subject="Inside Politics: It's terminal",
        from_email="everyone@labourtogether.co.uk",
        headers=headers,
    )
    assert classified == ("stephen_bush", "STEPHEN BUSH")


def test_newsletters_source_skips_non_newsletter_mail() -> None:
    headers = [{"name": "From", "value": "Random Person <person@example.com>"}]
    classified = MODULE._classify_ui_source(
        base_source="newsletters",
        subject="Re: meeting notes",
        from_email="person@example.com",
        headers=headers,
    )
    assert classified is None


def test_newsletters_source_excludes_promotional_sender() -> None:
    headers = [
        {"name": "From", "value": "Paper2Audio <news@paper2audio.com>"},
        {"name": "List-Unsubscribe", "value": "<mailto:unsubscribe@paper2audio.com>"},
    ]
    classified = MODULE._classify_ui_source(
        base_source="newsletters",
        subject="AI feature updates this week",
        from_email="news@paper2audio.com",
        headers=headers,
    )
    assert classified is None


def test_newsletters_source_excludes_webinar_invite() -> None:
    headers = [
        {"name": "From", "value": "MRS Events <events@mrs.org.uk>"},
        {"name": "List-Unsubscribe", "value": "<mailto:unsubscribe@mrs.org.uk>"},
    ]
    classified = MODULE._classify_ui_source(
        base_source="newsletters",
        subject="Join us in 6 days: research policy webinar",
        from_email="events@mrs.org.uk",
        headers=headers,
    )
    assert classified is None


def test_newsletters_source_excludes_non_news_event_updates() -> None:
    headers = [
        {"name": "From", "value": "Fabian Events <events@fabian.org.uk>"},
        {"name": "List-Unsubscribe", "value": "<mailto:unsubscribe@fabian.org.uk>"},
    ]
    classified = MODULE._classify_ui_source(
        base_source="newsletters",
        subject="Important info - Fabian Events - An evening with Olaf Scholz",
        from_email="events@fabian.org.uk",
        headers=headers,
    )
    assert classified is None


def test_newsletters_source_classifies_stephen_bush_via_everyone() -> None:
    headers = [
        {"name": "From", "value": "'Stephen Bush' via Everyone <everyone@labourtogether.co.uk>"},
        {"name": "Sender", "value": "everyone@labourtogether.co.uk"},
    ]
    classified = MODULE._classify_ui_source(
        base_source="newsletters",
        subject="Inside Politics: It's terminal",
        from_email="everyone@labourtogether.co.uk",
        headers=headers,
    )
    assert classified == ("stephen_bush", "STEPHEN BUSH")


def test_build_summary_outputs_multiline_punchy_format() -> None:
    summary = MODULE._build_summary(
        "AI and Tech - North vs South",
        None,
        (
            "The North's digital services sector grew faster than the national average from 2019 to 2023. "
            "London still accounts for 44% of UK AI activity while Manchester is at 4%. "
            "A 10 billion pound datacentre project in Blyth could shift capacity."
        ),
    )
    assert "\n\n" in summary
    assert "AI and Tech - North vs South" in summary
    assert "..." not in summary


def test_summary_html_preserves_multiple_lines() -> None:
    summary_html = MODULE._to_summary_html("Line one\n\nLine two")
    assert summary_html == "<p><strong>Line one</strong></p><ul><li>Line two</li></ul>"


def test_dotenv_loader_sets_env_values(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=test-key\n# comment\n", encoding="utf-8")
    os.environ.pop("OPENAI_API_KEY", None)
    loaded = MODULE._load_dotenv_file(env_file)
    assert loaded == 1
    assert os.environ.get("OPENAI_API_KEY") == "test-key"


def test_ai_summary_cache_round_trip() -> None:
    entries: dict[str, object] = {}
    MODULE._set_cached_ai_summary(
        entries=entries,
        message_id="abc123",
        content_hash="hash1",
        model="gpt-4o-mini",
        summary="Stable summary",
    )
    cached = MODULE._get_cached_ai_summary(
        entries=entries,
        message_id="abc123",
        content_hash="hash1",
        model="gpt-4o-mini",
    )
    assert cached == "Stable summary"

    mismatch = MODULE._get_cached_ai_summary(
        entries=entries,
        message_id="abc123",
        content_hash="different",
        model="gpt-4o-mini",
    )
    assert mismatch is None


def test_ai_summary_cache_rejects_legacy_style() -> None:
    entries = {
        "legacy1": {
            "summary": "Older summary",
            "content_hash": "hash-old",
            "model": "gpt-4o-mini",
        }
    }
    cached = MODULE._get_cached_ai_summary(
        entries=entries,
        message_id="legacy1",
        content_hash="hash-old",
        model="gpt-4o-mini",
    )
    assert cached is None


def test_ai_summary_cache_rejects_ellipsis_summary() -> None:
    entries = {
        "msg1": {
            "summary": "Calls for reform...",
            "content_hash": "hash1",
            "model": "gpt-4o-mini",
            "style_version": MODULE.SUMMARY_STYLE_VERSION,
        }
    }
    cached = MODULE._get_cached_ai_summary(
        entries=entries,
        message_id="msg1",
        content_hash="hash1",
        model="gpt-4o-mini",
    )
    assert cached is None


def test_summary_html_renders_bold_paragraphs() -> None:
    text = "**Chancellor shelves revaluation.** Details here.\n\n**Starmer faces revolt.** 35 MPs opposed."
    result = MODULE._to_summary_html(text)
    assert "<strong>Chancellor shelves revaluation.</strong>" in result
    assert "<strong>Starmer faces revolt.</strong>" in result
    assert "<ul>" not in result
    assert result.count("<p>") == 2


def test_summary_html_single_bold_paragraph() -> None:
    text = "**Breaking: PM announces snap reshuffle.** Three cabinet positions change."
    result = MODULE._to_summary_html(text)
    assert "<strong>Breaking: PM announces snap reshuffle.</strong>" in result
    assert result.count("<p>") == 1


def test_summary_line_cleanup_preserves_bold_markers() -> None:
    result = MODULE._summary_line_cleanup("**Bold topline.** Detail sentence.")
    assert result.startswith("**Bold topline.")


def test_normalize_summary_allows_five_paragraphs() -> None:
    text = "\n\n".join(f"**Para {i}.** Detail {i}." for i in range(5))
    result = MODULE._normalize_summary_text(text)
    assert result.count("**") == 10


def test_summary_html_legacy_format_without_bold_markers() -> None:
    """Heuristic output (no ** markers) still renders as headline + bullets."""
    summary_html = MODULE._to_summary_html("Line one\n\nLine two")
    assert summary_html == "<p><strong>Line one</strong></p><ul><li>Line two</li></ul>"


def test_enrich_digest_item_prefers_gmail_for_open_url() -> None:
    item = {
        "source": "substack",
        "article_url": "https://future-north.substack.com/p/ai-and-tech",
        "gmail_link": "https://mail.google.com/mail/u/0/#all/fmfcgz200",
    }

    enriched = MODULE.enrich_digest_item(item, html_body=None, text_body=None)
    assert enriched["open_url"] == "https://mail.google.com/mail/u/0/#all/fmfcgz200"
    assert enriched["open_url_type"] == "gmail"


def test_update_archive_appends_and_sorts_weeks(tmp_path: Path) -> None:
    archive_file = tmp_path / "archive_weeks.json"
    weeks_dir = tmp_path / "weeks"

    first = MODULE.update_archive(
        archive_file=archive_file,
        weeks_dir=weeks_dir,
        week_id="2026-01-31",
        week_label="W/C 31 Jan 2026",
        data={"days": [{"key": "sat", "items": []}]},
    )
    second = MODULE.update_archive(
        archive_file=archive_file,
        weeks_dir=weeks_dir,
        week_id="2026-02-07",
        week_label="W/C 7 Feb 2026",
        data={"days": [{"key": "sat", "items": [{"title": "Item"}]}]},
    )

    payload = MODULE._load_archive(archive_file)
    assert first["week_count"] == 1
    assert second["week_count"] == 2
    assert payload["weeks"][0]["week_id"] == "2026-02-07"
    assert payload["weeks"][1]["week_id"] == "2026-01-31"
    assert (weeks_dir / "2026-02-07.json").exists()


def test_sync_html_with_data_escapes_script_breakout_sequences(tmp_path: Path) -> None:
    html_file = tmp_path / "digest.html"
    html_file.write_text(
        (
            '<div class="week-label">W/C 1 Jan 2026</div>\n'
            "<script>\n"
            "const DATA = {\"days\": []};\n\n"
            "// Determine today's tab\n"
            "</script>\n"
        ),
        encoding="utf-8",
    )

    payload = {
        "days": [
            {
                "key": "sat",
                "items": [
                    {
                        "title": "</script><script>alert('xss')</script>",
                        "summary": "<p>safe</p>",
                    }
                ],
            }
        ]
    }
    MODULE.sync_html_with_data(html_file, payload, "W/C 8 Feb 2026")

    rendered = html_file.read_text(encoding="utf-8")
    assert "\\u003C/script\\u003E\\u003Cscript\\u003Ealert('xss')\\u003C/script\\u003E" in rendered
    assert "</script><script>alert('xss')</script>" not in rendered
