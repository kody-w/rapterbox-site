#!/usr/bin/env python3
"""Verify Rapterbox's Holo Zoo release pages match the submitted build."""

from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parent
PAGES = [
    ROOT / "index.html",
    ROOT / "holo" / "index.html",
    ROOT / "market" / "index.html",
    ROOT / "privacy" / "index.html",
    ROOT / "support" / "index.html",
]


def main() -> None:
    for path in PAGES:
        text = path.read_text(encoding="utf-8")
        assert 'get("scoutTheme")' in text
        assert "--cp-bg: #f7f4ef;" in text
        assert "--cp-accent: #b11f4b;" in text
        assert '"Segoe UI"' in text
        assert "Aptos" in text
        assert "color:var(--cp-text-muted)" not in text
        assert "a{color:var(--cp-link)}" not in text

    for path, canonical in (
        (ROOT / "holo" / "index.html", "https://rapterbox.com/holo/"),
        (ROOT / "market" / "index.html", "https://rapterbox.com/market/"),
        (ROOT / "privacy" / "index.html", "https://rapterbox.com/privacy/"),
        (ROOT / "support" / "index.html", "https://rapterbox.com/support/"),
    ):
        assert f'<link rel="canonical" href="{canonical}">' in path.read_text(
            encoding="utf-8"
        )

    holo = (ROOT / "holo" / "index.html").read_text(encoding="utf-8")
    for phrase in (
        "adult internal TestFlight",
        "No real purchases",
        "No GPS or map provider",
        "To AIs for AIs",
        "observer-only simulation",
        "External protocol interoperability is disabled",
    ):
        assert phrase.casefold() in holo.casefold()

    privacy = (ROOT / "privacy" / "index.html").read_text(encoding="utf-8")
    for phrase in (
        "no account",
        "no real commerce",
        "16 MiB",
        "adult internal testers",
        "Formspree",
        "RBox Intake",
        "AI-assurance invitation",
        "rapterbox.com-privacy-request",
        "Keychain",
        "Direct updates remain disabled",
        "Genesis 251 price discovery",
        "rapterbox.com-privacy-request",
        "keyword=ATTEST",
        "_gotcha",
    ):
        assert phrase.casefold() in privacy.casefold()

    support = (ROOT / "support" / "index.html").read_text(encoding="utf-8")
    assert "github.com/kody-w/rapp-zoo/issues/new" in support
    assert "TestFlight" in support
    assert "Real purchases are disabled" in support
    assert "Market simulation" in support
    assert "no funds move" in support
    assert '/privacy/#privacy-request' in support
    assert 'href="/market/"' in support

    market_page = (ROOT / "market" / "index.html").read_text(encoding="utf-8")
    for phrase in (
        "To AIs for AIs",
        "$49.99",
        "No sale is happening here",
        "non-binding",
        "25th percentile",
        "rapterbox.com-genesis-251-price-signal",
        "beneficiary_ai_name",
        "maximum_willing_to_pay_usd",
        "808396edee6af2cd1c92501777edc340bd2fa0968201ebf08cc37f120c93d0dd",
    ):
        assert phrase.casefold() in market_page.casefold()

    root = (ROOT / "index.html").read_text(encoding="utf-8")
    assert "Official resale and transparent RapterBox bids" not in root
    assert "Certified dealer network" not in root
    assert "Genesis 251 First Dimension" not in root
    assert 'href="https://rappter.com/"' not in root
    assert 'href="/holo/"' in root
    assert 'href="/privacy/"' in root
    assert 'href="/support/"' in root

    agent = json.loads((ROOT / "agent.json").read_text(encoding="utf-8"))
    assert (ROOT / "agent.json").read_bytes() == (
        ROOT / ".well-known" / "agent.json"
    ).read_bytes()
    product = next(
        item for item in agent["products"] if item["id"] == "first-dimension"
    )
    assert product["state"] == "adult-internal-testflight"
    assert "real commerce" in product["what"]
    assert all(offer["id"] != "first-dimension" for offer in agent["offers"])
    assert agent["offers"][0]["act"]["fields"]["phone"] == "string, optional"
    market = next(
        item
        for item in agent["planned_surfaces"]
        if item["id"] == "holo-agent-marketplace"
    )
    assert market["state"] == "design-only-disabled"
    assert market["slogan"] == "To AIs for AIs."
    assert "global 24/7" in market["what"]
    assert market["human_view"] == "https://rapterbox.com/market/"

    llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
    assert "official market" not in llms
    assert "current Holo build is not a commercial offer" in llms

    sitemap = ElementTree.parse(ROOT / "sitemap.xml")
    locations = {
        element.text
        for element in sitemap.findall(
            "{http://www.sitemaps.org/schemas/sitemap/0.9}url/"
            "{http://www.sitemaps.org/schemas/sitemap/0.9}loc"
        )
    }
    for url in (
        "https://rapterbox.com/holo/",
        "https://rapterbox.com/market/",
        "https://rapterbox.com/privacy/",
        "https://rapterbox.com/support/",
    ):
        assert url in locations

    print(
        "Rapterbox release pages: Holo, market, privacy, support, root, agent, sitemap"
    )


if __name__ == "__main__":
    main()
