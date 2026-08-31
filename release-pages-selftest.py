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
    ROOT / "values" / "index.html",
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
        (ROOT / "values" / "index.html", "https://rapterbox.com/values/"),
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
        "non-executing work-interface walkthrough",
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
        "rapterbox.com-privacy-request",
        "keyword=ATTEST",
    ):
        assert phrase.casefold() in privacy.casefold()

    support = (ROOT / "support" / "index.html").read_text(encoding="utf-8")
    assert "github.com/kody-w/rapp-zoo/issues/new" in support
    assert "TestFlight" in support
    assert "Real purchases are disabled" in support
    assert '/privacy/#privacy-request' in support

    values = (ROOT / "values" / "index.html").read_text(encoding="utf-8")
    for phrase in (
        "The company carries the need",
        "We earn payment by creating durable value",
        "Voluntary return",
        "People leave whole",
        "Stop rule",
    ):
        assert phrase.casefold() in values.casefold()

    root = (ROOT / "index.html").read_text(encoding="utf-8")
    assert "Official resale and transparent RapterBox bids" not in root
    assert "Certified dealer network" not in root
    assert "Genesis 251 First Dimension" not in root
    assert 'href="https://rappter.com/"' not in root
    assert 'href="/holo/"' in root
    assert 'href="/values/"' in root
    assert 'href="/privacy/"' in root
    assert 'href="/support/"' in root
    assert 'href="/market/"' not in root
    public_text = "\n".join(path.read_text(encoding="utf-8") for path in PAGES)
    for private_term in (
        "To AIs for AIs",
        "Global Companion Seat",
        "Muscle Fiber",
        "Four-Lens",
        "AI-to-AI",
        "operating title",
        "AI market",
        "AI marketplace",
        "human-funded AI",
        "beneficiary AI",
        "flat fee",
        "fixed-fee",
        "market simulation",
        "price discovery",
    ):
        assert private_term.casefold() not in public_text.casefold()

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
    assert "planned_surfaces" not in agent

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
        "https://rapterbox.com/values/",
        "https://rapterbox.com/privacy/",
        "https://rapterbox.com/support/",
    ):
        assert url in locations

    print(
        "Rapterbox release pages: Holo, values, privacy, support, root, agent, sitemap"
    )


if __name__ == "__main__":
    main()
