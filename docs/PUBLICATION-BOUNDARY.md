# Public publication boundary

`/PUBLICATION-POLICY.json` is the normative, machine-readable publication
policy for `kody-w/rapterbox-site`. This document is its human-readable
summary. When the two differ, the JSON policy controls.

## Public-eligible material

Only these categories are eligible for publication:

- customer-facing product summaries;
- customer-facing terms and privacy notices;
- waitlist pages and implementation assets, never submitted waitlist data;
- non-confidential descriptions of the RAPP foundation/product boundary; and
- static-site assets needed to serve those categories.

A public-eligible path is not an automatic approval. Content, URL, data, and
generated-artifact checks must all pass. Anything unclassified is denied.

## Never public

The site must not publish CODE RED, the LLC Constitution, the Ten
Commandments, private doctrine, ownership administration or percentages,
private provenance manifests, print-ready doctrine, links to private
repositories, secrets, submitted customer data, or non-public legal data.

The policy lists exact forbidden filenames, case-insensitive filename and
phrase patterns, data detectors, forbidden URL hosts, and repository-slug
rules. Those identifiers are scanner rules only; neither policy file contains
source doctrine, private excerpts, or private repository identifiers.

Customer-facing terms are allowed only when intentionally written for public
customers. Privileged communications, legal matter records, signatures,
government identifiers, and non-public contracts are not customer-facing
terms and remain forbidden.

## Names are exact

- **Rappter** is singular.
- **Rapter** is plural.
- **RapterBox LLC** is the company.
- **RapterBox** is also a separate company subproduct.
- **RAPP** names the public foundation. Only its non-confidential foundation
  and product-boundary material is eligible here.

## URLs and repositories

Local, loopback, and internal hosts are forbidden. Repository links are denied
unless the repository slug is explicitly allowlisted by the policy or the scan
records a successful unauthenticated public-visibility check for the exact
canonical URL. Unknown, inaccessible, authenticated-only, or ambiguous
visibility fails closed. Evidence must never disclose a private repository URL
or slug.

## Source and generated-artifact gate

Scanning is required before commit, merge, deploy, and release. It covers
selected source files and the final generated output, including bundles,
minified files, source maps, manifests, documents, recursively unpacked
archives, image OCR, document metadata, and redirect targets. A clean source
scan does not replace the post-generation scan.

Every publication candidate must have a coverage record. Unsupported,
unreadable, encrypted, truncated, or skipped files fail closed.

## Evidence

Evidence is bound to the exact policy hash, commit, and generated-artifact
hashes. It records coverage, scanner versions, rule outcomes, hashes, and
redacted fingerprints. It never records matched secrets, customer or legal
values, private excerpts, or private repository identifiers.

Evidence stays in access-controlled CI or security storage, not on the public
site, in public release artifacts, or in public logs. A violation blocks
publication and quarantines or deletes the candidate artifact. Missing, stale,
incomplete, or errored evidence also blocks publication.
