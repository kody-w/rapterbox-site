# Public IP Reference Audit

`scripts/audit_public_ip.py` is a read-only, Python-standard-library audit tool for
checking explicitly supplied public artifacts after public IP removal. It does
not discover private sources, authenticate, mutate remote systems, or require
secrets.

## RAPP protocol boundary

This tool emits only its documented audit JSON and Markdown reports. Those
reports are not RAPP artifacts or work-loop records, and the tool does not claim
RAPP/1 protocol conformance.

RAPP remains the external public open-source foundation, and RAPP/1 remains the
protocol authority. Nothing in this audit assigns RAPP ownership to an LLC,
defines an alternate frame, wire format, or identity envelope, or transfers
protocol authority. The audit also creates no offspring/cross outputs,
identities, or lineage.

If a separate integration wraps an audit result in a RAPP work-loop record, that
integration must use the canonical exact 11-key `rapp/1` frame. Any
`data_slush` must remain only inside `payload` and be bounded and
non-sensitive. Offspring/cross outputs must receive fresh identities and typed
parent lineage; they must never inherit authority. That integration behavior is
outside this tool's scope.

## Classifications

Each input artifact receives exactly one classification:

| Classification | Meaning |
| --- | --- |
| `unreachable` | An explicit URL or repository returned HTTP 404 or 410. |
| `reachable-current` | A public URL returned 2xx, a non-fork repository returned valid public metadata, or a public link document/search result had no stronger indicator. |
| `linked` | A reachable public link document contains a forbidden target URL. |
| `cached-indicator` | Saved public search-result metadata indicates a cached/indexed reference. This is an indicator, not proof that the target is reachable. |
| `fork-indicator` | Public repository/search metadata explicitly marks a repository as a fork. |
| `probe-error` | DNS, timeout, connection, fixture, malformed-metadata, non-public-input, or non-404/410 HTTP failure prevented a finding. |

Network and HTTP errors are never converted into findings. In particular, an
HTTP 404/410 remains `unreachable` even when its response contains a non-empty
HTML or sentinel body.

## Safety and data handling

- Only explicit `http://` or `https://` URLs and explicit GitHub repositories
  are accessed.
- URLs containing credentials and URLs using loopback, private, link-local,
  reserved, multicast, or unspecified addresses are rejected. Live probes
  resolve hostnames and reject redirects to non-public addresses.
- Requests send only a fixed user agent. No authorization, cookies, environment
  credentials, or user-provided headers are used.
- Response bodies, repository metadata, search titles, and search snippets are
  never written to reports or standard output.
- Every successfully fetched 2xx body is represented by its SHA-256 hash.
  404/410 sentinel bodies are deliberately neither treated as success nor
  hashed.
- Report URLs omit credentials, queries, and fragments. Local search-result and
  fixture paths are not included in reports or input-error messages.
- The tool performs GET-only probes and writes only the two requested local
  report files.

Inputs must themselves be appropriate public audit material. Do not place
private content, tokens, or credentials in fixture or search-result JSON.

## Usage

Live public probes:

```bash
python3 scripts/audit_public_ip.py \
  --url https://example.com/removed-page \
  --repo owner/public-copy \
  --link-document https://example.org/public-links.html \
  --forbidden-url https://example.com/removed-page \
  --search-results fixtures/public-search-results.json \
  --json-report artifacts/public-ip-audit.json \
  --markdown-report artifacts/public-ip-audit.md
```

Arguments may be repeated. `--repo` accepts `OWNER/NAME` or a public
`https://github.com/OWNER/NAME` URL. A link document requires at least one
`--forbidden-url`.

The default report paths are `public-ip-audit.json` and
`public-ip-audit.md`. Reports omit generation time by default, which makes the
same offline inputs byte-for-byte deterministic. Supply a fixed
`--generated-at` value when a report timestamp is required.

Exit status is:

- `0` when every artifact was classified without a probe error;
- `1` when a report was written but at least one artifact is `probe-error`;
- `2` for invalid command-line or input JSON.

## Deterministic offline fixtures

Use `--fixture-json ... --offline` to prevent all network access. The fixture is
a JSON object keyed by the exact URL that would be fetched:

```json
{
  "responses": {
    "https://example.com/removed-page": {
      "status": 404,
      "body": "sentinel text that will never appear in a report"
    },
    "https://example.org/public-links.html": {
      "status": 200,
      "body": "<a href=\"https://example.com/removed-page\">old link</a>"
    },
    "https://api.github.com/repos/owner/public-copy": {
      "status": 200,
      "json": {
        "fork": true
      }
    },
    "https://example.net/timed-out": {
      "error": "timeout"
    }
  }
}
```

Supported response bodies are `body` (UTF-8 text), `body_base64` (binary), or
`json` (canonical JSON); use only one per response. Supported fixture errors
include `timeout`, `dns-error`, `connection-refused`, `network-error`, and
`tls-error`. A missing offline response becomes `probe-error` with
`fixture-miss`.

Without `--offline`, fixture entries are used first and missing entries fall
back to live public probes.

## Saved public search results

`--search-results` accepts:

- a JSON list;
- `{"results": [...]}`; or
- `{"items": [...]}`.

Common public result fields such as `url`, `link`, and `html_url` identify the
reported source. `fork`, `is_fork`, or equivalent repository metadata produces
`fork-indicator`. `cache`, `cached`, `cache_url`, `cached_url`, `webcache`, or a
reference to a supplied forbidden URL produces `cached-indicator`.

Search bodies are not fetched. Search-result text is inspected only in memory
and is never copied into either report.

## Tests

```bash
python3 -m unittest -v tests/test_audit_public_ip.py
```
