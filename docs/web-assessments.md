# Executable Web assessments — alpha.7

## Operator workflow

1. Configure `SCOPE_ALLOWLIST` with the authorized host/IP. Start the application
   using the existing installation or hardened Compose instructions.
2. Open **Web Assessment**. Enter an HTTP(S) URL and the allowed/excluded path
   prefixes. Scope is one exact origin, including scheme and port. Review that
   these are read-only areas: even an application's GET routes can have effects.
3. Set page, HTTP-request and elapsed-time budgets. Optionally enable the current
   AI provider to prioritize the approved task IDs/categories. No new provider or
   model credential is required for deterministic execution.
4. For controlled authorization testing, configure two test-account credentials
   and synthetic owner-only fixtures as below. Leave this section empty for
   anonymous GET mapping/header review.
5. Start the assessment, refresh progress and download the Markdown report.
   Cancel stops dispatch of further requests; an already-dispatched request may
   finish. After fixing an issue, **Retest** starts a new bounded assessment with
   the same scope and fixtures. It does not run an automatic scheduled scan.

## Credentials and fixtures

On the backend, provide `MT_WEB_ACCOUNT_OWNER` and `MT_WEB_ACCOUNT_OTHER` through
runtime environment configuration. Hardened Compose forwards these two optional
variables. Custom reference names must start with `MT_WEB_ACCOUNT_` and must be
explicitly forwarded in your own deployment configuration. Values never belong
in a request, source file, Git commit or report.

The account table accepts a name, `kind` (`bearer` or `cookie`) and `secret_env`.
A bearer secret is the token value without `Bearer `. A cookie secret is an
already-established test session's Cookie header value. This release does not
perform browser form login, MFA or credential refresh. Missing/expired accounts
produce coverage gaps instead of confirmed findings. Public targets require
HTTPS when credentials are used.

Each check needs a literal query-free fixture URL, owner account, other account,
8–128 character synthetic marker, and `ownership_confirmed: true`. The operator
must establish that the fixture belongs exclusively to the owner and that the
other credential is a distinct test identity. Different token values alone do
not prove distinct identities. Do not use real private records as fixtures.

A confirmed medium-severity cross-account finding requires all of:

- Owner baseline returns 2xx and the synthetic marker.
- Anonymous control returns 401/403/404 without that marker.
- Other account returns 2xx and the marker.
- Fresh connections reproduce the owner and other-account results.
- All five non-truncated observations have valid server-created artifact signatures.

This establishes access to the configured fixture, not broad account takeover.
The medium rating is conservative and needs business-impact review. The worker
passes its observations through the native proof verifier using an internal
artifact validator. AI output and caller-supplied `supports` labels cannot create
confirmation. Missing controls, redirects, changed fixtures, authentication
failures and inconsistent results remain coverage gaps. Header observations are
informational candidates, never a claim of exploitable XSS or other impact.

## API

All endpoints inherit the application's `X-API-Key` authentication middleware.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| POST | `/api/web-assessments` | Validate, persist, queue; HTTP 202 |
| GET | `/api/web-assessments` | List recent assessments |
| GET | `/api/web-assessments/{id}` | Progress, evidence metadata, findings and gaps |
| POST | `/api/web-assessments/{id}/cancel` | Stop dispatching further work |
| POST | `/api/web-assessments/{id}/resume` | Resume remaining tasks of a paused job |
| POST | `/api/web-assessments/{id}/retest` | New assessment using the same URL/checks |
| GET | `/api/web-assessments/{id}/report` | Download a current Markdown report |

Example request (the hostname is illustrative; it is not a test target):

```json
{
  "target": "https://your-authorized-site.example/",
  "authorization_confirmed": true,
  "allowed_paths": ["/"],
  "excluded_paths": ["/logout", "/admin"],
  "max_pages": 10,
  "max_requests": 40,
  "max_seconds": 180,
  "ai_planning": false,
  "accounts": {
    "owner": {"kind": "bearer", "secret_env": "MT_WEB_ACCOUNT_OWNER"},
    "other": {"kind": "bearer", "secret_env": "MT_WEB_ACCOUNT_OTHER"}
  },
  "authorization_checks": [{
    "url": "https://your-authorized-site.example/api/fixtures/mt-owner-only",
    "owner": "owner",
    "other": "other",
    "marker": "MT-SYNTHETIC-FIXTURE-12345",
    "ownership_confirmed": true
  }]
}
```

Optional `source_files` is a bounded relative-path-to-source-text object. Source
is mapped using the existing static mapper; only its result is persisted. It is
not sent to AI. The retest endpoint does not preserve raw source: upload new
source for a fresh static mapping.

## Runtime and failure behavior

State transitions: queued → running → completed / partial / cancelled. An expired
running lease becomes paused. On resume, already-finished tasks stay finished;
a task interrupted in flight is recorded as unknown and is not automatically
replayed. Remaining tasks continue. Request reservations are persisted before
network dispatch, so interrupted requests still consume budget.

SQLite state is stored beside `DB_PATH` as `mt_web_assessments.db` (0600). Atomic
claims and worker leases prevent two workers claiming the same running job.
A heartbeat renews the 90-second lease. Unexpected process loss is surfaced as
paused after lease expiry; a manual resume or a fresh retest is then available.
Time budgets include downtime from the first start. Exhausted jobs are partial;
start a new assessment if a fresh budget is needed.

The HTTP adapter revalidates the current global allowlist before every request,
pins a validated resolved IP, preserves HTTPS certificate/hostname validation,
and never follows redirects or inherits environment proxies. Private/loopback/
link-local resolved addresses require an explicit IP/CIDR allowlist entry even
when their hostname is allowed. Query strings, encoded/ambiguous paths,
common action routes, cross-origin URLs and excluded paths are rejected.

Default response capture is capped at 256 KiB. Only hashes, HTTP status, header
names and synthetic-marker assertions are persisted. Raw bodies and credential
headers are discarded. Target throttling (429) or server errors (5xx) stop the
assessment with a partial report. Other failures become coverage gaps. Time is
checked before every dispatch; an in-progress socket or OS DNS operation may
outlast the remaining engagement budget. There is at most one model call per
assessment, with a 15-second planner deadline; dollar-cost accounting is not
implemented. AI failures or invalid task IDs use the deterministic task order.

`WEB_EVIDENCE_SIGNING_KEY` optionally separates evidence signing from
`API_AUTH_TOKEN`. Keep the signing key stable to validate old evidence. If the
fallback API token is rotated, old evidence will be reported as untrusted.
The generic `/api/verification/evaluate` endpoint
cannot provide the internal evidence validator and therefore cannot independently
confirm imported observation labels. Existing callers must handle candidate
results; this is an intentional trust-boundary change.

## Decision log and capability boundary

Confirmed goal: assess operator-authorized websites and return evidence-backed
reports, using URL + test accounts with optional source code. The first execution
profile deliberately completes a narrow, testable end-to-end flow. It coexists
with the legacy orchestrator, generic planning DAG and optional browser adapter;
it does not claim to make every existing DAG role executable or to import
Shannon/Strix/PentAGI engines.

Implemented: persistent task execution, same-origin GET mapping, controlled
object-authorization checks, evidence validation, optional AI task ranking,
static source mapping, progress, cancellation, crash recovery and reporting.

Remaining: browser form-login/SPA exploration, authenticated browser-session
lifecycle, OpenAPI/GraphQL intent execution, broader vulnerability-specific
validators, source-to-runtime correlation, cost telemetry, richer agent planning
and independent benchmark comparison. The legacy optional browser adapter is
still available separately and does not run as part of this profile.

## Validation

Run the new local-only integration suite without third-party test dependencies:

```bash
python -m unittest tests.test_web_assessment -v
```

It launches an ephemeral loopback fixture server; it does not contact a live
website or LLM provider. Cases cover vulnerable/secure authorization fixtures,
forged proof labels, changed evidence, scope revocation, DNS rebinding policy,
redirects, response limits, budget exhaustion, cancellation, recovery and AI
plan injection. Existing proof/contract regression tests also exercise trusted
fixture validation. Full dependency, API/UI and hardened-container CI gates must
still run in the repository's configured environment; local fixture success is
not a general pentesting benchmark score.
