# Email delivery — real sending, dev outbox, and the surrogate key

Centralized email delivery lives in `app/services/email.py` (provider
abstraction, NULL-branded templates, delivery recording, retries).
Invitations are the first sender; password resets route through the
same `deliver_email` path. SMTP ticket replies (`send_reply_email`)
are unchanged.

## Modes (config-driven, env vars — never code branches)

| `NULL_EMAIL_PROVIDER` | Behaviour |
|---|---|
| `none` (default) | **Development.** Nothing is sent. The message is logged (token redacted) and recorded in the local dev outbox (`dev_email_outbox` table); the invitation `accept_url` is returned to the inviting admin for local testing. |
| `resend` | **Configured.** The message is sent for real through the Resend API and the attempt is recorded on an `email_deliveries` row. The dev `accept_url` is NEVER returned. A failed submission is reported accurately (`delivery.status == "failed"` + error), never as a success. A selected-but-unconfigured provider fails loudly (`EmailConfigurationError` → HTTP 503, invitation NOT created). |

## Where the Resend key comes from (precedence)

1. **`NULL_RESEND_API_KEY` in the environment** — the production path.
   An operator key, set via the secure channel, never in code or chat.
2. **The Muse dynamic-credential surrogate** — the path on this VM.
   No key is in the environment and no process can read the key value
   out of secure storage, so the backend fetches a fresh `hsurr:`
   surrogate per send from authd (`app/services/resend_surrogate.py`,
   credential `custom.resend`, bearer_header placement) and sends it
   as the Bearer token THROUGH the egress proxy, which swaps it for
   the real key on the approved request to `api.resend.com`. The
   backend never sees, stores, logs, or transmits the real key.
3. **Neither** — the send fails loudly (503). There is no silent
   fallback to the dev outbox.

`email_delivery_configured()` is True when provider is `resend` AND a
key source exists (env key, or the authd socket present for the
surrogate channel). The send itself is the real proof — a missing
credential fails at send time.

## Transport facts (all verified against the live API)

- **Cloudflare** sits in front of `api.resend.com` and refuses the
  default Python user agent with HTTP 403 / error code 1010. Every
  request carries a browser User-Agent (Chrome on Linux, the same
  string the `custom.resend` connector's verified test-send helper
  uses), set both on the client and per request.
- **NO_PROXY** on this VM contains a bare `::1` entry that httpx 0.28
  cannot parse, so a client built with `trust_env=True` raises
  `InvalidURL` before any request. Clients are built with
  `trust_env=False` and the egress proxy (when configured) is passed
  explicitly as `proxy=` — surrogate requests still route through the
  proxy that performs the swap.
- **TLS** is verified against the **system CA store**
  (`ssl.create_default_context()`), not httpx's certifi bundle: the
  egress proxy terminates TLS with the Hatch CA, installed in
  `/usr/local/share/ca-certificates`. Verification stays on
  (`CERT_REQUIRED` + hostname check); only the trust anchors change.
  A default httpx client fails every Resend request here with
  `CERTIFICATE_VERIFY_FAILED` (found live Nov 26, 2026).

## Sender

`NULL_EMAIL_FROM` (default `no-reply@nullitsm.local`). The Resend
account has no verified domain yet, so the only sender that works is
the Resend onboarding address: set
`NULL_EMAIL_FROM=onboarding@resend.dev` for live sends. That sender
can only mail the account owner's inbox (`jamiah_mcq@yahoo.com`).
Before inviting anyone else, verify a domain in Resend and set it as
the sender. Resend free tier: 3,000 emails/month, 100/day.

## Delivery records + retries + idempotency

- One `email_deliveries` row per attempt batch: to/subject/template,
  provider, `provider_message_id` on success, `status`
  (`sent`/`failed`/`dev_recorded`), `attempts`, `last_error`. The
  rendered HTML + text bodies are stored so a retry re-sends the
  identical email without ever needing the raw invitation token again
  (only the SHA-256 hash is on the invitation row). Bodies are never
  returned by the API.
- A failed provider submission enqueues a Celery retry
  (`null.tasks.retry_email_delivery`, backoff 60s × 2^(attempts-1),
  max attempts `NULL_EMAIL_RETRY_MAX_ATTEMPTS`, default 3). The retry
  only re-sends rows still `failed` with attempts remaining; an
  already-`sent` row is never sent twice.
- Duplicate pending invitations are rejected at the API (400) and
  backed by partial unique indexes (migration 0018): at most one
  pending invitation per (organization, email) and one pending
  platform invitation per email. Expired pending rows are retired to
  `expired` at invite time so a re-invite after expiry works.

## Templates

NULL editorial (ivory `#F2EBDD`, ink `#171614`, purple `#6B4FA1` /
button `#A17ACB`), serif headings, letterspaced NULL wordmark.
Org invitation subject is exactly **"You've been invited to join
NULL ITSM"**; platform invitation **"You've been invited to join NULL
ITSM Platform Administration"**. Both carry the inviting org (or
NULL platform), recipient name, assigned role, inviter name, an
Accept Invitation button, a plain-text fallback URL, a 48-hour expiry
notice, and a "contact the org if unexpected" line. All user values
are HTML-escaped; plain-text mirrors are included.

## Attachments + scheduled reports (Phase 4)

`EmailProvider.send` accepts optional `attachments`
(`[{"filename", "content": bytes}]`); the Resend provider sends them
as base64 `attachments`, the dev outbox ignores them. Scheduled
reports (`run_scheduled_report`) email one CSV per recipient
(`<slug>-YYYYMMDD-HHMM.csv`, template `scheduled_report`) via
`deliver_email(..., retry=False)`: the CSV bytes are not stored, so a
failed delivery is recorded in `email_deliveries` and the `report.generated`
audit metadata, and the next scheduled run re-sends. `last_status`
reflects generation only. See DECISIONS.md for the rationale.

## Live acceptance status (Nov 26, 2026)

- The key is verified working via the `custom.resend` connector
  (test send Nov 25, 2026, message id
  `01a215ba-bba0-7967-a2d1-70f276c94fa0`).
- The backend's surrogate path is verified end to end: a real
  invitation email was sent Nov 26, 2026 from the live boot to
  `jamiah_mcq@yahoo.com` (invitation `af335528-4d53-474d-9d9e-5a872d82b8f3`,
  Resend message id `01a215df-d718-7767-afab-955c0f0944ff`,
  `delivery.status == "sent"`, `accept_url` hidden).
- **Still open — and the original invitation row is gone:** the Phase 4
  live boots recreate `null_itsm_live` from scratch
  (`live_boot_setup.py` drops it), so the invitation row behind that
  email no longer exists and its token cannot be accepted. Receipt
  confirmation in the Yahoo inbox is still meaningful (the send path
  is proven), but acceptance needs a **fresh invitation send** from a
  boot whose database is kept until the accept step runs. Do not mark
  the email work complete until receipt + acceptance are confirmed.
  The accept link points at `https://nullitsm.github.io/invite/accept`,
  whose accept page does not exist yet — that is frontend-track work;
  the backend accept endpoint (`POST /api/v1/auth/invitations/accept`)
  is ready.

## Tests

`tests/test_email_delivery.py` (26 tests): templates (subject,
content, branding, escaping), dev mode (accept_url + outbox +
delivery status), configured mode (browser UA, sent + hidden link,
failure reported not hidden, resend-after-failure, keyless 503),
surrogate mode (surrogate Bearer + proxy routing + system-CA
verification, surrogate-unavailable 503, no-proxy 503, env-key
precedence), idempotency (duplicate 400, expired re-invite, unique
index backstop, unauthorized 403), retries (send failed → sent +
audit, skip sent, stop at max attempts, no-op without a provider).
The provider boundary is mocked with `httpx.MockTransport` — no test
touches the real API or the real key.
