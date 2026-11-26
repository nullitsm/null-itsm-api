/**
 * NULL ITSM — browser API client (framework-free ES module).
 *
 * Talks to the NULL ITSM backend (FastAPI, `/api/v1`) from the existing
 * static NULL ITSM screens. No dependencies, no build step — import it
 * directly from a `<script type="module">`:
 *
 * @example
 * ```html
 * <script type="module">
 *   import { NullApiClient, NullApiError } from './null-api-client.js';
 *
 *   const api = new NullApiClient({
 *     baseUrl: 'http://localhost:8000',
 *     onLoadingChange: (loading) => {
 *       document.querySelector('#spinner').hidden = !loading;
 *     },
 *     onUnauthorized: () => { window.location.href = '/sign-in.html'; },
 *   });
 *
 *   // Sign-in flow (see docs/FRONTEND_INTEGRATION.md for the full flow):
 *   const result = await api.login('tech@example.com', 'correct horse battery staple');
 *   if (result.status === 'mfa_required') {
 *     const done = await api.mfaChallenge(result.mfa_token, '123456');
 *     // `done` carries the access/refresh tokens when MFA succeeds.
 *   } else if (result.status === 'org_required') {
 *     const tokens = await api.selectOrganization(result.org_select_token, result.organizations[0].id);
 *   } else if (result.status === 'no_org') {
 *     const org = await api.createOrganization({ name: 'Example Org' });
 *     await api.selectOrganization(result.org_select_token, org.id);
 *   }
 *   // After login, tokens + org context are stored; every later call just works:
 *   const tickets = await api.listTickets();
 *   const me = await api.me();
 * </script>
 * ```
 *
 * Token storage rules (deliberate):
 * - Access token: memory only. It lives ~15 minutes and is never written to
 *   any browser storage, so a stolen storage dump cannot replay a session.
 * - Refresh token: `sessionStorage` under `null-itsm-refresh-token`. It is
 *   rotated on every refresh (the old one is revoked server-side) and dies
 *   with the tab, so it does not survive a browser restart.
 * - Organization id: memory + `sessionStorage` under `null-itsm-org-id`,
 *   sent as the `X-Organization-Id` header on every request.
 *
 * Auth failures: on a 401 the client tries exactly one token refresh
 * (`POST /api/v1/auth/refresh`) and retries the original request once.
 * If the refresh fails, tokens are cleared and `onUnauthorized` runs
 * (default: redirect to the sign-in page).
 */

/** Storage keys (single source of truth — the docs reference these too). */
export const REFRESH_TOKEN_KEY = 'null-itsm-refresh-token';
export const ORG_ID_KEY = 'null-itsm-org-id';

/**
 * Error thrown by every client method when the API (or the network) fails.
 * `detail` is the API's human-readable message; `errors` holds the
 * per-field validation list the API returns for 422 responses, if any.
 */
export class NullApiError extends Error {
  /**
   * @param {number} status - HTTP status (0 = network failure, no response).
   * @param {string} detail - Human-readable message from the API.
   * @param {Array<object>} [errors=[]] - Per-field validation errors (422).
   */
  constructor(status, detail, errors = []) {
    super(detail || `Request failed (HTTP ${status})`);
    this.name = 'NullApiError';
    this.status = status;
    this.detail = detail || `Request failed (HTTP ${status})`;
    this.errors = errors;
  }
}

/**
 * Decode the payload of a JWT without verifying it. Used only to read the
 * `exp` claim for the client-side expiry check in {@link NullApiClient#requireAuth}.
 * Never trust client-decoded claims for authorization — the server verifies
 * the signature on every request.
 *
 * @param {string} token - JWT string.
 * @returns {object|null} Decoded payload, or null when it is not a JWT.
 */
function decodeJwtPayload(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join(''),
    );
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/** Generate a per-request id (crypto.randomUUID when available). */
function newRequestId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `req-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export class NullApiClient {
  /**
   * @param {object} [options={}]
   * @param {string} [options.baseUrl] - API origin. Default: the page's own
   *   origin when it is served from the API host (port 8000), otherwise
   *   `http://localhost:8000` (local dev).
   * @param {(loading: boolean) => void} [options.onLoadingChange] - Called
   *   with true/false around requests (driven by an in-flight counter, so
   *   overlapping requests keep the spinner up until the last one finishes).
   * @param {() => void} [options.onUnauthorized] - Called after tokens are
   *   cleared when a refresh fails. Default: redirect to `/sign-in.html`.
   * @param {string} [options.signInUrl='/sign-in.html'] - Redirect target
   *   used by the default `onUnauthorized`. Ignored when a custom
   *   `onUnauthorized` is supplied.
   */
  constructor(options = {}) {
    const { baseUrl, onLoadingChange, onUnauthorized, signInUrl = '/sign-in.html' } = options;
    this.baseUrl = (baseUrl || NullApiClient.defaultBaseUrl()).replace(/\/$/, '');
    this.onLoadingChange = typeof onLoadingChange === 'function' ? onLoadingChange : null;
    this.signInUrl = signInUrl;
    this.onUnauthorized =
      typeof onUnauthorized === 'function'
        ? onUnauthorized
        : () => {
            if (typeof window !== 'undefined') window.location.href = this.signInUrl;
          };

    /** @type {string|null} Access token — memory only, never persisted. */
    this.accessToken = null;
    /** @type {string|null} Current organization id (memory copy). */
    this.orgId = null;
    /** @type {number} In-flight request counter for onLoadingChange. */
    this._inFlight = 0;
    /** @type {Promise<object>|null} In-flight refresh, shared so concurrent 401s trigger one refresh. */
    this._refreshPromise = null;

    // Restore the durable half of the session (refresh token + org id).
    // The access token is intentionally NOT restored: it is memory-only and
    // the first 401 after a reload transparently refreshes it.
    try {
      this.orgId = window.sessionStorage.getItem(ORG_ID_KEY);
    } catch {
      this.orgId = null;
    }
  }

  /**
   * Default base URL: the page origin when served from the API host
   * (port 8000), else the local-dev API origin.
   * @returns {string}
   */
  static defaultBaseUrl() {
    if (typeof window !== 'undefined' && window.location) {
      const { origin, port, protocol } = window.location;
      if (port === '8000' || (protocol === 'http:' && !port)) return origin;
      // Served from another origin (e.g. the static frontend on its own
      // host/port) — fall through to the dev API origin.
    }
    return 'http://localhost:8000';
  }

  // ------------------------------------------------------------------ state

  /**
   * Store a fresh token pair (and, when present, the org from the token).
   * Called by login / MFA / org-select / org-switch / refresh.
   * @param {{ access_token?: string|null, refresh_token?: string|null }} tokens
   */
  setTokens({ access_token: accessToken, refresh_token: refreshToken } = {}) {
    if (accessToken) this.accessToken = accessToken;
    if (refreshToken) {
      try {
        window.sessionStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
      } catch {
        // Storage unavailable (private mode, etc.): the session still works
        // in memory until the tab closes; refresh after reload will fail
        // and onUnauthorized will fire, which is the safe fallback.
      }
    }
  }

  /** @returns {string|null} The stored refresh token, if any. */
  getRefreshToken() {
    try {
      return window.sessionStorage.getItem(REFRESH_TOKEN_KEY);
    } catch {
      return null;
    }
  }

  /**
   * Current organization context (the org id sent as `X-Organization-Id`).
   * @returns {string|null}
   */
  getOrgContext() {
    return this.orgId;
  }

  /**
   * Set (or clear, with `null`) the current organization context, persisted
   * to sessionStorage so a reload keeps the same org. Call after login,
   * org-select, or org-switch — or before a request that must target a
   * specific org.
   * @param {string|null} orgId
   */
  setOrgContext(orgId) {
    this.orgId = orgId || null;
    try {
      if (this.orgId) window.sessionStorage.setItem(ORG_ID_KEY, this.orgId);
      else window.sessionStorage.removeItem(ORG_ID_KEY);
    } catch {
      // Non-fatal: memory copy still applies for this tab's lifetime.
    }
  }

  /**
   * Clear all session state (memory + sessionStorage). Called on logout and
   * when a refresh fails.
   */
  clearSession() {
    this.accessToken = null;
    this.orgId = null;
    this._refreshPromise = null;
    try {
      window.sessionStorage.removeItem(REFRESH_TOKEN_KEY);
      window.sessionStorage.removeItem(ORG_ID_KEY);
    } catch {
      // Ignore storage errors on teardown.
    }
  }

  /**
   * Route-protection helper: true when an access token exists and has not
   * expired per its `exp` claim. Returns false when there is no token, the
   * token is not a decodable JWT, or `exp` is in the past (with a 30s clock
   * skew allowance). Note this is a UI gate only — the server re-verifies
   * the token on every request, and a token that passes here can still be
   * rejected (revoked, wrong org) with a 401.
   * @returns {boolean}
   */
  requireAuth() {
    if (!this.accessToken) return false;
    const payload = decodeJwtPayload(this.accessToken);
    if (!payload || typeof payload.exp !== 'number') return false;
    return payload.exp * 1000 > Date.now() + 30_000;
  }

  // ------------------------------------------------------------- core fetch

  /** @private Track in-flight count and notify onLoadingChange on transitions. */
  _setLoading(delta) {
    const before = this._inFlight;
    this._inFlight = Math.max(0, this._inFlight + delta);
    if (this.onLoadingChange && (before === 0) !== (this._inFlight === 0)) {
      this.onLoadingChange(this._inFlight > 0);
    }
  }

  /**
   * Low-level request. Handles headers, JSON in/out, the 401 → refresh →
   * retry-once flow, loading state, and normalized errors.
   *
   * @param {string} path - Path under the base URL (e.g. `/api/v1/tickets`).
   * @param {object} [options={}]
   * @param {string} [options.method='GET']
   * @param {object} [options.body] - JSON body (omitted when undefined).
   * @param {boolean} [options.auth=true] - Send the Bearer access token.
   * @param {string} [options.authToken] - Override the Bearer token
   *   (used by selectOrganization, which authenticates with the
   *   short-lived org_select_token instead of an access token).
   * @param {boolean} [options.allowRefresh=true] - Allow the 401 refresh
   *   flow. Disabled for the refresh call itself (no infinite loop) and
   *   for the retry (exactly one retry).
   * @returns {Promise<any>} Parsed JSON body, or null for empty (204) bodies.
   * @throws {NullApiError}
   */
  async request(path, options = {}) {
    const {
      method = 'GET',
      body,
      auth = true,
      authToken,
      allowRefresh = true,
    } = options;

    const headers = {
      'Content-Type': 'application/json',
      'X-Request-Id': newRequestId(),
    };
    const token = authToken || (auth ? this.accessToken : null);
    if (token) headers.Authorization = `Bearer ${token}`;
    if (this.orgId) headers['X-Organization-Id'] = this.orgId;

    this._setLoading(1);
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });

      if (response.status === 401 && allowRefresh && auth && !authToken) {
        // Exactly one refresh attempt, then one retry of the original call.
        const refreshed = await this._tryRefresh();
        if (refreshed) {
          return this.request(path, { ...options, allowRefresh: false });
        }
        this.clearSession();
        this.onUnauthorized();
        throw new NullApiError(401, 'Session expired — please sign in again.');
      }

      return await this._parseResponse(response);
    } catch (err) {
      if (err instanceof NullApiError) throw err;
      // Network failure, CORS failure, or the server being down: no HTTP
      // status exists, so status 0 marks "no response received".
      throw new NullApiError(0, 'Could not reach the API. Check your connection and try again.');
    } finally {
      this._setLoading(-1);
    }
  }

  /** @private Parse a response body; throw NullApiError on HTTP errors. */
  async _parseResponse(response) {
    if (response.status === 204) return null;
    const text = await response.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = null;
      }
    }
    if (!response.ok) {
      // FastAPI error shape: {"detail": "..."} or, for 422 validation,
      // {"detail": [{loc, msg, type}, ...]}.
      const detail = data && data.detail !== undefined ? data.detail : null;
      if (Array.isArray(detail)) {
        const first = detail[0];
        const message = first && first.msg ? `${first.msg}` : 'Validation failed.';
        return Promise.reject(new NullApiError(response.status, message, detail));
      }
      const message =
        typeof detail === 'string' && detail
          ? detail
          : `Request failed (HTTP ${response.status})`;
      throw new NullApiError(response.status, message);
    }
    return data;
  }

  /**
   * @private Refresh the token pair once (single-flight: concurrent 401s
   * share one refresh). Returns true when a new pair was stored.
   * The old refresh token is revoked server-side on success (rotation).
   */
  async _tryRefresh() {
    if (this._refreshPromise) return this._refreshPromise;
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) return false;
    this._refreshPromise = (async () => {
      try {
        const tokens = await this.request('/api/v1/auth/refresh', {
          method: 'POST',
          body: { refresh_token: refreshToken },
          auth: false,
          allowRefresh: false,
        });
        this.setTokens(tokens);
        return true;
      } catch {
        return false;
      } finally {
        this._refreshPromise = null;
      }
    })();
    return this._refreshPromise;
  }

  // ------------------------------------------------------------------- auth
  // All login-flow methods return the raw API payload so the caller can
  // branch on `status` ('ok' | 'mfa_required' | 'org_required' | 'no_org').

  /**
   * Sign in with email + password.
   * Response `status` decides the next step: `ok` (tokens present),
   * `mfa_required` (call {@link mfaChallenge} with `mfa_token`),
   * `org_required` (call {@link selectOrganization} with
   * `org_select_token` and one of `organizations`), `no_org` (the user
   * belongs to no org yet — call {@link createOrganization}, then
   * {@link selectOrganization}).
   * Rate-limited: 10/minute per IP.
   * @param {string} email
   * @param {string} password
   * @returns {Promise<object>} LoginResponse.
   */
  async login(email, password) {
    const result = await this.request('/api/v1/auth/login', {
      method: 'POST',
      body: { email, password },
      auth: false,
    });
    if (result.access_token && result.refresh_token) {
      this.setTokens(result);
      const payload = decodeJwtPayload(result.access_token);
      if (payload && payload.org) this.setOrgContext(payload.org);
    }
    return result;
  }

  /**
   * Complete MFA after a login that returned `mfa_required`.
   * @param {string} mfaToken - Short-lived token from the login response (5 min).
   * @param {string} code - 6-digit TOTP code.
   * @returns {Promise<object>} LoginResponse (same branching as {@link login}).
   */
  async mfaChallenge(mfaToken, code) {
    const result = await this.request('/api/v1/auth/mfa/challenge', {
      method: 'POST',
      body: { mfa_token: mfaToken, code },
      auth: false,
    });
    if (result.access_token && result.refresh_token) {
      this.setTokens(result);
      const payload = decodeJwtPayload(result.access_token);
      if (payload && payload.org) this.setOrgContext(payload.org);
    }
    return result;
  }

  /**
   * Finish a multi-org login: exchange the short-lived `org_select_token`
   * (from a login with status `org_required` / `no_org`) for a token pair
   * scoped to the chosen organization.
   * @param {string} orgSelectToken
   * @param {string} organizationId
   * @returns {Promise<object>} TokenResponse `{access_token, refresh_token}`.
   */
  async selectOrganization(orgSelectToken, organizationId) {
    const tokens = await this.request('/api/v1/auth/select-organization', {
      method: 'POST',
      body: { organization_id: organizationId },
      auth: true,
      authToken: orgSelectToken,
      allowRefresh: false,
    });
    this.setTokens(tokens);
    this.setOrgContext(organizationId);
    return tokens;
  }

  /**
   * Switch the active organization while already signed in. Uses the
   * stored refresh token; issues a fresh token pair scoped to the new org
   * and updates the org context.
   * @param {string} organizationId
   * @returns {Promise<object>} TokenResponse.
   */
  async switchOrganization(organizationId) {
    const tokens = await this.request('/api/v1/auth/switch-organization', {
      method: 'POST',
      body: { refresh_token: this.getRefreshToken(), organization_id: organizationId },
      auth: false,
      allowRefresh: false,
    });
    this.setTokens(tokens);
    this.setOrgContext(organizationId);
    return tokens;
  }

  /**
   * Rotate the refresh token and get a fresh access token. Normally the
   * client does this automatically on 401; call it directly for a
   * proactive refresh (e.g. before a long-lived page goes idle).
   * @returns {Promise<object>} TokenResponse.
   */
  async refreshToken() {
    const tokens = await this.request('/api/v1/auth/refresh', {
      method: 'POST',
      body: { refresh_token: this.getRefreshToken() },
      auth: false,
      allowRefresh: false,
    });
    this.setTokens(tokens);
    return tokens;
  }

  /**
   * Sign out: revokes the refresh token server-side, then clears all local
   * session state even if the server call fails (local teardown must never
   * depend on the network).
   * @returns {Promise<void>}
   */
  async logout() {
    const refreshToken = this.getRefreshToken();
    try {
      if (refreshToken) {
        await this.request('/api/v1/auth/logout', {
          method: 'POST',
          body: { refresh_token: refreshToken },
        });
      }
    } catch {
      // Best effort: the server-side session may already be gone, or the
      // network may be down. Local state is cleared either way.
    } finally {
      this.clearSession();
    }
  }

  /**
   * Request a password-reset email. Always returns success (no user
   * enumeration) — the UI must not reveal whether the address exists.
   * Rate-limited: 5/minute per IP.
   * @param {string} email
   * @returns {Promise<object>} `{status: 'ok', detail: string}`.
   */
  async requestPasswordReset(email) {
    return this.request('/api/v1/auth/password-reset/request', {
      method: 'POST',
      body: { email },
      auth: false,
    });
  }

  /**
   * Complete a password reset with the token from the reset email.
   * @param {string} token - Reset token (valid 60 minutes).
   * @param {string} newPassword - Minimum 12 characters.
   * @returns {Promise<object>} `{status: 'ok'}`.
   */
  async confirmPasswordReset(token, newPassword) {
    return this.request('/api/v1/auth/password-reset/confirm', {
      method: 'POST',
      body: { token, new_password: newPassword },
      auth: false,
    });
  }

  /**
   * Accept an organization invitation (no auth — the token is the credential).
   * @param {string} token - Invitation token from the invite email.
   * @param {string} fullName
   * @param {string} password - Minimum 12 characters.
   * @returns {Promise<object>} `{status, user_id, organization_id, organization_slug}`.
   */
  async acceptInvitation(token, fullName, password) {
    return this.request('/api/v1/auth/invitations/accept', {
      method: 'POST',
      body: { token, full_name: fullName, password },
      auth: false,
    });
  }

  /**
   * Start MFA enrollment for the signed-in user. Returns the TOTP secret
   * and `otpauth://` URI — render the URI as a QR code for the user to scan.
   * @returns {Promise<object>} `{secret, otpauth_uri}`.
   */
  async enrollMfa() {
    return this.request('/api/v1/auth/mfa/enroll', { method: 'POST' });
  }

  /**
   * Confirm MFA enrollment with a code from the authenticator app.
   * @param {string} code - 6-digit TOTP code.
   * @returns {Promise<object>} `{status: 'ok', mfa_enabled: true}`.
   */
  async verifyMfaEnrollment(code) {
    return this.request('/api/v1/auth/mfa/verify-enrollment', {
      method: 'POST',
      body: { code },
    });
  }

  /**
   * Disable MFA for the signed-in user.
   * @returns {Promise<object>} `{status: 'ok', mfa_enabled: false}`.
   */
  async disableMfa() {
    return this.request('/api/v1/auth/mfa/disable', { method: 'POST' });
  }

  /**
   * The signed-in user's identity, current org, owner flag, and permission
   * set — the source of truth for what the UI may show/enable.
   * @returns {Promise<object>} `{user_id, email, organization_id, organization_slug, is_org_owner, permissions[]}`.
   */
  async me() {
    return this.request('/api/v1/auth/me');
  }

  // ---------------------------------------------------------- organizations

  /**
   * Provision a new organization. The caller becomes its owner and
   * Administrator. Works for users with no organization yet (e.g. after a
   * login with status `no_org`).
   * @param {{ name: string, slug?: string }} org
   * @returns {Promise<object>} OrganizationOut.
   */
  async createOrganization({ name, slug } = {}) {
    return this.request('/api/v1/organizations', {
      method: 'POST',
      body: slug ? { name, slug } : { name },
    });
  }

  /**
   * Organizations the caller belongs to (active memberships). Feeds the
   * org switcher in the top bar.
   * @returns {Promise<Array<object>>} OrganizationOut[].
   */
  async myOrganizations() {
    return this.request('/api/v1/organizations/mine');
  }

  /**
   * One organization by id. The id must match the caller's current org
   * (server returns 403 otherwise).
   * @param {string} orgId
   * @returns {Promise<object>} OrganizationOut.
   */
  async getOrganization(orgId) {
    return this.request(`/api/v1/organizations/${encodeURIComponent(orgId)}`);
  }

  /**
   * Update an organization (currently: rename). Requires `org:manage`.
   * @param {string} orgId
   * @param {{ name?: string }} patch
   * @returns {Promise<object>} OrganizationOut.
   */
  async updateOrganization(orgId, patch) {
    return this.request(`/api/v1/organizations/${encodeURIComponent(orgId)}`, {
      method: 'PATCH',
      body: patch,
    });
  }

  /**
   * Members of an organization, with membership status and owner flag.
   * Requires `users:manage`.
   * @param {string} orgId
   * @returns {Promise<Array<object>>} MemberOut[].
   */
  async listMembers(orgId) {
    return this.request(`/api/v1/organizations/${encodeURIComponent(orgId)}/members`);
  }

  /**
   * Change a member's status (`active` | `suspended`) and optionally set a
   * membership expiry. Requires `users:manage`.
   * @param {string} orgId
   * @param {string} userId
   * @param {{ status: string, expires_at?: string }} patch
   * @returns {Promise<object>} `{status: 'ok', membership_status}`.
   */
  async updateMember(orgId, userId, patch) {
    return this.request(
      `/api/v1/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(userId)}`,
      { method: 'PATCH', body: patch },
    );
  }

  /**
   * The org's least-privilege policy (enforce-least-privilege, approval for
   * elevated access, periodic reviews, access expiration, review schedule).
   * Requires `roles:manage`.
   * @param {string} orgId
   * @returns {Promise<object>} Policy object.
   */
  async getPolicy(orgId) {
    return this.request(`/api/v1/organizations/${encodeURIComponent(orgId)}/policy`);
  }

  /**
   * Replace the org's least-privilege policy (only the fields supplied are
   * sent). Requires `roles:manage`.
   * @param {string} orgId
   * @param {object} policy - Any of `enforce_least_privilege`,
   *   `require_approval_for_elevated`, `periodic_access_review`,
   *   `access_expiration`, `access_review_schedule`.
   * @returns {Promise<object>} Updated policy object.
   */
  async setPolicy(orgId, policy) {
    return this.request(`/api/v1/organizations/${encodeURIComponent(orgId)}/policy`, {
      method: 'PUT',
      body: policy,
    });
  }

  /**
   * Invite a technician by email, optionally pre-assigning roles.
   * Requires `users:invite`. The invite token is emailed, never returned.
   * @param {string} orgId
   * @param {{ email: string, role_ids?: string[] }} invite
   * @returns {Promise<object>} InvitationOut (201).
   */
  async inviteTechnician(orgId, { email, role_ids: roleIds = [] } = {}) {
    return this.request(`/api/v1/organizations/${encodeURIComponent(orgId)}/invitations`, {
      method: 'POST',
      body: { email, role_ids: roleIds },
    });
  }

  /**
   * All invitations for an organization (newest first). Requires `users:invite`.
   * @param {string} orgId
   * @returns {Promise<Array<object>>} InvitationOut[].
   */
  async listInvitations(orgId) {
    return this.request(`/api/v1/organizations/${encodeURIComponent(orgId)}/invitations`);
  }

  /**
   * Revoke a pending invitation. Requires `users:invite`.
   * @param {string} orgId
   * @param {string} invitationId
   * @returns {Promise<object>} `{status: 'ok'}`.
   */
  async revokeInvitation(orgId, invitationId) {
    return this.request(
      `/api/v1/organizations/${encodeURIComponent(orgId)}/invitations/${encodeURIComponent(invitationId)}/revoke`,
      { method: 'POST' },
    );
  }

  /**
   * Start a periodic access review for the org. Requires `roles:manage`.
   * @param {string} orgId
   * @returns {Promise<object>} `{id, status, created_at}` (201).
   */
  async startAccessReview(orgId) {
    return this.request(`/api/v1/organizations/${encodeURIComponent(orgId)}/access-reviews`, {
      method: 'POST',
    });
  }

  /**
   * Complete an access review. Requires `roles:manage`.
   * @param {string} orgId
   * @param {string} reviewId
   * @returns {Promise<object>} `{id, status}`.
   */
  async completeAccessReview(orgId, reviewId) {
    return this.request(
      `/api/v1/organizations/${encodeURIComponent(orgId)}/access-reviews/${encodeURIComponent(reviewId)}/complete`,
      { method: 'POST' },
    );
  }

  // ------------------------------------------------------------------ users

  /**
   * All active users in the current org, with their role names.
   * Requires `users:manage`.
   * @returns {Promise<Array<object>>} UserOut[].
   */
  async listUsers() {
    return this.request('/api/v1/users');
  }

  /**
   * One user in the current org (404 when the user has no membership here —
   * the API never reveals users of other orgs). Requires `users:manage`.
   * @param {string} userId
   * @returns {Promise<object>} UserOut.
   */
  async getUser(userId) {
    return this.request(`/api/v1/users/${encodeURIComponent(userId)}`);
  }

  /**
   * Role names assigned to a user in the current org. Requires `users:manage`.
   * @param {string} userId
   * @returns {Promise<Array<string>>} Role names.
   */
  async getUserRoles(userId) {
    return this.request(`/api/v1/users/${encodeURIComponent(userId)}/roles`);
  }

  /**
   * The full permission catalog (code, module, description), ordered by
   * module then code. Requires `roles:manage`. This is the list the Users &
   * Roles screen renders when configuring a role.
   * @returns {Promise<Array<object>>} PermissionOut[].
   */
  async permissionCatalog() {
    return this.request('/api/v1/users/permissions/catalog');
  }

  // ------------------------------------------------------------------ roles

  /**
   * All roles in the current org, each with its permission codes.
   * Requires `roles:manage`.
   * @returns {Promise<Array<object>>} RoleOut[].
   */
  async listRoles() {
    return this.request('/api/v1/roles');
  }

  /**
   * Create a custom role. Requires `roles:manage`. The caller may only
   * grant permissions they themselves hold (enforced server-side).
   * @param {{ name: string, description?: string, access_level?: string, permission_codes?: string[] }} role
   * @returns {Promise<object>} RoleOut (201).
   */
  async createRole({ name, description = '', access_level: accessLevel = 'Least Privilege', permission_codes: permissionCodes = [] } = {}) {
    return this.request('/api/v1/roles', {
      method: 'POST',
      body: { name, description, access_level: accessLevel, permission_codes: permissionCodes },
    });
  }

  /**
   * One role in the current org. Requires `roles:manage`.
   * @param {string} roleId
   * @returns {Promise<object>} RoleOut.
   */
  async getRole(roleId) {
    return this.request(`/api/v1/roles/${encodeURIComponent(roleId)}`);
  }

  /**
   * Update a role's description / access level (name and permissions are
   * not changed here — see {@link configureRolePermissions}).
   * Requires `roles:manage`.
   * @param {string} roleId
   * @param {{ description?: string, access_level?: string }} patch
   * @returns {Promise<object>} RoleOut.
   */
  async updateRole(roleId, patch) {
    return this.request(`/api/v1/roles/${encodeURIComponent(roleId)}`, {
      method: 'PATCH',
      body: patch,
    });
  }

  /**
   * Delete a custom role (system roles cannot be deleted — the API returns
   * 400). Requires `roles:manage`.
   * @param {string} roleId
   * @returns {Promise<null>} No content (204).
   */
  async deleteRole(roleId) {
    return this.request(`/api/v1/roles/${encodeURIComponent(roleId)}`, {
      method: 'DELETE',
    });
  }

  /**
   * Replace a role's permission set wholesale. Requires
   * `permissions:manage` (note: distinct from `roles:manage`). The caller
   * may only grant permissions they themselves hold.
   * @param {string} roleId
   * @param {string[]} permissionCodes
   * @returns {Promise<object>} RoleOut.
   */
  async configureRolePermissions(roleId, permissionCodes) {
    return this.request(`/api/v1/roles/${encodeURIComponent(roleId)}/permissions`, {
      method: 'PUT',
      body: { permission_codes: permissionCodes },
    });
  }

  /**
   * Assign a role to a user in the current org. Requires `roles:manage`.
   * Elevated roles may require approval first — see {@link pendingApprovals}.
   * @param {string} userId
   * @param {string} roleId
   * @returns {Promise<object>} Service result (assignment record).
   */
  async assignRole(userId, roleId) {
    return this.request('/api/v1/roles/assign', {
      method: 'POST',
      body: { user_id: userId, role_id: roleId },
    });
  }

  /**
   * Revoke a role from a user in the current org. Requires `roles:manage`.
   * @param {string} userId
   * @param {string} roleId
   * @returns {Promise<object>} `{status: 'ok'}`.
   */
  async revokeRole(userId, roleId) {
    return this.request('/api/v1/roles/revoke', {
      method: 'POST',
      body: { user_id: userId, role_id: roleId },
    });
  }

  /**
   * Pending elevated-access approvals in the current org.
   * Requires `roles:manage`.
   * @returns {Promise<Array<object>>} ApprovalOut[].
   */
  async pendingApprovals() {
    return this.request('/api/v1/roles/approvals/pending');
  }

  /**
   * Approve or deny a pending elevated-access approval.
   * Requires `roles:manage`.
   * @param {string} approvalId
   * @param {boolean} approve - true to approve, false to deny.
   * @returns {Promise<object>} `{status}` (approved/denied).
   */
  async decideApproval(approvalId, approve) {
    return this.request(`/api/v1/roles/approvals/${encodeURIComponent(approvalId)}/decide`, {
      method: 'POST',
      body: { approve },
    });
  }

  // ------------------------------------------------------------------ audit

  /**
   * Audit log for the current org, newest first. Read-only by design —
   * there is no update or delete endpoint for audit records.
   * Requires `audit:read`.
   * @param {object} [filters={}]
   * @param {string} [filters.action] - Filter by action code (e.g. `ticket.created`).
   * @param {string} [filters.actor_id] - Filter by actor user id.
   * @param {number} [filters.limit=100] - Max rows (server cap: 500).
   * @param {number} [filters.offset=0]
   * @returns {Promise<Array<object>>} AuditLogOut[].
   */
  async listAuditLogs({ action, actor_id: actorId, limit = 100, offset = 0 } = {}) {
    const params = new URLSearchParams();
    if (action) params.set('action', action);
    if (actorId) params.set('actor_id', actorId);
    params.set('limit', String(limit));
    params.set('offset', String(offset));
    return this.request(`/api/v1/audit?${params.toString()}`);
  }

  // ---------------------------------------------------------------- tickets

  /**
   * All tickets in the current org, newest first. Requires `tickets:read`.
   * @returns {Promise<Array<object>>} TicketOut[].
   */
  async listTickets() {
    return this.request('/api/v1/tickets');
  }

  /**
   * Create a ticket. The number is assigned server-side, per-org
   * (`INC-000001`, …), and the caller becomes the requester. Status starts
   * as `open`. Requires `tickets:create`.
   * @param {{ title: string, description?: string, priority?: 'low'|'medium'|'high'|'critical', category?: string }} ticket
   * @returns {Promise<object>} TicketOut (201).
   */
  async createTicket({ title, description = '', priority = 'medium', category = 'General' } = {}) {
    return this.request('/api/v1/tickets', {
      method: 'POST',
      body: { title, description, priority, category },
    });
  }

  /**
   * One ticket by id (404 when it does not exist or belongs to another org —
   * the API never reveals which). Requires `tickets:read`.
   * @param {string} ticketId
   * @returns {Promise<object>} TicketOut.
   */
  async getTicket(ticketId) {
    return this.request(`/api/v1/tickets/${encodeURIComponent(ticketId)}`);
  }

  /**
   * Update a ticket's status, priority, and/or assignee. Only the fields
   * supplied are changed. Requires `tickets:update`.
   * Status must be one of `open`, `in_progress`, `pending`, `resolved`,
   * `closed`; priority one of `low`, `medium`, `high`, `critical`.
   * @param {string} ticketId
   * @param {{ status?: string, priority?: string, assignee_id?: string }} patch
   * @returns {Promise<object>} TicketOut.
   */
  async updateTicket(ticketId, patch) {
    return this.request(`/api/v1/tickets/${encodeURIComponent(ticketId)}`, {
      method: 'PATCH',
      body: patch,
    });
  }

  // ------------------------------------------------------- endpoints (Phase 3)

  /**
   * One-time enrollment tokens in the current org. Requires `endpoints:read`.
   * @returns {Promise<Array<object>>} EnrollmentTokenOut[].
   */
  async listEnrollmentTokens() {
    return this.request('/api/v1/endpoints/enrollment-tokens');
  }

  /**
   * Issue a one-time enrollment token. The raw token is in the response
   * **once** — show it to the admin and never store it. Requires
   * `endpoints:manage`.
   * @param {number} [expiresInHours=24]
   * @returns {Promise<object>} `{id, token, expires_at, ...}` (201).
   */
  async createEnrollmentToken(expiresInHours = 24) {
    return this.request('/api/v1/endpoints/enrollment-tokens', {
      method: 'POST',
      body: { expires_in_hours: expiresInHours },
    });
  }

  /**
   * Revoke an unused enrollment token. Requires `endpoints:manage`.
   * @param {string} tokenId
   */
  async revokeEnrollmentToken(tokenId) {
    return this.request(`/api/v1/endpoints/enrollment-tokens/${encodeURIComponent(tokenId)}/revoke`, {
      method: 'POST',
    });
  }

  /**
   * All endpoints in the current org. Requires `endpoints:read`.
   * @returns {Promise<Array<object>>} EndpointOut[].
   */
  async listEndpoints() {
    return this.request('/api/v1/endpoints');
  }

  /**
   * One endpoint by id. Requires `endpoints:read`.
   * @param {string} endpointId
   * @returns {Promise<object>} EndpointOut.
   */
  async getEndpoint(endpointId) {
    return this.request(`/api/v1/endpoints/${encodeURIComponent(endpointId)}`);
  }

  /**
   * Update an endpoint (display name, assigned user, …). Requires
   * `endpoints:modify`.
   * @param {string} endpointId
   * @param {object} patch
   * @returns {Promise<object>} EndpointOut.
   */
  async updateEndpoint(endpointId, patch) {
    return this.request(`/api/v1/endpoints/${encodeURIComponent(endpointId)}`, {
      method: 'PATCH',
      body: patch,
    });
  }

  /**
   * Revoke an endpoint's device credential. The agent gets 401 on every
   * call thereafter. Requires `endpoints:manage`.
   * @param {string} endpointId
   */
  async revokeEndpoint(endpointId) {
    return this.request(`/api/v1/endpoints/${encodeURIComponent(endpointId)}/revoke`, {
      method: 'POST',
    });
  }

  /**
   * Append-only inventory history for an endpoint. Requires `endpoints:read`.
   * @param {string} endpointId
   * @returns {Promise<Array<object>>}
   */
  async getEndpointInventory(endpointId) {
    return this.request(`/api/v1/endpoints/${encodeURIComponent(endpointId)}/inventory`);
  }

  /**
   * Job history for an endpoint. Requires `endpoints:read`.
   * @param {string} endpointId
   * @returns {Promise<Array<object>>}
   */
  async listEndpointJobs(endpointId) {
    return this.request(`/api/v1/endpoints/${encodeURIComponent(endpointId)}/jobs`);
  }

  /**
   * Issue a job to an endpoint (`patch_scan`, `patch_deploy`, `vuln_scan`,
   * `inventory_refresh`). Requires `endpoints:manage` (plus the
   * type-specific permission at issue time).
   * @param {string} endpointId
   * @param {{ type: string, payload?: object }} job
   * @returns {Promise<object>} AgentJobOut (201).
   */
  async issueEndpointJob(endpointId, { type, payload = {} } = {}) {
    return this.request(`/api/v1/endpoints/${encodeURIComponent(endpointId)}/jobs`, {
      method: 'POST',
      body: { type, payload },
    });
  }

  /**
   * Agent release catalog (global, not tenant data). Requires
   * `endpoints:read`.
   * @returns {Promise<Array<object>>}
   */
  async listAgentReleases() {
    return this.request('/api/v1/endpoints/releases');
  }

  // -------------------------------------------------------- patching (Phase 3)

  /**
   * Patch catalog for the current org. Requires `patching:read`.
   * @returns {Promise<Array<object>>}
   */
  async listPatches() {
    return this.request('/api/v1/patching/patches');
  }

  /**
   * Missing-patch findings per endpoint. Requires `patching:read`.
   * @returns {Promise<Array<object>>}
   */
  async listPatchFindings() {
    return this.request('/api/v1/patching/findings');
  }

  /**
   * Patch scans in the current org. Requires `patching:read`.
   * @returns {Promise<Array<object>>}
   */
  async listPatchScans() {
    return this.request('/api/v1/patching/scans');
  }

  /**
   * Patch deployments in the current org. Requires `patching:read`.
   * @returns {Promise<Array<object>>}
   */
  async listPatchDeployments() {
    return this.request('/api/v1/patching/deployments');
  }

  /**
   * Create a patch deployment (created → approved → executed → verified).
   * Requires `patching:deploy`.
   * @param {{ name: string, items: Array<{ endpoint_id: string, patch_id: string }>, scheduled_at?: string }} deployment
   * @returns {Promise<object>} (201).
   */
  async createPatchDeployment(deployment) {
    return this.request('/api/v1/patching/deployments', {
      method: 'POST',
      body: deployment,
    });
  }

  /**
   * Approve a deployment. Requires `patching:approve`.
   * @param {string} deploymentId
   */
  async approvePatchDeployment(deploymentId) {
    return this.request(`/api/v1/patching/deployments/${encodeURIComponent(deploymentId)}/approve`, {
      method: 'POST',
    });
  }

  /**
   * Execute a deployment (issues a `patch_deploy` agent job per item).
   * Requires `patching:deploy`.
   * @param {string} deploymentId
   */
  async executePatchDeployment(deploymentId) {
    return this.request(`/api/v1/patching/deployments/${encodeURIComponent(deploymentId)}/execute`, {
      method: 'POST',
    });
  }

  /**
   * Cancel a deployment (before execution). Requires `patching:deploy`.
   * @param {string} deploymentId
   */
  async cancelPatchDeployment(deploymentId) {
    return this.request(`/api/v1/patching/deployments/${encodeURIComponent(deploymentId)}/cancel`, {
      method: 'POST',
    });
  }

  /**
   * Verify a deployment (issues a `patch_scan` verification job).
   * Requires `patching:deploy`.
   * @param {string} deploymentId
   */
  async verifyPatchDeployment(deploymentId) {
    return this.request(`/api/v1/patching/deployments/${encodeURIComponent(deploymentId)}/verify`, {
      method: 'POST',
    });
  }

  // -------------------------------------------------- vulnerabilities (Phase 3)

  /**
   * Scan engines in the current org. Engine passwords are never returned
   * (`has_password` only). Requires `vulnerabilities:read`.
   * @returns {Promise<Array<object>>}
   */
  async listVulnEngines() {
    return this.request('/api/v1/vulnerabilities/engines');
  }

  /**
   * Create a scan engine (`greenbone` or `manual`). Requires
   * `vulnerabilities:manage`.
   * @param {{ name: string, engine_type: string, host?: string, port?: number, username?: string, password?: string }} engine
   * @returns {Promise<object>} (201).
   */
  async createVulnEngine(engine) {
    return this.request('/api/v1/vulnerabilities/engines', {
      method: 'POST',
      body: engine,
    });
  }

  /**
   * Delete a scan engine (deleting the default promotes the oldest
   * remaining engine). Requires `vulnerabilities:manage`.
   * @param {string} engineId
   */
  async deleteVulnEngine(engineId) {
    return this.request(`/api/v1/vulnerabilities/engines/${encodeURIComponent(engineId)}`, {
      method: 'DELETE',
    });
  }

  /**
   * Set the default scan engine. Requires `vulnerabilities:manage`.
   * @param {string} engineId
   */
  async setDefaultVulnEngine(engineId) {
    return this.request(`/api/v1/vulnerabilities/engines/${encodeURIComponent(engineId)}/set-default`, {
      method: 'POST',
    });
  }

  /**
   * CVE catalog (global public data). Filter with `?kev=true` or
   * `?severity=critical`. Requires `vulnerabilities:read`.
   * @param {{ kev?: boolean, severity?: string }} [filters={}]
   * @returns {Promise<Array<object>>}
   */
  async listCves({ kev, severity } = {}) {
    const params = new URLSearchParams();
    if (kev !== undefined) params.set('kev', String(kev));
    if (severity) params.set('severity', severity);
    const q = params.toString();
    return this.request(`/api/v1/vulnerabilities/cves${q ? `?${q}` : ''}`);
  }

  /**
   * Derived vulnerability summary (counts only, never invented rows).
   * Requires `vulnerabilities:read`.
   * @returns {Promise<object>} `{by_severity, by_status, open_kev, total_open}`.
   */
  async getVulnSummary() {
    return this.request('/api/v1/vulnerabilities/summary');
  }

  /**
   * Vulnerability findings in the current org. Requires
   * `vulnerabilities:read`.
   * @returns {Promise<Array<object>>}
   */
  async listVulnFindings() {
    return this.request('/api/v1/vulnerabilities/findings');
  }

  /**
   * One finding by id. Requires `vulnerabilities:read`.
   * @param {string} findingId
   */
  async getVulnFinding(findingId) {
    return this.request(`/api/v1/vulnerabilities/findings/${encodeURIComponent(findingId)}`);
  }

  /**
   * Update a finding (status transitions; setting `remediated` directly
   * is refused — use remediate → verify). Requires
   * `vulnerabilities:manage`.
   * @param {string} findingId
   * @param {object} patch
   */
  async updateVulnFinding(findingId, patch) {
    return this.request(`/api/v1/vulnerabilities/findings/${encodeURIComponent(findingId)}`, {
      method: 'PATCH',
      body: patch,
    });
  }

  /**
   * Remediate a finding: creates a real ticket + remediation link, finding
   * → `in_progress`. Requires `vulnerabilities:remediate`.
   * @param {string} findingId
   * @returns {Promise<object>} (201).
   */
  async remediateVulnFinding(findingId) {
    return this.request(`/api/v1/vulnerabilities/findings/${encodeURIComponent(findingId)}/remediate`, {
      method: 'POST',
      body: {},
    });
  }

  /**
   * Start verification of a remediated finding. Issues an agent
   * `vuln_scan` job when the endpoint is enrolled, otherwise queues a
   * verification scan. Requires `vulnerabilities:manage`.
   * @param {string} findingId
   * @returns {Promise<object>} `{finding, job_id?, scan_id?}`.
   */
  async verifyVulnFinding(findingId) {
    return this.request(`/api/v1/vulnerabilities/findings/${encodeURIComponent(findingId)}/verify`, {
      method: 'POST',
    });
  }

  /**
   * Vulnerability scans in the current org. Requires `vulnerabilities:read`.
   * @returns {Promise<Array<object>>}
   */
  async listVulnScans() {
    return this.request('/api/v1/vulnerabilities/scans');
  }

  /**
   * Import scan results into a manual-engine scan (or a queued
   * verification scan). Requires `vulnerabilities:manage`.
   * @param {string} scanId
   * @param {Array<object>} results
   * @returns {Promise<object>} `{scan_id, status, results_applied, findings_created, findings_updated, verified}`.
   */
  async importVulnScanResults(scanId, results) {
    return this.request(`/api/v1/vulnerabilities/scans/${encodeURIComponent(scanId)}/import-results`, {
      method: 'POST',
      body: { results },
    });
  }

  // ------------------------------------------------------------ CMDB (Phase 3)

  /**
   * Configuration items in the current org. Requires `cmdb:read`.
   * @returns {Promise<Array<object>>}
   */
  async listCmdbItems() {
    return this.request('/api/v1/cmdb/items');
  }

  /**
   * Create a configuration item. Requires `cmdb:manage`.
   * @param {{ name: string, ci_type: string, status?: string, asset_id?: string, endpoint_id?: string }} item
   * @returns {Promise<object>} (201).
   */
  async createCmdbItem(item) {
    return this.request('/api/v1/cmdb/items', {
      method: 'POST',
      body: item,
    });
  }

  /**
   * One CI with its relationships. Requires `cmdb:read`.
   * @param {string} ciId
   */
  async getCmdbItem(ciId) {
    return this.request(`/api/v1/cmdb/items/${encodeURIComponent(ciId)}`);
  }

  /**
   * Depth-2 dependency graph for a CI. Requires `cmdb:read`.
   * @param {string} ciId
   */
  async getCmdbGraph(ciId) {
    return this.request(`/api/v1/cmdb/items/${encodeURIComponent(ciId)}/graph`);
  }

  /**
   * Add a relationship between CIs (no self-links). Requires `cmdb:manage`.
   * @param {string} ciId
   * @param {{ target_ci_id: string, relationship_type: string }} relationship
   * @returns {Promise<object>} (201).
   */
  async createCmdbRelationship(ciId, relationship) {
    return this.request(`/api/v1/cmdb/items/${encodeURIComponent(ciId)}/relationships`, {
      method: 'POST',
      body: relationship,
    });
  }

  // ---------------------------------------------------------- network (Phase 3)

  /**
   * Network devices in the current org. Requires `network:read`.
   * @returns {Promise<Array<object>>}
   */
  async listNetworkDevices() {
    return this.request('/api/v1/network/devices');
  }

  /**
   * Create a network device. Requires `network:manage`.
   * @param {{ hostname: string, ip_address?: string, device_type?: string }} device
   * @returns {Promise<object>} (201).
   */
  async createNetworkDevice(device) {
    return this.request('/api/v1/network/devices', {
      method: 'POST',
      body: device,
    });
  }

  /**
   * Topology (devices + links) for the map. Requires `network:read`.
   * @returns {Promise<object>}
   */
  async getNetworkTopology() {
    return this.request('/api/v1/network/topology');
  }

  /**
   * Service dependencies. Requires `network:read`.
   * @returns {Promise<Array<object>>}
   */
  async listServiceDependencies() {
    return this.request('/api/v1/network/service-dependencies');
  }

  /**
   * Derived health for a device (from latest metrics + events, never
   * stored). Requires `network:read`.
   * @param {string} deviceId
   */
  async getNetworkDeviceHealth(deviceId) {
    return this.request(`/api/v1/network/devices/${encodeURIComponent(deviceId)}/health`);
  }

  /**
   * Run real discovery (ping sweep, bounded CIDR; SNMP only when
   * `pysnmp` is installed). Requires `network:discover`.
   * @param {string} cidr
   * @returns {Promise<object>} `{discovered, updated, unreachable, snmp_available, probe_method}`.
   */
  async discoverNetwork(cidr) {
    return this.request('/api/v1/network/discover', {
      method: 'POST',
      body: { cidr },
    });
  }

  /**
   * Network events (outages, thresholds). Requires `network:read`.
   * @returns {Promise<Array<object>>}
   */
  async listNetworkEvents() {
    return this.request('/api/v1/network/events');
  }

  /**
   * Acknowledge a network event. Requires `network:manage`.
   * @param {string} eventId
   */
  async acknowledgeNetworkEvent(eventId) {
    return this.request(`/api/v1/network/events/${encodeURIComponent(eventId)}/acknowledge`, {
      method: 'POST',
    });
  }

  /**
   * Certificates expiring within `days` (expiry derived from `not_after`).
   * Requires `network:read`.
   * @param {number} [days=30]
   * @returns {Promise<Array<object>>}
   */
  async listExpiringCertificates(days = 30) {
    return this.request(`/api/v1/network/certificates/expiring?days=${days}`);
  }

  // ----------------------------------------------------------------- health

  /**
   * Liveness probe — no auth, no dependencies. `{status: 'ok', service: 'null-itsm-api'}`.
   * @returns {Promise<object>}
   */
  async health() {
    return this.request('/health', { auth: false });
  }

  /**
   * Readiness probe — checks database + Redis. No auth. Always answers
   * HTTP 200; inspect `status` (`ok` vs `degraded`) and the per-check map.
   * @returns {Promise<object>} `{status, checks: {database, redis}}`.
   */
  async readiness() {
    return this.request('/health/ready', { auth: false });
  }
}
