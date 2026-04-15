export interface Env {
  GH_TOKEN: string;
  /** Turnstile secret for /ticket. Required unless ALLOW_TICKET_WITHOUT_TURNSTILE=true (local dev only). */
  TURNSTILE_SECRET_KEY?: string;
  /** When "true", /ticket may run without TURNSTILE_SECRET_KEY. Never enable in production. */
  ALLOW_TICKET_WITHOUT_TURNSTILE?: string;
  /** Optional expected Turnstile action for /ticket (default: "community_upload_ticket"). */
  TURNSTILE_EXPECTED_ACTION?: string;
  /** Set in wrangler.toml [vars] (or dashboard); must match the client’s community repo settings. */
  REPO_OWNER?: string;
  REPO_NAME?: string;
  BASE_BRANCH?: string;
  /** Optional: bind a KV namespace for per-IP daily caps */
  LIMIT_KV?: KVNamespace;
  /** Max successful uploads per IP per UTC day (default 20). Only if LIMIT_KV is bound. */
  DAILY_UPLOAD_LIMIT?: string;
  /** Max ticket issues per IP per UTC day (default 60). Only if LIMIT_KV is bound. */
  DAILY_TICKET_ISSUE_LIMIT?: string;
  /** Lifetime for one-time upload tickets in seconds (default 90). */
  UPLOAD_TICKET_TTL_SECONDS?: string;
}

interface SubmissionFile {
  relativePath: string;
  contentBase64: string;
}

interface Payload {
  schemaVersion: number;
  repoOwner: string;
  repoName: string;
  baseBranch: string;
  catalogFolder: string;
  gameFolderSegment: string;
  authorSegment: string;
  listingDescription: string;
  profileIds: string[];
  files: SubmissionFile[];
}

interface TicketRequestBody {
  payloadSha256: string;
  submitPath: string;
  turnstileToken?: string;
}

interface TicketRecord {
  payloadSha256: string;
  submitPath: string;
  ticketProof: string;
  expiresAtUnixSeconds: number;
}

const GITHUB_API = "https://api.github.com/";
const GITHUB_API_VERSION = "2022-11-28";
const SUBMIT_ENDPOINT_PATH = "/submit";
const TICKET_ENDPOINT_PATH = "/ticket";
/** GET: HTML shell for WebView2; hostname must be allowed in Turnstile (same as this Worker). */
const TURNSTILE_EMBED_PATH = "/turnstile-embed";
const MAX_FILES = 8;
const MAX_DECODED_BYTES_PER_FILE = 1 * 1024 * 1024;
const DEFAULT_DAILY_TICKET_ISSUE_LIMIT = 60;
const DEFAULT_TURNSTILE_ACTION = "community_upload_ticket";
const HEADER_TICKET_ID = "X-Community-Ticket-Id";
const HEADER_TICKET_PROOF = "X-Community-Ticket-Proof";
const TICKET_ID_TTL_BUFFER_SECONDS = 60;
const DEFAULT_UPLOAD_TICKET_TTL_SECONDS = 90;
const MAX_UPLOAD_TICKET_TTL_SECONDS = 300;

type ErrorPhase =
  | "misconfigured"
  | "unauthorized"
  | "rate_limited"
  | "pipeline_busy"
  | "method_not_allowed"
  | "invalid_json"
  | "validate"
  | "github_resolve_branch"
  | "github_create_branch"
  | "github_upload_file"
  | "github_create_pr"
  | "internal";

class WorkerResponseError extends Error {
  constructor(
    readonly httpStatus: number,
    readonly phase: ErrorPhase,
    message: string,
    readonly detail?: string,
    readonly github?: { status: number; message?: string; errors?: unknown },
    readonly code?: string
  ) {
    super(message);
    this.name = "WorkerResponseError";
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const requestUrl = new URL(request.url);
    const path = normalizeApiPath(requestUrl.pathname);
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const requestId = crypto.randomUUID();
    if (path === TURNSTILE_EMBED_PATH && request.method === "GET") {
      return turnstileEmbedHtmlResponse(request);
    }

    if (request.method !== "POST") {
      return jsonResponse(405, { success: false, error: "Method not allowed", phase: "method_not_allowed" }, request, requestId);
    }

    if (path !== SUBMIT_ENDPOINT_PATH && path !== TICKET_ENDPOINT_PATH) {
      return jsonResponse(404, { success: false, error: "Unknown endpoint", phase: "validate" }, request, requestId);
    }

    try {
      if (path === TICKET_ENDPOINT_PATH) {
        const ticketResult = await issueOneTimeTicket(request, env);
        if ("error" in ticketResult) {
          return jsonResponse(400, { success: false, error: ticketResult.error, phase: "validate" }, request, requestId);
        }

        return jsonResponse(
          200,
          {
            success: true,
            ticketId: ticketResult.ticketId,
            ticketProof: ticketResult.ticketProof,
            expiresAtUnixSeconds: ticketResult.expiresAtUnixSeconds,
          },
          request,
          requestId
        );
      }

      const token = (env.GH_TOKEN ?? "").trim();
      if (!token) {
        return jsonResponse(
          500,
          { success: false, error: "Server misconfigured (GH_TOKEN)", phase: "misconfigured" },
          request,
          requestId
        );
      }

      const owner = (env.REPO_OWNER ?? "").trim();
      const repo = (env.REPO_NAME ?? "").trim();
      const baseBranch = (env.BASE_BRANCH ?? "").trim();
      if (!owner || !repo || !baseBranch) {
        return jsonResponse(
          500,
          {
            success: false,
            error: "Server misconfigured (REPO_OWNER / REPO_NAME / BASE_BRANCH)",
            phase: "misconfigured",
          },
          request,
          requestId
        );
      }

      if (env.LIMIT_KV) {
        const limit = Math.max(1, parseInt(env.DAILY_UPLOAD_LIMIT ?? "20", 10) || 20);
        const kvKey = buildDailyIpKey("upload", request);
        const raw = await env.LIMIT_KV.get(kvKey);
        const count = parseInt(raw ?? "0", 10) || 0;
        if (count >= limit) {
          return jsonResponse(
            429,
            {
              success: false,
              error: `Daily upload limit reached (${limit}/day)`,
              phase: "rate_limited",
            },
            request,
            requestId
          );
        }
      }

      const rawBody = await request.text();
      const payloadSha256 = await sha256Hex(rawBody);

      let body: Payload;
      try {
        body = JSON.parse(rawBody) as Payload;
      } catch {
        return jsonResponse(400, { success: false, error: "Invalid JSON body", phase: "invalid_json" }, request, requestId);
      }

      try {
        const consumeError = await validateAndConsumeTicket(request, env, payloadSha256);
        if (consumeError) {
          return jsonResponse(401, { success: false, error: consumeError, phase: "unauthorized" }, request, requestId);
        }

        validatePayloadAgainstPinnedRepo(body, owner, repo, baseBranch);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return jsonResponse(400, { success: false, error: msg, phase: "validate" }, request, requestId);
      }

      let prUrl: string;
      try {
        await ensurePipelineIsIdle(token, owner, repo, baseBranch);
        prUrl = await submitPullRequest(token, body, owner, repo, baseBranch);
      } catch (e) {
        if (e instanceof WorkerResponseError) {
          return jsonResponse(
            e.httpStatus,
            {
              success: false,
              error: e.message,
              phase: e.phase,
              ...(e.detail ? { detail: e.detail } : {}),
              ...(e.code ? { code: e.code } : {}),
              ...(e.github ? { github: e.github } : {}),
            },
            request,
            requestId
          );
        }
        throw e;
      }

      if (env.LIMIT_KV) {
        const kvKey = buildDailyIpKey("upload", request);
        const raw = await env.LIMIT_KV.get(kvKey);
        const count = parseInt(raw ?? "0", 10) || 0;
        await env.LIMIT_KV.put(kvKey, String(count + 1), { expirationTtl: 172800 });
      }

      return jsonResponse(200, { success: true, pullRequestHtmlUrl: prUrl }, request, requestId);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("community-upload:", requestId, msg);
      return jsonResponse(
        500,
        { success: false, error: "Unexpected server error", phase: "internal" },
        request,
        requestId
      );
    }
  },
};

function corsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("Origin");
  if (!origin) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": ["Content-Type", HEADER_TICKET_ID, HEADER_TICKET_PROOF].join(", "),
    "Access-Control-Max-Age": "86400",
  };
}

function turnstileEmbedHtmlResponse(request: Request): Response {
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Verification</title>
  <style>
    body { font-family: Segoe UI, sans-serif; margin: 0; padding: 24px; background: #0f1115; color: #e8ecf1; }
    .card { max-width: 420px; margin: 0 auto; padding: 18px; border-radius: 12px; background: #1a1f27; }
    h1 { font-size: 18px; margin: 0 0 12px 0; }
    p { margin: 0 0 16px 0; color: #b7c0cc; }
  </style>
  <script>
    function onTurnstileLoad() {
      var params = new URLSearchParams(window.location.search);
      var sitekey = params.get("siteKey") || "";
      var action = params.get("action") || "${DEFAULT_TURNSTILE_ACTION}";
      if (!sitekey) {
        document.getElementById("turnstile-widget").textContent = "Missing siteKey query parameter.";
        return;
      }
      turnstile.render("#turnstile-widget", {
        sitekey: sitekey,
        action: action,
        callback: function (token) {
          window.location.href =
            "gamepadmapping-turnstile://done?token=" + encodeURIComponent(token || "");
        },
      });
    }
  </script>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileLoad" async defer></script>
</head>
<body>
  <div class="card">
    <h1>Security Verification</h1>
    <p>Please complete the challenge to continue uploading to the community.</p>
    <div id="turnstile-widget"></div>
  </div>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      ...corsHeaders(request),
    },
  });
}

async function issueOneTimeTicket(
  request: Request,
  env: Env
): Promise<
  | {
      ticketId: string;
      ticketProof: string;
      expiresAtUnixSeconds: number;
    }
  | { error: string }
> {
  if (!env.LIMIT_KV) {
    return { error: "Server misconfigured (LIMIT_KV is required for one-time tickets)" };
  }

  let body: TicketRequestBody;
  try {
    body = (await request.clone().json()) as TicketRequestBody;
  } catch {
    return { error: "Invalid ticket request JSON body" };
  }

  const requesterIp = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const turnstileError = await verifyTurnstileIfConfigured(env, requesterIp, body.turnstileToken);
  if (turnstileError) {
    return { error: turnstileError };
  }

  const issueLimitError = await enforceTicketIssueRateLimit(request, env);
  if (issueLimitError) {
    return { error: issueLimitError };
  }

  const payloadSha256 = (body.payloadSha256 ?? "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(payloadSha256)) {
    return { error: "payloadSha256 must be a 64-character SHA-256 hex string" };
  }

  const submitPath = normalizeSubmitPath(body.submitPath);
  if (!submitPath) {
    return { error: "submitPath must be an absolute path beginning with '/'" };
  }
  if (submitPath !== SUBMIT_ENDPOINT_PATH) {
    return { error: `submitPath must equal '${SUBMIT_ENDPOINT_PATH}'` };
  }

  const ticketTtl = Math.min(
    MAX_UPLOAD_TICKET_TTL_SECONDS,
    Math.max(30, Number.parseInt(env.UPLOAD_TICKET_TTL_SECONDS ?? `${DEFAULT_UPLOAD_TICKET_TTL_SECONDS}`, 10) || DEFAULT_UPLOAD_TICKET_TTL_SECONDS)
  );
  const nowSeconds = Math.floor(Date.now() / 1000);
  const expiresAtUnixSeconds = nowSeconds + ticketTtl;
  const ticketId = crypto.randomUUID().replace(/-/g, "");
  const ticketProof = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");

  const ticketRecord: TicketRecord = {
    payloadSha256,
    submitPath,
    ticketProof,
    expiresAtUnixSeconds,
  };
  const ttl = ticketTtl + TICKET_ID_TTL_BUFFER_SECONDS;
  await env.LIMIT_KV.put(`ticket:${ticketId}`, JSON.stringify(ticketRecord), { expirationTtl: ttl });
  await incrementTicketIssueCounter(request, env);
  return { ticketId, ticketProof, expiresAtUnixSeconds };
}

async function verifyTurnstileIfConfigured(
  env: Env,
  requesterIp: string,
  turnstileToken: string | undefined
): Promise<string | null> {
  const secret = (env.TURNSTILE_SECRET_KEY ?? "").trim();
  if (!secret) {
    const allowDev = (env.ALLOW_TICKET_WITHOUT_TURNSTILE ?? "").trim().toLowerCase() === "true";
    if (!allowDev) {
      return "Turnstile is not configured (set TURNSTILE_SECRET_KEY, or ALLOW_TICKET_WITHOUT_TURNSTILE=true for local dev only)";
    }
    return null;
  }

  const token = (turnstileToken ?? "").trim();
  if (!token) {
    return "Missing turnstileToken";
  }

  const form = new URLSearchParams();
  form.set("secret", secret);
  form.set("response", token);
  if (requesterIp && requesterIp !== "unknown") {
    form.set("remoteip", requesterIp);
  }

  let verification: TurnstileSiteVerifyResponse;
  try {
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: form,
    });
    verification = (await response.json()) as TurnstileSiteVerifyResponse;
  } catch {
    return "Could not verify Turnstile token";
  }

  if (!verification.success) {
    return "Turnstile verification failed";
  }

  const expectedAction = (env.TURNSTILE_EXPECTED_ACTION ?? DEFAULT_TURNSTILE_ACTION).trim();
  if (expectedAction.length > 0) {
    const actualAction = (verification.action ?? "").trim();
    if (actualAction !== expectedAction) {
      return "Turnstile action mismatch";
    }
  }

  return null;
}

async function enforceTicketIssueRateLimit(request: Request, env: Env): Promise<string | null> {
  if (!env.LIMIT_KV) {
    return null;
  }

  const limit = Math.max(1, Number.parseInt(env.DAILY_TICKET_ISSUE_LIMIT ?? `${DEFAULT_DAILY_TICKET_ISSUE_LIMIT}`, 10) || DEFAULT_DAILY_TICKET_ISSUE_LIMIT);
  const key = buildDailyIpKey("ticket-issue", request);
  const raw = await env.LIMIT_KV.get(key);
  const count = Number.parseInt(raw ?? "0", 10) || 0;
  if (count >= limit) {
    return `Daily ticket issuance limit reached (${limit}/day)`;
  }

  return null;
}

async function incrementTicketIssueCounter(request: Request, env: Env): Promise<void> {
  if (!env.LIMIT_KV) {
    return;
  }

  const key = buildDailyIpKey("ticket-issue", request);
  const raw = await env.LIMIT_KV.get(key);
  const count = Number.parseInt(raw ?? "0", 10) || 0;
  await env.LIMIT_KV.put(key, String(count + 1), { expirationTtl: 172800 });
}

function buildDailyIpKey(prefix: string, request: Request): string {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const now = new Date();
  const day = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}-${String(now.getUTCDate()).padStart(2, "0")}`;
  return `${prefix}:${day}:${ip}`;
}

interface TurnstileSiteVerifyResponse {
  success: boolean;
  action?: string;
}

async function validateAndConsumeTicket(
  request: Request,
  env: Env,
  contentSha256: string
): Promise<string | null> {
  if (!env.LIMIT_KV) {
    return "Server misconfigured (LIMIT_KV is required for one-time tickets)";
  }

  const ticketId = (request.headers.get(HEADER_TICKET_ID) ?? "").trim();
  const ticketProof = (request.headers.get(HEADER_TICKET_PROOF) ?? "").trim();
  if (!ticketId || !ticketProof) {
    return "Missing one-time upload ticket headers";
  }

  const ticketKey = `ticket:${ticketId}`;
  const ticketRaw = await env.LIMIT_KV.get(ticketKey);
  if (!ticketRaw) {
    return "Upload ticket is invalid or expired";
  }

  let ticket: TicketRecord;
  try {
    ticket = JSON.parse(ticketRaw) as TicketRecord;
  } catch {
    return "Upload ticket payload is invalid";
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (ticket.expiresAtUnixSeconds <= nowSeconds) {
    await env.LIMIT_KV.delete(ticketKey);
    return "Upload ticket has expired";
  }

  const requestPath = `${new URL(request.url).pathname}${new URL(request.url).search}`;
  if (!timingSafeEqual(ticket.payloadSha256, contentSha256)) {
    return "Upload ticket payload mismatch";
  }
  if (requestPath !== ticket.submitPath) {
    return "Upload ticket endpoint mismatch";
  }

  if (!timingSafeEqual(ticketProof, ticket.ticketProof)) {
    return "Upload ticket proof mismatch";
  }

  await env.LIMIT_KV.delete(ticketKey);
  return null;
}

function normalizeSubmitPath(raw: string | undefined): string {
  const s = (raw ?? "").trim();
  if (!s.startsWith("/")) return "";
  if (s.includes("://")) return "";
  return normalizeApiPath(s);
}

function normalizeApiPath(pathname: string): string {
  if (!pathname) return "/";
  if (pathname.length > 1 && pathname.endsWith("/")) {
    return pathname.slice(0, -1);
  }
  return pathname;
}

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function jsonResponse(status: number, obj: Record<string, unknown>, request: Request, requestId: string): Response {
  const body = { requestId, ...obj };
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Request-Id": requestId,
      ...corsHeaders(request),
    },
  });
}

function parseGithubErrorPayload(text: string): { message?: string; errors?: unknown } {
  const trimmed = text.trim();
  if (!trimmed) return {};
  try {
    const o = JSON.parse(trimmed) as { message?: string; errors?: unknown };
    return { message: o.message, errors: o.errors };
  } catch {
    return { message: trimmed.length > 800 ? trimmed.slice(0, 800) + "…" : trimmed };
  }
}

function lc(s: string): string {
  return s.trim().toLowerCase();
}

function validatePayloadAgainstPinnedRepo(body: Payload, owner: string, repo: string, baseBranch: string): void {
  if (body.schemaVersion !== 1) throw new Error("Unsupported schemaVersion");
  if (lc(body.repoOwner) !== lc(owner) || lc(body.repoName) !== lc(repo) || lc(body.baseBranch) !== lc(baseBranch)) {
    throw new Error("Repository target does not match worker configuration");
  }

  const gameSeg = validateSingleSegment(body.gameFolderSegment);
  const authorSeg = validateSingleSegment(body.authorSegment);
  if (!gameSeg || !authorSeg) throw new Error("gameFolderSegment and authorSegment are required");

  const catalogExpected = normalizeCatalogFolder(`${gameSeg}/${authorSeg}`);
  const catalogFolder = normalizeCatalogFolder(body.catalogFolder ?? "");
  if (catalogFolder !== catalogExpected) throw new Error("catalogFolder does not match game and author segments");

  const desc = (body.listingDescription ?? "").trim();
  if (!desc) throw new Error("listingDescription is required");

  const files = body.files ?? [];
  if (files.length === 0) throw new Error("files is required");
  if (files.length > MAX_FILES) throw new Error(`Too many files (max ${MAX_FILES})`);

  const prefix = catalogFolder + "/";
  const seenRelative = new Set<string>();
  for (const f of files) {
    const rel = normalizeRelativePath(f.relativePath);
    if (seenRelative.has(rel)) throw new Error(`Duplicate relativePath: ${f.relativePath}`);
    seenRelative.add(rel);
    if (!rel.startsWith(prefix)) throw new Error(`Invalid relativePath: ${f.relativePath}`);
    if (!rel.toLowerCase().endsWith(".json")) {
      throw new Error(`Only .json files are allowed: ${f.relativePath}`);
    }
    if (!f.contentBase64 || typeof f.contentBase64 !== "string") throw new Error("Each file needs contentBase64");
    let bytes: Uint8Array;
    try {
      bytes = base64ToBytes(f.contentBase64);
    } catch {
      throw new Error(`Invalid Base64 for ${f.relativePath}`);
    }
    if (bytes.byteLength > MAX_DECODED_BYTES_PER_FILE) {
      throw new Error(`File too large: ${f.relativePath}`);
    }
  }
}

function validateSingleSegment(raw: string | undefined): string {
  const s = (raw ?? "").trim();
  if (!s) return "";
  if (s.includes("/") || s.includes("\\")) throw new Error("Folder segment must not contain path separators");
  if (s === "." || s === "..") throw new Error("Invalid folder segment");
  return s;
}

function normalizeCatalogFolder(raw: string): string {
  const parts = raw
    .replace(/\\/g, "/")
    .split("/")
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  return parts.join("/");
}

function normalizeRelativePath(raw: string): string {
  return normalizeCatalogFolder(raw);
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.replace(/\s/g, ""));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function escapeGithubContentPath(relativePath: string): string {
  const n = relativePath.replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
  return n.split("/").filter(Boolean).map((p) => encodeURIComponent(p)).join("/");
}

async function gh(
  token: string,
  method: string,
  path: string,
  jsonBody?: Record<string, unknown>
): Promise<Response> {
  const init: RequestInit = {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": GITHUB_API_VERSION,
      "User-Agent": "GamepadMapping-CommunityUpload-Worker/1.1",
    },
  };
  if (jsonBody !== undefined) {
    (init.headers as Record<string, string>)["Content-Type"] = "application/json";
    init.body = JSON.stringify(jsonBody);
  }
  return fetch(GITHUB_API + path, init);
}

async function submitPullRequest(
  token: string,
  body: Payload,
  owner: string,
  repo: string,
  baseBranch: string
): Promise<string> {
  const catalogFolder = normalizeCatalogFolder(body.catalogFolder);
  const gameSeg = validateSingleSegment(body.gameFolderSegment);
  const authorSeg = validateSingleSegment(body.authorSegment);
  const desc = body.listingDescription.trim();

  const baseSha = await getBranchHeadSha(token, owner, repo, baseBranch);
  const branchName = `community/upload-${new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14)}-${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
  const safeBranch = branchName.length > 120 ? branchName.slice(0, 120) : branchName;

  await createBranch(token, owner, repo, safeBranch, baseSha);

  for (const f of body.files) {
    const rel = normalizeRelativePath(f.relativePath);
    const escaped = escapeGithubContentPath(rel);
    const bytes = base64ToBytes(f.contentBase64);
    const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
    await putRepositoryFile(token, owner, repo, escaped, safeBranch, utf8);
  }

  const profileIds = body.profileIds?.length ? body.profileIds : body.files.map((f) => f.relativePath);
  const prBody = buildPrBody(catalogFolder, profileIds, desc);
  const title = `Community templates: ${gameSeg} (${authorSeg})`;
  return await createPullRequest(token, owner, repo, safeBranch, baseBranch, title, prBody);
}

async function ensurePipelineIsIdle(token: string, owner: string, repo: string, baseBranch: string): Promise<void> {
  const runs = await listActiveWorkflowRuns(token, owner, repo, baseBranch, "in_progress");
  if (runs.length > 0) {
    throw new WorkerResponseError(
      409,
      "pipeline_busy",
      "Repository CI is currently processing another run. Please retry later.",
      formatBusyPipelineDetail(runs),
      undefined,
      "pipeline_busy"
    );
  }

  const queuedRuns = await listActiveWorkflowRuns(token, owner, repo, baseBranch, "queued");
  if (queuedRuns.length > 0) {
    throw new WorkerResponseError(
      409,
      "pipeline_busy",
      "Repository CI queue is currently busy. Please retry later.",
      formatBusyPipelineDetail(queuedRuns),
      undefined,
      "pipeline_busy"
    );
  }
}

interface WorkflowRunSummary {
  id?: number;
  name?: string;
  status?: string;
  html_url?: string;
}

async function listActiveWorkflowRuns(
  token: string,
  owner: string,
  repo: string,
  baseBranch: string,
  status: "queued" | "in_progress"
): Promise<WorkflowRunSummary[]> {
  const path =
    `repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/actions/runs`
    + `?branch=${encodeURIComponent(baseBranch)}`
    + `&status=${encodeURIComponent(status)}`
    + "&per_page=10";
  const res = await gh(token, "GET", path);
  const text = await res.text();
  if (!res.ok) {
    const ge = parseGithubErrorPayload(text);
    throw new WorkerResponseError(
      502,
      "pipeline_busy",
      `Could not check CI status (GitHub HTTP ${res.status}).`,
      ge.message,
      { status: res.status, message: ge.message, errors: ge.errors },
      "pipeline_status_check_failed"
    );
  }

  const data = JSON.parse(text) as { workflow_runs?: WorkflowRunSummary[] };
  return data.workflow_runs ?? [];
}

function formatBusyPipelineDetail(runs: WorkflowRunSummary[]): string {
  const first = runs[0];
  if (!first) return "A workflow run is active.";
  const id = typeof first.id === "number" ? `#${first.id}` : "(unknown id)";
  const name = (first.name ?? "workflow").trim();
  const status = (first.status ?? "unknown").trim();
  const url = (first.html_url ?? "").trim();
  return url.length > 0
    ? `Active run: ${name} ${id} [${status}] ${url}`
    : `Active run: ${name} ${id} [${status}]`;
}

async function getBranchHeadSha(token: string, owner: string, repo: string, branch: string): Promise<string> {
  const path = `repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/ref/heads/${encodeURIComponent(branch)}`;
  const res = await gh(token, "GET", path);
  const text = await res.text();
  if (!res.ok) {
    const ge = parseGithubErrorPayload(text);
    throw new WorkerResponseError(
      502,
      "github_resolve_branch",
      `Could not resolve base branch "${branch}" (GitHub HTTP ${res.status}).`,
      ge.message,
      { status: res.status, message: ge.message, errors: ge.errors }
    );
  }
  const data = JSON.parse(text) as { object?: { sha?: string } };
  const sha = data.object?.sha;
  if (!sha) {
    throw new WorkerResponseError(502, "github_resolve_branch", "GitHub response did not include a branch SHA.", text.slice(0, 400));
  }
  return sha;
}

async function createBranch(token: string, owner: string, repo: string, newBranch: string, baseSha: string): Promise<void> {
  const path = `repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/refs`;
  const res = await gh(token, "POST", path, {
    ref: `refs/heads/${newBranch}`,
    sha: baseSha,
  });
  const text = await res.text();
  if (!res.ok) {
    const ge = parseGithubErrorPayload(text);
    throw new WorkerResponseError(
      502,
      "github_create_branch",
      `Could not create upload branch (GitHub HTTP ${res.status}).`,
      ge.message,
      { status: res.status, message: ge.message, errors: ge.errors }
    );
  }
}

async function tryGetBlobSha(
  token: string,
  owner: string,
  repo: string,
  escapedPath: string,
  branch: string
): Promise<string | null> {
  const path = `repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${escapedPath}?ref=${encodeURIComponent(branch)}`;
  const res = await gh(token, "GET", path);
  if (res.status === 404) return null;
  const text = await res.text();
  if (!res.ok) return null;
  const data = JSON.parse(text) as { sha?: string };
  return data.sha ?? null;
}

async function putRepositoryFile(
  token: string,
  owner: string,
  repo: string,
  escapedPath: string,
  branch: string,
  json: string
): Promise<void> {
  const path = `repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${escapedPath}`;
  const existingSha = await tryGetBlobSha(token, owner, repo, escapedPath, branch);
  const payload: Record<string, string> = {
    message: existingSha
      ? `feat(community): update ${escapedPath.replace(/%2F/g, "/")}`
      : `feat(community): add ${escapedPath.replace(/%2F/g, "/")}`,
    content: btoa(unescape(encodeURIComponent(json))),
    branch,
  };
  if (existingSha) payload.sha = existingSha;

  const res = await gh(token, "PUT", path, payload);
  const text = await res.text();
  if (!res.ok) {
    const ge = parseGithubErrorPayload(text);
    const displayPath = escapedPath.replace(/%2F/g, "/");
    throw new WorkerResponseError(
      502,
      "github_upload_file",
      `Could not write template file to the submission branch (GitHub HTTP ${res.status}).`,
      `File: ${displayPath}${ge.message ? ` — ${ge.message}` : ""}`,
      { status: res.status, message: ge.message, errors: ge.errors }
    );
  }
}

async function createPullRequest(
  token: string,
  owner: string,
  repo: string,
  headBranch: string,
  baseBranch: string,
  title: string,
  prBody: string
): Promise<string> {
  const path = `repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls`;
  const res = await gh(token, "POST", path, {
    title,
    body: prBody,
    head: headBranch,
    base: baseBranch,
  });
  const text = await res.text();
  if (!res.ok) {
    const ge = parseGithubErrorPayload(text);
    throw new WorkerResponseError(
      502,
      "github_create_pr",
      `Could not open the pull request (GitHub HTTP ${res.status}).`,
      ge.message,
      { status: res.status, message: ge.message, errors: ge.errors }
    );
  }
  const data = JSON.parse(text) as { html_url?: string };
  if (!data.html_url) {
    throw new WorkerResponseError(502, "github_create_pr", "GitHub did not return a pull request URL.", text.slice(0, 400));
  }
  return data.html_url;
}

function buildPrBody(catalogFolder: string, profileIds: string[], listingDescription: string): string {
  const lines: string[] = [];
  lines.push("Automated community template submission from Gamepad Mapping.");
  lines.push("");
  lines.push(`**Catalog folder:** \`${catalogFolder}\``);
  lines.push("");
  lines.push("**Templates:**");
  for (const id of profileIds) lines.push(`- \`${id}\``);
  lines.push("");
  lines.push("**Listing description:**");
  lines.push(listingDescription);
  lines.push("");
  lines.push("After merge, the index workflow should refresh `index.json`.");
  return lines.join("\n");
}