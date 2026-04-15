export interface Env {
  GH_TOKEN: string;
  /** Required for public workers: clients must send Authorization: Bearer <UPLOAD_API_KEY> */
  UPLOAD_API_KEY?: string;
  /** Defaults below if unset */
  REPO_OWNER?: string;
  REPO_NAME?: string;
  BASE_BRANCH?: string;
  /** Optional: bind a KV namespace for per-IP daily caps */
  LIMIT_KV?: KVNamespace;
  /** Max successful uploads per IP per UTC day (default 20). Only if LIMIT_KV is bound. */
  DAILY_UPLOAD_LIMIT?: string;
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

const GITHUB_API = "https://api.github.com/";
const GITHUB_API_VERSION = "2022-11-28";
const MAX_FILES = 48;
const MAX_DECODED_BYTES_PER_FILE = 4 * 1024 * 1024;

const DEFAULT_OWNER = "Maxim00191";
const DEFAULT_REPO = "GamepadMapping-CommunityProfiles";
const DEFAULT_BRANCH = "main";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    if (request.method !== "POST") {
      return jsonResponse(405, { success: false, error: "Method not allowed" }, request);
    }

    try {
      const uploadKey = (env.UPLOAD_API_KEY ?? "").trim();
      if (uploadKey.length === 0) {
        return jsonResponse(500, { success: false, error: "Server misconfigured (UPLOAD_API_KEY)" }, request);
      }
      const auth = request.headers.get("Authorization") ?? "";
      if (auth !== `Bearer ${uploadKey}`) {
        return jsonResponse(401, { success: false, error: "Unauthorized" }, request);
      }

      const token = (env.GH_TOKEN ?? "").trim();
      if (!token) {
        return jsonResponse(500, { success: false, error: "Server misconfigured (GH_TOKEN)" }, request);
      }

      const owner = (env.REPO_OWNER ?? DEFAULT_OWNER).trim();
      const repo = (env.REPO_NAME ?? DEFAULT_REPO).trim();
      const baseBranch = (env.BASE_BRANCH ?? DEFAULT_BRANCH).trim();

      if (env.LIMIT_KV) {
        const limit = Math.max(1, parseInt(env.DAILY_UPLOAD_LIMIT ?? "20", 10) || 20);
        const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
        const d = new Date();
        const day = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(2, "0")}`;
        const kvKey = `upload:${day}:${ip}`;
        const raw = await env.LIMIT_KV.get(kvKey);
        const count = parseInt(raw ?? "0", 10) || 0;
        if (count >= limit) {
          return jsonResponse(429, { success: false, error: `Daily upload limit reached (${limit}/day)` }, request);
        }
      }

      let body: Payload;
      try {
        body = (await request.json()) as Payload;
      } catch {
        return jsonResponse(400, { success: false, error: "Invalid JSON body" }, request);
      }

      validatePayloadAgainstPinnedRepo(body, owner, repo, baseBranch);

      const prUrl = await submitPullRequest(token, body, owner, repo, baseBranch);

      if (env.LIMIT_KV) {
        const limit = Math.max(1, parseInt(env.DAILY_UPLOAD_LIMIT ?? "20", 10) || 20);
        const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
        const d = new Date();
        const day = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(2, "0")}`;
        const kvKey = `upload:${day}:${ip}`;
        const raw = await env.LIMIT_KV.get(kvKey);
        const count = parseInt(raw ?? "0", 10) || 0;
        await env.LIMIT_KV.put(kvKey, String(count + 1), { expirationTtl: 172800 });
      }

      return jsonResponse(200, { success: true, pullRequestHtmlUrl: prUrl }, request);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("community-upload:", msg);
      return jsonResponse(502, { success: false, error: "Upstream request failed" }, request);
    }
  },
};

function corsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("Origin");
  if (!origin) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(status: number, obj: Record<string, unknown>, request: Request): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(request),
    },
  });
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
  for (const f of files) {
    const rel = normalizeRelativePath(f.relativePath);
    if (!rel.startsWith(prefix)) throw new Error(`Invalid relativePath: ${f.relativePath}`);
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

async function getBranchHeadSha(token: string, owner: string, repo: string, branch: string): Promise<string> {
  const path = `repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/ref/heads/${encodeURIComponent(branch)}`;
  const res = await gh(token, "GET", path);
  const text = await res.text();
  if (!res.ok) throw new Error(`Resolve branch failed: ${res.status} ${text}`);
  const data = JSON.parse(text) as { object?: { sha?: string } };
  const sha = data.object?.sha;
  if (!sha) throw new Error("Could not read branch SHA");
  return sha;
}

async function createBranch(token: string, owner: string, repo: string, newBranch: string, baseSha: string): Promise<void> {
  const path = `repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/refs`;
  const res = await gh(token, "POST", path, {
    ref: `refs/heads/${newBranch}`,
    sha: baseSha,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Create branch failed: ${res.status} ${text}`);
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
  if (!res.ok) throw new Error(`Upload file failed: ${res.status} ${text}`);
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
  if (!res.ok) throw new Error(`Create pull request failed: ${res.status} ${text}`);
  const data = JSON.parse(text) as { html_url?: string };
  if (!data.html_url) throw new Error("Missing PR URL in response");
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