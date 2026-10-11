import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, open } from "node:fs/promises";
import { basename, extname, join } from "node:path";
import {
  CHUNK_SIZE,
  decodeKey,
  decryptBlob,
  downloadPasswordHeader,
  encodeKey,
  encryptBlob,
  newKeyMaterial,
  uploadPasswordValue,
} from "./crypto";

const BASE = "https://filetransfer.kpn.com";
const LINK_PREFIX = `${BASE}/download/`;

export interface ChunkRef {
  id: string;
  encryptionRawSecret: string;
}

export interface FileEntry {
  name: string;
  size: number;
  type: string;
  chunks: ChunkRef[];
}

export interface Manifest {
  description: string;
  filesMetadata: FileEntry[];
}

export interface InspectedFile extends FileEntry {
  valid: boolean;
  downloadCount: number;
  remainingDownloads: number;
}

export interface Inspection {
  transferId: string;
  downloadToken: string;
  hasPassword: boolean;
  createdAt: string;
  expiresIn: string;
  deleteAfter: string;
  description: string;
  files: InspectedFile[];
}

async function api(path: string, init: RequestInit): Promise<Response> {
  const res = await fetch(BASE + path, init);
  if (!res.ok) {
    const body = (await res.text()).slice(0, 300);
    throw new Error(`${init.method ?? "GET"} ${path} -> ${res.status}${res.headers.get("retry-after") ? ` (retry-after ${res.headers.get("retry-after")})` : ""}: ${body}`);
  }
  return res;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export function parseLink(link: string): { transferId: string; manifestKey: Buffer } {
  if (!link.startsWith(LINK_PREFIX)) throw new Error(`link must start with ${LINK_PREFIX}`);
  const [transferId, key] = link.slice(LINK_PREFIX.length).split("#", 2);
  if (!transferId || !key) throw new Error("link is missing the #key fragment");
  return { transferId, manifestKey: decodeKey(key) };
}

/** Steps 2-5 of the download flow. Consumes no download. */
export async function inspectTransfer(link: string, password?: string): Promise<Inspection> {
  const { transferId, manifestKey } = parseLink(link);
  const req = await (await api("/api/v1/download/request/", json({ transfer_id: transferId }))).json() as {
    download_token: string;
    transfer: { has_password: boolean; created_at: string; expires_in: string; delete_after: string };
  };
  const headers: Record<string, string> = { "Download-Token": req.download_token };
  if (req.transfer.has_password) {
    if (!password) throw new Error("transfer is password-protected and no password was given");
    headers.Password = downloadPasswordHeader(transferId, manifestKey, password);
  }
  const encrypted = Buffer.from(await (await api("/api/v1/download/metadata/", { headers })).arrayBuffer());
  const manifest = JSON.parse(decryptBlob(encrypted, manifestKey).toString("utf8")) as Manifest;

  const validated = await (
    await api("/api/v1/download/files/validate/", json({
      download_token: req.download_token,
      files: manifest.filesMetadata.map((f) => f.chunks[0].id),
    }))
  ).json() as { id: string; valid: boolean; download_count: number; remaining_downloads: number }[];
  const byId = new Map(validated.map((v) => [v.id, v]));

  return {
    transferId,
    downloadToken: req.download_token,
    hasPassword: req.transfer.has_password,
    createdAt: req.transfer.created_at,
    expiresIn: req.transfer.expires_in,
    deleteAfter: req.transfer.delete_after,
    description: manifest.description,
    files: manifest.filesMetadata.map((f) => {
      const v = byId.get(f.chunks[0].id);
      return { ...f, valid: v?.valid ?? false, downloadCount: v?.download_count ?? 0, remainingDownloads: v?.remaining_downloads ?? 0 };
    }),
  };
}

function safeName(name: string): string {
  const base = basename(name.replace(/\\/g, "/"));
  if (!base || base === "." || base === "..") throw new Error(`unsafe file name in manifest: ${JSON.stringify(name)}`);
  return base;
}

function freeTarget(dir: string, name: string): string {
  const ext = extname(name);
  const stem = name.slice(0, name.length - ext.length);
  let candidate = join(dir, name);
  for (let i = 1; existsSync(candidate); i++) candidate = join(dir, `${stem}_${i}${ext}`);
  return candidate;
}

/**
 * Steps 6-7. Every chunk is fetched, authenticated and written before the
 * `success` call, because that call consumes a download. Never retry this
 * whole function blindly: a retry after step 7 spends another download.
 */
export async function downloadTransfer(inspection: Inspection, destDir: string): Promise<string[]> {
  await mkdir(destDir, { recursive: true });
  const written: string[] = [];
  for (const file of inspection.files) {
    if (!file.valid) throw new Error(`server reports ${file.name} is not valid`);
    const target = freeTarget(destDir, safeName(file.name));
    const fh = await open(target, "wx");
    let total = 0;
    try {
      for (const chunk of file.chunks) {
        const res = await api(`/api/v1/download/file/${chunk.id}/`, { headers: { "Download-Token": inspection.downloadToken } });
        const plain = decryptBlob(Buffer.from(await res.arrayBuffer()), decodeKey(chunk.encryptionRawSecret));
        await fh.write(plain);
        total += plain.length;
      }
    } finally {
      await fh.close();
    }
    if (total !== file.size) throw new Error(`${file.name}: expected ${file.size} bytes, got ${total}`);
    written.push(target);
  }
  const ids = inspection.files.flatMap((f) => f.chunks.map((c) => c.id));
  const done = await (await api("/api/v1/download/files/success/", {
    ...json({ files: ids }),
    headers: { "Content-Type": "application/json", "Download-Token": inspection.downloadToken },
  })).json() as { transfer_is_valid: boolean };
  if (!done.transfer_is_valid) throw new Error("server reports the transfer is no longer valid after download");
  return written;
}

export interface UploadOptions {
  password?: string;
  deleteAfter?: string;
  deleteAfterCount?: string;
  description?: string;
}

function form(blob: Buffer, fields: Record<string, string>): FormData {
  const fd = new FormData();
  fd.append("file", new Blob([blob]), "blob");
  for (const [k, v] of Object.entries(fields)) fd.append(k, v);
  return fd;
}

export async function uploadTransfer(paths: string[], opts: UploadOptions = {}): Promise<{ link: string; managementToken: string }> {
  const info = await (await api("/api/v1/upload/info/", {})).json() as { max_upload_size_bytes?: number };
  const sizes = paths.map((p) => Bun.file(p).size);
  const total = sizes.reduce((a, b) => a + b, 0);
  if (info.max_upload_size_bytes && total > info.max_upload_size_bytes) {
    throw new Error(`total ${total} bytes exceeds server limit ${info.max_upload_size_bytes}`);
  }
  const created = await (
    await api("/api/v1/upload/request/", json({ delete_after: opts.deleteAfter ?? "7d", delete_after_count: opts.deleteAfterCount ?? "2l" }))
  ).json() as { created_transfer: { id: string; management_token: string } };
  const { id: transferId, management_token: token } = created.created_transfer;

  const filesMetadata: FileEntry[] = [];
  for (const [i, path] of paths.entries()) {
    const file = Bun.file(path);
    const chunks: ChunkRef[] = [];
    for (let off = 0; off < Math.max(sizes[i], 1); off += CHUNK_SIZE) {
      const plain = Buffer.from(await file.slice(off, off + CHUNK_SIZE).arrayBuffer());
      const material = newKeyMaterial(plain);
      const cipher = encryptBlob(plain, material);
      const res = await (await api("/api/v1/upload/file/", {
        method: "POST",
        body: form(cipher, {
          encrypted_contents_hash: createHash("sha256").update(cipher).digest("hex"),
          transfer_management_token: token,
        }),
      })).json() as { created_transfer_file: { id: string } };
      chunks.push({ id: res.created_transfer_file.id, encryptionRawSecret: encodeKey(material) });
    }
    filesMetadata.push({ name: basename(path), size: sizes[i], type: file.type || "application/octet-stream", chunks });
  }

  const manifest: Manifest = { description: opts.description ?? "", filesMetadata };
  const manifestPlain = Buffer.from(JSON.stringify(manifest), "utf8");
  const manifestMaterial = newKeyMaterial(manifestPlain);
  await api("/api/v1/upload/metadata/", {
    method: "PUT",
    body: form(encryptBlob(manifestPlain, manifestMaterial), { transfer_management_token: token }),
  });

  if (opts.password) {
    await api("/api/v1/upload/password/", json({
      transfer_management_token: token,
      password: uploadPasswordValue(transferId, manifestMaterial, opts.password),
    }));
  }
  return { link: `${LINK_PREFIX}${transferId}#${encodeKey(manifestMaterial)}`, managementToken: token };
}
