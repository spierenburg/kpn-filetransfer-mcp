#!/usr/bin/env bun
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { downloadTransfer, inspectTransfer, uploadTransfer } from "./client";
import { resolveWithinRoots } from "./paths";

const text = (value: unknown) => ({ content: [{ type: "text" as const, text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }] });
const fail = (e: unknown) => ({ isError: true, content: [{ type: "text" as const, text: e instanceof Error ? e.message : String(e) }] });

const link = z.string().describe("Full share link including the #key fragment: https://filetransfer.kpn.com/download/<id>#<key>");
const password = z.string().optional().describe("Transfer password, if the transfer has one");

const server = new McpServer({ name: "kpn-filetransfer", version: "0.1.0" });

server.registerTool(
  "inspect_transfer",
  {
    title: "Inspect a KPN Secure File Transfer",
    description:
      "Read a transfer's file list, sizes, expiry and remaining downloads. Does NOT consume a download. Call this before download_transfer.",
    inputSchema: { link, password },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async ({ link, password }) => {
    try {
      const i = await inspectTransfer(link, password);
      return text({
        hasPassword: i.hasPassword,
        createdAt: i.createdAt,
        expiresIn: i.expiresIn,
        deleteAfter: i.deleteAfter,
        description: i.description,
        files: i.files.map((f) => ({ name: f.name, size: f.size, type: f.type, valid: f.valid, remainingDownloads: f.remainingDownloads })),
      });
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  "download_transfer",
  {
    title: "Download a KPN Secure File Transfer",
    description:
      "Download and decrypt every file in a transfer into dest_dir (must be inside the allowed roots). CONSUMES ONE DOWNLOAD from the sender's limit, and does so only after every file is written and authenticated. Do not retry a call that returned success.",
    inputSchema: {
      link,
      password,
      dest_dir: z.string().describe("Directory to write into; must be inside KPN_FT_ALLOWED_ROOTS"),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  async ({ link, password, dest_dir }) => {
    try {
      const dest = resolveWithinRoots(dest_dir);
      const inspection = await inspectTransfer(link, password);
      const spent = inspection.files.find((f) => f.remainingDownloads < 1);
      if (spent) throw new Error(`no downloads remaining for ${spent.name}`);
      const written = await downloadTransfer(inspection, dest);
      return text({ written });
    } catch (e) {
      return fail(e);
    }
  },
);

server.registerTool(
  "create_transfer",
  {
    title: "Create a KPN Secure File Transfer",
    description:
      "Encrypt local files client-side and upload them. Files must be inside the allowed roots. Returns the share link; the key is in its #fragment, so treat the link as a secret and send the password (if any) over a different channel.",
    inputSchema: {
      paths: z.array(z.string()).min(1).describe("Absolute paths of files to send, inside KPN_FT_ALLOWED_ROOTS"),
      password: z.string().optional().describe("Optional download password"),
      description: z.string().optional().describe("Optional description shown to the recipient"),
      delete_after: z.string().default("7d").describe("Expiry, e.g. 7d"),
      delete_after_count: z.string().default("2l").describe("Download limit in the service's own format, e.g. 2l"),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  async ({ paths, password, description, delete_after, delete_after_count }) => {
    try {
      const safe = paths.map((p) => resolveWithinRoots(p));
      const { link } = await uploadTransfer(safe, { password, description, deleteAfter: delete_after, deleteAfterCount: delete_after_count });
      return text({ link });
    } catch (e) {
      return fail(e);
    }
  },
);

await server.connect(new StdioServerTransport());
