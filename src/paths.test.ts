import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { allowedRoots, resolveWithinRoots } from "./paths";

const base = mkdtempSync(join(tmpdir(), "kpnft-"));
const root = join(base, "root");
const outside = join(base, "outside");
mkdirSync(root);
mkdirSync(outside);
writeFileSync(join(outside, "secret.txt"), "x");
symlinkSync(outside, join(root, "escape"));
const roots = allowedRoots({ KPN_FT_ALLOWED_ROOTS: root });

describe("resolveWithinRoots", () => {
  test("accepts a file and a not-yet-created subdirectory inside the root", () => {
    writeFileSync(join(root, "a.txt"), "x");
    expect(() => resolveWithinRoots(join(root, "a.txt"), roots)).not.toThrow();
    expect(() => resolveWithinRoots(join(root, "new", "deeper"), roots)).not.toThrow();
  });

  test("rejects ../ traversal", () => {
    expect(() => resolveWithinRoots(join(root, "..", "outside", "secret.txt"), roots)).toThrow(/outside the allowed roots/);
  });

  test("rejects a symlink inside the root that points outside", () => {
    expect(() => resolveWithinRoots(join(root, "escape", "secret.txt"), roots)).toThrow(/outside the allowed roots/);
  });

  test("rejects a sibling whose name merely starts with the root's name", () => {
    mkdirSync(join(base, "root-evil"));
    expect(() => resolveWithinRoots(join(base, "root-evil"), roots)).toThrow(/outside the allowed roots/);
  });
});
