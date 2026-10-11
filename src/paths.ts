import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";

export function allowedRoots(env: NodeJS.ProcessEnv = process.env): string[] {
  const raw = env.KPN_FT_ALLOWED_ROOTS;
  const roots = raw ? raw.split(":").filter(Boolean) : [join(homedir(), "Downloads", "kpn-filetransfer")];
  return roots.map((r) => realOrSelf(resolve(r)));
}

// Resolves symlinks on the deepest existing ancestor so a link inside a root
// cannot point the tool at files outside it.
function realOrSelf(p: string): string {
  if (existsSync(p)) return realpathSync(p);
  const parent = dirname(p);
  if (parent === p) return p;
  return join(realOrSelf(parent), p.slice(parent.length + 1));
}

export function resolveWithinRoots(p: string, roots: string[] = allowedRoots()): string {
  const real = realOrSelf(resolve(p));
  if (!roots.some((r) => real === r || real.startsWith(r + sep))) {
    throw new Error(`path is outside the allowed roots (${roots.join(", ")}); set KPN_FT_ALLOWED_ROOTS to change them`);
  }
  return real;
}
