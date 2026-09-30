/**
 * Understand package-runner launch lines (npx, bunx, uvx, pipx) — a port of the
 * Python engine's `launchers.py`, shared by the pinning, advisory, toxic-flow,
 * and transport rules so they agree on which argument is the package.
 */

import {
  LOCAL_PACKAGE_RE,
  NPM_LAUNCHERS,
  NPM_PINNED_RE,
  PACKAGE_FLAGS,
  PINNED_LAUNCHERS,
  PY_PINNED_RE,
  VALUE_FLAGS,
} from "./patterns";
import { pyRe } from "./pycompat";

// Where a Python requirement's name ends: extras, version operators, markers.
const PY_NAME_END_RE = pyRe(String.raw`[\[=<>!~@;\s]`);

export interface PackageLaunch {
  launcher: string;
  /** The package token exactly as written, e.g. "pkg@1.2.3". */
  spec: string;
  ecosystem: "npm" | "pypi";
  /** A filesystem path or built artifact: nothing is fetched from a registry. */
  isLocal: boolean;
  isPinned: boolean;
  /** Package name with any version / extras stripped. */
  name: string;
  /** The pinned version, if any. */
  version: string | null;
}

/**
 * Lowercased executable name, splitting on both / and \ so Windows paths in a
 * config are understood on any OS (`C:\node\npx` -> `npx`).
 */
export function commandBasename(command: string): string {
  const parts = command.split(/[\\/]/);
  return parts[parts.length - 1].toLowerCase();
}

function makeLaunch(launcher: string, spec: string): PackageLaunch {
  const ecosystem = NPM_LAUNCHERS.has(launcher) ? "npm" : "pypi";
  let name: string;
  if (ecosystem === "npm") {
    const at = spec.lastIndexOf("@");
    name = at > 0 ? spec.slice(0, at) : spec; // keep a leading @scope
  } else {
    const end = PY_NAME_END_RE.exec(spec);
    name = end ? spec.slice(0, end.index) : spec;
  }
  const pinned = (ecosystem === "npm" ? NPM_PINNED_RE : PY_PINNED_RE).exec(spec);
  return {
    launcher,
    spec,
    ecosystem,
    isLocal: LOCAL_PACKAGE_RE.test(spec),
    isPinned: pinned !== null,
    name,
    version: pinned ? pinned[0].replace(/^[=@ ]+/, "") : null,
  };
}

/**
 * Return the package a runner launch line executes, or null. Honors
 * package-defining flags (`npx -p pkg`, `uvx --from pkg`, `pipx run --spec pkg`),
 * skips flags that take a value (`uvx --python 3.12 pkg`), and skips pipx's `run`.
 */
export function parseLaunch(command: string | null, args: string[]): PackageLaunch | null {
  if (!command) return null;
  const launcher = commandBasename(command);
  if (!PINNED_LAUNCHERS.has(launcher)) return null;

  const packageFlags = PACKAGE_FLAGS[launcher] ?? new Set<string>();
  const valueFlags = VALUE_FLAGS[launcher] ?? new Set<string>();
  let rest = [...args];
  if (launcher === "pipx" && rest[0] === "run") rest = rest.slice(1);

  let i = 0;
  while (i < rest.length) {
    const arg = rest[i];
    if (arg.startsWith("-")) {
      const eq = arg.indexOf("=");
      const flag = eq === -1 ? arg : arg.slice(0, eq);
      const hasInline = eq !== -1;
      const takesValue = packageFlags.has(flag) || valueFlags.has(flag);
      const value = hasInline ? arg.slice(eq + 1) : rest[i + 1];
      if (packageFlags.has(flag) && value) return makeLaunch(launcher, value);
      i += takesValue && !hasInline ? 2 : 1;
      continue;
    }
    return makeLaunch(launcher, arg);
  }
  return null;
}
