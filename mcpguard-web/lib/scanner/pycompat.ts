/**
 * Python-compatibility helpers for the TypeScript port.
 *
 * The Python engine is the source of truth, and several of its building blocks
 * behave differently from their JavaScript look-alikes: `re` on `str` is
 * Unicode-aware (`\w`, `\b`, `\d`, `\s`, case folding), `.` excludes only `\n`,
 * `$` also matches before a trailing newline, strings are indexed by code point,
 * and `repr()` / `str.strip()` / `urlparse()` have their own rules. Everything
 * here reproduces the Python behavior so both engines emit identical findings.
 */

// --- regular expressions -------------------------------------------------------

/** Characters Python's `\s` (and `str.isspace()` / `str.split()`) treat as whitespace. */
const PY_WS =
  "\\t-\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
/** Python's Unicode `\w`: `str.isalnum()` (letters + numbers) or underscore. */
const PY_W = "\\p{L}\\p{N}_";
const WORD_BOUNDARY = `(?:(?<=[${PY_W}])(?![${PY_W}])|(?<![${PY_W}])(?=[${PY_W}]))`;
const NOT_WORD_BOUNDARY = `(?:(?<=[${PY_W}])(?=[${PY_W}])|(?<![${PY_W}])(?![${PY_W}]))`;
/** Chars that may be backslash-escaped in a `u`-mode JS pattern. */
const JS_SYNTAX_CHARS = new Set("^$\\.*+?()[]{}|/".split(""));
/** Under IGNORECASE, Python also folds dotted/dotless I onto i (JS `iu` does not). */
const TURKISH_I = "\\u0130\\u0131";
const DOTTED_I = String.fromCharCode(0x130);
const DOTLESS_I = String.fromCharCode(0x131);

/**
 * Compile a Python `re` pattern (as written in the Python engine) into a JS
 * RegExp with the same matching semantics on `str`.
 *
 * `flags` accepts `i` (re.IGNORECASE) and `s` (re.DOTALL). The result always
 * carries JS's `u` flag, so matching is by code point like Python (a `.{0,40}`
 * window counts an emoji once) and `\p{...}` classes are available to rebuild
 * Python's Unicode-aware `\w` / `\b` / `\d`. Translation:
 *
 * - `\w` `\W` `\b` `\B` `\d` `\D` `\s` `\S` -> Python's Unicode definitions,
 * - `.` -> `[^\n]` (JS's `.` also stops at `\r`, U+2028, U+2029),
 * - `$` -> `(?=\n?$)` (Python's `$` also matches before a final newline),
 * - with `i`: any class or literal covering i/I also covers U+0130/U+0131,
 * - identity escapes of non-syntax chars (`\"`) -> the bare char.
 *
 * Unsupported Python-only syntax (named groups, inline flags) throws, so a
 * future pattern edit cannot silently change meaning.
 */
export function pyRe(source: string, flags = ""): RegExp {
  const ignoreCase = flags.includes("i");
  const dotAll = flags.includes("s");
  let out = "";
  let i = 0;
  while (i < source.length) {
    const c = source[i];
    if (c === "\\") {
      out += translateEscape(source[i + 1], false);
      i += 2;
    } else if (c === "[") {
      const [cls, next] = translateClass(source, i, ignoreCase);
      out += cls;
      i = next;
    } else if (c === ".") {
      out += dotAll ? "[^]" : "[^\\n]";
      i += 1;
    } else if (c === "$") {
      out += "(?=\\n?$)";
      i += 1;
    } else if (c === "(" && source[i + 1] === "?" && /[A-Za-z]/.test(source[i + 2] ?? "")) {
      throw new Error(`pyRe: unsupported group syntax in ${source}`);
    } else if (c === "(" && source.startsWith("(?<", i) && /[A-Za-z]/.test(source[i + 3] ?? "")) {
      throw new Error(`pyRe: named groups are not supported: ${source}`);
    } else if (ignoreCase && (c === "i" || c === "I")) {
      out += `[iI${TURKISH_I}]`;
      i += 1;
    } else {
      out += c;
      i += 1;
    }
  }
  return new RegExp(out, ignoreCase ? "iu" : "u");
}

function translateEscape(n: string | undefined, inClass: boolean): string {
  if (n === undefined) throw new Error("pyRe: trailing backslash");
  switch (n) {
    case "s":
      return inClass ? PY_WS : `[${PY_WS}]`;
    case "w":
      return inClass ? PY_W : `[${PY_W}]`;
    case "d":
      return "\\p{Nd}";
  }
  if (inClass) {
    if (n === "S" || n === "W" || n === "D" || n === "b" || n === "B") {
      throw new Error(`pyRe: \\${n} inside a character class is not supported`);
    }
    if (/[A-Za-z0-9]/.test(n) || JS_SYNTAX_CHARS.has(n) || n === "-") return "\\" + n;
    return n;
  }
  switch (n) {
    case "S":
      return `[^${PY_WS}]`;
    case "W":
      return `[^${PY_W}]`;
    case "D":
      return "\\P{Nd}";
    case "b":
      return WORD_BOUNDARY;
    case "B":
      return NOT_WORD_BOUNDARY;
    case "A":
      return "^";
    case "Z":
      return "$";
  }
  if (/[A-Za-z0-9]/.test(n) || JS_SYNTAX_CHARS.has(n)) return "\\" + n;
  return n; // Python treats "\<punct>" as the literal char
}

function translateClass(source: string, start: number, ignoreCase: boolean): [string, number] {
  let i = start + 1;
  let negated = false;
  if (source[i] === "^") {
    negated = true;
    i += 1;
  }
  let content = "";
  let first = true;
  for (;;) {
    const c = source[i];
    if (c === undefined) throw new Error(`pyRe: unterminated character class in ${source}`);
    if (c === "]" && !first) break;
    if (c === "\\") {
      content += translateEscape(source[i + 1], true);
      i += 2;
    } else {
      content += c === "]" ? "\\]" : c; // a leading "]" is literal in Python
      i += 1;
    }
    first = false;
  }
  if (ignoreCase) {
    // Python folds U+0130/U+0131 onto i under IGNORECASE; JS `iu` does not. Add
    // them beside the class (appending inside it could form a range with "-").
    const probe = new RegExp(`[${content}]`, "u");
    const coversI = probe.test("i") || probe.test("I");
    if (coversI && !(probe.test(DOTTED_I) && probe.test(DOTLESS_I))) {
      const cls = negated
        ? `(?![${TURKISH_I}])[^${content}]`
        : `(?:[${content}]|[${TURKISH_I}])`;
      return [cls, i + 1];
    }
  }
  return [`[${negated ? "^" : ""}${content}]`, i + 1];
}

const globalCache = new WeakMap<RegExp, RegExp>();

/** A `g`-flagged twin of `re` (cached), for `finditer`-style iteration. */
export function globalOf(re: RegExp): RegExp {
  let g = globalCache.get(re);
  if (!g) {
    g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    globalCache.set(re, g);
  }
  return g;
}

/** Python `pattern.finditer(text)`: every non-overlapping match. */
export function finditer(re: RegExp, text: string): RegExpExecArray[] {
  const g = globalOf(re);
  g.lastIndex = 0;
  return [...text.matchAll(g)] as RegExpExecArray[];
}

/** Escape `text` for literal use inside a pattern compiled with {@link pyRe}. */
export function reEscape(text: string): string {
  return text.replace(/[\\^$.*+?()[\]{}|/]/g, "\\$&");
}

// --- strings ---------------------------------------------------------------------

const WS_RUN = new RegExp(`[${PY_WS}]+`, "u");
const WS_LEAD = new RegExp(`^[${PY_WS}]+`, "u");
const WS_TRAIL = new RegExp(`[${PY_WS}]+$`, "u");

/** Python `str.split()` (no args): split on whitespace runs, dropping empties. */
export function pySplit(text: string): string[] {
  return text.split(WS_RUN).filter((s) => s.length > 0);
}

/** Python `str.strip()` / `lstrip()` / `rstrip()` with no args. */
export function pyStrip(text: string): string {
  return text.replace(WS_LEAD, "").replace(WS_TRAIL, "");
}
export function pyRstrip(text: string): string {
  return text.replace(WS_TRAIL, "");
}

/** Python `str.isspace()` for a single character. */
const WS_ONLY = new RegExp(`^[${PY_WS}]+$`, "u");
export function pyIsSpace(ch: string): boolean {
  return WS_ONLY.test(ch);
}

/** Python `str.removesuffix`. */
export function removeSuffix(text: string, suffix: string): string {
  return suffix && text.endsWith(suffix) ? text.slice(0, -suffix.length) : text;
}

/** Code points of `text` (Python indexes strings by code point, JS by UTF-16 unit). */
export function codePoints(text: string): string[] {
  return Array.from(text);
}

// Python str.isprintable(): false for Cc, Cf, Cs, Co, Cn, Zl, Zp, Zs (except " ").
const NON_PRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;

/** Python `ch.isprintable()` for one code point. */
export function pyIsPrintable(ch: string): boolean {
  return ch === " " || !NON_PRINTABLE.test(ch);
}

function hex(cp: number, width: number): string {
  return cp.toString(16).padStart(width, "0");
}

/** Python `repr(text)` for a `str`. */
export function pyRepr(text: string): string {
  const quote = text.includes("'") && !text.includes('"') ? '"' : "'";
  let out = quote;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (ch === quote || ch === "\\") out += "\\" + ch;
    else if (ch === "\t") out += "\\t";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (cp < 0x20 || cp === 0x7f) out += "\\x" + hex(cp, 2);
    else if (cp < 0x7f) out += ch;
    else if (pyIsPrintable(ch)) out += ch;
    else if (cp <= 0xff) out += "\\x" + hex(cp, 2);
    else if (cp <= 0xffff) out += "\\u" + hex(cp, 4);
    else out += "\\U" + hex(cp, 8);
  }
  return out + quote;
}

/** Python `text.encode("unicode_escape").decode("ascii")`. */
export function pyUnicodeEscape(text: string): string {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0x10000) out += "\\U" + hex(cp, 8);
    else if (cp >= 0x100) out += "\\u" + hex(cp, 4);
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (cp < 0x20 || cp >= 0x7f) out += "\\x" + hex(cp, 2);
    else out += ch;
  }
  return out;
}

/** Python's default `str` ordering (by code point, not UTF-16 unit). */
export function pyCompare(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done || y.done) return x.done && y.done ? 0 : x.done ? -1 : 1;
    const d = x.value.codePointAt(0)! - y.value.codePointAt(0)!;
    if (d !== 0) return d;
  }
}

/** Python `sorted(strings)`. */
export function pySorted(values: Iterable<string>): string[] {
  return [...values].sort(pyCompare);
}

const DECIMAL_DIGIT = /\p{Nd}/u;

/**
 * Python `int(text)` for a run of Unicode decimal digits (`\d` matches any Nd
 * digit and `int()` accepts them). Nd digits are encoded in contiguous runs of
 * complete 0-9 sets, so a digit's value is its offset from its run's start mod 10.
 */
export function pyDigitsToInt(text: string): number {
  let value = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    let start = cp;
    while (DECIMAL_DIGIT.test(String.fromCodePoint(start - 1))) start -= 1;
    value = value * 10 + ((cp - start) % 10);
  }
  return value;
}

// --- JSON with Python dict ordering -----------------------------------------------

/**
 * Python dicts keep keys in insertion order; JS objects list integer-like keys
 * ("1", "10") first. Objects built by {@link parseJson} (and by the config
 * parser) record their source key order here so iteration matches Python.
 */
const KEY_ORDER = new WeakMap<object, string[]>();

/** Define `key` as an own property (safe for "__proto__", unlike assignment). */
export function setOwn<T>(obj: Record<string, T>, key: string, value: T): void {
  Object.defineProperty(obj, key, { value, writable: true, enumerable: true, configurable: true });
}

/** Record `keys` as the Python iteration order of `obj`. */
function recordKeyOrder(obj: object, keys: string[]): void {
  KEY_ORDER.set(obj, keys);
}

/** Python `d.items()`: entries in source (insertion) order. */
export function orderedEntries<T>(obj: Record<string, T>): Array<[string, T]> {
  const keys = KEY_ORDER.get(obj);
  if (!keys) return Object.entries(obj);
  return keys
    .filter((k) => Object.prototype.hasOwnProperty.call(obj, k))
    .map((k) => [k, obj[k]] as [string, T]);
}

/** Build a string map from `[key, value]` pairs with Python dict semantics. */
export function orderedMap<T>(pairs: Iterable<[string, T]>): Record<string, T> {
  const out: Record<string, T> = {};
  const keys: string[] = [];
  for (const [k, v] of pairs) {
    if (!Object.prototype.hasOwnProperty.call(out, k)) keys.push(k);
    setOwn(out, k, v);
  }
  recordKeyOrder(out, keys);
  return out;
}

/** Python's json decoder raises RecursionError at this container depth (3.12). */
export const PY_JSON_MAX_DEPTH = 9997;

/** Thrown by {@link parseJson} where Python's `json.loads` raises RecursionError. */
export class JsonTooDeepError extends Error {}

/**
 * `JSON.parse` that also records each object's key order (duplicate keys: last
 * value wins, first position kept — like Python's `json.loads`). Invalid input
 * throws the native SyntaxError; nesting deeper than Python can decode throws
 * {@link JsonTooDeepError}. Iterative, so hostile nesting cannot overflow the stack.
 */
export function parseJson(text: string): unknown {
  JSON.parse(text); // validate first; the walk below assumes well-formed JSON
  type Frame =
    | { kind: "object"; pairs: Array<[string, unknown]>; key: string | null }
    | { kind: "array"; items: unknown[] };
  const stack: Frame[] = [];
  let i = 0;
  let result: unknown;
  const isWs = (c: string) => c === " " || c === "\t" || c === "\n" || c === "\r";
  const readString = (): string => {
    const start = i;
    i++;
    while (text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
    i++;
    return JSON.parse(text.slice(start, i)) as string;
  };
  const emit = (value: unknown): void => {
    const top = stack[stack.length - 1];
    if (!top) result = value;
    else if (top.kind === "array") top.items.push(value);
    else {
      top.pairs.push([top.key as string, value]);
      top.key = null;
    }
  };
  while (i < text.length) {
    const c = text[i];
    if (isWs(c) || c === "," || c === ":") {
      i++;
    } else if (c === "{" || c === "[") {
      if (stack.length + 1 > PY_JSON_MAX_DEPTH) throw new JsonTooDeepError("nested too deeply");
      stack.push(c === "{" ? { kind: "object", pairs: [], key: null } : { kind: "array", items: [] });
      i++;
    } else if (c === "}" || c === "]") {
      const frame = stack.pop()!;
      emit(frame.kind === "object" ? orderedMap(frame.pairs) : frame.items);
      i++;
    } else if (c === '"') {
      const str = readString();
      const top = stack[stack.length - 1];
      if (top && top.kind === "object" && top.key === null) top.key = str;
      else emit(str);
    } else {
      const start = i;
      while (i < text.length && !",]} \t\n\r".includes(text[i])) i++;
      emit(JSON.parse(text.slice(start, i)));
    }
  }
  return result;
}

// --- JSON values -----------------------------------------------------------------

/** Python truthiness of a JSON value. */
export function pyTruthy(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "string") return value.length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

/** Python `a or b`. */
export function pyOr<T, U>(a: T, b: U): T | U {
  return pyTruthy(a) ? a : b;
}

/**
 * Python `repr(float)`: shortest round-trip digits, scientific notation when the
 * exponent is < -4 or >= 16 (`1e-05`, `1e+16`), otherwise fixed with a `.0`.
 */
function pyFloatRepr(n: number): string {
  if (Number.isNaN(n)) return "nan";
  if (!Number.isFinite(n)) return n > 0 ? "inf" : "-inf";
  const [mantissa, expText] = n.toExponential().split("e");
  const exp = Number(expText);
  if (exp < -4 || exp >= 16) {
    const m = mantissa.replace(/\.0+$/, "");
    const sign = exp < 0 ? "-" : "+";
    return `${m}e${sign}${String(Math.abs(exp)).padStart(2, "0")}`;
  }
  const fixed = n.toFixed(Math.max(0, (mantissa.split(".")[1]?.length ?? 0) - exp));
  return fixed.includes(".") ? fixed : fixed + ".0";
}

function pyNumber(n: number): string {
  // JSON.parse cannot tell 1 from 1.0; integral values render as Python ints.
  if (Number.isInteger(n) && Math.abs(n) < 1e21) return BigInt(n).toString();
  return pyFloatRepr(n);
}

/** Python `str(value)` for a value produced by `json.loads`. */
export function pyStr(value: unknown): string {
  if (typeof value === "string") return value;
  return pyReprValue(value);
}

function pyReprValue(value: unknown): string {
  if (typeof value === "string") return pyRepr(value);
  if (value === null || value === undefined) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (typeof value === "number") return pyNumber(value);
  if (Array.isArray(value)) return `[${value.map(pyReprValue).join(", ")}]`;
  if (typeof value === "object") {
    const items = orderedEntries(value as Record<string, unknown>).map(
      ([k, v]) => `${pyRepr(k)}: ${pyReprValue(v)}`,
    );
    return `{${items.join(", ")}}`;
  }
  return String(value);
}

// --- urllib.parse.urlparse ---------------------------------------------------------

/** Mirrors Python's ValueError so rule-failure findings read identically. */
export class PyValueError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValueError";
  }
}

export interface ParsedUrl {
  scheme: string;
  netloc: string;
  path: string;
  params: string;
  query: string;
  fragment: string;
  /** Python's `.hostname` (lowercased; `null` when empty). */
  hostname: string | null;
}

const SCHEME_CHARS = /^[A-Za-z0-9+\-.]+$/;
const USES_PARAMS = new Set([
  "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu",
  "sip", "sips", "mms", "sftp", "tel",
]);

function partition(text: string, sep: string): [string, string, string] {
  const at = text.indexOf(sep);
  return at < 0 ? [text, "", ""] : [text.slice(0, at), sep, text.slice(at + sep.length)];
}

function rpartition(text: string, sep: string): [string, string, string] {
  const at = text.lastIndexOf(sep);
  return at < 0 ? ["", "", text] : [text.slice(0, at), sep, text.slice(at + sep.length)];
}

function isIPv4(text: string): boolean {
  const octets = text.split(".");
  if (octets.length !== 4) return false;
  return octets.every(
    (o) => /^[0-9]{1,3}$/.test(o) && Number(o) <= 255 && !(o.length > 1 && o[0] === "0"),
  );
}

/** Python `ipaddress.IPv6Address` acceptance (incl. an embedded IPv4 tail and %scope). */
function isIPv6(text: string): boolean {
  const [addr, sep, scope] = partition(text, "%");
  if (sep && (!scope || scope.includes("%"))) return false;
  if (!addr) return false;
  let parts = addr.split(":");
  if (parts.length < 3) return false;
  const last = parts[parts.length - 1];
  if (last.includes(".")) {
    if (!isIPv4(last)) return false;
    parts = [...parts.slice(0, -1), "0", "0"];
  }
  if (parts.length > 9) return false;
  let skip: number | null = null;
  for (let i = 1; i < parts.length - 1; i++) {
    if (!parts[i]) {
      if (skip !== null) return false;
      skip = i;
    }
  }
  let body: string[];
  if (skip !== null) {
    let hi = skip;
    let lo = parts.length - skip - 1;
    if (!parts[0]) {
      hi -= 1;
      if (hi) return false;
    }
    if (!parts[parts.length - 1]) {
      lo -= 1;
      if (lo) return false;
    }
    if (8 - (hi + lo) < 1) return false;
    body = [...parts.slice(0, hi), ...parts.slice(parts.length - lo)];
  } else {
    if (parts.length !== 8 || !parts[0] || !parts[parts.length - 1]) return false;
    body = parts;
  }
  return body.every((h) => /^[0-9A-Fa-f]{1,4}$/.test(h));
}

function checkBracketedNetloc(netloc: string): void {
  const hostAndPort = rpartition(netloc, "@")[2];
  const [before, open, bracketed] = partition(hostAndPort, "[");
  let hostname: string;
  if (open) {
    if (before) throw new PyValueError("Invalid IPv6 URL");
    const [h, , port] = partition(bracketed, "]");
    if (port && !port.startsWith(":")) throw new PyValueError("Invalid IPv6 URL");
    hostname = h;
  } else {
    hostname = partition(hostAndPort, ":")[0];
  }
  if (hostname.startsWith("v")) {
    if (!/^v[a-fA-F0-9]+\.[^]+$/.test(hostname)) {
      throw new PyValueError("IPvFuture address is invalid");
    }
  } else if (isIPv4(hostname)) {
    throw new PyValueError("An IPv4 address cannot be in brackets");
  } else if (!isIPv6(hostname)) {
    throw new PyValueError(`${pyRepr(hostname)} does not appear to be an IPv4 or IPv6 address`);
  }
}

function checkNetloc(netloc: string): void {
  if (!netloc || /^[\x00-\x7f]*$/.test(netloc)) return;
  const n = netloc.replace(/[@:#?]/g, "");
  const normalized = n.normalize("NFKC");
  if (n === normalized) return;
  for (const c of "/?#@:") {
    if (normalized.includes(c)) {
      throw new PyValueError(
        `netloc '${netloc}' contains invalid characters under NFKC normalization`,
      );
    }
  }
}

/** Python `urllib.parse.urlparse(url)` (3.12), including its ValueErrors. */
export function urlparse(input: string): ParsedUrl {
  let url = input.replace(/^[\x00-\x20]+/, "").replace(/[\t\r\n]/g, "");
  let scheme = "";
  let netloc = "";
  let query = "";
  let fragment = "";
  const colon = url.indexOf(":");
  if (colon > 0 && /^[A-Za-z]/.test(url) && SCHEME_CHARS.test(url.slice(0, colon))) {
    scheme = url.slice(0, colon).toLowerCase();
    url = url.slice(colon + 1);
  }
  if (url.startsWith("//")) {
    let delim = url.length;
    for (const c of "/?#") {
      const at = url.indexOf(c, 2);
      if (at >= 0) delim = Math.min(delim, at);
    }
    netloc = url.slice(2, delim);
    url = url.slice(delim);
    const open = netloc.includes("[");
    const close = netloc.includes("]");
    if (open !== close) throw new PyValueError("Invalid IPv6 URL");
    if (open && close) checkBracketedNetloc(netloc);
  }
  if (url.includes("#")) [url, , fragment] = partition(url, "#");
  if (url.includes("?")) [url, , query] = partition(url, "?");
  checkNetloc(netloc);

  let params = "";
  if (USES_PARAMS.has(scheme) && url.includes(";")) {
    let at: number;
    if (url.includes("/")) {
      at = url.indexOf(";", url.lastIndexOf("/"));
    } else {
      at = url.indexOf(";");
    }
    if (at >= 0) {
      params = url.slice(at + 1);
      url = url.slice(0, at);
    }
  }

  const hostinfo = rpartition(netloc, "@")[2];
  const [, openBr, bracketed] = partition(hostinfo, "[");
  const rawHost = openBr ? partition(bracketed, "]")[0] : partition(hostinfo, ":")[0];
  let hostname: string | null = null;
  if (rawHost) {
    const [h, pct, zone] = partition(rawHost, "%");
    hostname = h.toLowerCase() + pct + zone;
  }
  return { scheme, netloc, path: url, params, query, fragment, hostname };
}
