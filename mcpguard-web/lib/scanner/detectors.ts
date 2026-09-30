/**
 * Pure text detectors and helpers shared by the metadata rules — a port of the
 * Python engine's `detectors.py` and `util.py`. Each function takes a string and
 * returns what it found (never a finding); rules decide severity and location.
 */

import {
  ANSI_ESCAPE_RE,
  BASE64_RUN_RE,
  CONTROL_CHAR_RE,
  COVERT_PARAM_TOKENS,
  EXFIL_PATTERNS,
  INJECTION_PATTERNS,
  INVISIBLE_CHAR_SET,
  PADDING_RE,
  PREFERENCE_PATTERNS,
  SENSITIVE_PARAM_TOKENS,
  SHADOWING_PATTERNS,
  TAG_CHAR_RANGE,
  VARIATION_SELECTOR_RANGE,
  VARIATION_SELECTOR_SUPPLEMENT_RANGE,
} from "./patterns";
import {
  codePoints,
  finditer,
  globalOf,
  pyIsPrintable,
  pyIsSpace,
  pyRe,
  pyRstrip,
  pySorted,
  pySplit,
  pyUnicodeEscape,
} from "./pycompat";
import { nameWord } from "./unicodeNames";

const ELLIPSIS = String.fromCharCode(0x2026);

// --- util.py -----------------------------------------------------------------------

/** Collapse whitespace and cap length (in code points) for use as finding evidence. */
export function truncate(text: string, limit = 160): string {
  const collapsed = pySplit(text).join(" ");
  const chars = codePoints(collapsed);
  if (chars.length <= limit) return collapsed;
  return pyRstrip(chars.slice(0, limit - 1).join("")) + ELLIPSIS;
}

/** Evidence shows only a handful of matches; capping keeps hostile inputs linear. */
export const MAX_MATCHES = 50;

/**
 * Every distinct matched substring across `patterns`, in order of first
 * appearance; overlapping patterns can match nested spans, so only the longest
 * of any nested pair is kept.
 */
export function allMatches(patterns: RegExp | RegExp[], text: string): string[] {
  const pats = Array.isArray(patterns) ? patterns : [patterns];
  const found = new Set<string>();
  for (const pat of pats) {
    const g = globalOf(pat);
    g.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = g.exec(text)) !== null) {
      if (m[0] === "") g.lastIndex += (text.codePointAt(g.lastIndex) ?? 0) > 0xffff ? 2 : 1;
      found.add(pySplit(m[0]).join(" "));
      if (found.size >= MAX_MATCHES) break; // stops this pattern only, like Python
    }
  }
  const all = [...found];
  return all.filter((m) => !all.some((other) => m !== other && other.includes(m)));
}

/** Render one or more matches as finding evidence, noting the count when >1. */
export function matchesEvidence(matches: string[], limit = 300): string {
  if (matches.length === 1) return truncate(matches[0], limit);
  return truncate(`${matches.length} matches: ${matches.join(" | ")}`, limit);
}

const WORD_RE = pyRe(String.raw`[a-z0-9]+`);
// camelCase / PascalCase boundaries, including acronyms: "HTTPRequest" -> "HTTP Request".
const CAMEL_RE = pyRe(String.raw`(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])`);

/** Lowercased alphanumeric words, in order (splits snake_case, camelCase, kebab). */
export function words(text: string): string[] {
  const spaced = text.replace(new RegExp(CAMEL_RE.source, "gu"), " ").toLowerCase();
  return finditer(WORD_RE, spaced).map((m) => m[0]);
}

/** Fold a simple plural ("webhooks" -> "webhook") without mangling "process". */
export function normalizeWord(word: string): string {
  return codePoints(word).length > 3 && word.endsWith("s") && !word.endsWith("ss")
    ? word.slice(0, -1)
    : word;
}

/** True if `phrase` occurs as consecutive entries of `haystack`. */
export function containsPhrase(haystack: string[], phrase: string[]): boolean {
  for (let i = 0; i + phrase.length <= haystack.length; i++) {
    if (phrase.every((w, j) => haystack[i + j] === w)) return true;
  }
  return false;
}

/** Pre-split keywords ("write_file") into normalized word phrases. */
export function keywordPhrases(keywords: string[]): string[][] {
  return keywords.map((kw) => words(kw).map(normalizeWord));
}

// --- detectors.py ------------------------------------------------------------------

/** Instruction-override / concealment / pseudo-tag directives in `text`. */
export function injectionMatches(text: string): string[] {
  return allMatches(INJECTION_PATTERNS, text);
}

/** Directives to read sensitive files or ship data to an external destination. */
export function exfilMatches(text: string): string[] {
  return allMatches(EXFIL_PATTERNS, text);
}

/** Directives that steer how the model uses *other* tools (tool shadowing). */
export function shadowingMatches(text: string): string[] {
  return allMatches(SHADOWING_PATTERNS, text);
}

/** Language biasing the model's tool choice toward this tool (MPMA). */
export function preferenceMatches(text: string): string[] {
  return allMatches(PREFERENCE_PATTERNS, text);
}

const SENSITIVE_PARAM_PHRASES = keywordPhrases(SENSITIVE_PARAM_TOKENS);
const COVERT_PARAM_PHRASES = keywordPhrases(COVERT_PARAM_TOKENS);

/** `["sensitive" | "covert", token]` when a parameter *name* is itself a lure. */
export function suspiciousParameterName(name: string): ["sensitive" | "covert", string] | null {
  const tokens = words(name);
  const kinds: Array<["sensitive" | "covert", string[][]]> = [
    ["sensitive", SENSITIVE_PARAM_PHRASES],
    ["covert", COVERT_PARAM_PHRASES],
  ];
  for (const [kind, phrases] of kinds) {
    for (const phrase of phrases) {
      if (containsPhrase(tokens, phrase)) return [kind, phrase.join("_")];
    }
  }
  return null;
}

/**
 * Python `base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)`, or
 * null where Python raises. `blob` is a BASE64_RUN_RE match (alphabet + up to
 * two "="), so only the padding arithmetic can fail.
 */
function b64decodePython(blob: string): Uint8Array | null {
  const data = blob.replace(/=+$/, "");
  const existing = blob.length - data.length;
  const pad = (4 - (blob.length % 4)) % 4;
  if (existing + pad > 2) return null; // validate=True allows at most "=="
  const rem = data.length % 4;
  if (rem === 1 || (rem === 0 && existing + pad > 0) || (rem === 3 && existing + pad > 1)) {
    return null;
  }
  let binary: string;
  try {
    binary = atob(data);
  } catch {
    return null;
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const UTF8 = new TextDecoder("utf-8", { ignoreBOM: true }); // Python keeps a BOM

/**
 * Decoded base64 runs in `text` that carry injection or exfil directives. Only
 * runs that decode to mostly-printable text *and* then match a directive are
 * returned, so ordinary hashes, IDs, and binary blobs stay silent.
 */
export function decodeBase64Payloads(text: string): string[] {
  const found: string[] = [];
  for (const match of finditer(BASE64_RUN_RE, text)) {
    const raw = b64decodePython(match[0]);
    if (raw === null) continue;
    const decoded = UTF8.decode(raw); // errors="replace"
    const chars = codePoints(decoded);
    const printable = chars.filter((ch) => pyIsPrintable(ch) || pyIsSpace(ch)).length;
    if (!decoded || printable / chars.length < 0.9) continue;
    if (injectionMatches(decoded).length || exfilMatches(decoded).length) {
      found.push(truncate(decoded, 120));
    }
  }
  return found;
}

/** Everything in a string that a model reads but a human reviewer can't see. */
export interface HiddenContent {
  invisibles: string[]; // "U+200B" labels
  tagText: string; // decoded Unicode Tag ("ASCII smuggling") payload
  variationSelectors: number; // suspicious variation-selector count
  ansi: string[]; // escaped ANSI / control sequences
  htmlComments: string[];
  padding: boolean;
}

// Subdivision flags (England, Scotland, Wales) are legitimately spelled with tag
// characters: U+1F3F4, tag letters, then CANCEL TAG U+E007F. Built from code
// points so this source file stays free of invisible characters.
const BLACK_FLAG = String.fromCodePoint(0x1f3f4);
const FLAG_TAG_SEQUENCE_RE = new RegExp(
  BLACK_FLAG + "[" + String.fromCodePoint(0xe0020) + "-" + String.fromCodePoint(0xe007e) + "]{1,12}" +
    String.fromCodePoint(0xe007f),
  "gu",
);

/** Scan `text` for invisible, smuggled, or terminal-control content. */
export function findHiddenContent(text: string): HiddenContent {
  const scan = text.replace(FLAG_TAG_SEQUENCE_RE, BLACK_FLAG);
  const invisibles = new Set<string>();
  const tagChars: string[] = [];
  let variationSelectors = 0;
  let vsRun = 0;
  for (const ch of scan) {
    const cp = ch.codePointAt(0)!;
    if (INVISIBLE_CHAR_SET.has(ch)) {
      invisibles.add("U+" + cp.toString(16).toUpperCase().padStart(4, "0"));
    }
    if (cp >= TAG_CHAR_RANGE[0] && cp <= TAG_CHAR_RANGE[1]) {
      const ascii = cp - TAG_CHAR_RANGE[0];
      if (ascii >= 0x20 && ascii <= 0x7e) tagChars.push(String.fromCharCode(ascii));
      invisibles.add("U+E00xx (tag characters)");
    }
    if (cp >= VARIATION_SELECTOR_SUPPLEMENT_RANGE[0] && cp <= VARIATION_SELECTOR_SUPPLEMENT_RANGE[1]) {
      variationSelectors += 1;
    } else if (cp >= VARIATION_SELECTOR_RANGE[0] && cp <= VARIATION_SELECTOR_RANGE[1]) {
      vsRun += 1;
      // One selector after an emoji is normal; a run of them encodes data.
      if (vsRun === 2) variationSelectors += 2;
      else if (vsRun > 2) variationSelectors += 1;
    } else {
      vsRun = 0;
    }
  }

  let ansi = finditer(ANSI_ESCAPE_RE, text).map((m) => m[0]);
  if (!ansi.length && CONTROL_CHAR_RE.test(text)) {
    ansi = finditer(CONTROL_CHAR_RE, text).map((m) => m[0]);
  }
  return {
    invisibles: [...invisibles],
    tagText: tagChars.join(""),
    variationSelectors,
    ansi: [...new Set(ansi.map(pyUnicodeEscape))],
    htmlComments: htmlComments(text),
    padding: PADDING_RE.test(text),
  };
}

/**
 * `<!-- ... -->` spans, like HTML_COMMENT_RE but linear-time: a regex scan is
 * quadratic on text holding many unclosed `<!--`. Whitespace-collapsed,
 * deduplicated in order, at most `limit`.
 */
export function htmlComments(text: string, limit = MAX_MATCHES): string[] {
  const found = new Set<string>();
  let start = text.indexOf("<!--");
  while (start !== -1 && found.size < limit) {
    const end = text.indexOf("-->", start + 4);
    if (end === -1) break;
    found.add(pySplit(text.slice(start, end + 3)).join(" "));
    start = text.indexOf("<!--", end + 3);
  }
  return [...found];
}

/**
 * Scripts mixed within one identifier (e.g. `["CYRILLIC", "LATIN"]`): the first
 * word of each letter's Unicode name, exactly as Python's `unicodedata` gives
 * it (see unicodeNames.ts). Digits and punctuation are ignored.
 */
export function mixedScripts(name: string): string[] {
  const scripts = new Set<string>();
  for (const ch of name) {
    const word = nameWord(ch); // null when Python's ch.isalpha() is false
    if (word !== null) scripts.add(word);
  }
  return scripts.size > 1 ? pySorted(scripts) : [];
}
