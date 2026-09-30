"""Blank out comments and string literals in source so sink patterns match code only.

A line-oriented regex can't tell ``eval(x)`` from ``# never call eval(x)`` or
``raise ValueError("eval() is disabled")``. :func:`mask_source` runs a small
lexer and returns two views of the file, each the same length as the input with
every newline preserved (so line numbers and columns still line up):

* ``code`` — comments *and* string-literal contents replaced by spaces
  (the quote delimiters are kept, so ``exec(`...`)`` still reads as a call).
* ``text`` — only comments replaced; strings kept, for sinks whose danger
  lives inside a string (``os.system("curl … | sh")``, shell scripts).

The lexer is deliberately approximate (it does not parse), but it handles the
cases that matter for false positives: line and block comments, single / double
/ triple-quoted and template strings with escapes, and JavaScript regex
literals (so ``/'/`` doesn't open a string).
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["MaskedSource", "mask_source"]

_HASH_COMMENT_EXTS = frozenset({".py", ".sh", ".rb"})
_SLASH_COMMENT_EXTS = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go"})
_JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})
# After these characters a "/" starts a regex literal rather than division.
_REGEX_PRECEDERS = frozenset("(,=:[!&|?{};+-*%<>~^")


@dataclass(frozen=True, slots=True)
class MaskedSource:
    code: str
    text: str


def _blank(chunk: str) -> str:
    return "".join("\n" if c == "\n" else " " for c in chunk)


def mask_source(source: str, ext: str) -> MaskedSource:
    """Return ``code`` / ``text`` views of ``source`` for a file with extension ``ext``."""
    ext = ext.lower()
    hash_comments = ext in _HASH_COMMENT_EXTS
    slash_comments = ext in _SLASH_COMMENT_EXTS
    quotes = "'\"`" if ext in _JS_EXTS or ext == ".go" else "'\""
    triple = ext == ".py"
    js = ext in _JS_EXTS

    code: list[str] = []
    text: list[str] = []
    n = len(source)
    i = 0
    last_significant = ""  # previous non-space code char, for regex-literal detection

    def emit(code_view: str, text_view: str) -> None:
        code.append(code_view)
        text.append(text_view)

    while i < n:
        c = source[i]

        # --- comments (blanked in both views) ---
        if hash_comments and c == "#":
            end = source.find("\n", i)
            end = n if end == -1 else end
            chunk = source[i:end]
            emit(_blank(chunk), _blank(chunk))
            i = end
            continue
        if slash_comments and source.startswith("//", i):
            end = source.find("\n", i)
            end = n if end == -1 else end
            chunk = source[i:end]
            emit(_blank(chunk), _blank(chunk))
            i = end
            continue
        if slash_comments and source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end == -1 else end + 2
            chunk = source[i:end]
            emit(_blank(chunk), _blank(chunk))
            i = end
            continue

        # --- JS regex literal (kept in text view, blanked in code view) ---
        if js and c == "/" and (last_significant == "" or last_significant in _REGEX_PRECEDERS):
            j = i + 1
            in_class = False
            while j < n and source[j] != "\n":
                ch = source[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    break
                j += 1
            if j < n and source[j] == "/":
                body = source[i + 1 : j]
                emit("/" + _blank(body) + "/", source[i : j + 1])
                i = j + 1
                last_significant = "/"
                continue

        # --- strings: keep delimiters, blank contents in the code view ---
        if c in quotes:
            delim = source[i : i + 3] if triple and source[i : i + 3] in ("'''", '"""') else c
            start = i + len(delim)
            j = start
            multiline = len(delim) == 3 or c == "`"
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source.startswith(delim, j):
                    break
                if source[j] == "\n" and not multiline:
                    break  # unterminated single-line string: stop at end of line
                j += 1
            j = min(j, n)
            body = source[start:j]
            closing = delim if source.startswith(delim, j) else ""
            emit(delim + _blank(body) + closing, source[i : j + len(closing)])
            i = j + len(closing)
            last_significant = c
            continue

        code.append(c)
        text.append(c)
        if not c.isspace():
            last_significant = c
        i += 1

    return MaskedSource(code="".join(code), text="".join(text))
