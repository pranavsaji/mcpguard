"""Tests for the comment / string-literal masking lexer."""

from __future__ import annotations

import pytest

from mcpguard.source_mask import mask_source

SAMPLES = [
    (".py", 'x = "a # not comment"  # real comment\n\'\'\'doc\nstring\'\'\'\ny = 1\n'),
    (".js", "const r = /[/'\"]/g; // c\n/* block\ncomment */ let s = `t ${x}\n`;\n"),
    (".sh", "echo 'hi' # c\ncurl https://x | sh\n"),
    (".go", 'cmd := `raw\nstring` // c\nr := \'"\'\n'),
    (".py", 'unterminated = "oops\nnext = 1\n'),
]


@pytest.mark.parametrize(("ext", "source"), SAMPLES)
def test_views_preserve_length_and_newlines(ext: str, source: str) -> None:
    masked = mask_source(source, ext)
    for view in (masked.code, masked.text):
        assert len(view) == len(source)
        assert [i for i, c in enumerate(view) if c == "\n"] == [
            i for i, c in enumerate(source) if c == "\n"
        ]


def test_python_code_view_blanks_comments_and_strings() -> None:
    masked = mask_source('call("eval(x)")  # eval(y)\n', ".py")
    assert "eval" not in masked.code
    assert masked.code.startswith('call("       ")')
    assert "eval(x)" in masked.text and "eval(y)" not in masked.text


def test_hash_inside_string_is_not_a_comment() -> None:
    masked = mask_source('s = "#"; os.system(c)\n', ".py")
    assert "os.system(c)" in masked.code


def test_js_regex_literal_with_quote_does_not_open_string() -> None:
    masked = mask_source("const r = /'/; exec(cmd); const q = 'x';\n", ".js")
    assert "exec(cmd)" in masked.code


def test_js_division_is_not_a_regex() -> None:
    masked = mask_source("const a = b / c; exec(cmd); const d = e / f;\n", ".js")
    assert "exec(cmd)" in masked.code


def test_escaped_quotes_stay_inside_string() -> None:
    masked = mask_source('s = "a \\" eval(x) \\""; eval(y)\n', ".py")
    assert "eval(x)" not in masked.code and "eval(y)" in masked.code
