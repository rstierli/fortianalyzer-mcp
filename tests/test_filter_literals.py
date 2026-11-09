"""How a value is written into a FortiAnalyzer filter literal.

Every expected spelling here follows the rules measured on FortiAnalyzer
7.6.8 and 8.0.2 (issue #164): ``==`` compares backslashes literally, ``like``
reads a doubled backslash as one and ``\\%`` / ``\\_`` as the characters, and
a quote that follows a backslash never closes the literal, however many
backslashes precede it.
"""

import pytest

from fortianalyzer_mcp.utils.errors import ValidationError
from fortianalyzer_mcp.utils.validation import like_filter_pattern, sanitize_filter_value

#: The ``reason`` of a wireless DNS event as FortiAnalyzer stores it: a real
#: backslash before each quote. ``192.0.2.10`` stands in for the resolver.
STORED_REASON = 'Server 192.0.2.10 replied \\"non-existing domain\\"'


class TestComparisonLiteral:
    """``sanitize_filter_value`` writes the literal for ``==`` and its relatives."""

    def test_backslashes_are_written_once(self) -> None:
        """One stored backslash matched the one-backslash spelling; doubled matched nothing."""
        assert sanitize_filter_value("path\\to") == '"path\\to"'

    def test_stored_reason_value_compiles_to_the_spelling_that_matched(self) -> None:
        """Measured: this spelling returned the row on both builds, the doubled one did not."""
        assert sanitize_filter_value(STORED_REASON) == f"'{STORED_REASON}'"

    def test_a_double_quote_switches_to_single_quotes(self) -> None:
        assert sanitize_filter_value('say "hello"') == "'say \"hello\"'"

    def test_an_apostrophe_keeps_double_quotes(self) -> None:
        assert sanitize_filter_value("it's") == '"it\'s"'

    def test_both_quote_characters_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="both quote characters"):
            sanitize_filter_value('it\'s "x"', "name")

    def test_a_trailing_backslash_is_refused(self) -> None:
        """A quote after a backslash does not close the literal, so this value
        cannot be written as one; refuse it instead of sending a clause that
        runs on into whatever follows."""
        with pytest.raises(ValidationError, match="ends in a backslash"):
            sanitize_filter_value("accept\\", "action")

    def test_error_names_the_field(self) -> None:
        with pytest.raises(ValidationError, match="action"):
            sanitize_filter_value("accept\\", "action")

    def test_a_run_of_trailing_backslashes_is_refused_too(self) -> None:
        """However many backslashes precede the closing quote, it does not close."""
        with pytest.raises(ValidationError, match="ends in a backslash"):
            sanitize_filter_value("accept\\\\", "action")

    def test_a_callers_value_is_stripped(self) -> None:
        assert sanitize_filter_value(" admin ") == "admin"

    def test_strip_false_keeps_surrounding_spaces_inside_the_literal(self) -> None:
        """Used for a value resolved from a masking token, which is stored as is."""
        assert sanitize_filter_value(" admin ", strip=False) == '" admin "'
        assert sanitize_filter_value(" ", strip=False) == '" "'

    def test_a_trailing_backslash_is_refused_whatever_else_the_value_holds(self) -> None:
        """The quote choice does not rescue a value that ends in a backslash."""
        with pytest.raises(ValidationError, match="ends in a backslash"):
            sanitize_filter_value('say "x"\\', "msg")


class TestValuesNotReadAsValuesUnquoted:
    """Some values made only of unquoted-safe characters are still not values unquoted.

    Measured on 7.6.8 and 8.0.2 with ``app==<value>``: ``and``, ``or`` and
    ``not`` in any case, a value made of hyphens, and a value that starts or
    ends with one colon are answered with ``Invalid filter``. The same values
    in quotes are accepted.
    """

    @pytest.mark.parametrize("value", ["or", "OR", "and", "And", "not", "Not"])
    def test_an_operator_word_is_quoted(self, value: str) -> None:
        assert sanitize_filter_value(value) == f'"{value}"'

    @pytest.mark.parametrize("value", ["-", "--", ":", "a:", ":a"])
    def test_hyphens_and_a_single_edge_colon_are_quoted(self, value: str) -> None:
        assert sanitize_filter_value(value) == f'"{value}"'

    @pytest.mark.parametrize(
        "value",
        [
            "ornate",
            "like",
            "in",
            "null",
            "-foo",
            "foo-",
            "a-b",
            "-1",
            "a:b",
            "::1",
            "fe80::",
            "::a",
            "a::",
        ],
    )
    def test_a_value_the_parser_takes_unquoted_stays_unquoted(self, value: str) -> None:
        """Each of these was accepted unquoted on 8.0.2: a word that only
        starts like an operator, a negative number, and the IPv6 forms that
        start or end with two colons."""
        assert sanitize_filter_value(value) == value


class TestLikePattern:
    """``like_filter_pattern`` writes the ``%...%`` literal for ``contains``."""

    def test_plain_value_is_wrapped_in_wildcards(self) -> None:
        assert like_filter_pattern("Botnet") == '"%Botnet%"'

    def test_backslash_is_doubled(self) -> None:
        """Under ``like`` a doubled backslash is one literal backslash (measured)."""
        assert like_filter_pattern("path\\to") == '"%path\\\\to%"'

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("j_doe", '"%j\\_doe%"'), ("50%", '"%50\\%%"')],
        ids=["underscore", "percent"],
    )
    def test_wildcard_characters_in_the_value_are_escaped(self, value: str, expected: str) -> None:
        """Bare ``%`` and ``_`` are wildcards; ``\\%`` and ``\\_`` are the characters (measured)."""
        assert like_filter_pattern(value) == expected

    def test_a_trailing_backslash_is_fine_here(self) -> None:
        """The wildcard follows it, so the closing quote is not the next character."""
        assert like_filter_pattern("accept\\") == '"%accept\\\\%"'

    def test_stored_reason_value(self) -> None:
        assert like_filter_pattern(STORED_REASON) == (
            "'%Server 192.0.2.10 replied \\\\\"non-existing domain\\\\\"%'"
        )

    def test_both_quote_characters_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="both quote characters"):
            like_filter_pattern('it\'s "x"')

    def test_empty_value_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="cannot be empty"):
            like_filter_pattern("", "attack")

    @pytest.mark.parametrize(
        ("value", "expected"),
        [(" value ", '"% value %"'), ("  ", '"%  %"')],
        ids=["surrounding-spaces", "spaces-only"],
    )
    def test_whitespace_is_part_of_the_substring(self, value: str, expected: str) -> None:
        """A substring is matched as given; stripping it would widen the match."""
        assert like_filter_pattern(value) == expected

    def test_control_character_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="control character"):
            like_filter_pattern("DN\nS")
