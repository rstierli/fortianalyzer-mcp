"""A filter value that is a damaged or foreign masking token refuses the filter.

A token that does not open is left as written in a filter clause. FortiAnalyzer
then compares the field against the token text, nothing matches, and under a
negated operator that is every row. The first refusal looked only at a value
that is v2-shaped as a whole or ends in the mask suffix. A token that lost its
tag, lost or gained one character, picked up a character nobody sees, or sits
as the host of a URL is none of those, and went out.
"""

from collections.abc import Callable

import pytest

from fortianalyzer_mcp.masking.fpe_engine import FPEEngine
from fortianalyzer_mcp.masking.unmask import ArgUnmasker
from fortianalyzer_mcp.masking.wrapper import OutputMasker
from fortianalyzer_mcp.utils.errors import ValidationError

KEY = "2DE79D232DF5585D68CE47882AE256D6"
OTHER_KEY = "00112233445566778899AABBCCDDEEFF"


@pytest.fixture
def engine() -> FPEEngine:
    """The server's engine as it is by default: the v1 window closed."""
    return FPEEngine(KEY, accept_v1_tokens=False)


@pytest.fixture
def other() -> FPEEngine:
    """An engine under another key, as before a key rotation."""
    return FPEEngine(OTHER_KEY, accept_v1_tokens=False)


@pytest.fixture
def unmasker(engine: FPEEngine) -> ArgUnmasker:
    return ArgUnmasker(engine)


def masked_url(engine: FPEEngine, monkeypatch: pytest.MonkeyPatch) -> str:
    """``https://<host token>/<url token>`` as the output side writes it."""
    monkeypatch.setenv("FAZ_MASKING_KEY", KEY)
    return OutputMasker(engine).mask_result({"url": "https://www.example.net/a/b?x=1"})["url"]


#: What a model does to a token it copies. Each takes a whole v2 token.
DAMAGE: dict[str, Callable[[str], str]] = {
    "the tag dropped": lambda t: t[:-9],
    "the tag cut by one character": lambda t: t[:-1],
    "a character after the tag": lambda t: t + "x",
    "a dot after the tag": lambda t: t + ".",
    "a zero-width space after it": lambda t: t + "​",
    "a zero-width joiner before it": lambda t: "‍" + t,
    "a byte-order mark inside it": lambda t: t[:6] + "﻿" + t[6:],
}
DAMAGED = pytest.mark.parametrize("damage", DAMAGE.values(), ids=DAMAGE.keys())
COMPARISON = pytest.mark.parametrize("template", ['user!="{v}"', 'user=="{v}"', "user!={v}"])


class TestADamagedTokenRefusesTheFilter:
    @DAMAGED
    @COMPARISON
    def test_the_servers_own_token(
        self, unmasker: ArgUnmasker, engine: FPEEngine, damage: Callable[[str], str], template: str
    ) -> None:
        value = damage(engine.mint("username", "jsmith"))

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(template.format(v=value))

    @DAMAGED
    @COMPARISON
    def test_a_token_from_another_key(
        self, unmasker: ArgUnmasker, other: FPEEngine, damage: Callable[[str], str], template: str
    ) -> None:
        value = damage(other.mint("username", "jsmith"))

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(template.format(v=value))

    @pytest.mark.parametrize("window_open", [False, True], ids=["v1-closed", "v1-open"])
    @DAMAGED
    def test_a_foreign_token_is_refused_whatever_the_v1_window(
        self, other: FPEEngine, damage: Callable[[str], str], window_open: bool
    ) -> None:
        unmasker = ArgUnmasker(FPEEngine(KEY, accept_v1_tokens=window_open))
        value = damage(other.mint("username", "jsmith"))

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(f'user!="{value}"')

    @pytest.mark.parametrize("who", ["own", "foreign"])
    def test_a_domain_token_with_a_trailing_dot(
        self, unmasker: ArgUnmasker, engine: FPEEngine, other: FPEEngine, who: str
    ) -> None:
        token = (engine if who == "own" else other).mask_domain("example.com")

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(f'hostname!="{token}."')

    @pytest.mark.parametrize(
        "pattern", ["_{t}", "{t}_", "%_{t}%", "__{t}"], ids=["before", "after", "inside", "two"]
    )
    @pytest.mark.parametrize("who", ["own", "foreign"])
    def test_a_token_beside_the_one_character_wildcard_of_like(
        self, unmasker: ArgUnmasker, engine: FPEEngine, other: FPEEngine, who: str, pattern: str
    ) -> None:
        """``_`` continues a name, so the token after it is not found as one,
        and the pattern goes out with the token text in it."""
        token = (engine if who == "own" else other).mint("username", "jsmith")

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(f'user like "{pattern.format(t=token)}"')

    def test_the_refusal_names_no_value_and_says_what_it_can_be(
        self, unmasker: ArgUnmasker, other: FPEEngine
    ) -> None:
        cut = other.mint("username", "jsmith")[:-1]

        with pytest.raises(ValidationError) as refused:
            unmasker.unmask_filter(f'user!="{cut}"')

        message = str(refused.value)
        assert cut not in message and "jsmith" not in message
        assert "another key" in message and "altered" in message
        assert "the filter was not sent" in message


class TestATokenWhereTheResolverExpectsOne:
    """A URL, a ``host:port`` pair and a prefixed group-by value are resolved in
    parts. A part that is a token and does not open left the whole value as
    written, and the whole value is not token-shaped."""

    def test_a_foreign_host_token_in_a_url(
        self, unmasker: ArgUnmasker, other: FPEEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        url = masked_url(other, monkeypatch)

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(f'url!="{url}"')

    def test_a_damaged_host_token_in_a_url(self, unmasker: ArgUnmasker, engine: FPEEngine) -> None:
        host = engine.mint("hostname", "edge-fw-01")[:-1]

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(f'url!="https://{host}/index.html"')

    def test_a_foreign_domain_token_as_the_host_of_a_url(
        self, unmasker: ArgUnmasker, other: FPEEngine
    ) -> None:
        host = other.mask_domain("example.com")

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(f'url!="https://{host}/index.html"')

    def test_a_foreign_path_token_behind_a_plain_host(
        self, unmasker: ArgUnmasker, other: FPEEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tail = masked_url(other, monkeypatch).rsplit("/", 1)[1]

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(f'url!="https://www.example.org/{tail}"')

    def test_a_foreign_host_token_with_a_port(
        self, unmasker: ArgUnmasker, other: FPEEngine
    ) -> None:
        host = other.mint("hostname", "edge-fw-01")

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(f'hostname!="{host}:8443"')

    def test_the_servers_own_host_token_with_a_port_is_refused_and_not_sent(
        self, unmasker: ArgUnmasker, engine: FPEEngine
    ) -> None:
        """The resolver does not open a ``host-`` token that a port follows
        (a domain token or an address token it does). Until it does, the
        filter is refused: sent, the token text would match nothing."""
        host = engine.mint("hostname", "edge-fw-01")

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(f'hostname!="{host}:8443"')

    def test_a_foreign_path_token_without_a_host(
        self, unmasker: ArgUnmasker, other: FPEEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tail = masked_url(other, monkeypatch).rsplit("/", 1)[1]

        for url in (f"/{tail}", f"www.example.org/{tail}"):
            with pytest.raises(ValidationError, match="did not resolve"):
                unmasker.unmask_filter(f'url!="{url}"')

    def test_a_foreign_token_behind_a_group_by_prefix(
        self, unmasker: ArgUnmasker, other: FPEEngine
    ) -> None:
        token = other.mint("username", "jsmith")

        with pytest.raises(ValidationError, match="did not resolve"):
            unmasker.unmask_filter(f'groupby1!="user:{token}"')

    def test_a_structured_condition_is_read_the_same_way(
        self, unmasker: ArgUnmasker, other: FPEEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cut = other.mint("username", "jsmith")[:-1]
        url = masked_url(other, monkeypatch)

        for condition in (
            {"field": "user", "op": "ne", "value": cut},
            {"field": "user", "op": "not_in", "value": ["admin", cut + "​"]},
            {"field": "url", "op": "ne", "value": url},
        ):
            with pytest.raises(ValidationError, match="did not resolve"):
                unmasker.unmask_filter_conditions(condition)


class TestWhatStillGoesThrough:
    def test_the_servers_own_tokens_resolve_in_every_position(
        self, unmasker: ArgUnmasker, engine: FPEEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user = engine.mint("username", "jsmith")
        host = engine.mint("hostname", "edge-fw-01")
        domain = engine.mask_domain("example.com")
        url = masked_url(engine, monkeypatch)

        for sent, resolved in [
            (f'user!="{user}"', 'user!="jsmith"'),
            (f"user!={user}", "user!=jsmith"),
            (f'user like "%{user}%"', 'user like "%jsmith%"'),
            (f'hostname!="{domain}"', 'hostname!="example.com"'),
            (f'srcname!="{host}"', 'srcname!="edge-fw-01"'),
            (f'hostname!="{domain}:8443"', 'hostname!="example.com:8443"'),
            (f'groupby1!="user:{user}"', 'groupby1!="user:jsmith"'),
            (f'url!="{url}"', 'url!="https://www.example.net/a/b?x=1"'),
        ]:
            assert unmasker.unmask_filter(sent) == resolved

    @pytest.mark.parametrize(
        "expression",
        [
            'user!="admin"',
            'user!="host-web01"',
            'user!="user-admin"',
            "srcname!=host-fw01-dmz",
            'hostname!="www.example.com."',
            'hostname!="www.example.com:8443"',
            'url!="https://www.example.com/url-shortener/a"',
            'url!="https://host-web01.example.com/a"',
            'url!="https://www.example.com/a//host-web01/b"',
            'url!="/index.html?next=//www.example.com/"',
            'user!="jo\u200dhn"',
            'groupby1!="user:admin"',
            'user like "_dmin"',
            'user like "%\\_svc%"',
            'msg like "%user-agent%"',
            "(action==ssl-login-fail or ((action==login or action==FSS0-auth or "
            "action==NTLM-auth) and (status==failed or status==locked_out))) and user==alice",
        ],
    )
    def test_a_value_that_is_no_token(self, unmasker: ArgUnmasker, expression: str) -> None:
        assert unmasker.unmask_filter(expression) == expression

    def test_a_damaged_token_inside_a_sentence_is_left_as_written(
        self, unmasker: ArgUnmasker, other: FPEEngine
    ) -> None:
        """Only where the resolver expects one whole token. Token-shaped text
        inside prose is mostly not a token."""
        cut = other.mint("username", "jsmith")[:-1]
        expression = f'msg like "%see {cut} for details%"'

        assert unmasker.unmask_filter(expression) == expression

    def test_a_real_name_of_token_shape_is_refused_too(self, unmasker: ArgUnmasker) -> None:
        """The price, and the message names it: a real value written as a
        marker, four hex digits and a rest cannot be told from a token that
        lost its tag."""
        with pytest.raises(ValidationError, match="a real value of that shape"):
            unmasker.unmask_filter('devname!="host-dc01-core"')
