from app.api.routes.ws import AUTH_SUBPROTOCOL, _subprotocol_token


class _Socket:
    def __init__(self, protocols: str = "") -> None:
        self.headers = {"sec-websocket-protocol": protocols}


def test_websocket_token_uses_auth_subprotocol() -> None:
    token, negotiated = _subprotocol_token(
        _Socket(f"{AUTH_SUBPROTOCOL}, signed.jwt.token")  # type: ignore[arg-type]
    )

    assert token == "signed.jwt.token"
    assert negotiated is True


def test_websocket_token_rejects_unmarked_protocol_value() -> None:
    token, negotiated = _subprotocol_token(
        _Socket("signed.jwt.token")  # type: ignore[arg-type]
    )

    assert token is None
    assert negotiated is False
