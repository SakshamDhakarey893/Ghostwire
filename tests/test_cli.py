from ghostwire import get_password


def test_provided_password():
    password = get_password(
        "test-password"
    )

    assert password == "test-password"


def test_password_confirmation(monkeypatch):
    answers = iter(
        [
            "test-password",
            "test-password",
        ]
    )

    monkeypatch.setattr(
        "getpass.getpass",
        lambda _: next(answers),
    )

    password = get_password(
        None,
        confirm=True,
    )

    assert password == "test-password"


def test_password_mismatch(monkeypatch):
    answers = iter(
        [
            "password-one",
            "password-two",
        ]
    )

    monkeypatch.setattr(
        "getpass.getpass",
        lambda _: next(answers),
    )

    import pytest

    with pytest.raises(ValueError):
        get_password(
            None,
            confirm=True,
        )