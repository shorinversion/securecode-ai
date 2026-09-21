from securecode_ai.adapters.github_api import repository_path


def test_repository_encoding_is_path_safe() -> None:
    assert repository_path("a/b", "x y") == "/repos/a%2Fb/x%20y"
