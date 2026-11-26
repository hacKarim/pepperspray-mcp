from pepperspray.tools.flag_tools import extract_flags, validate_flag


def test_extract_default_flagbrace():
    flags = extract_flags("noise flag{abc_123} more")
    assert "flag{abc_123}" in flags


def test_extract_custom_prefix_and_hash():
    out = extract_flags("CTF{win} and 5d41402abc4b2a76b9719d911017c592")
    assert "CTF{win}" in out
    assert "5d41402abc4b2a76b9719d911017c592" in out  # md5


def test_validate_accepts_flag_formats():
    assert validate_flag("flag{ok}") is True
    assert validate_flag("myctf{ok}") is True


def test_validate_rejects_garbage():
    assert validate_flag("just text") is False
    assert validate_flag("flag{}") is False
