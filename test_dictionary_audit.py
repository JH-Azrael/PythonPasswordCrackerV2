from realworld_dictionary_audit import (
    hash_tool,
    make_hash,
    check_password,
    load_words,
    dictionary_attack
)


# Test hash setup

def test_hash_methods():
    """
    Makes sure the hashing methods we want are loaded.
    """

    methods = hash_tool.schemes()

    assert "argon2" in methods
    assert "bcrypt" in methods
    assert "pbkdf2_sha256" in methods
    assert "scrypt" in methods


# Test make_hash()

def test_make_hash():
    """
    Makes sure make_hash() creates a hash.
    """

    password = "test123"

    password_hash = make_hash(
        password,
        "pbkdf2_sha256"
    )

    # The result should be a string.
    assert isinstance(password_hash, str)

    # The hash should not be the same as the password.
    assert password_hash != password


def test_make_hash_bad_method():
    """
    Makes sure an unsupported hash method causes an error.
    """

    try:
        make_hash(
            "test123",
            "fake_method"
        )

        # If no error happened, fail the test.
        assert False

    except ValueError:

        # The correct error happened.
        assert True


# Test check_password()

def test_check_password_correct():
    """
    Makes sure the correct password matches its hash.
    """

    password = "pirate123"

    password_hash = make_hash(
        password,
        "pbkdf2_sha256"
    )

    result = check_password(
        password,
        password_hash
    )

    assert result == True


def test_check_password_wrong():
    """
    Makes sure the wrong password does not match.
    """

    password_hash = make_hash(
        "pirate123",
        "pbkdf2_sha256"
    )

    result = check_password(
        "wrongpassword",
        password_hash
    )

    assert result == False


# Test load_words()

def test_load_words(tmp_path):
    """
    Makes sure passwords are loaded from a file.
    """

    # Make a temporary word list.
    file = tmp_path / "words.txt"

    file.write_text(
        "password\n"
        "hello123\n"
        "pirate\n"
    )

    # Load the file.
    words = load_words(str(file))

    # Make sure the words were loaded correctly.
    assert words == [
        "password",
        "hello123",
        "pirate"
    ]


def test_load_words_skips_empty_lines(tmp_path):
    """
    Makes sure blank lines are ignored.
    """

    file = tmp_path / "words.txt"

    file.write_text(
        "password\n"
        "\n"
        "pirate\n"
        "\n"
    )

    words = load_words(str(file))

    assert words == [
        "password",
        "pirate"
    ]


def test_load_words_missing_file():
    """
    Makes sure a missing file causes an error.
    """

    try:
        load_words("this_file_does_not_exist.txt")

        assert False

    except FileNotFoundError:
        assert True


# Test dictionary_attack()

def test_dictionary_attack_finds_password():
    """
    Makes sure the attack can find the correct password.
    """

    password = "pirate"

    password_hash = make_hash(
        password,
        "pbkdf2_sha256"
    )

    words = [
        "password",
        "hello",
        "pirate",
        "computer"
    ]

    result = dictionary_attack(
        password_hash,
        words,
        100
    )

    assert "Password found" in result
    assert "pirate" in result


def test_dictionary_attack_wrong_password():
    """
    Makes sure the program reports when no password is found.
    """

    password_hash = make_hash(
        "pirate",
        "pbkdf2_sha256"
    )

    words = [
        "password",
        "hello",
        "computer"
    ]

    result = dictionary_attack(
        password_hash,
        words,
        100
    )

    assert "No password found" in result


def test_dictionary_attack_limit():
    """
    Makes sure the attack stops when it reaches the guess limit.
    """

    password_hash = make_hash(
        "pirate",
        "pbkdf2_sha256"
    )

    words = [
        "one",
        "two",
        "three",
        "four",
        "five"
    ]

    result = dictionary_attack(
        password_hash,
        words,
        2
    )

    assert "Stopped after 2 guesses" in result


# Test empty word list

def test_dictionary_attack_empty_list():
    """
    Makes sure an empty word list does not crash the program.
    """

    password_hash = make_hash(
        "pirate",
        "pbkdf2_sha256"
    )

    words = []

    result = dictionary_attack(
        password_hash,
        words,
        100
    )

    assert "No password found after 0 guesses" in result