# This program tests passwords using a word list.
#
# 1. Lets the user pick a hashing method.
# 2. Hashes a password.
# 3. Checks if the password matches the hash.
# 4. Loads passwords from rockyou.txt.
# 5. Tries those passwords against the hash.


# Used for password hashing.
from passlib.context import CryptContext

# Used to open the word list file.
from pathlib import Path

# Used to keep track of time.
import time


# Hash setup

hash_tool = CryptContext(
    schemes=[
        "argon2",
        "bcrypt",
        "pbkdf2_sha256",
        "scrypt"
    ],
    deprecated="auto"
)


# Make a hash

def make_hash(password, method):
    """
    Takes a password and turns it into a hash.
    """

    # Make sure the hash method is supported.
    if method not in hash_tool.schemes():
        raise ValueError("Unsupported method: " + method)

    # Make the hash.
    password_hash = hash_tool.hash(
        password,
        scheme=method
    )

    # Give the hash back.
    return password_hash


# Check a password

def check_password(password, password_hash):
    """
    Checks if a password matches a hash.
    """

    # Check the password against the hash.
    match = hash_tool.verify(password, password_hash)

    # Give back True or False.
    return match


# Load the word list

def load_words(file_name):
    """
    Loads passwords from a word list file.
    """

    # Find the file.
    file = Path(file_name)

    # Read the file.
    text = file.read_text(
        encoding="utf-8",
        errors="ignore"
    )

    # Make an empty list for the passwords.
    words = []

    # Go through every line in the file.
    for line in text.splitlines():

        # Remove extra spaces.
        word = line.strip()

        # Add the word if the line is not empty.
        if word:
            words.append(word)

    # Give back the list of words.
    return words


# Dictionary attack

def dictionary_attack(password_hash, words, limit=100000):
    """
    Tries each password from the word list.

    Stops if:
    1. The password is found.
    2. The guess limit is reached.
    3. There are no more words to try.
    """

    # Number of guesses tried.
    tries = 0

    # Save the time the attack started.
    start = time.time()

    # Go through each word in the list.
    for word in words:

        # Remove extra spaces.
        word = word.strip()

        # Skip empty lines.
        if not word:
            continue

        # Add one to the number of tries.
        tries += 1

        # Check the guess limit.

        if tries > limit:

            # Find how much time has passed.
            seconds = time.time() - start

            # Find how many guesses were made each second.
            if seconds > 0:
                speed = tries / seconds
            else:
                speed = tries

            return (
                "Stopped after " + str(tries - 1) + " guesses.\n"
                + "Time: " + str(round(seconds, 2)) + "s | "
                + "Speed: " + str(round(speed)) + " guesses/sec"
            )

        # Show progress.

        # Print progress every 10,000 guesses.
        if tries % 10000 == 0:

            # Find how much time has passed.
            seconds = time.time() - start

            # Find the guessing speed.
            if seconds > 0:
                speed = tries / seconds
            else:
                speed = tries

            print(
                "Tried " + str(tries) + " guesses... "
                + "(" + str(round(speed)) + " guesses/sec)"
            )

        # Check the current password.

        if check_password(word, password_hash):

            # Find how much time passed.
            seconds = time.time() - start

            # Find the guessing speed.
            if seconds > 0:
                speed = tries / seconds
            else:
                speed = tries

            return (
                "Password found: '" + word + "' after "
                + str(tries) + " guesses.\n"
                + "Time: " + str(round(seconds, 2)) + "s | "
                + "Speed: " + str(round(speed)) + " guesses/sec"
            )

    # No password was found.

    # Find the total time.
    seconds = time.time() - start

    # Find the guessing speed.
    if seconds > 0:
        speed = tries / seconds
    else:
        speed = tries

    return (
        "No password found after " + str(tries) + " guesses.\n"
        + "Time: " + str(round(seconds, 2)) + "s | "
        + "Speed: " + str(round(speed)) + " guesses/sec"
    )


# Main program

def main():
    """
    Runs the program.
    """

    # Pick a hash method.

    print("Supported hash methods:")
    print(", ".join(hash_tool.schemes()))

    method = input(
        "\nPick one "
        "(argon2, bcrypt, pbkdf2_sha256, scrypt): "
    ).strip()

    # Enter a password.

    password = input(
        "Enter a test password to hash: "
    ).strip()

    # Make the password hash.
    password_hash = make_hash(
        password,
        method
    )

    print("\nPassword hash:")
    print(password_hash)

    # Check the password.

    test_password = input(
        "\nEnter the password again: "
    ).strip()

    if check_password(test_password, password_hash):
        print("Password matches!")
    else:
        print("Wrong password.")

    # Load the word list.

    file_name = "rockyou.txt"

    try:

        # Load the passwords from the file.
        words = load_words(file_name)

        print(
            "\nLoaded " + str(len(words))
            + " passwords from " + file_name
        )

    except FileNotFoundError:

        print("\nWord list not found.")
        print(
            "Make sure rockyou.txt is in the same folder "
            "as this program."
        )

        return

    # Pick the guess limit.

    limit_text = input(
        "\nHow many guesses should be tried? "
        "(Press Enter for 50000): "
    ).strip()

    if limit_text:
        limit = int(limit_text)
    else:
        limit = 50000

    # Start the attack.

    print("\nRunning dictionary attack...")

    answer = dictionary_attack(
        password_hash,
        words,
        limit
    )

    # Print the final answer.
    print(answer)


# Start the program

# Run main() when this file is opened directly.
if __name__ == "__main__":
    main()