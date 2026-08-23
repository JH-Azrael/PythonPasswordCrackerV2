# realworld_dictionary_audit.py
# Safe password auditing demo: hashes a test password using a real-world scheme,
# then runs a dictionary audit using a wordlist file you provide.

from passlib.context import CryptContext
from pathlib import Path
import time

# Real-world password hashing schemes (self-describing hash strings)
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt", "pbkdf2_sha256", "scrypt"],
    deprecated="auto",
)

def make_hash(password: str, scheme: str) -> str:
    """Hash a password using a selected real-world scheme."""
    if scheme not in pwd_context.schemes():
        raise ValueError(f"Unsupported scheme: {scheme}")
    return pwd_context.hash(password, scheme=scheme)



def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored hash (scheme auto-detected)."""
    return pwd_context.verify(password, stored_hash)




def load_wordlist(filename: str) -> list[str]:
    """
    Load guesses from a wordlist file (one per line).
    Ignores blank lines. Uses errors='ignore' to handle weird characters.
    """
    path = Path(filename)
    text = path.read_text(encoding="utf-8", errors="ignore")
    guesses = [line.strip() for line in text.splitlines() if line.strip()]
    return guesses




def dictionary_attack(stored_hash: str, guesses: list[str], max_guesses: int = 100_000) -> str:
    """
    Dictionary audit demo:
    tries each guess and checks whether it matches the hash.
    Prints progress every 10,000 attempts so it doesn't look frozen.
    """
    attempts = 0
    start = time.time()

    for guess in guesses:
        guess = guess.strip()
        if not guess:
            continue

        attempts += 1
        if attempts > max_guesses:
            elapsed = time.time() - start
            rate = attempts / elapsed if elapsed > 0 else attempts
            return (
                f"Stopped after {attempts-1} guesses (hit max_guesses).\n"
                f"Time: {elapsed:.2f}s | Rate: {rate:.0f} guesses/sec"
            )

        if attempts % 10_000 == 0:
            elapsed = time.time() - start
            rate = attempts / elapsed if elapsed > 0 else attempts
            print(f"Tried {attempts:,} guesses... ({rate:.0f} guesses/sec)")

        if verify_password(guess, stored_hash):
            elapsed = time.time() - start
            rate = attempts / elapsed if elapsed > 0 else attempts
            return (
                f"Match found: '{guess}' after {attempts} guesses.\n"
                f"Time: {elapsed:.2f}s | Rate: {rate:.0f} guesses/sec"
            )

    elapsed = time.time() - start
    rate = attempts / elapsed if elapsed > 0 else attempts
    return (
        f"No match found after {attempts} guesses.\n"
        f"Time: {elapsed:.2f}s | Rate: {rate:.0f} guesses/sec"
    )

def main():
    print("Supported real-world schemes:")
    print(", ".join(pwd_context.schemes()))

    scheme = input("\nPick one (argon2, bcrypt, pbkdf2_sha256, scrypt): ").strip()

    # You generate the hash locally for a test password you control.
    real_password = input("Enter a test password to hash: ").strip()
    stored_hash = make_hash(real_password, scheme)

    print("\nStored hash (contains scheme + salt + parameters):")
    print(stored_hash)

    # Optional verification demo
    test = input("\nRe-enter password to verify: ").strip()
    print("Verified!" if verify_password(test, stored_hash) else "Wrong password.")

    # Wordlist file prompt (your change request)
    wordlist_file = "rockyou.txt"

    try:
        guesses = load_wordlist(wordlist_file)
        print(f"Loaded {len(guesses):,} guesses from {wordlist_file}")
    except FileNotFoundError:
        print("Wordlist file not found. Make sure it’s in the same folder as this script, or give a full path.")
        return




    # Optional cap (helps if the list is massive)
    max_str = input("Max guesses to try (press Enter for 50000): ").strip()
    max_guesses = int(max_str) if max_str else 50_000




    print("\nRunning dictionary attack...")
    print(dictionary_attack(stored_hash, guesses, max_guesses=max_guesses))

if __name__ == "__main__":
    main()