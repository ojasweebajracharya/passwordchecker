import requests
import hashlib
import sys

def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + str(query_char)  # only needs first 5 characters of hash function
    # They send us everything beginning with those 5 and then we can check the rest ourselves.
    # They will never know our full password.
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(F"Error fetching: {res.status_code}, check the api and try again.")
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines()) # converted the hashes into tuple with hash and count
    for h, count in hashes:
        if h == hash_to_check:
            return count

    return 0


def pwned_api_check(password):
    # converts password to sha1 hashed version
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    # loop through all the passwords entered
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times. You should change your password. ")
        else:
            print(f"{password} was not found. Carry on! :D")
    return "Done"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:])) # accepts all the arguments entered