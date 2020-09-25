import requests
import hashlib
import sys
from requests.models import Response


def data_request_pwned_api(data: str):
    url = f'https://api.pwnedpasswords.com/range/{data}'
    response = requests.get(url)
    response_code = response.status_code
    if response_code != 200:
        raise RuntimeError(f"Error: {response_code}, check your api url")
    return response


def print_response(response: Response):
    print(response.text)


def check_pwned_api(password: str):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_five_characters, remaining = sha1_password[:5], sha1_password[5:]
    response = data_request_pwned_api(first_five_characters)
    return get_count_from_password_leaks(response, remaining)


def get_count_from_password_leaks(hash: Response, hash_to_check: str):
    lst = (line.split(':') for line in hash.text.splitlines())
    for h, count in lst:
        if h == hash_to_check:
            return count or 0


def main(args: list = ["python"]):
    password = args[0]
    count = check_pwned_api(password)
    print(f"Good news, the password \"{password}\" was not found."
          ) if count is None else print(
              f"Oh no... the password \"{password}\" was found {count} times")


if __name__ == "__main__":
    password = sys.argv[1:2]
    main() if len(password) == 0 else main(password)
