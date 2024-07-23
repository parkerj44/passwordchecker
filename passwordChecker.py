import requests
import hashlib
import sys

def request_data_api(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again.')
    return res

def leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for box, count in hashes:
        if box == hash_to_check:
            return count
    return 0

def pwned_check_api(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5password, remaining = sha1password[:5], sha1password[5:]
    result = request_data_api(first_5password)
    return leak_count(result, remaining)

def main(args):
   for password in args:
       num_of_usage = pwned_check_api(password)
       if num_of_usage:
           print(f'{password} was found {num_of_usage} times you should probably change your password')
       else:
           print(f'{password} was NOT found. Carry on!')

    return 'Finished!'

main(sys.argv[1:])

