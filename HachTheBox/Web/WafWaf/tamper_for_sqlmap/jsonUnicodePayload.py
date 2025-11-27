import codecs

def tamper(payload, **kwargs):
    unicodedData = ''

    for char in payload:
        char = codecs.encode(bytes(char, 'utf-8'), "hex")	# convert char to hexadecimal value
        unicodedData += "\\u00" + char.decode('utf-8')   # build the unicode for the char

    # Build the payload
    #payload = "{\"user\":\"%s\"}" % unicodedData

    return unicodedData
