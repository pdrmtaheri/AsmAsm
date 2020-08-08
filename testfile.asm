inc r15
idiv qword [r12*4]
jmp r9
jmp [r9+r12*8]
neg r14
not qword [r13]
call r10
call [r10+r11*8]
syscall
ret