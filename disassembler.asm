%include "common.asm"

%define INST_STC  0xf9
%define INST_CLC  0xf8
%define INST_STD  0xfd
%define INST_CLD  0xfc
%define INST_SYSCALL 0x0f05
%define INST_LEAVE 0xc9

section .data
    bufsize          dw 8192
    filename         db "out.o",0
    outfile          db "out.asm",0

    instruction_len db 0

section .bss
    buf             resb 8192
    datasize        resq 1
    file_descriptor resq 1
    out_file_descriptor resq 1
    instruction     resb 8

section .text
    global _start

_start:
    call open_file
    call read_file
    call disassemble_file
    call close_file

exit:
    mov rax, SYS_EXIT
    mov rdi, EXIT_SUCCESS
    syscall
    ret

open_file:
    mov rax, SYS_OPEN
    mov rdi, filename
    mov rsi, READONLY_ACCESS
    mov rdx, RWX_PERM
    syscall
    mov qword [file_descriptor], rax

    mov rax, SYS_OPEN
    mov rdi, outfile
    mov rsi, RW_CREAT
    mov rdx, RWX_PERM
    syscall
    mov qword [out_file_descriptor], rax

    ret

read_file:
    mov rax, SYS_READ
    mov rdi, [file_descriptor]
    mov rsi, buf
    mov rdx, bufsize
    syscall
    mov [datasize], rax

    ret

disassemble_file:
    xor rcx, rcx
    main_loop:
        cmp rcx, [datasize]
        jae main_loop_break

        cmp byte [buf + rcx], INST_STC
        je call_disassemble_stc

        cmp byte [buf + rcx], INST_CLC
        je call_disassemble_clc

        cmp byte [buf + rcx], INST_STD
        je call_disassemble_std

        cmp byte [buf + rcx], INST_CLD
        je call_disassemble_cld

        cmp byte [buf + rcx], INST_LEAVE
        je call_disassemble_leave

        cmp word [buf + rcx], INST_SYSCALL
        je call_disassemble_syscall

        jmp main_loop_next

        call_disassemble_stc:
        call disassemble_stc
        jmp main_loop_next

        call_disassemble_clc:
        call disassemble_clc
        jmp main_loop_next

        call_disassemble_std:
        call disassemble_std
        jmp main_loop_next

        call_disassemble_cld:
        call disassemble_cld
        jmp main_loop_next

        call_disassemble_syscall:
        call disassemble_syscall
        jmp main_loop_next

        call_disassemble_leave:
        call disassemble_leave
        jmp main_loop_next

        main_loop_next:
        inc rcx
        jmp main_loop
    
    main_loop_break:
    ret

disassemble_stc:
    mov word [instruction], "st"
    mov byte [instruction+2], "c"
    mov byte [instruction_len], 3
    call output_instruction
    ret

disassemble_clc:
    mov word [instruction], "cl"
    mov byte [instruction+2], "c"
    mov byte [instruction_len], 3
    call output_instruction
    ret

disassemble_std:
    mov word [instruction], "st"
    mov byte [instruction+2], "d"
    mov byte [instruction_len], 3
    call output_instruction
    ret

disassemble_cld:
    mov word [instruction], "cl"
    mov byte [instruction+2], "c"
    mov byte [instruction_len], 3
    call output_instruction
    ret

disassemble_leave:
    mov dword [instruction], "leav"
    mov byte [instruction+4], "e"
    mov byte [instruction_len], 5
    call output_instruction
    ret

disassemble_syscall:
    mov dword [instruction], "sysc"
    mov word [instruction+4], "al"
    mov word [instruction+6], "l"
    mov byte [instruction_len], 7
    call output_instruction
    ret

output_instruction:
    push rcx
    mov rax, SYS_WRITE
    mov rdi, [out_file_descriptor]
    mov rsi, instruction
    xor rdx, rdx
    mov dl, [instruction_len]
    syscall
    pop rcx
    ret

close_file:
    mov rax, SYS_CLOSE
    mov rdi, [file_descriptor]
    syscall

    mov rax, SYS_CLOSE
    mov rdi, [out_file_descriptor]
    syscall

    ret
