
%include "common.asm"

section .data
    bufsize         dw  8192
    filename        db  "testfile.asm",0

    instruction_len dw  0
    machine_code_len dw 0

    INST_STC        db  "stc",0
    INST_CLC        db  "clc",0
    INST_STD        db  "std",0
    INST_CLD        db  "cld",0

    INST_SYSCALL    db  "syscall",0

section .bss
    buf             resb 8192
    datasize        resq 1
    file_descriptor resq 1

    instruction     resb 200
    machine_code    resb 200

    strcmp_len      resb 1

section .text
    global _start

; ========== UTILS ==========
compare_strings:
    push rcx
    push rdx
    xor rcx, rcx
    strcmp_loop:
        mov dl, [rbx + rcx]
        cmp dl, [rax + rcx]
        jne strcmp_end

        inc rcx
        cmp cl, [strcmp_len]
        je strcmp_end

        jmp strcmp_loop

    strcmp_end:
    pop rdx
    pop rcx
    ret

; ========= File IO =========
_start:
    call open_file
    call read_file
    call assemble_file
    call close_file

exit:
    mov rax, SYS_EXIT
    mov rdi, EXIT_SUCCESS
    syscall

open_file:
    mov rax, SYS_OPEN
    mov rdi, filename
    mov rsi, READONLY_ACCESS
    mov rdx, RWX_PERM
    syscall
    mov qword [file_descriptor], rax

    ret

read_file:
    mov rax, SYS_READ
    mov rdi, [file_descriptor]
    mov rsi, buf
    mov rdx, bufsize
    syscall
    mov [datasize], rax

    ret

assemble_file:
    xor rcx, rcx                                ; character pointer on buf
    main_loop:
        call read_instruction
        call assemble_instruction

        cmp qword rcx, [datasize]
        jl main_loop

    ret

read_instruction:
    call clear_instruction
    xor rax, rax
    next_char:
        mov rdx, [buf + rcx]
        mov [instruction + rax], rdx

        inc rcx
        inc rax

        cmp byte [buf + rcx], 10                    ; newline
        je read_instruction_end

        cmp qword rcx, [datasize]
        jl next_char
    
    read_instruction_end:
    inc rcx                                    ; skip over newline for next iteration
    mov word [instruction_len], ax
    ret

clear_instruction:
    push rcx
    xor rcx, rcx
    clear_char:
        cmp rcx, [instruction_len]
        jae clear_instruction_end

        mov byte [instruction + rcx], 0
        inc rcx
    
    clear_instruction_end:
    mov word [instruction_len], 0
    pop rcx

    ret

assemble_instruction:
    call assemble_zero_operand_instructions
    ret

; ========== ZERO OPERANDS ==========
assemble_zero_operand_instructions:
    mov rbx, instruction

    mov rax, INST_STC
    mov byte [strcmp_len], INST_STC_LEN
    call compare_strings
    je call_assemble_stc

    mov rax, INST_CLC
    mov byte [strcmp_len], INST_CLC_LEN
    call compare_strings
    je call_assemble_clc

    mov rax, INST_STD
    mov byte [strcmp_len], INST_STD_LEN
    call compare_strings
    je call_assemble_std

    mov rax, INST_CLD
    mov byte [strcmp_len], INST_CLD_LEN
    call compare_strings
    je call_assemble_cld

    mov rax, INST_SYSCALL
    mov byte [strcmp_len], INST_SYSCALL_LEN
    call compare_strings
    je call_assemble_syscall

    ret                                        ; return in case instruction is not one of STC, CLC, STD, CLD

    call_assemble_stc:
    mov byte [machine_code], INST_STC_OPCODE
    mov word [machine_code_len], INST_STC_OPCODE_LEN
    ret

    call_assemble_clc:
    mov byte [machine_code], INST_CLC_OPCODE
    mov word [machine_code_len], INST_CLC_OPCODE_LEN
    ret

    call_assemble_std:
    mov byte [machine_code], INST_STD_OPCODE
    mov word [machine_code_len], INST_STD_OPCODE_LEN
    ret

    call_assemble_cld:
    mov byte [machine_code], INST_CLD_OPCODE
    mov word [machine_code_len], INST_CLD_OPCODE_LEN
    ret

    call_assemble_syscall:
    mov word [machine_code], INST_SYSCALL_OPCODE
    mov word [machine_code_len], INST_SYSCALL_OPCODE_LEN
    ret

close_file:
    mov rax, SYS_CLOSE
    mov rdi, [file_descriptor]
    syscall

    ret
