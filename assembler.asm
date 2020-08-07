
%include "common.asm"

section .data
    bufsize          dw 8192
    filename         db "testfile.asm",0

    instruction_len  dw 0
    machine_code_len dw 0
    dummy_str_len    dw 0

    op1_has_base     db 0

    op1_reg_len     dw 0
    op1_scale_len   dw 0
    op1_index_len   dw 0
    op1_base_len    dw 0
    op1_disp_len    dw 0
    op1_size_declr_len  dw 0

    INST_STC        db  "stc",0
    INST_CLC        db  "clc",0
    INST_STD        db  "std",0
    INST_CLD        db  "cld",0

    INST_SYSCALL    db  "syscall",0

    INST_LEAVE      db  "leave",0

    INST_NOT        db  "not ",0

section .bss
    buf             resb 8192
    datasize        resq 1
    file_descriptor resq 1

    instruction     resb 200
    machine_code    resb 200

    strcmp_len      resb 1

    dummy_str       resb 100
    op1_reg         resb 3
    op1_type        resb 1                      ; 0: reg, 1: mem, 2: immediate
    op1_scale       resb 1
    op1_index       resb 3
    op1_base        resb 3
    op1_disp        resb 8
    op1_size_declr  resb 5

section .text
    global _start

; ========== UTILS ==========
compare_strings:
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
    ret

clear_memory:                                ; clears starting from rax to len rbx
    push rcx
    xor rcx, rcx
    clear_char:
        cmp rcx, rbx
        jae clear_memory_end

        mov byte [rax + rcx], 0
        inc rcx

    clear_memory_end:
    pop rcx
    ret

memcpy:                                  ; copies from rsi to rdi with len rbx
    push rcx
    xor rcx, rcx
    memcpy_loop:
        cmp rcx, rbx
        jae memcpy_end

        mov r8b, [rsi + rcx]
        mov byte [rdi + rcx], r8b
        inc rcx
        jmp memcpy_loop

    memcpy_end:
    pop rcx
    ret

is_hex:                                  ; checks for numerical hex value in [rax]
    cmp byte [rax], "0"
    je is_hex_test_x
    mov rax, 0
    ret

    is_hex_test_x:
    cmp byte [rax+1], "x"
    je is_hex_true
    mov rax, 0
    ret

    is_hex_true:
    mov rax, 1
    ret

is_numeric:                                  ; checks for numerical hex value in [rax] to len rbx
    push rcx
    xor rcx, rcx
    check_char:
        cmp rcx, rbx
        jae is_numeric_true

        cmp byte [rax + rcx], "9"
        ja is_numeric_false

        cmp byte [rax + rcx], "0"
        jb is_numeric_false

        inc rcx
        jmp check_char

    is_numeric_false:
    mov rax, 0
    pop rcx
    ret

    is_numeric_true:
    mov rax, 1
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
    mov rax, instruction
    mov bx, [instruction_len]
    call clear_memory
    mov word [instruction_len], 0

    mov rax, machine_code
    mov bx, [machine_code_len]
    call clear_memory
    mov word [machine_code_len], 0

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

assemble_instruction:
    push rcx

    call assemble_zero_operand_instructions
    call assemble_single_operand_instructions

    pop rcx
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

    mov rax, INST_LEAVE
    mov byte [strcmp_len], INST_LEAVE_LEN
    call compare_strings
    je call_assemble_leave

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

    call_assemble_leave:
    mov byte [machine_code], INST_LEAVE_OPCODE
    mov word [machine_code_len], INST_LEAVE_OPCODE_LEN
    ret

assemble_single_operand_instructions:
    mov rax, INST_NOT
    mov byte [strcmp_len], INST_NOT_LEN
    call compare_strings
    je call_assemble_not
    ret

    call_assemble_not:
    call assemble_not
    ret

assemble_not:
    call process_size_declaration
    call process_operand_1
    ret

process_size_declaration:
    push rcx
    mov rax, op1_size_declr
    xor rbx, rbx
    mov bx, [op1_size_declr_len]
    call clear_memory
    xor rbx, rbx

    size_declr_loop:
        cmp byte [instruction + rcx] , " "
        je size_declr_break

        mov dl, [instruction + rcx]
        mov byte [op1_size_declr + rbx], dl

        inc rbx
        inc rcx
        jmp size_declr_loop

    size_declr_break:
    mov [op1_size_declr_len], bx
    call is_op1_size_declr_valid

    cmp rax, 1
    jne invalid_size_declr
    mov rdx, rcx
    pop rcx
    mov rcx, rdx
    ret

    invalid_size_declr:
    pop rcx
    ret

is_op1_size_declr_valid:
    cmp byte [op1_size_declr_len], 4
    jne size_declr_five

    cmp dword [op1_size_declr], "byte"
    je size_declr_valid

    cmp dword [op1_size_declr], "word"
    je size_declr_valid

    jmp size_declr_invalid

    size_declr_five:
    cmp byte [op1_size_declr_len], 5
    jne size_declr_invalid

    cmp dword [op1_size_declr], "dwor"
    je size_declr_half_valid

    cmp dword [op1_size_declr], "qwor"
    je size_declr_half_valid

    size_declr_invalid:
    mov rax, 0
    ret

    size_declr_half_valid:
    cmp byte [op1_size_declr + 4], "d"
    jne size_declr_invalid

    size_declr_valid:
    mov rax, 1
    ret

process_operand_1:                                 ; determines op1_*
    cmp byte [instruction + rcx], "["
    jne process_register
    jmp process_memory

    process_register:
    mov byte [op1_type], 0
    call process_register_operand_1
    ret

    process_memory:
    mov rax, instruction
    add rax, rcx
    call is_hex
    cmp rax, 1                               ; immediate data, ow, memory
    je process_immediate_operand_1

    mov byte [op1_type], 1
    call process_memory_operand_1
    ret

    process_immediate_operand_1:
    mov byte [op1_type], 2
    ; fill in this blank
    ret

process_register_operand_1:
    xor rdx, rdx
    inc rcx
    process_register_next_char:
        mov al, [instruction + rcx]
        cmp al, " "
        je process_register_next_char_break
        cmp al, 10
        je process_register_next_char_break

        mov byte [op1_reg + rdx], al
        inc rcx
        inc rdx
        jmp process_register_next_char

    process_register_next_char_break:
    ret

process_memory_operand_1:
    process_memory_next_part:
        cmp byte [instruction + rcx], "]"
        je process_memory_next_part_break
        call process_next_memory_operand_1
        jmp process_memory_next_part
    
    process_memory_next_part_break:
    ret

process_next_memory_operand_1:
    enter 8, 0                     ; to store previous arithmetic operator

    mov rax, dummy_str
    mov bx, [dummy_str_len]
    call clear_memory
    mov word [dummy_str_len], 0

    mov dl , [instruction + rcx]
    mov [rbp-8], dl
    xor rdx, rdx
    inc rcx
    process_next_memory_next_char:
        mov al, [instruction + rcx]
        cmp al, "+"
        je flush_next_memory_operand_1

        mov al, [instruction + rcx]
        cmp al, "*"
        je flush_next_memory_operand_1

        mov al, [instruction + rcx]
        cmp al, "]"
        je flush_next_memory_operand_1

        mov [dummy_str + rdx], al
        inc word [dummy_str_len]
        inc rcx
        inc rdx
        jmp process_next_memory_next_char
    
    flush_next_memory_operand_1:
    cmp byte [rbp-8], "*"
    je flush_has_multiplication

    cmp byte [instruction + rcx], "*"
    je flush_has_multiplication

    mov rax, dummy_str
    call is_hex
    cmp rax, 1                ; is hex, hence [dummy_str] holds the displacement. ow, base
    je flush_displacement

;   flush_base:
    cmp byte [op1_has_base], 1
    je flush_index

    mov byte [op1_has_base], 1
    mov rsi, dummy_str
    mov rdi, op1_base
    xor rbx, rbx
    mov bx, [dummy_str_len]
    mov word [op1_base_len], bx
    call memcpy
    leave
    ret

    flush_has_multiplication:
    mov rax, dummy_str
    xor rbx, rbx
    mov bx, [dummy_str_len]
    call is_numeric
    cmp rax, 1                ; is number, hence [dummy_str] holds the scale. ow, index
    je flush_scale

    flush_index:
    mov rsi, dummy_str
    mov rdi, op1_index
    xor rbx, rbx
    mov bx, [dummy_str_len]
    mov word [op1_index_len], bx
    call memcpy
    leave
    ret

    flush_displacement:
    mov rsi, dummy_str
    mov rdi, op1_disp
    xor rbx, rbx
    mov bx, [dummy_str_len]
    mov word [op1_disp_len], bx
    call memcpy
    leave
    ret

    flush_scale:
    mov rsi, dummy_str
    mov rdi, op1_scale
    xor rbx, rbx
    mov bx, [dummy_str_len]
    mov word [op1_scale_len], bx
    call memcpy
    leave
    ret

close_file:
    mov rax, SYS_CLOSE
    mov rdi, [file_descriptor]
    syscall

    ret
