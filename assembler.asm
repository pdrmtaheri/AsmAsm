
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

    op_size         db 0
    addr_size       db 0

    op_prefix       db 1
    addr_prefix     db 1
    rex_field       db 1

    INST_STC        db  "stc",0
    INST_CLC        db  "clc",0
    INST_STD        db  "std",0
    INST_CLD        db  "cld",0

    INST_SYSCALL    db  "syscall",0

    INST_LEAVE      db  "leave",0

    INST_NOT        db  "not ",0
    INST_NEG        db  "neg ",0
    INST_IDIV       db  "idiv ",0
    INST_INC        db  "inc ",0
    INST_DEC        db  "dec ",0

section .bss
    buf             resb 8192
    datasize        resq 1
    file_descriptor resq 1

    instruction     resb 200
    machine_code    resb 200

    strcmp_len      resb 1

    dummy_str       resb 100
    op1_reg         resb 4
    op1_type        resb 1                      ; 0: reg, 1: mem, 2: immediate
    op1_scale       resb 1
    op1_index       resb 4
    op1_base        resb 4
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

    call cleanup_previous_instruction
    call assemble_zero_operand_instructions
    call assemble_single_operand_instructions

    pop rcx
    ret

cleanup_previous_instruction:
    mov word [machine_code_len], 0
    mov word [dummy_str_len], 0

    mov word [op1_has_base], 0

    mov word [op1_reg_len], 0
    mov word [op1_scale_len], 0
    mov word [op1_index_len], 0
    mov word [op1_base_len], 0
    mov word [op1_disp_len], 0
    mov word [op1_size_declr_len], 0

    mov byte [op_size], 0
    mov byte [addr_size], 0

    mov byte [op_prefix], 0
    mov byte [addr_prefix], 0
    mov byte [rex_field], 0

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

    mov rax, INST_NEG
    mov byte [strcmp_len], INST_NEG_LEN
    call compare_strings
    je call_assemble_neg

    mov rax, INST_IDIV
    mov byte [strcmp_len], INST_IDIV_LEN
    call compare_strings
    je call_assemble_idiv

    mov rax, INST_INC
    mov byte [strcmp_len], INST_INC_LEN
    call compare_strings
    je call_assemble_inc

    mov rax, INST_DEC
    mov byte [strcmp_len], INST_DEC_LEN
    call compare_strings
    je call_assemble_dec
    ret


    call_assemble_not:
    call assemble_not
    ret

    call_assemble_neg:
    call assemble_neg
    ret


    call_assemble_idiv:
    call assemble_idiv
    ret

    call_assemble_inc:
    call assemble_inc
    ret

    call_assemble_dec:
    call assemble_dec
    ret

assemble_idiv:
    call process_size_declaration
    call process_operand_1
    call determine_operand_size
    call determine_address_size
    call determine_prefix
    call determine_rex

    mov byte [machine_code], INST_IDIV_OPCODE
    cmp byte [op_size], 8
    je assemble_idiv_skip_adding_w
    or byte [machine_code], 0b00000001

    assemble_idiv_skip_adding_w:
    mov byte [machine_code + 1], INST_IDIV_MOD_REG_RM
    cmp byte [op1_type], 1
    je assemble_idiv_memory
    or byte [machine_code + 1], 0b11000000

    mov rax, op1_reg
    mov bx, [op1_reg_len]
    call get_register_code
    or byte [machine_code+1], al

    ret

    assemble_idiv_memory:
    cmp word [op1_index_len], 0
    jne assemble_idiv_handle_sib
    mov rax, op1_base
    mov bx, [op1_base_len]
    call get_register_code
    or byte [machine_code+1], al
    jmp assemble_idiv_handle_disp

    assemble_idiv_handle_sib:
    or byte [machine_code+1], 0b00000100
    call create_sib_byte_in_al
    mov [machine_code+2], al

    assemble_idiv_handle_disp:
    cmp word [op1_disp_len], 0
    jne assemble_idiv_add_disp
    ret

    assemble_idiv_add_disp:
    cmp word [op1_disp_len], 4
    ja assemble_idiv_disp_32
    or byte [machine_code+1], 0b01000000      ; 8bit disp
    jmp assemble_idiv_add_disp_bytes

    assemble_idiv_disp_32:
    or byte [machine_code+1], 0b10000000      ; 32bit disp
    jmp assemble_idiv_add_disp_bytes

    assemble_idiv_add_disp_bytes:
    call append_disp_byte_from_rax
    ret

assemble_inc:
    call process_size_declaration
    call process_operand_1
    call determine_operand_size
    call determine_address_size
    call determine_prefix
    call determine_rex

    mov byte [machine_code], INST_INC_OPCODE
    cmp byte [op_size], 8
    je assemble_inc_skip_adding_w
    or byte [machine_code], 0b00000001

    assemble_inc_skip_adding_w:
    mov byte [machine_code + 1], INST_INC_MOD_REG_RM
    cmp byte [op1_type], 1
    je assemble_inc_memory
    or byte [machine_code + 1], 0b11000000

    mov rax, op1_reg
    mov bx, [op1_reg_len]
    call get_register_code
    or byte [machine_code+1], al

    ret

    assemble_inc_memory:
    cmp word [op1_index_len], 0
    jne assemble_inc_handle_sib
    mov rax, op1_base
    mov bx, [op1_base_len]
    call get_register_code
    or byte [machine_code+1], al
    jmp assemble_inc_handle_disp

    assemble_inc_handle_sib:
    or byte [machine_code+1], 0b00000100
    call create_sib_byte_in_al
    mov [machine_code+2], al

    assemble_inc_handle_disp:
    cmp word [op1_disp_len], 0
    jne assemble_inc_add_disp
    ret

    assemble_inc_add_disp:
    cmp word [op1_disp_len], 4
    ja assemble_inc_disp_32
    or byte [machine_code+1], 0b01000000      ; 8bit disp
    jmp assemble_inc_add_disp_bytes

    assemble_inc_disp_32:
    or byte [machine_code+1], 0b10000000      ; 32bit disp
    jmp assemble_inc_add_disp_bytes

    assemble_inc_add_disp_bytes:
    call append_disp_byte_from_rax
    ret

assemble_dec:
    call process_size_declaration
    call process_operand_1
    call determine_operand_size
    call determine_address_size
    call determine_prefix
    call determine_rex

    mov byte [machine_code], INST_DEC_OPCODE
    cmp byte [op_size], 8
    je assemble_dec_skip_adding_w
    or byte [machine_code], 0b00000001

    assemble_dec_skip_adding_w:
    mov byte [machine_code + 1], INST_DEC_MOD_REG_RM
    cmp byte [op1_type], 1
    je assemble_dec_memory
    or byte [machine_code + 1], 0b11000000

    mov rax, op1_reg
    mov bx, [op1_reg_len]
    call get_register_code
    or byte [machine_code+1], al

    ret

    assemble_dec_memory:
    cmp word [op1_index_len], 0
    jne assemble_dec_handle_sib
    mov rax, op1_base
    mov bx, [op1_base_len]
    call get_register_code
    or byte [machine_code+1], al
    jmp assemble_dec_handle_disp

    assemble_dec_handle_sib:
    or byte [machine_code+1], 0b00000100
    call create_sib_byte_in_al
    mov [machine_code+2], al

    assemble_dec_handle_disp:
    cmp word [op1_disp_len], 0
    jne assemble_dec_add_disp
    ret

    assemble_dec_add_disp:
    cmp word [op1_disp_len], 4
    ja assemble_dec_disp_32
    or byte [machine_code+1], 0b01000000      ; 8bit disp
    jmp assemble_dec_add_disp_bytes

    assemble_dec_disp_32:
    or byte [machine_code+1], 0b10000000      ; 32bit disp
    jmp assemble_dec_add_disp_bytes

    assemble_dec_add_disp_bytes:
    call append_disp_byte_from_rax
    ret

assemble_neg:
    call process_size_declaration
    call process_operand_1
    call determine_operand_size
    call determine_address_size
    call determine_prefix
    call determine_rex

    mov byte [machine_code], INST_NEG_OPCODE
    cmp byte [op_size], 8
    je assemble_neg_skip_adding_w
    or byte [machine_code], 0b00000001

    assemble_neg_skip_adding_w:
    mov byte [machine_code + 1], INST_NEG_MOD_REG_RM
    cmp byte [op1_type], 1
    je assemble_neg_memory
    or byte [machine_code + 1], 0b11000000

    mov rax, op1_reg
    mov bx, [op1_reg_len]
    call get_register_code
    or byte [machine_code+1], al

    ret

    assemble_neg_memory:
    cmp word [op1_index_len], 0
    jne assemble_neg_handle_sib
    mov rax, op1_base
    mov bx, [op1_base_len]
    call get_register_code
    or byte [machine_code+1], al
    jmp assemble_neg_handle_disp

    assemble_neg_handle_sib:
    or byte [machine_code+1], 0b00000100
    call create_sib_byte_in_al
    mov [machine_code+2], al

    assemble_neg_handle_disp:
    cmp word [op1_disp_len], 0
    jne assemble_neg_add_disp
    ret

    assemble_neg_add_disp:
    cmp word [op1_disp_len], 4
    ja assemble_neg_disp_32
    or byte [machine_code+1], 0b01000000      ; 8bit disp
    jmp assemble_neg_add_disp_bytes

    assemble_neg_disp_32:
    or byte [machine_code+1], 0b10000000      ; 32bit disp
    jmp assemble_neg_add_disp_bytes

    assemble_neg_add_disp_bytes:
    call append_disp_byte_from_rax
    ret

assemble_not:
    call process_size_declaration
    call process_operand_1
    call determine_operand_size
    call determine_address_size
    call determine_prefix
    call determine_rex

    mov byte [machine_code], INST_NOT_OPCODE
    cmp byte [op_size], 8
    je assemble_not_skip_adding_w
    or byte [machine_code], 0b00000001

    assemble_not_skip_adding_w:
    mov byte [machine_code + 1], INST_NOT_MOD_REG_RM
    cmp byte [op1_type], 1
    je assemble_not_memory
    or byte [machine_code + 1], 0b11000000

    mov rax, op1_reg
    mov bx, [op1_reg_len]
    call get_register_code
    or byte [machine_code+1], al

    ret

    assemble_not_memory:
    cmp word [op1_index_len], 0
    jne assemble_not_handle_sib
    mov rax, op1_base
    mov bx, [op1_base_len]
    call get_register_code
    or byte [machine_code+1], al
    jmp assemble_not_handle_disp

    assemble_not_handle_sib:
    or byte [machine_code+1], 0b00000100
    call create_sib_byte_in_al
    mov [machine_code+2], al

    assemble_not_handle_disp:
    cmp word [op1_disp_len], 0
    jne assemble_not_add_disp
    ret

    assemble_not_add_disp:
    cmp word [op1_disp_len], 4
    ja assemble_not_disp_32
    or byte [machine_code+1], 0b01000000      ; 8bit disp
    jmp assemble_not_add_disp_bytes

    assemble_not_disp_32:
    or byte [machine_code+1], 0b10000000      ; 32bit disp
    jmp assemble_not_add_disp_bytes

    assemble_not_add_disp_bytes:
    call append_disp_byte_from_rax
    ret

determine_rex:
    cmp byte [op1_type], 0 ; reg
    je check_64bit_register
    jmp check_64bit_memory

    check_64bit_register:
    cmp byte [op1_reg], "r"
    je add_64bit_register
    ret

    add_64bit_register:
    mov byte [rex_field], REX
    mov rax, op1_reg
    xor rbx, rbx
    mov bx, [op1_reg_len]
    call is_new_register
    cmp rax, 1
    jne no_need_b_in_rex
    or byte [rex_field], 0b00000001

    no_need_b_in_rex:
    cmp byte [op_size], 64
    jne no_chance_rex
    or byte [rex_field], 0b00001000
    ret

    check_64bit_memory:
    cmp word [op1_index_len], 0
    je check_64bit_memory_base
    cmp byte [op1_index], "r"
    jne check_64bit_memory_base
    mov byte [rex_field], REX
    or byte [rex_field], 0b00000010

    check_64bit_memory_base:
    cmp word [op1_base_len], 0
    je no_rex
    cmp byte [op1_base], "r"
    jne no_rex
    mov byte [rex_field], REX
    or byte [rex_field], 0b00000001

    no_rex:
    cmp byte [rex_field], 0
    je no_chance_rex
    
    cmp byte [op_size], 64
    jne no_chance_rex
    or byte [rex_field], 0b00001000
    ret

    no_chance_rex:
    ret

is_new_register:
    cmp byte [rax+1], "a"
    jae not_new_register
    mov rax, 1
    ret

    not_new_register:
    mov rax, 0
    ret

determine_prefix:
    call determine_op_prefix
    call determine_addr_prefix
    ret

determine_op_prefix:
    cmp byte [op_size], 16
    jne no_op_prefix

    mov byte [op_prefix], 0x66

    no_op_prefix:
    ret

determine_addr_prefix:
    cmp byte [addr_size], 32
    jne no_addr_prefix

    mov byte [addr_prefix], 0x67

    no_addr_prefix:
    ret

append_disp_byte_from_rax:
    push rcx
    call create_disp_byte_in_rax      ;byte: rbx
    mov dword [dummy_str], eax

    xor rcx, rcx
    adbfr_loop:
        cmp rcx, rbx
        jae adbfr_break
        mov dl, [dummy_str + rcx]

        cmp word [op1_index_len], 0
        jne adbfr_has_sib
        mov [machine_code+rcx + 2], dl 
        jmp adbfr_next

        adbfr_has_sib:
        mov [machine_code+rcx + 3], dl 

        adbfr_next:
        inc rcx
        jmp adbfr_loop

    adbfr_break:
    mov dword [dummy_str], 0
    pop rcx
    ret

create_disp_byte_in_rax:
    push rcx
    xor rax, rax
    mov rcx, 2
    cdbia_loop:
        cmp cx, [op1_disp_len]
        jae cdbia_break

        mov dl, [op1_disp + rcx]
        sub dl, "0"
        shl rax, 4
        add al, dl

        inc rcx
        jmp cdbia_loop

    cdbia_break:
    push rax

    mov rax, rcx ; number of nibs
    sub rax, 2
    mov dl, 2
    div dl
    cmp dl, 0
    je cdbia_end
    inc rax

    cdbia_end:
    mov rbx, rax
    pop rax
    pop rcx
    ret

create_sib_byte_in_al:
    xor al, al

    cmp word [op1_scale_len], 0
    je add_index_part

    cmp byte [op1_scale], "2"
    jne add_scale_4
    or al, 0b01000000
    jmp add_index_part

    add_scale_4:
    cmp byte [op1_scale], "4"
    jne add_scale_8
    or al, 0b10000000
    jmp add_index_part

    add_scale_8:
    or al, 0b11000000

    add_index_part:
    push ax
    mov rax, op1_index
    mov bx, [op1_index_len]
    call get_register_code
    mov bl, al
    shl bl, 3
    pop ax
    or al, bl

    push ax
    mov rax, op1_base
    mov bx, [op1_base_len]
    call get_register_code
    mov bl, al
    pop ax
    or al, bl

    ret

determine_operand_size:
    cmp byte [op_size], 0
    jne dos_return

    cmp byte [op1_type], 0        ; reg
    jne determine_ow

    mov rax, op1_reg
    mov bx, [op1_reg_len]
    call get_register_size
    mov byte [op_size], al

    ret

    determine_ow:
    ; fill in the blank

    dos_return:
    ret

determine_address_size:
    cmp byte [op1_has_base], 1
    je determine_by_base

    cmp byte [op1_index_len], 0
    jne determine_by_index

    mov byte [addr_size], 64
    ret

    determine_by_base:
    mov rax, op1_base
    mov bx, [op1_base_len]
    call get_register_size
    mov byte [addr_size], al
    ret

    determine_by_index:
    mov rax, op1_index
    mov bx, [op1_index_len]
    call get_register_size
    mov byte [addr_size], al
    ret

get_register_size:                    ; register in [rax] with len bx. result in al
    cmp bx, 4
    jne determine_2

    cmp byte [rax + 3], "d"
    je size_32

    cmp byte [rax + 3], "w"
    je size_16

    cmp byte [rax + 3], "b"
    je size_8


    determine_2:
    cmp bx, 2
    jne determine_3

    cmp byte [rax+1], "l"
    je size_8

    cmp byte [rax+1], "h"
    je size_8

    cmp byte [rax], "r"
    je size_64

    jmp size_16

    determine_3:         ; 3 letters

    cmp word [rax], "r8"
    je determine_r8_r9_subs

    cmp word [rax], "r9"
    je determine_r8_r9_subs

    cmp byte [rax], "e"
    je size_32

    cmp byte [rax], "r"
    je size_64

    determine_r8_r9_subs:
    cmp byte [rax + 2], "d"
    je size_32

    cmp byte [rax + 2], "w"
    je size_16

    cmp byte [rax + 2], "b"
    je size_8

    size_8:
    mov al, 8
    ret

    size_16:
    mov al, 16
    ret

    size_32:
    mov al, 32
    ret

    size_64:
    mov al, 64
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
    inc rcx
    ret

    invalid_size_declr:
    pop rcx
    ret

is_op1_size_declr_valid:
    cmp byte [op1_size_declr_len], 4
    jne size_declr_five

    cmp dword [op1_size_declr], "byte"
    je size_declr_valid_8

    cmp dword [op1_size_declr], "word"
    je size_declr_valid_16

    jmp size_declr_invalid

    size_declr_five:
    cmp byte [op1_size_declr_len], 5
    jne size_declr_invalid

    cmp dword [op1_size_declr], "dwor"
    je size_declr_half_valid_32

    cmp dword [op1_size_declr], "qwor"
    je size_declr_half_valid_64

    size_declr_invalid:
    mov byte [op_size], 0
    mov rax, 0
    ret

    size_declr_half_valid_32:
    cmp byte [op1_size_declr + 4], "d"
    jne size_declr_invalid
    mov byte [op_size], 32
    mov rax, 1
    ret

    size_declr_half_valid_64:
    cmp byte [op1_size_declr + 4], "d"
    jne size_declr_invalid
    mov byte [op_size], 64
    mov rax, 1
    ret

    size_declr_valid_8:
    mov byte [op_size], 8
    mov rax, 1
    ret

    size_declr_valid_16:
    mov byte [op_size], 16
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
    process_register_next_char:
        mov al, [instruction + rcx]
        cmp al, " "
        je process_register_next_char_break
        cmp al, 10
        je process_register_next_char_break

        mov byte [op1_reg + rdx], al
        inc word [op1_reg_len]
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

get_register_code:                          ; register in [rax], len: rbx, result: rax
    cmp rbx, 2
    jne grc_four
    call get_register_code_2
    ret

    grc_four:
    cmp rbx, 4
    jne grc_three
    call get_register_code_4
    ret

    grc_three:
    cmp byte [rax], "e"
    jne grc_two_r
    call get_register_code_e2
    ret

    grc_two_r:
    call get_register_code_r2
    ret

get_register_code_4:
    cmp word [rax+1], "10"
    jne grc4_r11x
    mov rax, 0b010
    ret

    grc4_r11x:
    cmp word [rax+1], "11"
    jne grc4_r12x
    mov rax, 0b011
    ret

    grc4_r12x:
    cmp word [rax+1], "12"
    jne grc4_r13x
    mov rax, 0b100
    ret

    grc4_r13x:
    cmp word [rax+1], "13"
    jne grc4_r14x
    mov rax, 0b101
    ret

    grc4_r14x:
    cmp word [rax+1], "14"
    jne grc4_r15x
    mov rax, 0b110
    ret

    grc4_r15x:
    cmp word [rax+1], "15"
    jne invalid_reg_4
    mov rax, 0b111
    ret

    invalid_reg_4:
    mov rax, -1
    ret

get_register_code_e2:
    cmp word [rax+1], "ax"
    jne grce2_ebx
    mov rax, 0b000
    ret

    grce2_ebx:
    cmp word [rax+1], "bx"
    jne grce2_ecx
    mov rax, 0b011
    ret

    grce2_ecx:
    cmp word [rax+1], "cx"
    jne grce2_edx
    mov rax, 0b001
    ret

    grce2_edx:
    cmp word [rax+1], "dx"
    jne grce2_esp
    mov rax, 0b010
    ret

    grce2_esp:
    cmp word [rax+1], "sp"
    jne grce2_ebp
    mov rax, 0b100
    ret

    grce2_ebp:
    cmp word [rax+1], "bp"
    jne grce2_esi
    mov rax, 0b101
    ret

    grce2_esi:
    cmp word [rax+1], "si"
    jne grce2_edi
    mov rax, 0b110
    ret

    grce2_edi:
    cmp word [rax+1], "di"
    jne grce2_invalid_register
    mov rax, 0b111
    ret

    grce2_invalid_register:
    mov rax, -1
    ret

get_register_code_r2:
    cmp byte [rax+1], "8"
    jne grcr2_r9
    mov rax, 0b000
    ret

    grcr2_r9:
    cmp byte [rax+1], "9"
    jne grcr2_r10
    mov rax, 0b001
    ret

    grcr2_r10:
    cmp word [rax+1], "10"
    jne grcr2_r11
    mov rax, 0b010
    ret

    grcr2_r11:
    cmp word [rax+1], "11"
    jne grcr2_r12
    mov rax, 0b011
    ret

    grcr2_r12:
    cmp word [rax+1], "12"
    jne grcr2_r13
    mov rax, 0b100
    ret

    grcr2_r13:
    cmp word [rax+1], "13"
    jne grcr2_r14
    mov rax, 0b101
    ret

    grcr2_r14:
    cmp word [rax+1], "14"
    jne grcr2_r15
    mov rax, 0b110
    ret

    grcr2_r15:
    cmp word [rax+1], "15"
    jne grcr2_rcx
    mov rax, 0b111
    ret

    grcr2_rax:
    cmp word [rax+1], "ax"
    jne grcr2_rbx
    mov rax, 0b000
    ret

    grcr2_rbx:
    cmp word [rax+1], "bx"
    jne grcr2_rcx
    mov rax, 0b011
    ret

    grcr2_rcx:
    cmp word [rax+1], "cx"
    jne grcr2_rdx
    mov rax, 0b001
    ret

    grcr2_rdx:
    cmp word [rax+1], "dx"
    jne grcr2_rsp
    mov rax, 0b010
    ret
    
    grcr2_rsp:
    cmp word [rax+1], "sp"
    jne grcr2_rbp
    mov rax, 0b100
    ret

    grcr2_rbp:
    cmp word [rax+1], "bp"
    jne grcr2_rsi
    mov rax, 0b101
    ret

    grcr2_rsi:
    cmp word [rax+1], "si"
    jne grcr2_rdi
    mov rax, 0b110
    ret

    grcr2_rdi:
    cmp word [rax+1], "di"
    jne grcr2_invalid_reg
    mov rax, 0b111
    ret

    grcr2_invalid_reg:
    mov rax, -1
    ret

get_register_code_2:
    cmp word [rax], "al"
    jne grc2_ah
    mov rax, 0b000
    ret

    grc2_ah:
    cmp word [rax], "ah"
    jne grc2_ax
    mov rax, 0b100
    ret

    grc2_ax:
    cmp word [rax], "ax"
    jne grc2_bl
    mov rax, 0b000
    ret

    grc2_bl:
    cmp word [rax], "bl"
    jne grc2_bh
    mov rax, 0b011
    ret

    grc2_bh:
    cmp word [rax], "bh"
    jne grc2_bx
    mov rax, 0b111
    ret

    grc2_bx:
    cmp word [rax], "bx"
    jne grc2_cl
    mov rax, 0b011
    ret

    grc2_cl:
    cmp word [rax], "cl"
    jne grc2_ch
    mov rax, 0b001
    ret

    grc2_ch:
    cmp word [rax], "ch"
    jne grc2_cx
    mov rax, 0b101
    ret

    grc2_cx:
    cmp word [rax], "cx"
    jne grc2_dl
    mov rax, 0b001
    ret

    grc2_dl:
    cmp word [rax], "dl"
    jne grc2_dh
    mov rax, 0b010
    ret

    grc2_dh:
    cmp word [rax], "dh"
    jne grc2_dx
    mov rax, 0b110
    ret

    grc2_dx:
    cmp word [rax], "dx"
    jne grc2_si
    mov rax, 0b010
    ret

    grc2_si:
    cmp word [rax], "si"
    jne grc2_sp
    mov rax, 0b110
    ret

    grc2_sp:
    cmp word [rax], "sp"
    jne grc2_bp
    mov rax, 0b100
    ret

    grc2_bp:
    cmp word [rax], "bp"
    jne grc2_di
    mov rax, 0b101
    ret

    grc2_di:
    cmp word [rax], "di"
    jne grc2_r8
    mov rax, 0b111
    ret

    grc2_r8:
    cmp word [rax], "r8"
    jne grc2_r9
    mov rax, 0b000
    ret

    grc2_r9:
    cmp word [rax], "r9"
    jne invalid_reg_2
    mov rax, 0b001
    ret

    invalid_reg_2:
    mov rax, -1
    ret
