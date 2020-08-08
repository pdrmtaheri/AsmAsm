%define SYS_READ 0
%define SYS_WRITE 1
%define SYS_OPEN 2
%define SYS_CLOSE 3
%define SYS_EXIT 60
%define SYS_CREAT 85

%define RWX_PERM 0777
%define RW_CREAT 0102o
%define READONLY_ACCESS 0

%define BYTE_MIN 0
%define BYTE_MAX 255

%define EXIT_SUCCESS 0


%define INST_STC_LEN 3
%define INST_STC_OPCODE 0xf9
%define INST_STC_OPCODE_LEN 1

%define INST_CLC_LEN 3
%define INST_CLC_OPCODE 0xf8
%define INST_CLC_OPCODE_LEN 1

%define INST_STD_LEN 3
%define INST_STD_OPCODE 0xfd
%define INST_STD_OPCODE_LEN 1

%define INST_CLD_LEN 3
%define INST_CLD_OPCODE 0xfc
%define INST_CLD_OPCODE_LEN 1

%define INST_SYSCALL_LEN 7
%define INST_SYSCALL_OPCODE 0x0f05
%define INST_SYSCALL_OPCODE_LEN 2

%define INST_LEAVE_LEN 5
%define INST_LEAVE_OPCODE 0xc9
%define INST_LEAVE_OPCODE_LEN 1

%define INST_NOT_LEN 4
%define INST_NOT_OPCODE 0b11110110             ; last zero for w
%define INST_NOT_MOD_REG_RM 0b00010000         ; first two zeros for mod, last three for r/m

%define INST_NEG_LEN 4
%define INST_NEG_OPCODE 0b11110110
%define INST_NEG_MOD_REG_RM 0b00011000

%define INST_IDIV_LEN 5
%define INST_IDIV_OPCODE 0b11110110
%define INST_IDIV_MOD_REG_RM 0b00111000

%define INST_INC_LEN 4
%define INST_INC_OPCODE 0b11110110
%define INST_INC_MOD_REG_RM 0b00000000

%define INST_DEC_LEN 4
%define INST_DEC_OPCODE 0b11110110
%define INST_DEC_MOD_REG_RM 0b00001000

%define W_8 0
%define W_16 1
%define W_32 1

%define REX 0b01000000
