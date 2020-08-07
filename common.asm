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


%define W_8 0
%define W_16 1
%define W_32 1
