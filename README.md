**Repository Overview:**

This repository provides in-depth coverage of key vulnerability classes with hands-on examples and techniques. Each section explores exploitation strategies and mitigation bypasses in various vulnerability contexts.

### Vulnerability Classes Covered

1. **Stack Buffer Overflow**
   * Shellcode stored in user land.
   * Overflow the stack with a ROP chain.
   * Use ROP chain to bypass SMEP & KVA.
   * Use ROP gadgets to redirect execution to shellcode in user land.
   * System State Restoration with Trap Frame after shellcode execution.

2. **Arbitrary Write**
   * Construct a read primitive using the write primitive.
   * Traverse _EPROCES list using both primitives.
   * Read the system process token using read primitive.
   * Write the system process to the current process using the write primitive. 
