# TODO.md`ntdll.dll`

What I'd like to do;

- Check IAT/EAT ptrs & bound check against NTDLL/KERNEL32
- Identify privately mapped regions with syscall prologues / similar setup to syscalls
- Check PEB->LDR structs (eg; Multiple NTDLL instances, compare modules vs PEB, detect shadow-loading)
