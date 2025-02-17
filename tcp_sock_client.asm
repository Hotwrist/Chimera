; AUTHOR: John Ebinyi Odey a.k.a Redhound, Giannis, Hotwrist
; BIRTH: February 2025
; DESCRIPTION:  This Intel x86_64 program is a TCP Socket client that connects to a running
;		TCP server via port 8080.

BITS 64

section .text
    global _start

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    xor rdi, rdi           ; Clear rdi
    mov dil, 2             ; AF_INET
    mov rsi, 1             ; SOCK_STREAM
    xor rdx, rdx           ; Protocol 0
    mov rax, 41            ; syscall: socket
    syscall
    mov rdi, rax           ; Save socket descriptor

    ; struct sockaddr_in (AF_INET, Port: 8080, IP: 127.0.0.1)
    push rdx               ; Zero out stack space
    mov dword [rsp], 0x0100007F  ; IP: 127.0.0.1 (Little Endian)
    mov word [rsp-2], 0x901F ; Port 8080 (0x901F -> Little Endian for port 8080)
    mov word [rsp-4], 2     ; AF_INET (correct position)

    ; connect(socket, struct sockaddr *, sizeof(struct sockaddr_in))
    lea rsi, [rsp-4]        ; Load pointer to sockaddr_in
    mov dl, 16              ; sizeof(sockaddr_in)
    mov rax, 42             ; syscall: connect
    syscall

    ; send(socket, "Hello from shellcode", 22, 0)
    mov rsi, message
    mov rdx, 22             ; Length of message
    xor r10, r10           ; Flags = 0
    mov rax, 44            ; syscall: send
    syscall

    ; close(socket)
    mov rax, 3             ; syscall: close
    syscall

    ; exit(0)
    xor rdi, rdi
    mov rax, 60            ; syscall: exit
    syscall

section .data
message: db "Hello from John Doe...smiles", 0x0A  ; Message to send

