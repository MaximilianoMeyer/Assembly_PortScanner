section .data
    prompt_ip db "Enter target IP (e.g., 192.168.1.1): ", 0
    prompt_ip_len equ $ - prompt_ip
    
    prompt_start db "Enter start port: ", 0
    prompt_start_len equ $ - prompt_start
    
    prompt_end db "Enter end port: ", 0
    prompt_end_len equ $ - prompt_end
    
    msg_scanning db "Scanning ports on ", 0
    msg_scanning_len equ $ - msg_scanning
    
    msg_open db "[+] Port ", 0
    msg_open_len equ $ - msg_open
    
    msg_open2 db " is OPEN", 10, 0
    msg_open2_len equ $ - msg_open2
    
    msg_progress db ".", 0
    
    newline db 10, 0

section .bss
    ip_input resb 16
    ip_binary resd 1
    port_start_input resb 8
    port_end_input resb 8
    port_start resq 1
    port_end resq 1
    sockfd resq 1
    sockaddr resb 16
    port_buffer resb 16
    temp_buffer resb 32

section .text
    global _start

_start:
    ; Solicitar IP
    mov rax, 1                   ; sys_write
    mov rdi, 1                   ; stdout
    lea rsi, [prompt_ip]
    mov rdx, prompt_ip_len
    syscall
    
    ; Ler IP
    mov rax, 0                   ; sys_read
    mov rdi, 0                   ; stdin
    lea rsi, [ip_input]
    mov rdx, 16
    syscall
    
    ; Remover newline
    lea rdi, [ip_input]
    call remove_newline
    
    ; Converter IP string para binário
    lea rdi, [ip_input]
    call ip_to_binary
    mov [ip_binary], eax
    
    ; Solicitar porta inicial
    mov rax, 1
    mov rdi, 1
    lea rsi, [prompt_start]
    mov rdx, prompt_start_len
    syscall
    
    mov rax, 0
    mov rdi, 0
    lea rsi, [port_start_input]
    mov rdx, 8
    syscall
    
    lea rdi, [port_start_input]
    call string_to_int
    mov [port_start], rax
    
    ; Solicitar porta final
    mov rax, 1
    mov rdi, 1
    lea rsi, [prompt_end]
    mov rdx, prompt_end_len
    syscall
    
    mov rax, 0
    mov rdi, 0
    lea rsi, [port_end_input]
    mov rdx, 8
    syscall
    
    lea rdi, [port_end_input]
    call string_to_int
    mov [port_end], rax
    
    ; Mostrar mensagem de scanning
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_scanning]
    mov rdx, msg_scanning_len
    syscall
    
    mov rax, 1
    mov rdi, 1
    lea rsi, [ip_input]
    mov rdx, 16
    syscall
    
    mov rax, 1
    mov rdi, 1
    lea rsi, [newline]
    mov rdx, 1
    syscall
    
    ; Iniciar scan
    mov r12, [port_start]
    
scan_loop:
    mov rax, [port_end]
    cmp r12, rax
    jg exit_program
    
    ; Criar socket
    mov rax, 41                  ; sys_socket
    mov rdi, 2                   ; AF_INET
    mov rsi, 1                   ; SOCK_STREAM
    mov rdx, 0                   ; protocol
    syscall
    
    cmp rax, 0
    jl next_port                 ; Erro ao criar socket
    mov [sockfd], rax
    
    ; Configurar timeout (1 segundo)
    ; struct timeval { tv_sec, tv_usec }
    push 0                       ; tv_usec = 0
    push 1                       ; tv_sec = 1
    
    mov rax, 54                  ; sys_setsockopt
    mov rdi, [sockfd]
    mov rsi, 1                   ; SOL_SOCKET
    mov rdx, 20                  ; SO_RCVTIMEO
    mov r10, rsp
    mov r8, 16
    syscall
    
    add rsp, 16                  ; Limpar stack
    
    ; Preparar sockaddr_in
    xor rax, rax
    mov rcx, 16
    lea rdi, [sockaddr]
    rep stosb                    ; Zerar sockaddr
    
    mov word [sockaddr], 2       ; AF_INET
    
    ; Converter porta para network byte order
    mov ax, r12w
    xchg al, ah                  ; htons
    mov word [sockaddr + 2], ax
    
    ; Copiar IP em network byte order
    mov eax, [ip_binary]
    mov dword [sockaddr + 4], eax
    
    ; Connect com timeout
    mov rax, 42                  ; sys_connect
    mov rdi, [sockfd]
    lea rsi, [sockaddr]
    mov rdx, 16
    syscall
    
    ; Verificar se conectou
    cmp rax, 0
    je port_open
    
    ; Porta fechada ou filtrada
    jmp close_socket
    
port_open:
    ; Printar porta aberta
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_open]
    mov rdx, msg_open_len
    syscall
    
    ; Converter porta para string
    mov rax, r12
    lea rdi, [port_buffer]
    call int_to_string
    
    mov rax, 1
    mov rdi, 1
    lea rsi, [port_buffer]
    mov rdx, 16
    syscall
    
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_open2]
    mov rdx, msg_open2_len
    syscall
    
close_socket:
    ; Fechar socket
    mov rax, 3                   ; sys_close
    mov rdi, [sockfd]
    syscall
    
next_port:
    ; Mostrar progresso
    mov rax, r12
    sub rax, [port_start]
    and rax, 0xFF
    test rax, 0x1F               ; A cada 32 portas
    jnz skip_progress
    
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_progress]
    mov rdx, 1
    syscall
    
skip_progress:
    inc r12
    jmp scan_loop

exit_program:
    mov rax, 1
    mov rdi, 1
    lea rsi, [newline]
    mov rdx, 1
    syscall
    
    mov rax, 60                  ; sys_exit
    xor rdi, rdi
    syscall

; ==========================
; FUNÇÕES AUXILIARES
; ==========================

; Remove newline de string
; rdi = ponteiro para string
remove_newline:
    push rax
    push rdi
.loop:
    mov al, [rdi]
    cmp al, 10                   ; '\n'
    je .found
    cmp al, 0
    je .done
    inc rdi
    jmp .loop
.found:
    mov byte [rdi], 0
.done:
    pop rdi
    pop rax
    ret

; Converte IP string para binário (network byte order)
; rdi = ponteiro para string IP
; retorna eax = IP em binário
ip_to_binary:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    xor rax, rax                 ; Resultado final
    xor rbx, rbx                 ; Byte atual
    xor rcx, rcx                 ; Contador de octetos
    
.parse_loop:
    movzx rdx, byte [rdi]
    
    cmp dl, '.'
    je .next_octet
    
    cmp dl, 0
    je .last_octet
    
    ; Converter dígito
    sub dl, '0'
    imul rbx, 10
    add rbx, rdx
    
    inc rdi
    jmp .parse_loop
    
.next_octet:
    ; Adicionar octeto ao resultado
    shl rax, 8
    or rax, rbx
    xor rbx, rbx
    inc rcx
    inc rdi
    jmp .parse_loop
    
.last_octet:
    shl rax, 8
    or rax, rbx
    
    ; Converter para network byte order (big-endian)
    bswap eax
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Converte string para inteiro
; rdi = ponteiro para string
; retorna rax = número
string_to_int:
    push rbx
    push rcx
    push rdi
    
    xor rax, rax
    xor rbx, rbx
    
.loop:
    movzx rcx, byte [rdi]
    
    cmp cl, '0'
    jl .done
    cmp cl, '9'
    jg .done
    
    sub cl, '0'
    imul rax, 10
    add rax, rcx
    
    inc rdi
    jmp .loop
    
.done:
    pop rdi
    pop rcx
    pop rbx
    ret

; Converte inteiro para string
; rax = número
; rdi = buffer destino
int_to_string:
    push rax
    push rbx
    push rcx
    push rdx
    push rdi
    
    mov rbx, 10
    mov rcx, 0
    
    ; Limpar buffer
    push rdi
    mov rcx, 16
    mov al, ' '
    rep stosb
    pop rdi
    
    mov rax, [rsp + 32]          ; Recuperar número original
    
    ; Caso especial: zero
    test rax, rax
    jnz .convert
    mov byte [rdi], '0'
    jmp .done
    
.convert:
    lea rsi, [rdi + 15]          ; Começar do final
    mov byte [rsi], 0
    
.div_loop:
    test rax, rax
    jz .reverse
    
    xor rdx, rdx
    div rbx
    add dl, '0'
    dec rsi
    mov [rsi], dl
    jmp .div_loop
    
.reverse:
    ; Copiar de volta para início do buffer
    inc rsi
    mov rcx, 0
.copy_loop:
    mov al, [rsi + rcx]
    test al, al
    jz .done
    mov [rdi + rcx], al
    inc rcx
    jmp .copy_loop
    
.done:
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
