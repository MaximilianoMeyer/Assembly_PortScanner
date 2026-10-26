; =============================================================================
; port_scanner.asm  -  Windows x64 / NASM
; TCP connect scan (non-blocking, up to 64 simultaneous connections) + banner
; grabbing + OS guessing based on the banner.
;
; Build (MinGW-w64):
;   nasm -f win64 port_scanner.asm -o port_scanner.obj
;   gcc -nostdlib -o port_scanner.exe port_scanner.obj -lws2_32 -lkernel32 -Wl,-e,_start
;
; Build (MSVC):
;   nasm -f win64 port_scanner.asm -o port_scanner.obj
;   link /subsystem:console /entry:_start /nodefaultlib port_scanner.obj kernel32.lib ws2_32.lib
;
; Windows x64 Convention:
;   args: RCX, RDX, R8, R9, then the stack (starting at [rsp+32] at the time of the call)
;   volatile: RAX, RCX, RDX, R8-R11    non-volatile: RBX, RBP, RDI, RSI, R12-R15
;   RSP must be 16-byte aligned at the time of a CALL, with 32 bytes of
;   shadow space reserved. Upon entry to any function, RSP = 8 (mod 16).
;
; All internal functions follow the same convention (args in RCX/RDX/R8).
; =============================================================================

bits 64
default rel

%define AF_INET          2
%define SOCK_STREAM      1
%define IPPROTO_TCP      6
%define SOL_SOCKET       0xFFFF
%define SO_ERROR         0x1007
%define FIONBIO          0x8004667E
%define POLLRDNORM       0x0100
%define POLLWRNORM       0x0010
%define WSAEWOULDBLOCK   10035

%define MAX_INFLIGHT     64          ; tamanho do vetor de WSAPOLLFD
%define POLL_INTERVAL    50          ; ms entre varreduras de timeout
%define CONNECT_TIMEOUT  1000        ; ms para o connect completar
%define BANNER_TIMEOUT   1000        ; ms esperando banner apos conectar
%define BANNER_MAX       256

%define ST_CONNECTING    1
%define ST_READING       2

extern GetStdHandle
extern WriteFile
extern ReadFile
extern ExitProcess
extern GetTickCount
extern WSAStartup
extern WSACleanup
extern socket
extern ioctlsocket
extern connect
extern send
extern recv
extern closesocket
extern WSAPoll
extern getsockopt
extern WSAGetLastError

; -----------------------------------------------------------------------------
section .data
; -----------------------------------------------------------------------------
ioctl_arg           dd 1

http_probe          db "GET / HTTP/1.0", 13, 10, "Host: target", 13, 10, 13, 10
http_probe_len      equ $ - http_probe

prompt_ip           db "Enter target IPv4 (e.g., 192.168.1.1): ", 0
prompt_start        db "Enter start port (1-65535): ", 0
prompt_end          db "Enter end port (1-65535): ", 0
msg_scanning        db "Scanning ", 0
msg_range           db " ports ", 0
range_through       db " through ", 0
msg_open_prefix     db "[+] ", 0
msg_open_suffix     db " OPEN", 13, 10, 0
msg_closed_prefix   db "[-] ", 0
msg_closed_suffix   db " closed/filtered", 13, 10, 0
msg_timeout_suffix  db " timeout", 13, 10, 0
msg_banner_ind      db "    banner: ", 0
msg_os_ind          db "    os guess: ", 0
os_linux            db "Linux/Unix", 0
os_windows          db "Windows", 0
msg_invalid_ip      db "Invalid IPv4 address.", 13, 10, 0
msg_invalid_ports   db "Invalid port range.", 13, 10, 0
msg_input_error     db "Input error.", 13, 10, 0
msg_wsa_error       db "WSAStartup failed.", 13, 10, 0
msg_socket_error    db "Could not create socket; aborting.", 13, 10, 0
msg_summary1        db "Finished. Open ports: ", 0
msg_summary2        db ", tested: ", 0
msg_summary3        db ", timeouts: ", 0
newline             db 13, 10, 0

sub_ubuntu          db "Ubuntu", 0
sub_debian          db "Debian", 0
sub_openssh         db "OpenSSH_", 0
sub_linux           db "Linux", 0
sub_windows         db "Windows", 0
sub_microsoft       db "Microsoft", 0

; -----------------------------------------------------------------------------
section .bss
; -----------------------------------------------------------------------------
alignb 8
hStdout             resq 1
hStdin              resq 1
bytes_written       resq 1
bytes_read          resq 1

; WSAPOLLFD: fd(8) events(2) revents(2) pad(4) = 16 bytes.
; Slots ativos ficam SEMPRE compactados em [0 .. n_active).
pollfds             resb MAX_INFLIGHT * 16
slot_port           resd MAX_INFLIGHT
slot_state          resd MAX_INFLIGHT
slot_start          resd MAX_INFLIGHT      ; GetTickCount no inicio da fase

n_active            resd 1
ip_binary           resd 1                 ; IPv4 em ordem de rede
port_start          resd 1
port_end            resd 1
next_port           resd 1
open_count          resd 1
tested_count        resd 1
timeout_count       resd 1
so_err              resd 1
so_err_len          resd 1

sockaddr_in         resb 16
wsaData             resb 512
ip_input            resb 64
line_buffer         resb 64
num_buffer          resb 32
banner_buf          resb BANNER_MAX + 1    ; unico: cada banner e tratado na hora

; =============================================================================
section .text
; =============================================================================
global _start

; -----------------------------------------------------------------------------
; _start
; Entrada: RSP = 8 (mod 16).  sub 56 -> alinhado, com shadow space (32) e um
; slot de 5o argumento em [rsp+32].  Nunca retorna (termina via ExitProcess).
; -----------------------------------------------------------------------------
_start:
    sub rsp, 56

    ; handles primeiro, para que mensagens de erro ja possam ser impressas
    mov ecx, -11                    ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [hStdout], rax
    mov ecx, -10                    ; STD_INPUT_HANDLE
    call GetStdHandle
    mov [hStdin], rax

    mov ecx, 0x0202                 ; Winsock 2.2
    lea rdx, [wsaData]
    call WSAStartup
    test eax, eax
    jnz wsa_fail

    ; --- IP ---
    lea rcx, [prompt_ip]
    call write_cstr
    lea rcx, [ip_input]
    mov edx, 64
    call read_line
    test eax, eax
    jle input_err
    lea rcx, [ip_input]
    call parse_ipv4
    test eax, eax
    jz bad_ip
    mov [ip_binary], edx

    ; --- porta inicial ---
    lea rcx, [prompt_start]
    call prompt_port
    cmp eax, -1
    je input_err
    test eax, eax
    jz bad_ports
    mov [port_start], eax

    ; --- porta final ---
    lea rcx, [prompt_end]
    call prompt_port
    cmp eax, -1
    je input_err
    test eax, eax
    jz bad_ports
    mov [port_end], eax
    cmp eax, [port_start]
    jb bad_ports

    ; --- cabecalho ---
    lea rcx, [msg_scanning]
    call write_cstr
    lea rcx, [ip_input]
    call write_cstr
    lea rcx, [msg_range]
    call write_cstr
    mov ecx, [port_start]
    call print_uint
    lea rcx, [range_through]
    call write_cstr
    mov ecx, [port_end]
    call print_uint
    lea rcx, [newline]
    call write_cstr

    mov eax, [port_start]
    mov [next_port], eax

; ---- laco principal: preenche slots -> espera eventos -> expira ------------
.main_loop:
.fill:
    mov eax, [next_port]
    cmp eax, [port_end]
    ja .fill_done                   ; nao ha mais portas para iniciar
    cmp dword [n_active], MAX_INFLIGHT
    jae .fill_done                  ; vetor cheio
    call start_connection
    test eax, eax
    jz .fill
    cmp dword [n_active], 0         ; socket() falhou: fatal so se nada em voo
    je socket_fatal
.fill_done:
    cmp dword [n_active], 0
    je scan_complete                ; nada em voo e nada a iniciar

    lea rcx, [pollfds]
    mov edx, [n_active]
    mov r8d, POLL_INTERVAL
    call WSAPoll
    test eax, eax
    jle .after_poll                 ; 0 = nada pronto, <0 = erro (timeouts limpam)
    call process_events
.after_poll:
    call expire_slots
    jmp .main_loop

; ---- fim ------------------------------------------------------------------
scan_complete:
    lea rcx, [msg_summary1]
    call write_cstr
    mov ecx, [open_count]
    call print_uint
    lea rcx, [msg_summary2]
    call write_cstr
    mov ecx, [tested_count]
    call print_uint
    lea rcx, [msg_summary3]
    call write_cstr
    mov ecx, [timeout_count]
    call print_uint
    lea rcx, [newline]
    call write_cstr
    call WSACleanup
    xor ecx, ecx
    call ExitProcess

; ---- saidas de erro (alcancadas apenas a partir de _start, RSP alinhado) ---
wsa_fail:
    lea rcx, [msg_wsa_error]
    jmp fatal_exit
socket_fatal:
    lea rcx, [msg_socket_error]
    jmp fatal_exit
bad_ip:
    lea rcx, [msg_invalid_ip]
    jmp fatal_exit
bad_ports:
    lea rcx, [msg_invalid_ports]
    jmp fatal_exit
input_err:
    lea rcx, [msg_input_error]
fatal_exit:
    call write_cstr
    mov ecx, 1
    call ExitProcess

; =============================================================================
; Gerenciamento de conexoes
; =============================================================================

; -----------------------------------------------------------------------------
; start_connection: abre socket nao bloqueante para next_port e registra slot.
; Retorna EAX = 0 ok, -1 se socket() falhou.
; -----------------------------------------------------------------------------
start_connection:
    push rbx
    push rsi
    push rdi
    sub rsp, 48

    mov ecx, AF_INET
    mov edx, SOCK_STREAM
    mov r8d, IPPROTO_TCP
    call socket
    cmp rax, -1                     ; INVALID_SOCKET
    je .fatal
    mov rbx, rax                    ; rbx = SOCKET

    mov rcx, rbx
    mov edx, FIONBIO
    lea r8, [ioctl_arg]
    call ioctlsocket

    ; sockaddr_in
    lea rdx, [sockaddr_in]
    xor eax, eax
    mov [rdx], rax
    mov [rdx + 8], rax
    mov word [rdx], AF_INET
    mov eax, [next_port]
    mov edi, eax                    ; edi = porta (host order)
    rol ax, 8                       ; htons
    mov [rdx + 2], ax
    mov eax, [ip_binary]
    mov [rdx + 4], eax

    ; registra slot ANTES do connect
    mov esi, [n_active]             ; rsi = indice do novo slot
    inc dword [n_active]
    mov eax, esi
    shl eax, 4
    lea rdx, [pollfds]
    mov [rdx + rax], rbx
    mov word  [rdx + rax + 8], POLLWRNORM
    mov word  [rdx + rax + 10], 0
    mov dword [rdx + rax + 12], 0
    lea rdx, [slot_port]
    mov [rdx + rsi*4], edi
    lea rdx, [slot_state]
    mov dword [rdx + rsi*4], ST_CONNECTING
    call GetTickCount
    lea rdx, [slot_start]
    mov [rdx + rsi*4], eax
    inc dword [next_port]
    inc dword [tested_count]

    mov rcx, rbx
    lea rdx, [sockaddr_in]
    mov r8d, 16
    call connect
    test eax, eax
    jz .connected
    call WSAGetLastError
    cmp eax, WSAEWOULDBLOCK
    je .ok                          ; em andamento: o poll acompanha
    ; falha imediata
    mov ecx, esi
    call remove_slot
    mov ecx, edi
    call print_closed
    jmp .ok
.connected:                         ; conectou na hora (ex.: loopback)
    mov ecx, esi
    call begin_reading
.ok:
    xor eax, eax
    jmp .out
.fatal:
    mov eax, -1
.out:
    add rsp, 48
    pop rdi
    pop rsi
    pop rbx
    ret

; -----------------------------------------------------------------------------
; begin_reading(ecx = slot): passa para ST_READING e envia probe HTTP se a
; porta for tipicamente HTTP.
; -----------------------------------------------------------------------------
begin_reading:
    push rbx
    push rsi
    sub rsp, 40

    mov ebx, ecx
    mov eax, ebx
    shl eax, 4
    lea rdx, [pollfds]
    mov rsi, [rdx + rax]            ; SOCKET
    mov word [rdx + rax + 8], POLLRDNORM
    lea rdx, [slot_state]
    mov dword [rdx + rbx*4], ST_READING
    call GetTickCount
    lea rdx, [slot_start]
    mov [rdx + rbx*4], eax

    lea rdx, [slot_port]
    mov ecx, [rdx + rbx*4]
    call should_probe
    test eax, eax
    jz .out
    mov rcx, rsi
    lea rdx, [http_probe]
    mov r8d, http_probe_len
    xor r9d, r9d
    call send
.out:
    add rsp, 40
    pop rsi
    pop rbx
    ret

; -----------------------------------------------------------------------------
; remove_slot(ecx = slot): fecha o socket e compacta o vetor (move o ultimo
; slot para o buraco).
; -----------------------------------------------------------------------------
remove_slot:
    push rbx
    sub rsp, 32

    mov ebx, ecx
    mov eax, ebx
    shl eax, 4
    lea rdx, [pollfds]
    mov rcx, [rdx + rax]
    call closesocket

    mov eax, [n_active]
    dec eax                         ; eax = indice do ultimo slot
    mov [n_active], eax
    cmp ebx, eax
    je .done                        ; removeu o proprio ultimo

    lea rdx, [pollfds]
    mov ecx, eax
    shl ecx, 4                      ; origem  = ultimo*16
    mov r8d, ebx
    shl r8d, 4                      ; destino = buraco*16
    mov r9, [rdx + rcx]
    mov [rdx + r8], r9
    mov r9, [rdx + rcx + 8]
    mov [rdx + r8 + 8], r9

    lea rdx, [slot_port]
    mov r9d, [rdx + rax*4]
    mov [rdx + rbx*4], r9d
    lea rdx, [slot_state]
    mov r9d, [rdx + rax*4]
    mov [rdx + rbx*4], r9d
    lea rdx, [slot_start]
    mov r9d, [rdx + rax*4]
    mov [rdx + rbx*4], r9d
.done:
    add rsp, 32
    pop rbx
    ret

; -----------------------------------------------------------------------------
; process_events: percorre os slots do ultimo ao primeiro (assim a compactacao
; nunca desloca um slot ainda nao visitado).
; -----------------------------------------------------------------------------
process_events:
    push rbx
    sub rsp, 32

    mov ebx, [n_active]
.next:
    test ebx, ebx
    jz .out
    dec ebx
    mov eax, ebx
    shl eax, 4
    lea rdx, [pollfds]
    movzx ecx, word [rdx + rax + 10]    ; revents
    test ecx, ecx
    jz .next
    lea rdx, [slot_state]
    mov ecx, ebx
    cmp dword [rdx + rbx*4], ST_CONNECTING
    jne .reading
    call handle_connecting
    jmp .next
.reading:
    call handle_reading
    jmp .next
.out:
    add rsp, 32
    pop rbx
    ret

; -----------------------------------------------------------------------------
; handle_connecting(ecx = slot): checa SO_ERROR apos evento no poll.
; -----------------------------------------------------------------------------
handle_connecting:
    push rbx
    push rsi
    sub rsp, 40

    mov ebx, ecx
    mov dword [so_err], 0
    mov dword [so_err_len], 4
    mov eax, ebx
    shl eax, 4
    lea rdx, [pollfds]
    mov rcx, [rdx + rax]            ; SOCKET
    mov edx, SOL_SOCKET
    mov r8d, SO_ERROR
    lea r9, [so_err]
    lea rax, [so_err_len]
    mov [rsp + 32], rax             ; 5o argumento: optlen
    call getsockopt
    test eax, eax
    jnz .failed
    cmp dword [so_err], 0
    jne .failed

    mov ecx, ebx                    ; conectado
    call begin_reading
    jmp .out
.failed:
    lea rdx, [slot_port]
    mov esi, [rdx + rbx*4]
    mov ecx, ebx
    call remove_slot
    mov ecx, esi
    call print_closed
.out:
    add rsp, 40
    pop rsi
    pop rbx
    ret

; -----------------------------------------------------------------------------
; handle_reading(ecx = slot): recv do banner.
; -----------------------------------------------------------------------------
handle_reading:
    push rbx
    push rsi
    push rdi
    sub rsp, 32

    mov ebx, ecx
    lea rdx, [slot_port]
    mov esi, [rdx + rbx*4]          ; esi = porta
    mov eax, ebx
    shl eax, 4
    lea rdx, [pollfds]
    mov rcx, [rdx + rax]
    lea rdx, [banner_buf]
    mov r8d, BANNER_MAX
    xor r9d, r9d
    call recv
    mov edi, eax                    ; edi = bytes lidos
    test edi, edi
    js .err
    jz .nobanner

    ; sanitiza: so imprimiveis + TAB/CR/LF; o resto vira '.'
    lea r8, [banner_buf]
    xor ecx, ecx
.san:
    cmp ecx, edi
    jae .trim
    movzx eax, byte [r8 + rcx]
    cmp al, 9
    je .keep
    cmp al, 10
    je .keep
    cmp al, 13
    je .keep
    cmp al, 0x20
    jb .rep
    cmp al, 0x7E
    jbe .keep
.rep:
    mov byte [r8 + rcx], '.'
.keep:
    inc ecx
    jmp .san

.trim:                              ; remove CR/LF finais
    test edi, edi
    jz .terminate
    movzx eax, byte [r8 + rdi - 1]
    cmp al, 10
    je .cut
    cmp al, 13
    jne .terminate
.cut:
    dec edi
    jmp .trim
.terminate:
    mov byte [r8 + rdi], 0          ; buffer tem BANNER_MAX+1 bytes
    test edi, edi
    jz .nobanner

    mov ecx, ebx
    call remove_slot
    mov ecx, esi
    lea rdx, [banner_buf]
    mov r8d, edi
    call print_open_banner
    jmp .out

.err:
    call WSAGetLastError
    cmp eax, WSAEWOULDBLOCK
    je .out                         ; falso alarme: continua esperando
    ; qualquer outro erro apos conectar: a porta esta aberta, sem banner
.nobanner:
    mov ecx, ebx
    call remove_slot
    mov ecx, esi
    call print_open_nobanner
.out:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret

; -----------------------------------------------------------------------------
; expire_slots: timeout individual por slot (GetTickCount, seguro contra wrap).
;   CONNECTING expirado -> "timeout"
;   READING    expirado -> porta aberta, sem banner
; -----------------------------------------------------------------------------
expire_slots:
    push rbx
    push rsi
    push rdi
    sub rsp, 32

    call GetTickCount
    mov edi, eax                    ; edi = agora
    mov ebx, [n_active]
.next:
    test ebx, ebx
    jz .out
    dec ebx
    lea rdx, [slot_state]
    mov r8d, [rdx + rbx*4]
    mov ecx, CONNECT_TIMEOUT
    cmp r8d, ST_READING
    jne .chk
    mov ecx, BANNER_TIMEOUT
.chk:
    lea rdx, [slot_start]
    mov eax, edi
    sub eax, [rdx + rbx*4]          ; decorrido
    cmp eax, ecx
    jb .next

    lea rdx, [slot_port]
    mov esi, [rdx + rbx*4]
    cmp r8d, ST_READING
    je .reading
    inc dword [timeout_count]
    mov ecx, ebx
    call remove_slot
    mov ecx, esi
    call print_timeout
    jmp .next
.reading:
    mov ecx, ebx
    call remove_slot
    mov ecx, esi
    call print_open_nobanner
    jmp .next
.out:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret

; -----------------------------------------------------------------------------
; should_probe(ecx = porta) -> eax = 1 se for porta HTTP comum
; -----------------------------------------------------------------------------
should_probe:
    cmp ecx, 80
    je .yes
    cmp ecx, 8080
    je .yes
    cmp ecx, 8000
    je .yes
    cmp ecx, 8008
    je .yes
    cmp ecx, 8888
    je .yes
    xor eax, eax
    ret
.yes:
    mov eax, 1
    ret

; =============================================================================
; Saida
; =============================================================================

; print_status(ecx = porta, rdx = prefixo, r8 = sufixo)
print_status:
    push rbx
    push rsi
    sub rsp, 40
    mov ebx, ecx
    mov rsi, r8
    mov rcx, rdx
    call write_cstr
    mov ecx, ebx
    call print_uint
    mov rcx, rsi
    call write_cstr
    add rsp, 40
    pop rsi
    pop rbx
    ret

print_closed:                       ; ecx = porta
    lea rdx, [msg_closed_prefix]
    lea r8,  [msg_closed_suffix]
    jmp print_status

print_timeout:                      ; ecx = porta
    lea rdx, [msg_closed_prefix]
    lea r8,  [msg_timeout_suffix]
    jmp print_status

print_open_nobanner:                ; ecx = porta
    inc dword [open_count]
    lea rdx, [msg_open_prefix]
    lea r8,  [msg_open_suffix]
    jmp print_status

; print_open_banner(ecx = porta, rdx = banner NUL-terminado, r8d = tamanho)
print_open_banner:
    push rbx
    push rsi
    push rdi
    sub rsp, 32

    mov rsi, rdx
    mov edi, r8d
    inc dword [open_count]
    lea rdx, [msg_open_prefix]
    lea r8,  [msg_open_suffix]
    call print_status               ; ecx ainda = porta

    lea rcx, [msg_banner_ind]
    call write_cstr
    mov rcx, rsi
    mov edx, edi
    call write_bytes
    lea rcx, [newline]
    call write_cstr

    mov rcx, rsi
    call guess_os
    test rax, rax
    jz .out
    mov rbx, rax
    lea rcx, [msg_os_ind]
    call write_cstr
    mov rcx, rbx
    call write_cstr
    lea rcx, [newline]
    call write_cstr
.out:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret

; write_cstr(rcx = string NUL-terminada)
write_cstr:
    mov rdx, rcx
.len:
    cmp byte [rdx], 0
    je .go
    inc rdx
    jmp .len
.go:
    sub rdx, rcx
    jmp write_bytes                 ; tail call

; write_bytes(rcx = buf, rdx = tamanho)
write_bytes:
    push rbx
    push rsi
    sub rsp, 40                     ; [rsp+32] = 5o argumento
    mov rbx, rcx
    mov rsi, rdx
.loop:
    test rsi, rsi
    jz .done
    mov rcx, [hStdout]
    mov rdx, rbx
    mov r8, rsi
    lea r9, [bytes_written]
    mov qword [rsp + 32], 0         ; lpOverlapped = NULL
    call WriteFile
    test eax, eax
    jz .done                        ; falha: desiste
    mov eax, [bytes_written]
    test eax, eax
    jz .done                        ; evita laco infinito
    add rbx, rax
    sub rsi, rax
    jmp .loop
.done:
    add rsp, 40
    pop rsi
    pop rbx
    ret

; print_uint(ecx = valor)
print_uint:
    push rbx
    sub rsp, 32
    lea rbx, [num_buffer + 31]      ; fim (exclusivo)
    mov eax, ecx
    mov r8d, 10
.d:
    xor edx, edx
    div r8d
    add dl, '0'
    dec rbx
    mov [rbx], dl
    test eax, eax
    jnz .d
    lea rdx, [num_buffer + 31]
    sub rdx, rbx                    ; tamanho
    mov rcx, rbx
    call write_bytes
    add rsp, 32
    pop rbx
    ret

; =============================================================================
; Entrada e parsing
; =============================================================================

; read_line(rcx = buf, edx = capacidade) -> eax = tamanho, 0 = EOF, -1 = erro
; Remove o "\r\n" final e termina com NUL.
read_line:
    push rbx
    push rsi
    push rdi
    sub rsp, 48                     ; [rsp+32] = 5o argumento
    mov rbx, rcx
    mov esi, edx
    dec esi                         ; reserva 1 byte para o NUL
    xor edi, edi
.loop:
    cmp edi, esi
    jae .fail                       ; linha longa demais
    mov rcx, [hStdin]
    lea rdx, [rbx + rdi]
    mov r8d, 1
    lea r9, [bytes_read]
    mov qword [rsp + 32], 0
    call ReadFile
    test eax, eax
    jz .fail
    cmp dword [bytes_read], 0
    je .eof
    cmp byte [rbx + rdi], 10
    je .nl
    inc edi
    jmp .loop
.nl:
    test edi, edi
    jz .term
    cmp byte [rbx + rdi - 1], 13    ; descarta o CR
    jne .term
    dec edi
.term:
.eof:
    mov byte [rbx + rdi], 0
    mov eax, edi
    jmp .out
.fail:
    mov eax, -1
.out:
    add rsp, 48
    pop rdi
    pop rsi
    pop rbx
    ret

; prompt_port(rcx = prompt) -> eax = porta 1..65535, 0 = invalida, -1 = erro de entrada
prompt_port:
    sub rsp, 40
    call write_cstr
    lea rcx, [line_buffer]
    mov edx, 64
    call read_line
    test eax, eax
    jle .inerr
    lea rcx, [line_buffer]
    call parse_uint
    test edx, edx
    jz .bad
    test eax, eax
    jnz .out                        ; eax = valor valido
.bad:
    xor eax, eax
    jmp .out
.inerr:
    mov eax, -1
.out:
    add rsp, 40
    ret

; parse_uint(rcx = str) -> eax = valor (<= 65535), edx = 1 ok / 0 falha
parse_uint:
    xor eax, eax
    xor r8d, r8d
.l:
    movzx r9d, byte [rcx + r8]
    test r9d, r9d
    jz .done
    sub r9d, '0'
    cmp r9d, 9
    ja .fail
    imul eax, eax, 10
    add eax, r9d
    cmp eax, 65535
    ja .fail
    inc r8d
    jmp .l
.done:
    test r8d, r8d
    jz .fail
    mov edx, 1
    ret
.fail:
    xor eax, eax
    xor edx, edx
    ret

; parse_ipv4(rcx = str) -> eax = 1 ok / 0 falha, edx = endereco em ordem de rede
parse_ipv4:
    xor r8d, r8d                    ; octeto atual
    xor r9d, r9d                    ; digitos do octeto
    xor r10d, r10d                  ; pontos vistos
    xor r11d, r11d                  ; acumulador (ordem do host)
.l:
    movzx eax, byte [rcx]
    test eax, eax
    jz .end
    inc rcx
    cmp eax, '.'
    je .dot
    sub eax, '0'
    cmp eax, 9
    ja .fail
    imul r8d, r8d, 10
    add r8d, eax
    cmp r8d, 255
    ja .fail
    inc r9d
    cmp r9d, 3
    ja .fail
    jmp .l
.dot:
    test r9d, r9d
    jz .fail
    cmp r10d, 3
    jae .fail
    shl r11d, 8
    or r11d, r8d
    inc r10d
    xor r8d, r8d
    xor r9d, r9d
    jmp .l
.end:
    test r9d, r9d
    jz .fail
    cmp r10d, 3
    jne .fail
    shl r11d, 8
    or r11d, r8d
    bswap r11d                      ; primeiro octeto no byte menos significativo
    mov edx, r11d
    mov eax, 1
    ret
.fail:
    xor eax, eax
    xor edx, edx
    ret

; =============================================================================
; Deteccao de SO
; =============================================================================

%macro PROBE 2                      ; %1 = needle, %2 = label de destino
    mov rcx, rbx
    lea rdx, [%1]
    call find_sub
    test eax, eax
    jnz %2
%endmacro

; guess_os(rcx = banner NUL-terminado) -> rax = string do SO ou 0
; Windows e testado primeiro: "OpenSSH_for_Windows" tambem contem "OpenSSH_".
guess_os:
    push rbx
    sub rsp, 32
    mov rbx, rcx
    PROBE sub_windows,   .win
    PROBE sub_microsoft, .win
    PROBE sub_ubuntu,    .lin
    PROBE sub_debian,    .lin
    PROBE sub_openssh,   .lin
    PROBE sub_linux,     .lin
    xor eax, eax
    jmp .out
.lin:
    lea rax, [os_linux]
    jmp .out
.win:
    lea rax, [os_windows]
.out:
    add rsp, 32
    pop rbx
    ret

; find_sub(rcx = haystack, rdx = needle, ambos NUL-terminados) -> eax = 1/0
find_sub:
.outer:
    cmp byte [rcx], 0
    je .notfound
    xor r8d, r8d
.inner:
    mov al, [rdx + r8]
    test al, al
    jz .found                       ; needle inteira casou
    cmp al, [rcx + r8]
    jne .next
    inc r8d
    jmp .inner
.next:
    inc rcx
    jmp .outer
.found:
    mov eax, 1
    ret
.notfound:
    xor eax, eax
    ret
