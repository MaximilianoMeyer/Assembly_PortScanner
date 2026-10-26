; asmSyn.asm
; Linux x86-64 / NASM, direct syscalls (no libc).
; TCP connect scan + banner grabbing + OS guessing via banner and TTL (using raw sockets).
;
; New features compared to v2:
;   - Individual timeout per slot (using monotonic clock_gettime + a deadline for each slot).
;   - Raw socket (AF_INET/SOCK_RAW/IPPROTO_TCP) listens for SYN/ACK and RST packets from the target,
;     reads the TTL from the IP header, estimates the initial TTL, and guesses the OS.
;   - Final report comparing the banner against the TTL-based estimate.
;   - Banners are stripped of trailing CR/LF characters.
;
; Build:
;   nasm -felf64 asmSyn.asm -o asmSyn.o
;   ld -o asmSyn asmSyn.o
; Run (raw sockets require root privileges or the CAP_NET_RAW capability):
;   sudo ./asmSyn
;   # or: sudo setcap cap_net_raw+ep ./asmSyn && ./asmSyn
; The scan will still function without privileges, though TTL-based detection will be unavailable.
;
; Use only on hosts/networks that you own or have authorization to test.

default abs

%define SYS_read          0
%define SYS_write         1
%define SYS_close         3
%define SYS_poll          7
%define SYS_socket        41
%define SYS_connect       42
%define SYS_sendto        44
%define SYS_recvfrom      45
%define SYS_getsockopt    55
%define SYS_exit          60
%define SYS_clock_gettime 228

%define AF_INET         2
%define SOCK_STREAM     1
%define SOCK_RAW        3
%define SOCK_NONBLOCK   0x800
%define IPPROTO_TCP     6
%define SOL_SOCKET      1
%define SO_ERROR        4
%define CLOCK_MONOTONIC 1

%define POLLIN          0x001
%define POLLOUT         0x004
%define POLLERR         0x008
%define POLLHUP         0x010
%define POLLNVAL        0x020

%define MAX_INFLIGHT    64
%define CONNECT_TIMEOUT 1000            ; ms
%define BANNER_TIMEOUT  800             ; ms
%define BANNER_MAX      256
%define RAW_BUF         128
%define RAW_IDX         MAX_INFLIGHT    ; ultimo pollfd = raw socket

; Slot states
%define ST_FREE         0
%define ST_CONNECTING   1
%define ST_READING      2

; deadline = agora + %1 ms (ebx = slot). Clobbers rax.
%macro SET_DEADLINE 1
    call now_ms
    add rax, %1
    mov [slot_deadline + rbx*8], rax
%endmacro

section .rodata
prompt_ip       db "Enter target IPv4 (e.g., 192.168.1.1): ", 0
prompt_start    db "Enter start port (1-65535): ", 0
prompt_end      db "Enter end port (1-65535): ", 0
msg_scanning    db "Scanning ", 0
msg_range       db " ports ", 0
range_through   db " through ", 0
msg_open_prefix db "[+] ", 0
msg_open_suffix db " OPEN", 10, 0
msg_closed_prefix db "[-] ", 0
msg_closed_suffix db " closed/filtered", 10, 0
msg_timeout_suffix db " timeout", 10, 0
msg_banner_ind  db "    banner: ", 0
msg_os_ind      db "    os guess: ", 0
os_linux        db "Linux/Unix", 0
os_windows      db "Windows", 0
os_network      db "Network device/Solaris", 0
msg_invalid_ip  db "Invalid IPv4 address.", 10, 0
msg_invalid_ports db "Invalid port range. Use 1 <= start <= end <= 65535.", 10, 0
msg_input_error db "Input error or line too long.", 10, 0
msg_socket_error db "Could not create socket; aborting.", 10, 0
msg_no_raw      db "[!] Raw socket indisponivel (precisa de root/CAP_NET_RAW): TTL desativado.", 10, 0
msg_summary1    db "Finished. Open ports: ", 0
msg_summary2    db ", tested: ", 0
msg_summary3    db ", timeouts/errors: ", 0
msg_banner_os   db "Banner OS guess: ", 0
msg_ttl_none    db "TTL: nenhum SYN/ACK ou RST do alvo observado.", 10, 0
msg_ttl_ind     db "TTL observed: ", 0
msg_ttl_mid     db " (initial ~", 0
msg_ttl_arrow   db ") -> ", 0
msg_agree       db "Banner and TTL agree.", 10, 0
msg_disagree    db "Banner and TTL disagree (NAT/proxy/TTL customizado?).", 10, 0
newline         db 10, 0

; HTTP probe (enviado so para algumas portas)
http_probe      db "GET / HTTP/1.0", 13, 10, "Host: target", 13, 10, 13, 10
http_probe_len  equ $ - http_probe

; Substrings para o OS guess por banner (case-sensitive)
sub_ubuntu      db "Ubuntu", 0
sub_debian      db "Debian", 0
sub_openssh     db "OpenSSH_", 0
sub_linux       db "Linux", 0
sub_windows     db "Windows", 0
sub_microsoft   db "Microsoft", 0
sub_iis         db "IIS/", 0
sub_freebsd     db "FreeBSD", 0
sub_netbsd      db "NetBSD", 0

; Tabela (needle, resultado). Ordem importa: Windows antes de OpenSSH_
; (existe "OpenSSH_for_Windows"). Terminada por 0.
align 8
os_table:
    dq sub_windows,   os_windows
    dq sub_microsoft, os_windows
    dq sub_iis,       os_windows
    dq sub_ubuntu,    os_linux
    dq sub_debian,    os_linux
    dq sub_linux,     os_linux
    dq sub_freebsd,   os_linux
    dq sub_netbsd,    os_linux
    dq sub_openssh,   os_linux
    dq 0, 0

section .bss
alignb 8
timespec        resq 2
ttl_os_ptr      resq 1
banner_os_ptr   resq 1
slot_deadline   resq MAX_INFLIGHT
ip_input        resb 64
line_buffer     resb 64
ip_binary       resd 1
port_start      resd 1
port_end        resd 1
next_port       resd 1
current_inflight resd 1
open_count      resd 1
tested_count    resd 1
timeout_count   resd 1
raw_fd          resd 1
ttl_value       resd 1
ttl_quality     resd 1                  ; 0=nada, 1=RST, 2=SYN/ACK (melhor)
ttl_initial     resd 1
socket_error    resd 1
sockopt_len     resd 1
sockaddr        resb 16
pollfds         resb (MAX_INFLIGHT + 1) * 8
slot_ports      resd MAX_INFLIGHT
slot_states     resd MAX_INFLIGHT
slot_probed     resd MAX_INFLIGHT
banner_len      resd MAX_INFLIGHT
num_buffer      resb 32
raw_buf         resb RAW_BUF
banner_buf      resb MAX_INFLIGHT * BANNER_MAX

section .text
global _start

_start:
    lea rsi, [prompt_ip]
    call write_cstr

    lea rdi, [ip_input]
    mov esi, 64
    call read_line
    test eax, eax
    jle input_error_exit

    lea rdi, [ip_input]
    call parse_ipv4
    test eax, eax
    jz invalid_ip_exit
    mov [ip_binary], edx

    lea rsi, [prompt_start]
    call write_cstr
    lea rdi, [line_buffer]
    mov esi, 64
    call read_line
    test eax, eax
    jle input_error_exit
    lea rdi, [line_buffer]
    call parse_uint
    test edx, edx
    jz invalid_ports_exit
    cmp eax, 1
    jb invalid_ports_exit
    cmp eax, 65535
    ja invalid_ports_exit
    mov [port_start], eax

    lea rsi, [prompt_end]
    call write_cstr
    lea rdi, [line_buffer]
    mov esi, 64
    call read_line
    test eax, eax
    jle input_error_exit
    lea rdi, [line_buffer]
    call parse_uint
    test edx, edx
    jz invalid_ports_exit
    cmp eax, 1
    jb invalid_ports_exit
    cmp eax, 65535
    ja invalid_ports_exit
    mov [port_end], eax
    mov eax, [port_start]
    cmp eax, [port_end]
    ja invalid_ports_exit

    ; Header
    lea rsi, [msg_scanning]
    call write_cstr
    lea rsi, [ip_input]
    call write_cstr
    lea rsi, [msg_range]
    call write_cstr
    mov eax, [port_start]
    call print_uint
    lea rsi, [range_through]
    call write_cstr
    mov eax, [port_end]
    call print_uint
    lea rsi, [newline]
    call write_cstr

    ; fd = -1 em todos os pollfds (fd 0 seria stdin)
    xor ebx, ebx
.init_poll:
    mov dword [pollfds + rbx*8], -1
    inc ebx
    cmp ebx, MAX_INFLIGHT + 1
    jb .init_poll
    mov dword [raw_fd], -1

    ; Raw socket ANTES do scan, para nao perder o primeiro SYN/ACK
    mov eax, SYS_socket
    mov edi, AF_INET
    mov esi, SOCK_RAW | SOCK_NONBLOCK
    mov edx, IPPROTO_TCP
    syscall
    test rax, rax
    js .no_raw
    mov [raw_fd], eax
    mov [pollfds + RAW_IDX*8], eax
    mov word [pollfds + RAW_IDX*8 + 4], POLLIN
    jmp .raw_done
.no_raw:
    lea rsi, [msg_no_raw]
    call write_cstr
.raw_done:

    mov eax, [port_start]
    mov [next_port], eax

.scan_fill:
    mov eax, [next_port]
    cmp eax, [port_end]
    jbe .have_ports
    cmp dword [current_inflight], 0
    jne .wait
    jmp scan_complete
.have_ports:
    cmp dword [current_inflight], MAX_INFLIGHT
    jae .wait

    call find_free_slot
    cmp eax, -1
    je .wait
    mov ebx, eax

    ; create socket
    mov eax, SYS_socket
    mov edi, AF_INET
    mov esi, SOCK_STREAM | SOCK_NONBLOCK
    xor edx, edx
    syscall
    test rax, rax
    js socket_fatal
    mov r8, rax

    ; build sockaddr
    lea rdi, [sockaddr]
    xor eax, eax
    mov ecx, 16
    rep stosb
    mov word [sockaddr], AF_INET
    mov eax, [next_port]
    xchg al, ah                     ; host -> network byte order
    mov word [sockaddr + 2], ax
    mov eax, [ip_binary]
    mov [sockaddr + 4], eax

    mov eax, SYS_connect
    mov rdi, r8
    lea rsi, [sockaddr]
    mov edx, 16
    syscall
    mov r9, rax

    ; register slot
    mov eax, [next_port]
    mov [slot_ports + rbx*4], eax
    mov dword [slot_states + rbx*4], ST_CONNECTING
    mov dword [slot_probed + rbx*4], 0
    mov dword [banner_len + rbx*4], 0
    mov [pollfds + rbx*8], r8d
    mov word [pollfds + rbx*8 + 4], POLLOUT
    mov word [pollfds + rbx*8 + 6], 0
    SET_DEADLINE CONNECT_TIMEOUT    ; preserva r8/r9
    inc dword [current_inflight]
    inc dword [tested_count]
    inc dword [next_port]

    test r9, r9
    jz .imm_success
    cmp r9, -115                    ; EINPROGRESS
    je .scan_fill
    cmp r9, -114                    ; EALREADY
    je .scan_fill
    ; falha imediata
    call release_slot
    mov edi, [slot_ports + rbx*4]
    call print_closed
    jmp .scan_fill

.imm_success:
    mov word [pollfds + rbx*8 + 4], POLLIN
    mov dword [slot_states + rbx*4], ST_READING
    SET_DEADLINE BANNER_TIMEOUT
    mov edi, [slot_ports + rbx*4]
    call should_probe
    test eax, eax
    jz .scan_fill
    mov edi, [pollfds + rbx*8]
    call send_probe
    mov dword [slot_probed + rbx*4], 1
    jmp .scan_fill

.wait:
    cmp dword [current_inflight], 0
    je .scan_fill
    call compute_timeout            ; eax = ms ate o proximo deadline
    mov edx, eax
    lea rdi, [pollfds]
    mov esi, MAX_INFLIGHT + 1
    mov eax, SYS_poll
    syscall
    test rax, rax
    js .poll_error
    jz .post_poll

    xor ebx, ebx
.process_slots:
    cmp ebx, MAX_INFLIGHT
    jae .post_poll
    mov eax, [slot_states + rbx*4]
    cmp eax, ST_FREE
    je .next_slot

    movzx ecx, word [pollfds + rbx*8 + 6]
    test ecx, (POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLIN)
    jz .next_slot

    cmp eax, ST_CONNECTING
    je .handle_connecting
    jmp .handle_reading

.handle_connecting:
    mov dword [socket_error], 0
    mov dword [sockopt_len], 4
    mov eax, SYS_getsockopt
    mov edi, [pollfds + rbx*8]
    mov esi, SOL_SOCKET
    mov edx, SO_ERROR
    lea r10, [socket_error]
    lea r8, [sockopt_len]
    syscall
    test rax, rax
    js .conn_err
    cmp dword [socket_error], 0
    jne .conn_failed

    ; conectou -> leitura, probe opcional
    mov word [pollfds + rbx*8 + 4], POLLIN
    mov dword [slot_states + rbx*4], ST_READING
    SET_DEADLINE BANNER_TIMEOUT

    mov edi, [slot_ports + rbx*4]
    call should_probe
    test eax, eax
    jz .next_slot
    mov edi, [pollfds + rbx*8]
    call send_probe
    mov dword [slot_probed + rbx*4], 1
    jmp .next_slot

.conn_failed:
    call release_slot
    mov edi, [slot_ports + rbx*4]
    call print_closed
    jmp .next_slot

.conn_err:
    call release_slot
    inc dword [timeout_count]
    jmp .next_slot

.handle_reading:
    ; rsi = &banner_buf[slot * BANNER_MAX]
    lea rsi, [banner_buf]
    mov eax, ebx
    imul eax, BANNER_MAX
    add rsi, rax
    mov edi, [pollfds + rbx*8]
    mov edx, BANNER_MAX - 1         ; reserva 1 byte para o NUL
    mov eax, SYS_read
    syscall
    test rax, rax
    js .read_err
    jz .read_eof

    mov ecx, eax
    xor edx, edx
.sanitize:
    cmp edx, ecx
    jae .sanitize_done
    movzx eax, byte [rsi + rdx]
    cmp al, 0x20
    jb .san_ctrl
    cmp al, 0x7E
    ja .san_repl
    jmp .san_next
.san_ctrl:
    cmp al, 10
    je .san_next
    cmp al, 13
    je .san_next
    cmp al, 9
    je .san_next
.san_repl:
    mov byte [rsi + rdx], '.'
.san_next:
    inc edx
    jmp .sanitize
.sanitize_done:
    ; remove CR/LF finais
.trim:
    test ecx, ecx
    jz .trim_done
    mov al, [rsi + rcx - 1]
    cmp al, 10
    je .trim_dec
    cmp al, 13
    jne .trim_done
.trim_dec:
    dec ecx
    jmp .trim
.trim_done:
    mov [banner_len + rbx*4], ecx
    mov byte [rsi + rcx], 0         ; NUL (find_sub depende disso)
    call release_slot
    mov edi, [slot_ports + rbx*4]
    call print_open_with_banner
    jmp .next_slot

.read_err:
    cmp rax, -11                    ; EAGAIN -> espera proximo poll
    je .next_slot
    call release_slot
    inc dword [timeout_count]
    mov edi, [slot_ports + rbx*4]
    call print_timeout
    jmp .next_slot

.read_eof:
    call release_slot
    mov edi, [slot_ports + rbx*4]
    call print_open_no_banner

.next_slot:
    inc ebx
    jmp .process_slots

.post_poll:
    call drain_raw                  ; coleta TTL de pacotes do alvo

    ; expira slots cujo deadline passou: CONNECTING -> timeout,
    ; READING -> aberta sem banner
    call now_ms
    mov r12, rax
    xor ebx, ebx
.sweep:
    cmp ebx, MAX_INFLIGHT
    jae .scan_fill
    mov r13d, [slot_states + rbx*4]
    cmp r13d, ST_FREE
    je .sweep_next
    cmp r12, [slot_deadline + rbx*8]
    jb .sweep_next
    call release_slot
    cmp r13d, ST_READING
    je .sweep_reading
    inc dword [timeout_count]
    mov edi, [slot_ports + rbx*4]
    call print_timeout
    jmp .sweep_next
.sweep_reading:
    mov edi, [slot_ports + rbx*4]
    call print_open_no_banner
.sweep_next:
    inc ebx
    jmp .sweep

.poll_error:
    cmp rax, -4                     ; EINTR
    je .wait
    xor ebx, ebx
.poll_cleanup:
    cmp ebx, MAX_INFLIGHT
    jae .scan_fill
    cmp dword [slot_states + rbx*4], ST_FREE
    je .poll_cleanup_next
    call release_slot
    inc dword [timeout_count]
.poll_cleanup_next:
    inc ebx
    jmp .poll_cleanup

scan_complete:
    call drain_raw
    lea rsi, [msg_summary1]
    call write_cstr
    mov eax, [open_count]
    call print_uint
    lea rsi, [msg_summary2]
    call write_cstr
    mov eax, [tested_count]
    call print_uint
    lea rsi, [msg_summary3]
    call write_cstr
    mov eax, [timeout_count]
    call print_uint
    lea rsi, [newline]
    call write_cstr
    call print_os_report
    mov eax, SYS_exit
    xor edi, edi
    syscall

; ---------- tempo ----------

; now_ms -> rax = milissegundos (CLOCK_MONOTONIC). Preserva todos os outros regs.
now_ms:
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r11
    mov eax, SYS_clock_gettime
    mov edi, CLOCK_MONOTONIC
    lea rsi, [timespec]
    syscall
    mov r8, [timespec]
    imul r8, r8, 1000
    mov rax, [timespec + 8]
    xor edx, edx
    mov ecx, 1000000
    div rcx
    add rax, r8
    pop r11
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    ret

; compute_timeout -> eax = ms ate o deadline mais proximo (0 se ja venceu)
; Clobbers r9, r10. Preserva rbx.
compute_timeout:
    push rbx
    call now_ms
    mov r10, rax
    mov r9d, CONNECT_TIMEOUT
    xor ebx, ebx
.loop:
    cmp ebx, MAX_INFLIGHT
    jae .done
    cmp dword [slot_states + rbx*4], ST_FREE
    je .next
    mov rax, [slot_deadline + rbx*8]
    sub rax, r10
    jg .pos
    xor r9d, r9d
    jmp .done
.pos:
    cmp rax, r9
    jae .next
    mov r9, rax
.next:
    inc ebx
    jmp .loop
.done:
    mov eax, r9d
    pop rbx
    ret

; ---------- raw socket / TTL ----------

; drain_raw: le todos os pacotes pendentes do raw socket (nao bloqueante).
; Aceita so pacotes TCP vindos do alvo, com porta de origem dentro do range
; escaneado e flags SYN/ACK ou RST. SYN/ACK tem prioridade sobre RST
; (firewalls podem forjar RST com outro TTL).
drain_raw:
    cmp dword [raw_fd], 0
    jl .out
.again:
    mov eax, SYS_recvfrom
    mov edi, [raw_fd]
    lea rsi, [raw_buf]
    mov edx, RAW_BUF
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .out                        ; EAGAIN / erro / 0
    mov r8, rax                     ; tamanho recebido
    cmp r8, 40
    jb .again
    movzx ecx, byte [raw_buf]
    and ecx, 0x0F
    shl ecx, 2                      ; tamanho do cabecalho IP
    cmp ecx, 20
    jb .again
    lea rdx, [rcx + 20]
    cmp rdx, r8                     ; cabecalho TCP precisa caber
    ja .again
    cmp byte [raw_buf + 9], IPPROTO_TCP
    jne .again
    mov eax, [raw_buf + 12]         ; IP de origem (network order)
    cmp eax, [ip_binary]
    jne .again
    movzx eax, word [raw_buf + rcx] ; porta de origem (network order)
    rol ax, 8
    cmp eax, [port_start]
    jb .again
    cmp eax, [port_end]
    ja .again
    movzx eax, byte [raw_buf + rcx + 13]    ; flags TCP
    mov edx, eax
    and edx, 0x12
    cmp edx, 0x12
    je .synack
    test al, 0x04                   ; RST
    jz .again
    mov edx, 1
    jmp .record
.synack:
    mov edx, 2
.record:
    cmp edx, [ttl_quality]
    jbe .again
    mov [ttl_quality], edx
    movzx eax, byte [raw_buf + 8]   ; TTL
    mov [ttl_value], eax
    jmp .again
.out:
    ret

; print_os_report: resumo final (banner x TTL)
print_os_report:
    cmp qword [banner_os_ptr], 0
    je .ttl_part
    lea rsi, [msg_banner_os]
    call write_cstr
    mov rsi, [banner_os_ptr]
    call write_cstr
    lea rsi, [newline]
    call write_cstr
.ttl_part:
    cmp dword [raw_fd], 0
    jl .done
    mov eax, [ttl_value]
    test eax, eax
    jnz .have_ttl
    lea rsi, [msg_ttl_none]
    call write_cstr
    jmp .done
.have_ttl:
    ; TTL inicial tipico: 64 (Linux/macOS/BSD), 128 (Windows), 255 (Cisco/Solaris)
    cmp eax, 64
    ja .gt64
    mov dword [ttl_initial], 64
    lea rax, [os_linux]
    jmp .set
.gt64:
    cmp eax, 128
    ja .gt128
    mov dword [ttl_initial], 128
    lea rax, [os_windows]
    jmp .set
.gt128:
    mov dword [ttl_initial], 255
    lea rax, [os_network]
.set:
    mov [ttl_os_ptr], rax
    lea rsi, [msg_ttl_ind]
    call write_cstr
    mov eax, [ttl_value]
    call print_uint
    lea rsi, [msg_ttl_mid]
    call write_cstr
    mov eax, [ttl_initial]
    call print_uint
    lea rsi, [msg_ttl_arrow]
    call write_cstr
    mov rsi, [ttl_os_ptr]
    call write_cstr
    lea rsi, [newline]
    call write_cstr

    mov rax, [banner_os_ptr]
    test rax, rax
    jz .done
    cmp rax, [ttl_os_ptr]
    je .agree
    lea rsi, [msg_disagree]
    call write_cstr
    jmp .done
.agree:
    lea rsi, [msg_agree]
    call write_cstr
.done:
    ret

; ---------- helpers ----------

; release_slot: ebx = slot. Fecha o fd e marca o slot como livre.
; Clobbers: rax, rdi, rcx, r11
release_slot:
    mov edi, [pollfds + rbx*8]
    mov eax, SYS_close
    syscall
    mov dword [slot_states + rbx*4], ST_FREE
    mov dword [pollfds + rbx*8], -1
    mov dword [pollfds + rbx*8 + 4], 0      ; events + revents
    dec dword [current_inflight]
    ret

; send_probe: edi = fd. Envia o HTTP probe.
send_probe:
    mov eax, SYS_sendto
    lea rsi, [http_probe]
    mov edx, http_probe_len
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    ret

; should_probe(port in edi) -> eax=1 se deve enviar HTTP probe
should_probe:
    cmp edi, 80
    je .yes
    cmp edi, 8080
    je .yes
    cmp edi, 8000
    je .yes
    cmp edi, 8008
    je .yes
    cmp edi, 8888
    je .yes
    xor eax, eax
    ret
.yes:
    mov eax, 1
    ret

; print_open_with_banner(port in edi, slot in ebx)
print_open_with_banner:
    push rbx
    push rdi
    lea rsi, [msg_open_prefix]
    call write_cstr
    pop rdi
    mov eax, edi
    call print_uint
    lea rsi, [msg_open_suffix]
    call write_cstr
    inc dword [open_count]

    mov eax, [banner_len + rbx*4]
    test eax, eax
    jz .done

    lea rsi, [msg_banner_ind]
    call write_cstr
    lea rsi, [banner_buf]
    mov eax, ebx
    imul eax, BANNER_MAX
    add rsi, rax
    mov edx, [banner_len + rbx*4]
    call write_bytes
    lea rsi, [newline]
    call write_cstr

    ; OS guess
    lea rsi, [banner_buf]
    mov eax, ebx
    imul eax, BANNER_MAX
    add rsi, rax
    call guess_os_from_banner
    test rax, rax
    jz .done
    cmp qword [banner_os_ptr], 0    ; guarda o 1o palpite para o relatorio final
    jne .print_guess
    mov [banner_os_ptr], rax
.print_guess:
    push rax                        ; write_bytes clobbera r8/r9, entao usa a pilha
    lea rsi, [msg_os_ind]
    call write_cstr
    pop rsi
    call write_cstr
    lea rsi, [newline]
    call write_cstr
.done:
    pop rbx
    ret

; print_open_no_banner(port in edi)
print_open_no_banner:
    push rdi
    lea rsi, [msg_open_prefix]
    call write_cstr
    pop rdi
    mov eax, edi
    call print_uint
    lea rsi, [msg_open_suffix]
    call write_cstr
    inc dword [open_count]
    ret

; print_closed(port in edi)
print_closed:
    push rdi
    lea rsi, [msg_closed_prefix]
    call write_cstr
    pop rdi
    mov eax, edi
    call print_uint
    lea rsi, [msg_closed_suffix]
    call write_cstr
    ret

; print_timeout(port in edi)
print_timeout:
    push rdi
    lea rsi, [msg_closed_prefix]
    call write_cstr
    pop rdi
    mov eax, edi
    call print_uint
    lea rsi, [msg_timeout_suffix]
    call write_cstr
    ret

; write_cstr: rsi = string terminada em NUL
write_cstr:
    push rbx
    mov rbx, rsi
.len:
    cmp byte [rbx], 0
    je .have_len
    inc rbx
    jmp .len
.have_len:
    mov rdx, rbx
    sub rdx, rsi
    call write_bytes
    pop rbx
    ret

; write_bytes: rsi=buffer, rdx=len
write_bytes:
    test rdx, rdx
    jz .done
    mov r8, rsi
    mov r9, rdx
.loop:
    mov eax, SYS_write
    mov edi, 1
    mov rsi, r8
    mov rdx, r9
    syscall
    test rax, rax
    js .err
    jz .done
    add r8, rax
    sub r9, rax
    jnz .loop
.done:
    ret
.err:
    cmp rax, -4
    je .loop
    ret

; print_uint: eax = valor; imprime so o numero (sem newline)
print_uint:
    push rbx
    push rdx
    push rsi
    lea rsi, [num_buffer + 31]
    mov byte [rsi], 0
    mov ebx, 10
    xor ecx, ecx
.digits:
    xor edx, edx
    div ebx
    add dl, '0'
    dec rsi
    mov [rsi], dl
    inc ecx
    test eax, eax
    jnz .digits
    mov edx, ecx                    ; rsi ja aponta para o 1o digito
    call write_bytes
    pop rsi
    pop rdx
    pop rbx
    ret

; read_line: rdi=buffer, esi=capacidade -> eax=tamanho (-1 erro)
read_line:
    push rbx
    push r12
    mov rbx, rdi
    mov r12d, esi
    xor r10d, r10d
.loop:
    cmp r10d, r12d
    jae .too_long
    xor eax, eax
    xor edi, edi
    lea rsi, [rbx + r10]
    mov edx, 1
    syscall
    test rax, rax
    js .err
    jz .eof
    cmp byte [rbx + r10], 10
    je .newline
    inc r10d
    jmp .loop
.newline:
    mov byte [rbx + r10], 0
    mov eax, r10d
    jmp .ret
.eof:
    test r10d, r10d
    jz .eof_empty
    mov byte [rbx + r10], 0
    mov eax, r10d
    jmp .ret
.eof_empty:
    xor eax, eax
    jmp .ret
.err:
    cmp rax, -4
    je .loop
.too_long:
    mov eax, -1
.ret:
    pop r12
    pop rbx
    ret

; parse_uint: rdi=str -> eax=valor, edx=1 se ok
parse_uint:
    xor eax, eax
    xor edx, edx
    xor ecx, ecx
.loop:
    movzx r8d, byte [rdi + rcx]
    test r8b, r8b
    jz .done
    cmp r8b, '0'
    jb .fail
    cmp r8b, '9'
    ja .fail
    imul eax, eax, 10
    sub r8d, '0'
    add eax, r8d
    cmp eax, 65535
    ja .fail
    inc ecx
    jmp .loop
.done:
    test ecx, ecx
    jz .fail
    mov edx, 1
    ret
.fail:
    xor edx, edx
    ret

; parse_ipv4: rdi=str -> eax=1 ok, edx = IP em network byte order
parse_ipv4:
    push rbx
    push r12
    push r13
    mov r12, rdi
    xor r13d, r13d
    xor ebx, ebx
    xor r8d, r8d
    xor r9d, r9d
.loop:
    movzx eax, byte [r12]
    test al, al
    jz .end
    cmp al, '.'
    je .dot
    cmp al, '0'
    jb .fail
    cmp al, '9'
    ja .fail
    imul r8d, r8d, 10
    sub eax, '0'
    add r8d, eax
    cmp r8d, 255
    ja .fail
    inc r9d
    cmp r9d, 3
    ja .fail
    inc r12
    jmp .loop
.dot:
    test r9d, r9d
    jz .fail
    cmp ebx, 3
    jae .fail
    shl r13d, 8
    or r13d, r8d
    inc ebx
    xor r8d, r8d
    xor r9d, r9d
    inc r12
    jmp .loop
.end:
    test r9d, r9d
    jz .fail
    cmp ebx, 3
    jne .fail
    shl r13d, 8
    or r13d, r8d
    mov eax, 1
    mov edx, r13d
    bswap edx
    jmp .ret
.fail:
    xor eax, eax
    xor edx, edx
.ret:
    pop r13
    pop r12
    pop rbx
    ret

; guess_os_from_banner(rsi = buffer NUL-terminado) -> rax = cstr ou 0
guess_os_from_banner:
    push rbx
    push r12
    mov r12, rsi
    lea rbx, [os_table]
.next:
    mov rsi, [rbx]
    test rsi, rsi
    jz .unknown
    mov rdi, r12
    call find_sub
    test eax, eax
    jnz .hit
    add rbx, 16
    jmp .next
.hit:
    mov rax, [rbx + 8]
    jmp .ret
.unknown:
    xor eax, eax
.ret:
    pop r12
    pop rbx
    ret

; find_sub(rdi=haystack NUL-term, rsi=needle NUL-term) -> eax=1 achou, 0 nao
find_sub:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    xor ecx, ecx
.nl:
    cmp byte [r13 + rcx], 0
    je .nl_done
    inc ecx
    jmp .nl
.nl_done:
    test ecx, ecx
    jz .found
.outer:
    cmp byte [r12], 0
    je .not_found
    xor ebx, ebx
.cmp:
    cmp ebx, ecx
    jae .found
    mov al, [r12 + rbx]
    test al, al                     ; fim do haystack no meio do match
    jz .not_found
    cmp al, [r13 + rbx]
    jne .next_pos
    inc ebx
    jmp .cmp
.next_pos:
    inc r12
    jmp .outer
.found:
    mov eax, 1
    jmp .ret
.not_found:
    xor eax, eax
.ret:
    pop r13
    pop r12
    pop rbx
    ret

; find_free_slot -> eax = indice ou -1
find_free_slot:
    xor eax, eax
.loop:
    cmp eax, MAX_INFLIGHT
    jae .none
    cmp dword [slot_states + rax*4], ST_FREE
    je .found
    inc eax
    jmp .loop
.found:
    ret
.none:
    mov eax, -1
    ret

socket_fatal:
    lea rsi, [msg_socket_error]
    call write_cstr
    mov eax, SYS_exit
    mov edi, 1
    syscall

invalid_ip_exit:
    lea rsi, [msg_invalid_ip]
    call write_cstr
    mov edi, 1
    jmp exit_with_code
invalid_ports_exit:
    lea rsi, [msg_invalid_ports]
    call write_cstr
    mov edi, 1
    jmp exit_with_code
input_error_exit:
    lea rsi, [msg_input_error]
    call write_cstr
    mov edi, 1
exit_with_code:
    mov eax, SYS_exit
    syscall
