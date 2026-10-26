; port_scanner.asm
; Linux x86-64 / NASM
; TCP connect scanner with bounded concurrency using nonblocking sockets + poll.
; Intended for authorized lab/host testing only.
;
; Build:
;   nasm -felf64 port_scanner.asm -o port_scanner.o
;   ld -o port_scanner port_scanner.o
; Run:
;   ./port_scanner
;
; Syscalls (Linux x86-64):
;   read=0, write=1, close=3, poll=7, socket=41, connect=42,
;   getsockopt=55, exit=60
;
; Notes:
; - AF_INET=2, SOCK_STREAM=1, SOCK_NONBLOCK=0x800
; - SOL_SOCKET=1, SO_ERROR=4
; - pollfd { int fd; short events; short revents } = 8 bytes
; - sockaddr_in is 16 bytes: family, port, addr, zero padding
; - Input parsing validates IPv4 dotted-decimal and ports 1..65535.
; - Maximum 128 simultaneous sockets; poll timeout is 1000 ms.
; - "open" means TCP connect succeeded. Other outcomes are reported as
;   closed/filtered/timeout (TCP connect alone cannot distinguish these).
;
; This version keeps code standalone and uses syscalls directly.

%define SYS_read        0
%define SYS_write       1
%define SYS_close       3
%define SYS_poll        7
%define SYS_socket      41
%define SYS_connect     42
%define SYS_getsockopt  55
%define SYS_exit        60

%define AF_INET         2
%define SOCK_STREAM     1
%define SOCK_NONBLOCK   0x800
%define SOL_SOCKET      1
%define SO_ERROR        4
%define POLLOUT         0x004
%define POLLERR         0x008
%define POLLHUP         0x010
%define POLLNVAL        0x020
%define MAX_INFLIGHT    128
%define CONNECT_TIMEOUT 1000

section .rodata
prompt_ip       db "Enter target IPv4 (e.g., 192.168.1.1): "
prompt_ip_len   equ $ - prompt_ip
prompt_start    db "Enter start port (1-65535): "
prompt_start_len equ $ - prompt_start
prompt_end      db "Enter end port (1-65535): "
prompt_end_len  equ $ - prompt_end
msg_scanning    db "Scanning "
msg_scanning_len equ $ - msg_scanning
msg_range       db " ports "
msg_range_len   equ $ - msg_range
range_through   db " through "
range_through_len equ $ - range_through
msg_open_prefix db "[+] "
msg_open_prefix_len equ $ - msg_open_prefix
msg_open_suffix db " OPEN", 10
msg_open_suffix_len equ $ - msg_open_suffix
msg_closed_prefix db "[-] "
msg_closed_prefix_len equ $ - msg_closed_prefix
msg_closed_suffix db " closed/filtered", 10
msg_closed_suffix_len equ $ - msg_closed_suffix
msg_timeout_suffix db " timeout", 10
msg_timeout_suffix_len equ $ - msg_timeout_suffix
msg_invalid_ip  db "Invalid IPv4 address.", 10
msg_invalid_ip_len equ $ - msg_invalid_ip
msg_invalid_ports db "Invalid port range. Use 1 <= start <= end <= 65535.", 10
msg_invalid_ports_len equ $ - msg_invalid_ports
msg_input_error db "Input error or line too long.", 10
msg_input_error_len equ $ - msg_input_error
msg_socket_error db "Could not create socket; aborting.", 10
msg_socket_error_len equ $ - msg_socket_error
msg_summary1    db "Finished. Open ports: "
msg_summary1_len equ $ - msg_summary1
msg_summary2    db ", tested: "
msg_summary2_len equ $ - msg_summary2
msg_summary3    db ", timeouts/errors: "
msg_summary3_len equ $ - msg_summary3
newline         db 10

section .bss
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
sockaddr        resb 16
; pollfd records: fd(int32), events(int16), revents(int16)
pollfds         resb MAX_INFLIGHT * 8
; Slot metadata: port(uint32), state(uint32); 0=free, 1=in flight
slot_ports      resd MAX_INFLIGHT
slot_states     resd MAX_INFLIGHT
; write_all / formatter scratch
num_buffer      resb 32
write_ptr       resq 1
write_len       resq 1

section .text
global _start

_start:
    lea rsi, [prompt_ip]
    mov edx, prompt_ip_len
    call write_all

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
    mov edx, prompt_start_len
    call write_all
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
    mov edx, prompt_end_len
    call write_all
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

    ; Print target and range.
    lea rsi, [msg_scanning]
    mov edx, msg_scanning_len
    call write_all
    lea rsi, [ip_input]
    call string_length
    mov edx, eax
    call write_all
    lea rsi, [msg_range]
    mov edx, msg_range_len
    call write_all
    mov eax, [port_start]
    call format_uint
    mov rsi, rdi
    mov edx, ecx
    call write_all
    ; Write the range separator.
    lea rsi, [range_through]
    mov edx, range_through_len
    call write_all
    mov eax, [port_end]
    call format_uint
    mov rsi, rdi
    mov edx, ecx
    call write_all
    lea rsi, [newline]
    mov edx, 1
    call write_all

    mov eax, [port_start]
    mov [next_port], eax

.scan_fill:
    ; If every port was submitted and no connection remains, finish.
    mov eax, [next_port]
    cmp eax, [port_end]
    jbe .have_ports
    cmp dword [current_inflight], 0
    jne .wait
    jmp scan_complete
.have_ports:
    ; Start new nonblocking connects until the window is full or range ends.
    mov eax, [current_inflight]
    cmp eax, MAX_INFLIGHT
    jae .wait
    mov eax, [next_port]
    cmp eax, [port_end]
    ja .wait

    call find_free_slot
    cmp eax, -1
    je .wait
    mov ebx, eax                    ; slot index

    mov eax, SYS_socket
    mov edi, AF_INET
    mov esi, SOCK_STREAM | SOCK_NONBLOCK
    xor edx, edx
    syscall
    test rax, rax
    js socket_fatal
    mov r8, rax                     ; fd

    ; Fill sockaddr_in for this port.
    lea rdi, [sockaddr]
    xor eax, eax
    mov ecx, 16
    rep stosb
    mov word [sockaddr], AF_INET
    mov eax, [next_port]
    xchg al, ah
    mov word [sockaddr + 2], ax
    mov eax, [ip_binary]
    mov [sockaddr + 4], eax

    mov eax, SYS_connect
    mov rdi, r8
    lea rsi, [sockaddr]
    mov edx, 16
    syscall
    mov r9, rax                     ; Preserve connect() result before reusing RAX.

    ; Save slot state regardless of immediate or pending result.
    mov eax, [next_port]
    mov [slot_ports + rbx*4], eax
    mov [slot_states + rbx*4], dword 1
    mov [pollfds + rbx*8], r8d
    mov word [pollfds + rbx*8 + 4], POLLOUT
    mov word [pollfds + rbx*8 + 6], 0
    inc dword [current_inflight]
    inc dword [tested_count]
    inc dword [next_port]

    test r9, r9
    jz .immediate_success
    cmp r9, -115                   ; -EINPROGRESS
    je .scan_fill
    cmp r9, -114                   ; -EALREADY
    je .scan_fill
    ; Immediate connect failure: close and report closed/filtered.
    mov edi, r8d
    mov eax, SYS_close
    syscall
    mov dword [slot_states + rbx*4], 0
    dec dword [current_inflight]
    mov eax, [slot_ports + rbx*4]
    mov edi, eax
    call print_closed
    jmp .scan_fill

.immediate_success:
    mov edi, r8d
    mov eax, SYS_close
    syscall
    mov dword [slot_states + rbx*4], 0
    dec dword [current_inflight]
    mov eax, [slot_ports + rbx*4]
    mov edi, eax
    call print_open
    jmp .scan_fill

.wait:
    cmp dword [current_inflight], 0
    je .scan_fill
    lea rdi, [pollfds]
    mov esi, MAX_INFLIGHT
    mov edx, CONNECT_TIMEOUT
    mov eax, SYS_poll
    syscall
    test rax, rax
    js .poll_error
    jz .poll_timeout

    ; Process ready descriptors.
    xor ebx, ebx
.process_slots:
    cmp ebx, MAX_INFLIGHT
    jae .scan_fill
    cmp dword [slot_states + rbx*4], 0
    je .next_slot
    movzx eax, word [pollfds + rbx*8 + 6]
    test eax, (POLLOUT | POLLERR | POLLHUP | POLLNVAL)
    jz .next_slot

    ; getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
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
    js .result_error
    cmp dword [socket_error], 0
    jne .result_closed

    mov eax, SYS_close
    mov edi, [pollfds + rbx*8]
    syscall
    mov dword [slot_states + rbx*4], 0
    mov word [pollfds + rbx*8 + 4], 0
    dec dword [current_inflight]
    mov edi, [slot_ports + rbx*4]
    call print_open
    jmp .next_slot

.result_closed:
    mov eax, SYS_close
    mov edi, [pollfds + rbx*8]
    syscall
    mov dword [slot_states + rbx*4], 0
    mov word [pollfds + rbx*8 + 4], 0
    dec dword [current_inflight]
    mov edi, [slot_ports + rbx*4]
    call print_closed
    jmp .next_slot

.result_error:
    mov eax, SYS_close
    mov edi, [pollfds + rbx*8]
    syscall
    mov dword [slot_states + rbx*4], 0
    mov word [pollfds + rbx*8 + 4], 0
    dec dword [current_inflight]
    inc dword [timeout_count]
    jmp .next_slot

.next_slot:
    inc ebx
    jmp .process_slots

.poll_timeout:
    ; Expire all currently pending sockets after timeout; count as timeout.
    xor ebx, ebx
.expire_slots:
    cmp ebx, MAX_INFLIGHT
    jae .scan_fill
    cmp dword [slot_states + rbx*4], 0
    je .expire_next
    mov eax, SYS_close
    mov edi, [pollfds + rbx*8]
    syscall
    mov dword [slot_states + rbx*4], 0
    mov word [pollfds + rbx*8 + 4], 0
    dec dword [current_inflight]
    inc dword [timeout_count]
    mov edi, [slot_ports + rbx*4]
    call print_timeout
.expire_next:
    inc ebx
    jmp .expire_slots

.poll_error:
    cmp rax, -4                     ; EINTR
    je .wait
    ; On other poll errors, close all pending descriptors safely.
    xor ebx, ebx
.poll_cleanup:
    cmp ebx, MAX_INFLIGHT
    jae .scan_fill
    cmp dword [slot_states + rbx*4], 0
    je .poll_cleanup_next
    mov eax, SYS_close
    mov edi, [pollfds + rbx*8]
    syscall
    mov dword [slot_states + rbx*4], 0
    mov word [pollfds + rbx*8 + 4], 0
    dec dword [current_inflight]
    inc dword [timeout_count]
.poll_cleanup_next:
    inc ebx
    jmp .poll_cleanup

scan_complete:
    lea rsi, [msg_summary1]
    mov edx, msg_summary1_len
    call write_all
    mov eax, [open_count]
    call format_uint
    mov rsi, rdi
    mov edx, ecx
    call write_all
    lea rsi, [msg_summary2]
    mov edx, msg_summary2_len
    call write_all
    mov eax, [tested_count]
    call format_uint
    mov rsi, rdi
    mov edx, ecx
    call write_all
    lea rsi, [msg_summary3]
    mov edx, msg_summary3_len
    call write_all
    mov eax, [timeout_count]
    call format_uint
    mov rsi, rdi
    mov edx, ecx
    call write_all
    lea rsi, [newline]
    mov edx, 1
    call write_all
    mov eax, SYS_exit
    xor edi, edi
    syscall

; ---------- output routines ----------
print_open:
    push rdi
    lea rsi, [msg_open_prefix]
    mov edx, msg_open_prefix_len
    call write_all
    pop rdi
    mov eax, edi
    call format_uint
    mov rsi, rdi
    mov edx, ecx
    call write_all
    lea rsi, [msg_open_suffix]
    mov edx, msg_open_suffix_len
    call write_all
    inc dword [open_count]
    ret

print_closed:
    push rdi
    lea rsi, [msg_closed_prefix]
    mov edx, msg_closed_prefix_len
    call write_all
    pop rdi
    mov eax, edi
    call format_uint
    mov rsi, rdi
    mov edx, ecx
    call write_all
    lea rsi, [msg_closed_suffix]
    mov edx, msg_closed_suffix_len
    call write_all
    ret

print_timeout:
    push rdi
    lea rsi, [msg_closed_prefix]
    mov edx, msg_closed_prefix_len
    call write_all
    pop rdi
    mov eax, edi
    call format_uint
    mov rsi, rdi
    mov edx, ecx
    call write_all
    lea rsi, [msg_timeout_suffix]
    mov edx, msg_timeout_suffix_len
    call write_all
    ret

; write_all: rsi=buffer, rdx=len. Preserves rbx, returns.
write_all:
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
    js .error
    jz .done
    add r8, rax
    sub r9, rax
    jnz .loop
.done:
    ret
.error:
    cmp rax, -4                     ; EINTR
    je .loop
    ret

; read_line: rdi=buffer, esi=capacity; returns eax=len (>0), 0=EOF, -1=error/too long.
; Reads one byte at a time for simple, correct line handling.
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
    js .error
    jz .eof
    cmp byte [rbx + r10], 10
    je .newline
    inc r10d
    jmp .loop
.newline:
    mov byte [rbx + r10], 0
    mov eax, r10d
    pop r12
    pop rbx
    ret
.eof:
    test r10d, r10d
    jz .eof_empty
    mov byte [rbx + r10], 0
    mov eax, r10d
    pop r12
    pop rbx
    ret
.eof_empty:
    xor eax, eax
    pop r12
    pop rbx
    ret
.error:
    cmp rax, -4
    je .loop
    mov eax, -1
    pop r12
    pop rbx
    ret
.too_long:
    mov eax, -1
    pop r12
    pop rbx
    ret

; string_length: rsi=string, returns eax length.
string_length:
    xor eax, eax
.loop:
    cmp byte [rsi + rax], 0
    je .done
    inc eax
    jmp .loop
.done:
    ret

; parse_uint: rdi=string, returns eax=value, edx=1 success / 0 failure.
; Strict decimal; checks overflow beyond 65535.
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
    jo .fail
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

; parse_ipv4: rdi=string; returns eax=1 success, edx=network-order bytes for sockaddr.
; Parse octets, reject empty/extra/missing octets, non-digits, >255.
parse_ipv4:
    push rbx
    push r12
    push r13
    mov r12, rdi
    xor r13d, r13d                 ; assembled host integer, octets left-shifted
    xor ebx, ebx                   ; octet index
    xor r8d, r8d                   ; current octet
    xor r9d, r9d                   ; digits in current octet
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
    jo .fail
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
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    xor eax, eax
    xor edx, edx
    pop r13
    pop r12
    pop rbx
    ret

; format_uint: eax=value, returns rdi=buffer, ecx=length.
; Produces digits at num_buffer start and NUL terminator.
format_uint:
    push rbx
    push rdx
    push rsi
    lea rdi, [num_buffer]
    lea rsi, [num_buffer + 31]
    mov byte [rsi], 0
    mov ebx, 10
    xor ecx, ecx
    test eax, eax
    jnz .digits
    dec rsi
    mov byte [rsi], '0'
    mov ecx, 1
    jmp .copy
.digits:
    xor edx, edx
    div ebx
    add dl, '0'
    dec rsi
    mov [rsi], dl
    inc ecx
    test eax, eax
    jnz .digits
.copy:
    ; Move digits to buffer start.
    lea rdi, [num_buffer]
    mov edx, ecx
    mov r8, rsi
    mov r9, rdi
    rep movsb
    mov byte [num_buffer + rdx], 0
    mov ecx, edx
    lea rdi, [num_buffer]
    pop rsi
    pop rdx
    pop rbx
    ret

find_free_slot:
    xor eax, eax
.loop:
    cmp eax, MAX_INFLIGHT
    jae .none
    cmp dword [slot_states + rax*4], 0
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
    mov edx, msg_socket_error_len
    call write_all
    mov eax, SYS_exit
    mov edi, 1
    syscall

invalid_ip_exit:
    lea rsi, [msg_invalid_ip]
    mov edx, msg_invalid_ip_len
    call write_all
    mov edi, 1
    jmp exit_with_code
invalid_ports_exit:
    lea rsi, [msg_invalid_ports]
    mov edx, msg_invalid_ports_len
    call write_all
    mov edi, 1
    jmp exit_with_code
input_error_exit:
    lea rsi, [msg_input_error]
    mov edx, msg_input_error_len
    call write_all
    mov edi, 1
exit_with_code:
    mov eax, SYS_exit
    syscall

section .bss
socket_error resd 1
sockopt_len resd 1
