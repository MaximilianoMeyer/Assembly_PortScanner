# Assembly_PortScanner
Simple Assembly Port Scanner

A simple implementation of a port scanner, built in assembly.


# How to compile:

- nasm -f elf64 port_scanner.asm -o port_scanner.o
- to link: ld port_scanner.o -o port_scanner
- Start: ./port_scanner IP
