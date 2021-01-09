#!/bin/bash

function compile() {
	gcc synflood.c -lnet -o synflood &> /dev/null
	gcc backdoor.c -lnet -lpcap -o backdoor &> /dev/null
}

printf "[*] Compiling...\n"
compile
printf "[*] Done\n"