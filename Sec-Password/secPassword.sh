#!/bin/bash
# Author: iTrox

######################################################
#################### COLOURS EDIT ####################
######################################################
green="\e[0;32m\033[1m"
end="\033[0m\e[0m"
red="\e[0;31m\033[1m"
blue="\e[0;34m\033[1m"
yellow="\e[0;33m\033[1m"
purple="\e[0;35m\033[1m"
turquoise="\e[0;36m\033[1m"
gray="\e[0;37m\033[1m"

###################################################
#################### FUNCTIONS ####################
###################################################

# Bye Ctrl+C
function ctrl_c(){
    echo -e "\n\n ${red}[!] Exit...${end}\n"
    tput cnorm && exit 1
}
trap ctrl_c INT

# Banner
print_banner() {
    echo;
    echo -e " ${orange} ███████ ███████  ██████     ██████   █████  ███████ ███████ ██     ██  ██████  ██████  ██████ ${end}"
    echo -e " ${orange} ██      ██      ██          ██   ██ ██   ██ ██      ██      ██     ██ ██    ██ ██   ██ ██   ██ ${end}"
    echo -e " ${orange} ███████ █████   ██          ██████  ███████ ███████ ███████ ██  █  ██ ██    ██ ██████  ██   ██ ${end}"
    echo -e " ${orange}      ██ ██      ██          ██      ██   ██      ██      ██ ██ ███ ██ ██    ██ ██   ██ ██   ██ ${end}"
    echo -e " ${orange} ███████ ███████  ██████     ██      ██   ██ ███████ ███████  ███ ███   ██████  ██   ██ ██████ ${end}\n\n"
    echo -e "  ${turquoise}Secure password creator ${end}"
    echo -e "  ${turquoise}Version 2.0${end}"
    echo -e "  ${blue}Made by iTrox${end}\n"
    echo -e "  ${turquoise}secPassword [-h] or [--help] to view help menu${end}\n"
}

# Help menu
show_help() {
	echo -e " \n${yellow}Usage: $(basename $0) [-M] [-m] [-n] [-s] -l <longitud> [-h]\n${end}"
	echo -e "    ${turquoise}-M${end}    ${gray}Include uppercase${end}"
	echo -e "    ${turquoise}-m${end}    ${gray}Include lowercase${end}"
	echo -e "    ${turquoise}-n${end}    ${gray}Include numbers${end}"
	echo -e "    ${turquoise}-s${end}    ${gray}Include symbols ($, %, &, etc...)${end}"
	echo -e "    ${turquoise}-l${end}    ${gray}Define password length (required, min. 16, max. 128)${end}"
	echo -e "    ${turquoise}-h${end}    ${gray}Show help panel${end}\n"
}

# REDIRECT: HELP MENU
if [[ "$1" = "-h" || "$1" = "--help" ]]; then
    show_help
    exit 0
fi

# Main function
main() {
	uppercase=0
	lowercase=0
	numbers=0
	symbols=0
	length=0

	while getopts "MmnsSl:h" opt; do
		case $opt in
			M) uppercase=1 ;;
			m) lowercase=1 ;;
			n) numbers=1 ;;
			s) symbols=1 ;;
			l) length=$OPTARG ;;
			h) show_help; exit 0 ;;
			*) show_help; exit 1 ;;
		esac
	done

	if [[ $length -eq 0 ]]; then
		echo -e "\n ${red}[!] Error:${end} ${gray}Password length is required${end}\n" 1>&2
		show_help
		exit 1
	fi

	if [[ $length -lt 16 ]]; then
		echo -e "\n ${red}[!] Error:${end} ${gray}Password length must be at least 16 characters${end}\n" 1>&2
		show_help
		exit 1
	fi

	if [[ $length -gt 128 ]]; then
		echo -e "\n ${red}[!] Error:${end} ${gray}Password length must not exceed 128 characters${end}\n" 1>&2
		show_help
		exit 1
	fi

	if [[ $uppercase -eq 0 && $lowercase -eq 0 && $numbers -eq 0 && $symbols -eq 0 ]]; then
		echo -e "\n ${red}[!] Error:${end} ${gray}You must select at least one character option (-M, -m, -n or -s)${end}\n" 1>&2
		show_help
		exit 1
	fi

	UPPERCASE_CHARS="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	LOWERCASE_CHARS="abcdefghijklmnopqrstuvwxyz"
	NUMBER_CHARS="0123456789"
	SYMBOL_CHARS="!¡¿?#$%&/\\()[]{},.-;:_+@><"

	CHAR_POOL=""
	[[ $uppercase -eq 1 ]] && CHAR_POOL+=$UPPERCASE_CHARS
	[[ $lowercase -eq 1 ]] && CHAR_POOL+=$LOWERCASE_CHARS
	[[ $numbers -eq 1 ]] && CHAR_POOL+=$NUMBER_CHARS
	[[ $symbols -eq 1 ]] && CHAR_POOL+=$SYMBOL_CHARS

	password=""
	for ((i = 0; i < $length; i++)); do
		random_index=$(($RANDOM % ${#CHAR_POOL}))
		password+=${CHAR_POOL:$random_index:1}
	done

	echo -e " ${purple}Password generated:${end} $password"
}

####################################################
#################### RUN SCRIPT ####################
####################################################
print_banner
main "$@"