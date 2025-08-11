#!/usr/bin/env ruby
# Author: iTrox (Javier González)

COLORS = {
    blue: "\e[34m",
    calypso: "\e[96m",
    green: "\e[32m",
    red: "\e[31m",
    yellow: "\e[33m",
    orange: "\e[38;5;208m",
    violet: "\e[35m",
    gray: "\e[90m",
    reset: "\e[0m"
}

trap("INT") do
    puts "\n\n#{COLORS[:yellow]}[!] Process interrupted#{COLORS[:reset]}\n"
    exit 1
end

def print_banner
    puts
    puts " #{COLORS[:orange]} ██████   █████  ███    ██ ██████   ██████  ███    ███     ███    ███  █████   ██████      ██████ ██████  ███████  █████  ████████  ██████  ██████ #{COLORS[:end]}"
    puts " #{COLORS[:orange]} ██   ██ ██   ██ ████   ██ ██   ██ ██    ██ ████  ████     ████  ████ ██   ██ ██          ██      ██   ██ ██      ██   ██    ██    ██    ██ ██   ██ #{COLORS[:end]}"
    puts " #{COLORS[:orange]} ██████  ███████ ██ ██  ██ ██   ██ ██    ██ ██ ████ ██     ██ ████ ██ ███████ ██          ██      ██████  █████   ███████    ██    ██    ██ ██████ #{COLORS[:end]}"
    puts " #{COLORS[:orange]} ██   ██ ██   ██ ██  ██ ██ ██   ██ ██    ██ ██  ██  ██     ██  ██  ██ ██   ██ ██          ██      ██   ██ ██      ██   ██    ██    ██    ██ ██   ██ #{COLORS[:end]}"
    puts " #{COLORS[:orange]} ██   ██ ██   ██ ██   ████ ██████   ██████  ██      ██     ██      ██ ██   ██  ██████      ██████ ██   ██ ███████ ██   ██    ██     ██████  ██   ██ #{COLORS[:end]}\n\n"
    puts "  #{COLORS[:turquoise]}Create a random MAC address#{COLORS[:end]}"
    puts "  #{COLORS[:turquoise]}Version 2.0#{COLORS[:end]}"
    puts "  #{COLORS[:blue]}Made by iTrox (Javier González)#{COLORS[:end]}\n"
end

def main
    first_octets = (1..3).map { rand(256).to_s(16).upcase.rjust(2, '0') }.join(':')
    random_last_octets = (1..3).map { rand(256).to_s(16).upcase.rjust(2, '0') }.join(':')
    mac = "#{first_octets}:#{random_last_octets}"
    
    puts " \n#{COLORS[:green]}[✔] Random MAC address create:#{COLORS[:end]} #{COLORS[:turquoise]}#{mac}#{COLORS[:end]}\n\n"
end

print_banner
main