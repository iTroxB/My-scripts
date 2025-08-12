#!/usr/bin/env ruby
# Author: iTrox (Javier González)

require 'optparse'

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
    puts <<~BANNER

    #{COLORS[:orange]} ██████  ██    ██ ████████      ██████ ██   ██ ██ ██      ███████ ███    ██  ██████  
    #{COLORS[:orange]} ██   ██ ██    ██    ██        ██      ██   ██ ██ ██      ██      ████   ██ ██    ██ 
    #{COLORS[:orange]} ██████  ██    ██    ██        ██      ███████ ██ ██      █████   ██ ██  ██ ██    ██ 
    #{COLORS[:orange]} ██   ██ ██    ██    ██        ██      ██   ██ ██ ██      ██      ██  ██ ██ ██    ██ 
    #{COLORS[:orange]} ██   ██  ██████     ██         ██████ ██   ██ ██ ███████ ███████ ██   ████  ██████ #{COLORS[:reset]}

      #{COLORS[:calypso]}Script para generar listas de RUTs chilenos válidos en diversos formatos#{COLORS[:reset]}
      #{COLORS[:calypso]}Version 1.0#{COLORS[:reset]}
      #{COLORS[:calypso]}Inspirado en tool Rut Chileno de Apuromafo (https://github.com/apuromafo/Repositorio_Python/tree/main/009_Rut_Chileno)#{COLORS[:reset]}
      #{COLORS[:green]}Creado por iTrox (Javier González)#{COLORS[:reset]}
      #{COLORS[:gray]}Usar -h para ver ayuda#{COLORS[:reset]}
    BANNER
    puts
end

print_banner

class RutGenerator
    def initialize
        @multipliers = [2, 3, 4, 5, 6, 7]
    end

    def generate_rut(million_range, format)
        min, max = million_range.split('-').map(&:to_i)
        first_two = rand(min..max).to_s
        middle_six = rand(0..999999).to_s.rjust(6, '0')
        base_number = first_two + middle_six
        verifier = calculate_verifier(base_number)

        format_rut(base_number, verifier, format)
    end

    private

    def calculate_verifier(number)
        reversed = number.to_s.reverse
        sum = 0

        reversed.chars.each_with_index do |char, index|
            digit = char.to_i
            multiplier = @multipliers[index % @multipliers.size]
            sum += digit * multiplier
        end

        remainder = sum % 11
        verifier = 11 - remainder

        case verifier
        when 11 then 0
        when 10 then 'K'
        else verifier
        end
    end

    def format_rut(number, verifier, format_option)
        case format_option
        when 1
            formatted = number.gsub(/(\d)(?=(\d{3})+(?!\d))/, '\1.').reverse.gsub(/(\d)(?=(\d{3})+(?!\d))/, '\1.').reverse
            "#{formatted}-#{verifier}"
        when 2
            formatted = number.gsub(/(\d)(?=(\d{3})+(?!\d))/, '\1.').reverse.gsub(/(\d)(?=(\d{3})+(?!\d))/, '\1.').reverse
            "#{formatted}#{verifier}"
        when 3
            "#{number}-#{verifier}"
        else
            "#{number}#{verifier}"
        end
    end
end

def show_help
    puts <<~HELP
    Uso: #{$0} [opciones]

    Opciones:
        -r, --range RANGO      Rango de millones (ej: 10-15) (default: 10-20)
        -n, --number NUMERO    Cantidad de RUTs a generar (default: 10)
        -f, --format FORMATO   Formato de salida:
                                1: 12.345.678-9 (con puntos y guión)
                                2: 12.345.6789 (con puntos y sin guión)
                                3: 12345678-9 (sin puntos, con guión)
                                4: 123456789 (sin puntos ni guión)
        -h, --help             Muestra ayuda

    Ejemplos:
        #{$0} -r 15-20 -n 5 -f 3
        #{$0} --range 10-15 --number 100 --format 1
    HELP
    exit
end

def parse_arguments
    options = { range: '10-20', number: 10, format: 1 }

    OptionParser.new do |opts|
        opts.banner = "Uso: #{$0} [opciones]"

        opts.on('-r RANGO', '--range RANGO', 'Rango de millones (ej: 10-15)') do |r|
            unless r =~ /\A\d+-\d+\z/
                puts "Error: Rango debe ser MIN-MAX (ej: 10-15)"
                puts "Use -h para ayuda"
                exit 1
            end
            options[:range] = r
        end

        opts.on('-n NUMERO', '--number NUMERO', Integer, 'Cantidad de RUTs') do |n|
            options[:number] = n.positive? ? n : (puts "Error: Número debe ser > 0"; exit 1)
        end

        opts.on('-f FORMATO', '--format FORMATO', Integer, 'Formato de salida') do |f|
            options[:format] = (1..4).cover?(f) ? f : (puts "Error: Formato debe ser 1-4"; exit 1)
        end

        opts.on('-h', '--help', 'Mostrar ayuda') { show_help }
    end.parse!

    options
end

begin
    options = parse_arguments
    generator = RutGenerator.new

    options[:number].times do
        puts generator.generate_rut(options[:range], options[:format])
    end

rescue => e
    puts "Error: #{e.message}"
    puts "Usar -h para ayuda"
    exit 1
end