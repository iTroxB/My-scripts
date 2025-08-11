#!/usr/bin/env ruby
# Author: iTrox (Javier González)

require 'optparse'
require 'open3'
require 'fileutils'
require 'tempfile'

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
    
    #{COLORS[:orange]} ██████   ██████  █████  ██████      ███████  █████  ██████      ███████ ██   ██ ████████ ██████   █████   ██████ ████████  ██████  ██████  
    #{COLORS[:orange]} ██   ██ ██      ██   ██ ██   ██     ██      ██   ██ ██   ██     ██       ██ ██     ██    ██   ██ ██   ██ ██         ██    ██    ██ ██   ██ 
    #{COLORS[:orange]} ██████  ██      ███████ ██████      █████   ███████ ██████      █████     ███      ██    ██████  ███████ ██         ██    ██    ██ ██████   
    #{COLORS[:orange]} ██      ██      ██   ██ ██          ██      ██   ██ ██          ██       ██ ██     ██    ██   ██ ██   ██ ██         ██    ██    ██ ██   ██ 
    #{COLORS[:orange]} ██       ██████ ██   ██ ██          ███████ ██   ██ ██          ███████ ██   ██    ██    ██   ██ ██   ██  ██████    ██     ██████  ██   ██  #{COLORS[:reset]}
    
      #{COLORS[:turquoise]}Obtaining WPA-EAP identities, EAP certificates, HTTP passwords, Handshakes, DNS queries, NBTNS queries and LLMNR queries#{COLORS[:reset]}
      #{COLORS[:turquoise]}Ruby transcription of pcapFilter.sh (https://gist.github.com/r4ulcl/f3470f097d1cd21dbc5a238883e79fb2)#{COLORS[:reset]}
      #{COLORS[:turquoise]}Version 1.0#{COLORS[:reset]}
      #{COLORS[:blue]}# Author: iTrox (Javier González)#{COLORS[:reset]}
      #{COLORS[:gray]}Use -h for help#{COLORS[:reset]}
    BANNER
    puts
end

def help
    puts <<~HELP
    #{$0} -f <pcap/folder> [OPTION]

    -f <.pcap>: Read pcap or file of .caps
    -h : help
    -o <file> : Output results to file (will append if file exists)

    OPTIONS:
        -A : all
        -P : Get HTTP POST passwords (HTTP)
        -I : Filter WPA-EAP Identity
        -C : Export EAP certs
        -H : Get Handshakes 1 and 2
        -D : Get DNS querys
        -R : Responder vulnerable protocols (NBT-NS + LLMNR)
        -N : Get NBT-NS querys
        -L : Get LLMNR querys
        --debug : Show debug information
    HELP
end

def filter(file, options, output_file = nil)
    output = []
    
    begin
        output << "\n#{COLORS[:green]}FILE: #{file}#{COLORS[:reset]}"
        output << "#{COLORS[:gray]}Started at: #{Time.now}#{COLORS[:reset]}"

        if options[:all]
            options[:passwords] = true
            options[:identity] = true
            options[:handshakes] = true
            options[:dns] = true
            options[:nbtns] = true
            options[:llmnr] = true
            options[:cert] = true
        end

        if options[:passwords]
            output << "\n\t[+] Get POST passwords\n"
            command = "tshark -r #{file} -Y 'http.request.method == POST and (http matches \"(?i)pass\" or tcp contains \"login\")' -T fields -e http.file_data -e http.request.full_uri"
            output << execute_command(command, "HTTP passwords")
        end

        if options[:identity]
            output << "\n\t[+] Get WPA-EAP Identities\n"
            output << 'DESTINATION'.ljust(20) + "\tSOURCE".ljust(20) + "\tIDENTITY"
            command = "tshark -nr #{file} -Y \"eap.type == 1 && eap.code == 2\" -T fields -e wlan.da -e wlan.sa -e eap.identity 2>&1 | sort -u"
            output << execute_command(command, "WPA-EAP identities")
        end

        if options[:handshakes]
            output << "\n\t[+] Get Handshakes in pcap\n"
            command = "tshark -nr #{file} -Y \"wlan_rsna_eapol.keydes.msgnr == 1 or wlan_rsna_eapol.keydes.msgnr == 2\""
            output << execute_command(command, "Handshakes")
        end

        if options[:dns]
            output << "\n\t[+] Get DNS queries\n"
            command = "tshark -nr #{file} -Y \"dns.flags == 0x0100\" -T fields -e ip.src -e dns.qry.name"
            output << execute_command(command, "DNS queries")
        end

        if options[:nbtns]
            output << "\n\t[+] Get NBTNS queries in file to responder\n"
            command = "tshark -nr #{file} -Y \"nbns\" -T fields -e ip.src -e nbns.name"
            output << execute_command(command, "NBT-NS queries")
        end

        if options[:llmnr]
            output << "\n\t[+] Get LLMNR queries in file to responder\n"
            command = "tshark -nr #{file} -Y \"llmnr\" -T fields -e ip.src -e dns.qry.name"
            output << execute_command(command, "LLMNR queries")
        end

        if options[:cert]
            begin
                tmpbase = File.basename(file)
                certs_dir = "/tmp/certs_#{Time.now.to_i}/"
                FileUtils.mkdir_p(certs_dir)

                output << "\n\t[+] Extracting EAP certificates to #{certs_dir}\n"

                command = "tshark -r #{file} -Y \"ssl.handshake.certificate and eapol\" -T fields -e \"tls.handshake.certificate\" -e \"wlan.sa\" -e \"wlan.da\""
                certs_found = false

                Open3.popen3(command) do |stdin, stdout, stderr, wait_thr|
                    stdout.each_line do |line|
                        cert, sa, da = line.strip.split
                        next if cert.nil? || cert.empty?

                        certs_found = true
                        filename = "#{tmpbase}-#{sa}-#{da}-#{Time.now.to_i}.der"
                        file_path = File.join(certs_dir, filename)

                        output << "\n#{COLORS[:green]}Certificate from #{sa} to #{da}#{COLORS[:reset]}"
                        output << "Saved certificate in: #{file_path}"

                        begin
                            cert_data = cert.gsub(':', '')
                            File.binwrite(file_path, [cert_data].pack('H*'))

                            openssl_command = "openssl x509 -inform der -text -in #{file_path}"
                            output << execute_command(openssl_command, "Certificate info")
                        rescue => e
                            output << "#{COLORS[:red]}Error processing certificate: #{e.message}#{COLORS[:reset]}"
                        end
                    end
                end

                unless certs_found
                    output << "#{COLORS[:orange]}No EAP certificates found in the capture#{COLORS[:reset]}"
                end

                output << "\n#{COLORS[:green]}All certs saved in: #{certs_dir}#{COLORS[:reset]}"
            rescue => e
                output << "#{COLORS[:red]}Error in certificate extraction: #{e.message}#{COLORS[:reset]}"
                output << e.backtrace.join("\n") if options[:debug]
            end
        end

        if output_file
            begin
                File.open(output_file, 'a') do |f|
                    clean_output = output.join("\n").gsub(/\e\[[\d;]+m/, '')
                    f.puts clean_output
                    f.puts "\n" + ("=" * 80) + "\n"
                end
                output << "\n#{COLORS[:green]}[✔︎] Results appended to: #{output_file}#{COLORS[:reset]}"
            rescue => e
                output << "#{COLORS[:red]}[✘] Error writing to output file: #{e.message}#{COLORS[:reset]}"
                output << "#{COLORS[:orange]}Showing results on screen only#{COLORS[:reset]}"
            end
        end

        output << "\n#{COLORS[:green]}[✔︎] Analysis completed successfully#{COLORS[:reset]}"
        output << "#{COLORS[:gray]}Finished at: #{Time.now}#{COLORS[:reset]}"

    rescue => e
        output << "\n#{COLORS[:red]}[✘] ERROR: processing file #{file}: #{e.message}#{COLORS[:reset]}"
        output << e.backtrace.join("\n") if options[:debug]
        output << "#{COLORS[:orange]}Partial results:#{COLORS[:reset]}"
    end

    puts output.join("\n")
end

def execute_command(command, description = "")
    output = []
    begin
        Open3.popen3(command) do |stdin, stdout, stderr, wait_thr|
            stdout_data = stdout.read
            stderr_data = stderr.read

            if wait_thr.value.success?
                if stdout_data.empty?
                    output << "#{COLORS[:orange]}[!] No results found for #{description}#{COLORS[:reset]}" unless description.empty?
                else
                    output << stdout_data
                end
            else
                output << "#{COLORS[:orange]}[!] Command failed: #{command}#{COLORS[:reset]}"
                output << "#{COLORS[:red]}[✘] Error: #{stderr_data}#{COLORS[:reset]}" unless stderr_data.empty?
            end
        end
    rescue => e
        output << "#{COLORS[:red]}[✘]Error executing command: #{e.message}#{COLORS[:reset]}"
        output << "#{COLORS[:orange]}[!] Command: #{command}#{COLORS[:reset]}"
    end
    output.join
end

def check_tshark
    unless system('which tshark > /dev/null 2>&1')
        puts "#{COLORS[:red]}tshark not found. Please install Wireshark/tshark first.#{COLORS[:reset]}"
        puts "#{COLORS[:blue]}On Debian/Ubuntu: sudo apt install wireshark#{COLORS[:reset]}"
        puts "#{COLORS[:blue]}On CentOS/RHEL: sudo yum install wireshark#{COLORS[:reset]}"
        exit 1
    end

    tshark_version = `tshark -v 2>&1 | head -1 | awk '{print $2}'`.chomp
    puts "#{COLORS[:gray]}Using tshark version: #{tshark_version}#{COLORS[:reset]}" if tshark_version
end

begin
    options = {}
    output_file = nil

    print_banner

    OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} [options]"

        opts.on("-h", "--help", "Show help") do
            help
            exit
        end

        opts.on("-f", "--file FILE", "Input pcap file or directory") do |f|
            options[:file] = f
        end

        opts.on("-o", "--output FILE", "Output results to file (will append if exists)") do |f|
            begin
                File.open(f, 'a') { |file| file.puts "# PCAP Analysis started at #{Time.now}" }
                output_file = f
            rescue => e
                puts "#{COLORS[:red]}Cannot write to output file: #{e.message}#{COLORS[:reset]}"
                exit 1
            end
        end

        opts.on("-A", "--all", "All options") do
            options[:all] = true
        end

        opts.on("-P", "--passwords", "Get HTTP POST passwords") do
            options[:passwords] = true
        end

        opts.on("-I", "--identity", "Filter WPA-EAP Identity") do
            options[:identity] = true
        end

        opts.on("-H", "--handshakes", "Get Handshakes") do
            options[:handshakes] = true
        end

        opts.on("-D", "--dns", "Get DNS queries") do
            options[:dns] = true
        end

        opts.on("-R", "--responder", "Responder vulnerable protocols") do
            options[:nbtns] = true
            options[:llmnr] = true
        end

        opts.on("-N", "--nbtns", "Get NBT-NS queries") do
            options[:nbtns] = true
        end

        opts.on("-L", "--llmnr", "Get LLMNR queries") do
            options[:llmnr] = true
        end

        opts.on("-C", "--cert", "Export EAP certs") do
            options[:cert] = true
        end

        opts.on("--debug", "Show debug information") do
            options[:debug] = true
        end
    end.parse!

    check_tshark

    unless options[:file]
        puts "#{COLORS[:red]}[✘] Error: Input file or directory required#{COLORS[:reset]}"
        help
        exit 1
    end

    unless File.exist?(options[:file])
        puts "#{COLORS[:red]}[✘] Error: File or directory not found: #{options[:file]}#{COLORS[:reset]}"
        exit 1
    end

    unless options.values_at(:all, :passwords, :identity, :handshakes, :dns, :nbtns, :llmnr, :cert).any?
        puts "#{COLORS[:red]}[✘] Error: At least one analysis option required#{COLORS[:reset]}"
        help
        exit 2
    end

    if File.directory?(options[:file])
        puts "#{COLORS[:blue]}➜ Processing directory: #{options[:file]}#{COLORS[:reset]}"
        files = Dir.glob(File.join(options[:file], '*.{pcap,cap}'))
        
        if files.empty?
            puts "#{COLORS[:orange]}[!] No .pcap or .cap files found in directory#{COLORS[:reset]}"
            exit 0
        end

        files.each do |f|
            puts "#{COLORS[:blue]}➜ Processing: #{f}#{COLORS[:reset]}"
            filter(f, options, output_file)
        end
    else
        unless options[:file].downcase.end_with?('.pcap', '.cap')
            puts "#{COLORS[:orange]}[!] Warning: File extension not .pcap or .cap#{COLORS[:reset]}"
        end
        filter(options[:file], options, output_file)
    end

rescue OptionParser::MissingArgument => e
    puts "#{COLORS[:red]}Error: #{e.message}#{COLORS[:reset]}"
    help
    exit 1
rescue Interrupt
    puts "\n#{COLORS[:red]}[✘] Analysis interrupted by user#{COLORS[:reset]}"
    exit 130
rescue StandardError => e
    puts "#{COLORS[:red]}[✘] Unexpected error: #{e.message}#{COLORS[:reset]}"
    puts e.backtrace if options[:debug]
    exit 1
end