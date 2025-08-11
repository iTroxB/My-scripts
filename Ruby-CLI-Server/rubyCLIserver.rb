#!/usr/bin/env ruby
# Author: iTrox (Javier González)

require 'socket'
require 'webrick'
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
    
    #{COLORS[:orange]} ██████  ██    ██ ██████  ██    ██      ██████ ██      ██     ███████ ███████ ██████  ██    ██ ███████ ██████    
    #{COLORS[:orange]} ██   ██ ██    ██ ██   ██  ██  ██      ██      ██      ██     ██      ██      ██   ██ ██    ██ ██      ██   ██ 
    #{COLORS[:orange]} ██████  ██    ██ ██████    ████       ██      ██      ██     ███████ █████   ██████  ██    ██ █████   ██████   
    #{COLORS[:orange]} ██   ██ ██    ██ ██   ██    ██        ██      ██      ██          ██ ██      ██   ██  ██  ██  ██      ██   ██ 
    #{COLORS[:orange]} ██   ██  ██████  ██████     ██         ██████ ███████ ██     ███████ ███████ ██   ██   ████   ███████ ██   ██  #{COLORS[:reset]}
    
      #{COLORS[:calypso]}Local Ruby server to trace HTTP requests and store logs#{COLORS[:reset]}
      #{COLORS[:calypso]}Version 2.0#{COLORS[:reset]}
      #{COLORS[:green]}Made by iTrox (Javier González)#{COLORS[:reset]}
      #{COLORS[:gray]}Use -h for help#{COLORS[:reset]}
    BANNER
    puts
end

print_banner

options = {
    port: 8794,
    log_file: nil
}

OptionParser.new do |opts|
    opts.banner = "Use: #{File.basename($0)} [options]"
    opts.separator ""
    opts.separator "Options:"

    opts.on("-p PORT", "--port PORT", Integer, "Sets the server port (default is 8794)") do |p|
        if p < 1 || p > 65535
            puts "#{COLORS[:red]}[✘] Error: the port must be between 1 and 65535#{COLORS[:reset]}"
            exit 1
        end
        options[:port] = p
    end

    opts.on("-o FILE", "--output FILE", String, "File where the logs of the requests are saved") do |f|
        options[:log_file] = f
    end

    opts.on("-h", "--help", "Help menu") do
        puts opts
        puts "\nExamples:"
        puts "  #{File.basename($0)} -p 8080"
        puts "  #{File.basename($0)} -o server.log"
        puts "  #{File.basename($0)} -p 9999 -o logs.log"
        exit
    end
end.parse!

class RequestHandler < WEBrick::HTTPServlet::AbstractServlet
    def initialize(server, log_file)
        super(server)
        @log_file = log_file
    end

    def do_GET(request, response)
        log_request(request)
        response.status = 200
        response.body = "GET request received"
    end

    def do_POST(request, response)
        log_request(request)
        response.status = 200
        response.body = "POST request received"
    end

    private

    def log_request(request)
        timestamp = Time.now.strftime("%Y-%m-%d %H:%M:%S")
        log_data = "\n[#{timestamp}] Request received\n"
        log_data += "Origin: #{request.peeraddr[2]}:#{request.peeraddr[1]}\n"
        log_data += "Method: #{request.request_method}\n"
        log_data += "Path: #{request.path}\n"
        log_data += "Headers:\n"

        request.header.each do |name, values|
            values.each do |value|
                log_data += "  #{name}: #{value}\n"
            end
        end

        if request.body && !request.body.empty?
            log_data += "Body: #{request.body.force_encoding('UTF-8')}\n"
        end

        puts log_data

        if @log_file
            File.open(@log_file, 'a:UTF-8') do |f|
                f.puts log_data
                f.puts "=" * 80
                f.puts ""
            end
        end
    end
end

def port_available?(port)
    server = TCPServer.new('127.0.0.1', port)
    server.close
    true
rescue Errno::EADDRINUSE
    false
rescue => e
    puts "#{COLORS[:red]}[✘] Error verifying port#{COLORS[:reset]} #{e.message}"
    false
end

begin
    unless port_available?(options[:port])
        puts "\n#{COLORS[:red]}[✘] ERROR: Port #{options[:port]} is either already in use or not available. Please choose another port with the -p parameter#{COLORS[:reset]}"
        exit 1
    end

    server = WEBrick::HTTPServer.new(Port: options[:port])
    server.mount('/', RequestHandler, options[:log_file])

    puts "\n#{COLORS[:turquoise]}➜ HTTP Ruby server#{COLORS[:reset]}".center(60)
    puts "#{COLORS[:blue]}" + "=" * 60 + "#{COLORS[:reset]}"
    puts "  ➜ Listening in port: #{COLORS[:yellow]}#{options[:port]}#{COLORS[:reset]}"
    puts "  ➜ Logs saved in: #{COLORS[:yellow]}#{options[:log_file] || 'consola'}#{COLORS[:reset]}"
    puts "  ➜ Press #{COLORS[:yellow]}Ctrl+C#{COLORS[:reset]} to stop server"
    puts "#{COLORS[:blue]}" + "=" * 60 + "#{COLORS[:reset]}"

    trap('INT') do
        server.shutdown
        puts "\n#{COLORS[:blue]}" + "➜ Server stopped".center(60, '=') + "#{COLORS[:reset]}"
        puts "➜ Final logs saved in: #{COLORS[:yellow]}#{options[:log_file]}#{COLORS[:reset]}" if options[:log_file]
    end

    server.start
rescue Errno::EACCES => e
    puts "\n#{COLORS[:red]}[✘] ERROR:#{COLORS[:reset]} permission denied to use port #{options[:port]}. Try with a port higher than 1024 or run as superuser"
    exit 1
rescue Errno::EADDRINUSE => e
    puts "\n#{COLORS[:red]}[✘] ERROR:#{COLORS[:reset]} port #{options[:port]} is already in use"
    puts "\n#{COLORS[:yellow]}[!] Please choose another port with the -p parameter#{COLORS[:reset]}"
    exit 1
rescue => e
    puts "\n#{COLORS[:red]}[✘] Unexpected ERROR:#{COLORS[:reset]} #{e.message}"
    puts "➜ Details: #{e.backtrace.first}"
    exit 1
end