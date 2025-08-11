#!/usr/bin/env ruby
# Author: iTrox (Javier González)

require 'optparse'
require 'uri'
require 'net/http'

COLORS = {
    green: "\e[0;32m\e[1m",
    red: "\e[0;31m\e[1m",
    blue: "\e[0;34m\e[1m",
    orange: "\e[0;33m\e[1m",
    turquoise: "\e[0;36m\e[1m",
    gray: "\e[0;37m\e[1m",
    reset: "\e[0m"
}

CRITICAL_HEADERS = [
    'content-security-policy',
    'set-cookie',
    'authorization',
    'www-authenticate',
    'access-control-allow-origin',
    'strict-transport-security'
]

trap("INT") do
    puts "\n\n#{COLORS[:red]}[!] Process interrupted#{COLORS[:reset]}\n"
    exit 1
end

def print_banner
    puts <<~BANNER
    
    #{COLORS[:orange]} ██   ██  ██████  ███████ ████████     ██   ██ ███████  █████  ██████  ███████ ██████      ██ ███    ██      ██ ███████  ██████ ████████  ██████  ██████
    #{COLORS[:orange]} ██   ██ ██    ██ ██         ██        ██   ██ ██      ██   ██ ██   ██ ██      ██   ██     ██ ████   ██      ██ ██      ██         ██    ██    ██ ██   ██
    #{COLORS[:orange]} ███████ ██    ██ ███████    ██        ███████ █████   ███████ ██   ██ █████   ██████      ██ ██ ██  ██      ██ █████   ██         ██    ██    ██ ██████
    #{COLORS[:orange]} ██   ██ ██    ██      ██    ██        ██   ██ ██      ██   ██ ██   ██ ██      ██   ██     ██ ██  ██ ██ ██   ██ ██      ██         ██    ██    ██ ██   ██
    #{COLORS[:orange]} ██   ██  ██████  ███████    ██        ██   ██ ███████ ██   ██ ██████  ███████ ██   ██     ██ ██   ████  █████  ███████  ██████    ██     ██████  ██   ██ #{COLORS[:reset]}
    
      #{COLORS[:turquoise]}Host Header Injection Scanner#{COLORS[:reset]}
      #{COLORS[:turquoise]}Version 2.0#{COLORS[:reset]}
      #{COLORS[:blue]}Made by iTrox (Javier González)#{COLORS[:reset]}
      #{COLORS[:gray]}Use -h for help#{COLORS[:reset]}
    BANNER
    puts
end

def help_menu
    print_banner
    puts <<~HELP
    
    #{COLORS[:orange]}Usage: #{File.basename($0)} [options]#{COLORS[:reset]}
    
    #{COLORS[:orange]}Options:#{COLORS[:reset]}
      #{COLORS[:turquoise]}-l, --list FILE#{COLORS[:reset]}     #{COLORS[:gray]}File containing URLs to test#{COLORS[:reset]}
      #{COLORS[:turquoise]}-t, --timeout SEC#{COLORS[:reset]}   #{COLORS[:gray]}Request timeout in seconds (default: 5)#{COLORS[:reset]}
      #{COLORS[:turquoise]}-d, --delay MS#{COLORS[:reset]}      #{COLORS[:gray]}Delay between requests in milliseconds#{COLORS[:reset]}
      #{COLORS[:turquoise]}-s, --silent#{COLORS[:reset]}        #{COLORS[:gray]}Silent mode (only show vulnerable URLs)#{COLORS[:reset]}
      #{COLORS[:turquoise]}-v, --verbose#{COLORS[:reset]}       #{COLORS[:gray]}Show detailed debugging info#{COLORS[:reset]}
      #{COLORS[:turquoise]}-h, --help#{COLORS[:reset]}          #{COLORS[:gray]}Show this help message#{COLORS[:reset]}
    
    #{COLORS[:orange]}Testing Behavior:#{COLORS[:reset]}
      #{COLORS[:gray]}• Uses the protocol specified in each URL (HTTP/HTTPS)#{COLORS[:reset]}
      #{COLORS[:gray]}• Only checks redirects for HTTP URLs#{COLORS[:reset]}
      #{COLORS[:gray]}• Checks header/body reflection for all URLs#{COLORS[:reset]}
    HELP
end

def valid_url?(url)
    uri = URI.parse(url)
    uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
rescue URI::InvalidURIError
    false
end

def apply_delay(ms)
    sleep(ms / 1000.0) if ms > 0
end

def scan_url(url, domain, timeout, verbose)
    uri = URI.parse(url)
    
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.read_timeout = timeout
    http.open_timeout = timeout

    headers_to_test = {
        'Host' => domain,
        'X-Forwarded-Host' => domain,
        'X-Host' => domain,
        'Forwarded' => "for=#{domain};host=#{domain}",
        'X-Forwarded-Server' => domain,
        'X-HTTP-Host-Override' => domain
    }

    headers_to_test.each do |header, value|
        request = Net::HTTP::Get.new(uri.request_uri)
        request[header] = value

        if verbose
            puts "#{COLORS[:blue]}➜ Testing #{header}: #{value}#{COLORS[:reset]}"
        end

        response = http.request(request)
        vuln_info = check_response(response, domain, header, uri.scheme)
        
        if vuln_info[:vulnerable]
            return [vuln_info.merge(
                url: url,
                protocol: uri.scheme
            )]
        end
    end

    []
end

def check_response(response, domain, injected_header, original_protocol)
    if original_protocol == 'http' && (300..399).include?(response.code.to_i)
        location = response['location']
        if location&.include?(domain)
            return {
                vulnerable: true,
                type: 'HTTP Redirection',
                severity: 'Medium',
                proof: "Redirects to #{location}",
                injected_header: injected_header,
                payload: domain
            }
        end
    end

    reflected_headers = response.each_header.each_with_object({}) do |(k,v), h|
        h[k] = v if k.downcase != 'location' && v.include?(domain)
    end

    unless reflected_headers.empty?
        severity = if reflected_headers.keys.any? { |h| CRITICAL_HEADERS.include?(h.downcase) }
                    'High'
                  elsif reflected_headers.keys.any? { |h| !h.downcase.start_with?('x-') }
                    'Medium'
                  else
                    'Low'
                  end

        return {
            vulnerable: true,
            type: 'Header Reflection',
            severity: severity,
            proof: "Reflected in: #{reflected_headers.keys.join(', ')}",
            injected_header: injected_header,
            payload: domain,
            reflected_headers: reflected_headers
        }
    end

    if response.body.include?(domain)
        return {
            vulnerable: true,
            type: 'Body Reflection',
            severity: 'Low',
            proof: "Reflected in response body",
            injected_header: injected_header,
            payload: domain
        }
    end

    { vulnerable: false }
end

def report_vulnerability(result, silent)
    if silent
        puts "#{result[:url]} (#{result[:severity]})"
    else
        severity_color = case result[:severity]
                        when 'High' then COLORS[:red]
                        when 'Medium' then COLORS[:orange]
                        else COLORS[:turquoise]
                        end

        puts "#{COLORS[:red]}[✔] Vulnerable:#{COLORS[:reset]} #{result[:url]}"
        puts "  #{COLORS[:gray]}Protocol: #{result[:protocol].upcase}#{COLORS[:reset]}"
        puts "  #{COLORS[:gray]}Type: #{result[:type]}#{COLORS[:reset]}"
        puts "  #{severity_color}Severity: #{result[:severity]}#{COLORS[:reset]}"
        puts "  #{COLORS[:gray]}Injected: #{result[:injected_header]} = #{result[:payload]}#{COLORS[:reset]}"
        puts "  #{COLORS[:gray]}Evidence: #{result[:proof]}#{COLORS[:reset]}"
        
        if result[:reflected_headers]
            puts "  #{COLORS[:gray]}Reflected headers:#{COLORS[:reset]}"
            result[:reflected_headers].each do |k,v|
                puts "    #{COLORS[:gray]}#{k}: #{v}#{COLORS[:reset]}"
            end
        end
        
        puts
    end
end

def main
    options = {
        timeout: 5,
        delay: 0,
        silent: false,
        verbose: false
    }

    OptionParser.new do |opts|
        opts.banner = "Usage: #{File.basename($0)} [options]"

        opts.on("-lFILE", "--list=FILE", "File containing URLs to test") do |f|
            options[:file] = f
        end
        opts.on("-tSEC", "--timeout=SEC", Integer, "Request timeout in seconds") do |t|
            options[:timeout] = t
        end
        opts.on("-dMS", "--delay=MS", Integer, "Delay between requests in ms") do |d|
            options[:delay] = d
        end
        opts.on("-s", "--silent", "Silent mode (only show vulnerable)") do
            options[:silent] = true
        end
        opts.on("-v", "--verbose", "Show debugging info") do
            options[:verbose] = true
        end
        opts.on("-h", "--help", "Show help") do
            help_menu
            exit
        end
    end.parse!

    unless options[:file]
        puts "#{COLORS[:yellow]}[!] You must specify a URL list file with -l#{COLORS[:reset]}"
        exit 1
    end

    unless File.exist?(options[:file])
        puts "#{COLORS[:yellow]}[!] File not found: #{options[:file]}#{COLORS[:reset]}"
        exit 1
    end

    print_banner if options[:silent] || !options[:silent]

    domain = "www.itrox.site"
    vulnerable_count = 0

    File.readlines(options[:file], chomp: true).each do |url|
        next if url.strip.empty?

        unless valid_url?(url)
            puts "#{COLORS[:red]}[✘] Invalid URL skipped: #{url}#{COLORS[:reset]}" unless options[:silent]
            puts unless options[:silent]
            next
        end

        results = scan_url(url, domain, options[:timeout], options[:verbose])

        if results.any?
            results.each { |r| report_vulnerability(r, options[:silent]) }
            vulnerable_count += 1
        else
            unless options[:silent]
                puts "#{COLORS[:green]}[✘] Not vulnerable: #{url}#{COLORS[:reset]}"
                puts
            end
        end

        apply_delay(options[:delay])
    end

    unless options[:silent]
        puts "#{COLORS[:green]}\n[✔] Scan completed: #{vulnerable_count} vulnerable URLs found#{COLORS[:reset]}"
    end
end

main