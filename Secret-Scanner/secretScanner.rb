#!/usr/bin/env ruby
# Author: iTrox (Javier González)

require 'find'

COLORS = {
    blue: "\e[34m",
    calypso: "\e[96m",
    green: "\e[32m",
    red: "\e[31m",
    orange: "\e[38;5;208m",
    violet: "\e[35m",
    gray: "\e[90m",
    reset: "\e[0m"
}

$output_file = nil

def write_output(message, console: true)
    if console
        puts message
    end
    if $output_file
        clean_message = message.gsub(/\e\[[0-9;]*[mG]/, '')
        $output_file.puts clean_message
    end
end

trap("INT") do
    write_output("\n\n#{COLORS[:yellow]}[!] Process interrupted#{COLORS[:reset]}\n")
    $output_file.close if $output_file
    exit 1
end

def print_banner
    banner = <<~BANNER
    
    #{COLORS[:orange]} ███████ ███████  ██████ ██████  ███████ ████████     ███████  ██████  █████  ███    ██ ███    ██ ███████ ██████  
    #{COLORS[:orange]} ██      ██      ██      ██   ██ ██         ██        ██      ██      ██   ██ ████   ██ ████   ██ ██      ██   ██ 
    #{COLORS[:orange]} ███████ █████   ██      ██████  █████      ██        ███████ ██      ███████ ██ ██  ██ ██ ██  ██ █████   ██████  
    #{COLORS[:orange]}      ██ ██      ██      ██   ██ ██         ██             ██ ██      ██   ██ ██  ██ ██ ██  ██ ██ ██      ██   ██ 
    #{COLORS[:orange]} ███████ ███████  ██████ ██   ██ ███████    ██        ███████  ██████ ██   ██ ██   ████ ██   ████ ███████ ██   ██  #{COLORS[:reset]}
    
      #{COLORS[:calypso]}Static scanner that detects sensitive patterns in source code#{COLORS[:reset]}
      #{COLORS[:calypso]}Version 1.0#{COLORS[:reset]}
      #{COLORS[:blue]}Made by iTrox (Javier González)#{COLORS[:reset]}
      #{COLORS[:gray]}Use -h for help#{COLORS[:reset]}
    BANNER
    write_output(banner)
    write_output("")
end

print_banner

STRINGS_SENSIBLES = [
    /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0 -9]?)\b/i,
    /\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:\b|\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}\b|\b(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}\b|\b(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}\b|\b(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}\b|\b[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}\b|\b:(?::[0-9a-f]{1,4}){1,7}\b/i,
    'access', 'access_code', 'access_token', 'action', 'address', 'admin', 'admin_email', 'administration', 'admin_password', 'aes', 'aes_key', 'api', 'api_key', 'apikey', 'apisecret', 'api_token', 'api_url', 'app_key', 'auth', 'authentication', 'authentication_header', 'authorization', 'auth_password', 'auth_token', 'auth_user', 'aws_access_key', 'aws_access_key_id', 'aws_secret_access_key', 'aws_secret_key', 'azure_client_secret', 'azure_key', 'azure_storage_key', 'base64_decode', 'base64_encoded', 'base_url', 'basic_auth', 'bastion_host', 'bastion_user', 'bearer', 'bearerauth', 'bearer_token', 'begin certificate', 'begin dsa private key', 'begin openssh private key', 'begin private key', 'begin rsa private key', 'billing_key', 'chacha', 'callbacks', 'callback_url', 'cc_number', 'certificate', 'child_process', 'client_id', 'client_secret', 'cloudinary_api_secret', 'cmd', '--', 'config', 'configuration', 'connection_string', 'conn_str', 'cookie_secret', 'cred', 'credential', 'credit_card', 'csrf', 'csrf_token', 'curl -x', 'cvv', 'database_url', 'db_host', 'db_name', 'db_password', 'db_port', 'db.query', 'db_user', 'db_username', 'debug', 'decryption_key', 'delete', 'delete from', 'des', 'digitalocean_token', 'discord_webhook', 'django_secret_key', 'dns_name', 'dns_zone', 'docker_hub_token', 'document.write', 'domain', 'dotenv', 'driver', 'drop table', 'email', 'encryption_key', 'encryption_salt', '-----end', 'endpoint', '.env', 'env', 'env_file', 'environment', 'environment_type', 'env_secret', 'eval(', 'eval.+.+.+', 'exec(', 'exec.+.+.+', 'exec(`|\s', 'exec_sql', 'expiry_date', 'firebase_key', 'flask_secret_key', 'ftp_password', 'gcp_service_account', 'github_token', 'gitlab_token', 'google_api_key', 'hash', 'heroku_api_key', 'hmac', 'hmac_key', 'host', 'hostname', 'id', 'identification', 'import os', 'information_schema', 'ini', 'innerhtml =', 'insert', 'insert into', 'internal_ip', 'invite_code', 'ip', 'ipaddr', 'ip_address', 'iv', 'jdbc', 'jdbc_url', 'jwt', 'jwt_secret', 'jwt_token', 'key', 'keystore', 'keystore_password', 'knex.raw', 'license_key', 'localhost', 'localstorage.setitem',  'localstorage.setitem("token", rawtoken)', 'login', 'login_token', 'master_key', 'md5', 'mongodb_uri', 'mongo_uri', 'mysql_password', 'mysql.query', 'nc -e', 'netcat', 'network_key', 'new buffer.+.+.+', 'nextauth_secret', 'node_env', 'npm_token', 'oauth', 'oauth2', 'oauth_token', 'odbc', 'openai_api_key', "' or '' = '", 'or 1=1', 'os.environ', 'passwd', 'password', 'payment_token', 'personal_access_token', 'pgp_key', 'phone', 'poly', 'port', 'private_ip', 'private_key', 'prod_env', 'properties', 'proxy_url', 'public_ip', 'public_key', 'pwd', 'query', 'query.+.+.+', 'rawquery', 'raw_sql', 'rc2', 'rc4', 'redirect', 'redis_url', 'refresh_token', 'remote_host', 'root_password', 'root_token', 'rsa','rsa_key', 's3_bucket', 'salt', 'secret', 'secret_key', 'secret_key_base', 'select', 'select * from', '"select * from users where id = " + userinput', 'sendgrid_api_key', 'sendgrid_key', 'sentry_dsn', 'sequelize.query', 'server_url', 'session_key', 'session_secret', 'sessionstorage.setitem', 'session_token', 'settings', 'sha','signing_key', 'slack_token', 'slack_webhook', 'smtp_pass', 'smtp_user', 'spring_datasource_password', 'sql', 'sql_query', 'ssh_config', 'ssh-dss', 'ssh_key', 'sshpass', 'ssh-rsa', 'ssl', 'ssl_cert', 'stripe_api_key', 'stripe_secret_key', 'subnet_id', 'subprocess', 'superuser_password', 'sysobjects', 'system(', 'system.+.+.+', 'telegram_bot_token', 'test_mode', 'tls', 'token', 'truststore', 'twilio_auth_token', 'twilio_sid', 'twilio_token', 'unescaped', 'unsafe_query', 'unsanitized', 'update', 'update set', 'url', 'user', 'userinput', 'username', 'user_password', 'user_token', 'vault_key', 'vault_token', 'verbose', 'vpc_id', 'wan_ip', 'webhook_url', 'wget http', 'window.name', 'xp_cmdshell', 'xsrf_token', 'yaml', 'yml'
].freeze

DEFAULT_THREADS = 1
DEFAULT_DELAY = 0.1

def highlight_keyword(line, keyword)
    if keyword.is_a?(Regexp)
        line.gsub(keyword) { |match| "#{COLORS[:red]}#{match}#{COLORS[:reset]}" }
    else
        line.gsub(/(#{Regexp.escape(keyword)})/i) { |match| "#{COLORS[:red]}#{match}#{COLORS[:reset]}" }
    end
end

def scan_file(file_path, delay: DEFAULT_DELAY)
    write_output("=" * 100)
    write_output("#{COLORS[:blue]}➜ Scanning file #{file_path}#{COLORS[:reset]}")
    write_output("=" * 100)
    findings = 0

    begin
        File.foreach(file_path).with_index(1) do |line, line_num|
            STRINGS_SENSIBLES.each do |pattern|
                if pattern.is_a?(Regexp)
                    line.scan(pattern).each do |match|
                        matched_text = match.is_a?(Array) ? match[0] : match
                        highlighted_line = line.strip.gsub(pattern) { |m| "#{COLORS[:red]}#{m}#{COLORS[:reset]}" }
                        write_output("#{COLORS[:yellow]}[!] Find detected in line #{line_num}:#{COLORS[:reset]}" + 
                                   " #{COLORS[:orange]}[IP: #{matched_text}]#{COLORS[:reset]}" + 
                                   " | #{highlighted_line}")
                        findings += 1
                        sleep(delay) if delay > 0
                    end
                else
                    regex_pattern = Regexp.new(Regexp.escape(pattern), Regexp::IGNORECASE)
                    if line.match(regex_pattern)
                        matched_text = line.match(regex_pattern)[0]
                        highlighted_line = line.strip.gsub(regex_pattern) { |m| "#{COLORS[:red]}#{m}#{COLORS[:reset]}" }
                        write_output("#{COLORS[:yellow]}[!] Find detected in line #{line_num}:#{COLORS[:reset]}" + 
                                   " #{COLORS[:orange]}[#{pattern}]#{COLORS[:reset]}" + 
                                   " | #{highlighted_line}")
                        findings += 1
                        sleep(delay) if delay > 0
                    end
                end
            end
        end
        write_output("=" * 100)
        findings
    rescue => e
        write_output("\n#{COLORS[:red]}[✘] Error reading #{file_path}: #{e.message}#{COLORS[:reset]}\n")
        0
    end
end

def scan_directory(directory, delay: DEFAULT_DELAY)
    write_output("=" * 100)
    write_output("#{COLORS[:blue]}➜ Scanning directory #{directory}#{COLORS[:reset]}\n")
    write_output("=" * 100)
    files_scanned = 0
    total_findings = 0

    begin
        Find.find(directory) do |path|
            next unless File.file?(path)
            
            write_output("#{COLORS[:blue]}➜ Processing file #{path}#{COLORS[:reset]}")
            
            if File.extname(path).downcase =~ /\.(asp|aspx|bash|bat|cfg|cfm|cgi|cjs|conf|css|csv|cts|db|do|dsx|env|go|htaccess|html|ini|java|js|json|jsp|jsx|log|mjs|mts|php|pl|ps1|py|rb|rpg|rs|sh|sql|svc|svg|ts|tsx|txt|vue|xml|yaml|yml)/i
                files_scanned += 1
                findings = scan_file(path, delay: delay)
                total_findings += findings
            else
                write_output("\n#{COLORS[:yellow]}[!] Skipping incompatible file: #{path}#{COLORS[:reset]}\n")
            end
        end
        
        write_output("\n#{COLORS[:green]}[✔] Scan summary:#{COLORS[:reset]}")
        write_output("    Scanned files: #{files_scanned}")
        write_output("    Findings discovered: #{total_findings}")
        
    rescue Errno::ENOENT => e
        write_output("\n#{COLORS[:red]}[✘] ERROR: directory not found - #{e.message}#{COLORS[:reset]}\n")
    rescue Errno::EACCES => e
        write_output("\n#{COLORS[:red]}[✘] Permission error #{e.message}#{COLORS[:reset]}\n")
    rescue => e
        write_output("\n#{COLORS[:red]}[✘] Unexpected error #{e.message}#{COLORS[:reset]}\n")
    end
end

def show_help
    help_text = <<~HELP
    #{COLORS[:blue]}Use:#{COLORS[:reset]}
        ruby #{__FILE__} [options]
    
    #{COLORS[:blue]}Options:#{COLORS[:reset]}
        -f <FILE>         Scan a specific file
        -d <DIRECTORY>    Scan all files in a directory
        -t <THREADS>      Control the threads (1-10, default: #{DEFAULT_THREADS})
        -o <OUTPUT_FILE>  Save output to file
        -h                Show help menu
    
    #{COLORS[:blue]}Examples:#{COLORS[:reset]}
        ruby #{__FILE__} -f app.js
        ruby #{__FILE__} -d ./src -t 4 -o scan_results.txt
    HELP
    write_output(help_text)
    exit
end

if ARGV.empty? || ARGV.include?('-h')
    show_help
end

target = nil
threads = DEFAULT_THREADS
is_directory = false
output_filename = nil

while ARGV.any?
    arg = ARGV.shift
    case arg
    when '-f'
        target = ARGV.shift
    when '-d'
        target = ARGV.shift
        is_directory = true
    when '-t'
        threads = ARGV.shift.to_i
        threads = DEFAULT_THREADS if threads < 1 || threads > 10
    when '-o'
        output_filename = ARGV.shift
    end
end

unless target
    write_output("\n#{COLORS[:red]}[✘] ERROR: You must specify a file (-f) or directory (-d)...#{COLORS[:reset]}\n\n")
    show_help
end

if output_filename
    begin
        $output_file = File.open(output_filename, 'w')
        write_output("#{COLORS[:green]}[✔] Output will be saved to: #{output_filename}#{COLORS[:reset]}\n\n", console: true)
    rescue => e
        write_output("\n#{COLORS[:red]}[✘] Error creating output file: #{e.message}#{COLORS[:reset]}\n\n")
        exit 1
    end
end

delay = DEFAULT_DELAY / threads

if is_directory
    unless Dir.exist?(target)
        write_output("\n#{COLORS[:yellow]}[!] Directory #{target} does not exist...#{COLORS[:reset]}\n\n")
        $output_file.close if $output_file
        exit 1
    end
    scan_directory(target, delay: delay)
else
    unless File.exist?(target)
        write_output("\n#{COLORS[:yellow]}[!] File #{target} does not exist...#{COLORS[:reset]}\n\n")
        $output_file.close if $output_file
        exit 1
    end
    findings = scan_file(target, delay: delay)
    write_output("\n#{COLORS[:green]}[✔] Scan summary:#{COLORS[:reset]}")
    write_output("    Scanned file: #{target}")
    write_output("    Findings discovered: #{findings} \n")
end

write_output("", console: false)
write_output("=" * 100)
write_output("\n#{COLORS[:green]}[✔] Scanning complete...#{COLORS[:reset]}\n\n")

$output_file.close if $output_file
