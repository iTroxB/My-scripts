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
    yellow: "\e[33m",
    reset: "\e[0m"
}

$output_file = nil
$scan_report = {
    total_files_scanned: 0,
    total_findings: 0,
    findings_by_category: Hash.new(0),
    findings_by_file: {},
    patterns_detected: [],
    patterns_not_detected: []
}

STRINGS_SENSIBLES = [
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
    /\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b/,
    /\b4[0-9]{12}(?:[0-9]{3})?\b/,
    /\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b/,
    /\b3[47][0-9]{13}\b/,
    /\b6(?:011|5[0-9]{2}|4[4-9][0-9])[0-9]{12}\b/,
    /\b3(?:0[0-5]|[68][0-9])[0-9]{11,13}\b/,
    /\b(?:2131|1800|35[0-9]{2})[0-9]{11}\b/,
    /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/i,
    /\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:\b|\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}\b|\b(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}\b|\b(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}\b|\b(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}\b|\b[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}\b|\b:(?::[0-9a-f]{1,4}){1,7}\b/i,
    'access', 'access_code', 'access_token', 'action', 'address', 'admin', 'admin_email', 'administration', 'admin_password', 'aes', 'aes_key',
    'api', 'api_key', 'apikey', 'apisecret', 'api_token', 'api_url', 'app_key', 'auth', 'authentication', 'authentication_header', 'authorization',
    'auth_password', 'auth_token', 'auth_user', 'aws_access_key', 'aws_access_key_id', 'aws_secret_access_key', 'aws_secret_key', 'azure_client_secret',
    'azure_key', 'azure_storage_key', 'base64_decode', 'base64_encoded', 'base_url', 'basic_auth', 'bastion_host', 'bastion_user', 'bearer',
    'bearerauth', 'bearer_token', 'begin', 'begin certificate', 'begin dsa private key', 'begin openssh private key', 'begin private key',
    'begin rsa private key', 'billing_key', 'chacha', 'callbacks', 'callback_url', 'cc_number', 'certificate', 'child_process', 'client_id',
    'client_secret', 'cloudinary_api_secret', 'cmd', '--', 'config', 'configuration', 'connection_string', 'conn_str', 'cookie_secret', 'cred',
    'credential', 'credit_card', 'csrf', 'csrf_token', 'curl -x', 'cve-20', 'cvv', 'database_url', 'db_host', 'db_name', 'db_password', 'db_port',
    'db.query', 'db_user', 'db_username', 'debug', 'decryption_key', 'delete', 'delete from', 'des', 'digitalocean_token', 'discord_webhook',
    'django_secret_key', 'dns_name', 'dns_zone', 'docker_hub_token', 'document.write', 'domain', 'dotenv', 'driver', 'drop table', 'email',
    'encryption_key', 'encryption_salt', '-----end', 'endpoint', '.env', 'env', 'env_file', 'environment', 'environment_type', 'env_secret', 'eval(',
    'eval.+.+.+', 'exec(', 'exec.+.+.+', 'exec(`|\s', 'exec_sql', 'expiry_date', 'firebase_key', 'flask_secret_key', 'ftp_password', 'gcp_service_account',
    'github_token', 'gitlab_token', 'google_api_key', 'hash', 'heroku_api_key', 'hmac', 'hmac_key', 'host', 'hostname', 'id', 'identification', 'import os',
    'information_schema', 'ini', 'innerhtml =', 'insert', 'insert into', 'internal_ip', 'invite_code', 'ip', 'ipaddr', 'ip_address', 'iv', 'jdbc',
    'jdbc_url', 'jwt', 'jwt_secret', 'jwt_token', 'key', 'keystore', 'keystore_password', 'knex.raw', 'license_key', 'localhost', 'localstorage.setitem',
    'localstorage.setitem("token", rawtoken)', 'login', 'login_token', 'master_key', 'md5', 'mongodb_uri', 'mongo_uri', 'mysql_password', 'mysql.query',
    'nc -e', 'netcat', 'network_key', 'new buffer.+.+.+', 'nextauth_secret', 'node_env', 'npm_token', 'oauth', 'oauth2', 'oauth_token', 'odbc',
    'openai_api_key', "' or '' = '", 'or 1=1', 'os.environ', 'passwd', 'password', 'payment_token', 'personal_access_token', 'pgp_key', 'phone', 'poly',
    'port', 'private_ip', 'private_key', 'prod_env', 'properties', 'proxy_url', 'public_ip', 'public_key', 'pwd', 'query', 'query.+.+.+', 'rawquery',
    'raw_sql', 'rc2', 'rc4', 'redirect', 'redis_url', 'refresh_token', 'remote_host', 'root_password', 'root_token', 'rsa','rsa_key', 's3_bucket', 'salt',
    'secret', 'secret_key', 'secret_key_base', 'select', 'select * from', '"select * from users where id = " + userinput', 'sendgrid_api_key', 'sendgrid_key',
    'sentry_dsn', 'sequelize.query', 'server_url', 'session_key', 'session_secret', 'sessionstorage.setitem', 'session_token', 'settings', 'sha','signing_key',
    'slack_token', 'slack_webhook', 'smtp_pass', 'smtp_user', 'spring_datasource_password', 'sql', 'sql_query', 'ssh_config', 'ssh-dss', 'ssh_key', 'sshpass',
    'ssh-rsa', 'ssl', 'ssl_cert', 'stripe_api_key', 'stripe_secret_key', 'subnet_id', 'subprocess', 'superuser_password', 'sysobjects', 'system(',
    'system.+.+.+', 'telegram_bot_token', 'test_mode', 'tls', 'token', 'truststore', 'twilio_auth_token', 'twilio_sid', 'twilio_token', 'unescaped',
    'unsafe_query', 'unsanitized', 'update', 'update set', 'url', 'user', 'userinput', 'username', 'user_password', 'user_token', 'vault_key', 'vault_token',
    'verbose', 'vpc_id', 'wan_ip', 'webhook_url', 'wget http', 'window.name', 'xp_cmdshell', 'xsrf_token', 'yaml', 'yml'
].freeze

PATTERN_CATEGORIES = {
    emails: [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/],
    
    jwt_tokens: [/\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b/],
    
    credit_cards: [
        /\b4[0-9]{12}(?:[0-9]{3})?\b/,
        /\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b/,
        /\b3[47][0-9]{13}\b/,
        /\b6(?:011|5[0-9]{2}|4[4-9][0-9])[0-9]{12}\b/,
        /\b3(?:0[0-5]|[68][0-9])[0-9]{11,13}\b/,
        /\b(?:2131|1800|35[0-9]{2})[0-9]{11}\b/,
        'cc_number', 'credit_card', 'cvv', 'expiry_date'
    ],
    
    ip_addresses: [
        /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/i,
        /\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:\b|\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}\b|\b(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}\b|\b(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}\b|\b(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}\b|\b[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}\b|\b:(?::[0-9a-f]{1,4}){1,7}\b/i,
        'ip', 'ipaddr', 'ip_address', 'internal_ip', 'private_ip', 'public_ip', 'wan_ip'
    ],
    
    api_keys: [
        'api_key', 'apikey', 'google_api_key', 'openai_api_key', 'stripe_api_key', 'sendgrid_api_key', 'aws_access_key', 'aws_access_key_id', 'azure_key',
        'firebase_key', 'heroku_api_key', 'slack_token', 'github_token', 'gitlab_token', 'digitalocean_token', 'docker_hub_token', 'npm_token',
        'telegram_bot_token', 'twilio_auth_token', 'twilio_token', 'twilio_sid', 'sendgrid_key'
    ],
    
    secrets_tokens: [
        'secret', 'secret_key', 'secret_key_base', 'token', 'access_token', 'api_token', 'auth_token', 'bearer_token', 'jwt_secret', 'jwt_token',
        'private_key', 'encryption_key', 'decryption_key', 'session_token', 'login_token', 'root_token', 'vault_token', 'user_token', 'oauth_token',
        'refresh_token', 'payment_token', 'personal_access_token', 'cookie_secret', 'session_secret', 'env_secret', 'cloudinary_api_secret', 'apisecret',
        'flask_secret_key', 'django_secret_key', 'nextauth_secret'
    ],
    
    credentials: [
        'password', 'passwd', 'pwd', 'credential', 'client_secret', 'aws_secret_access_key', 'aws_secret_key', 'db_password', 'mysql_password',
        'root_password', 'ftp_password', 'smtp_pass', 'admin_password', 'auth_password', 'user_password', 'superuser_password', 'keystore_password',
        'spring_datasource_password', 'azure_client_secret'
    ],
    
    database: [
        'database_url', 'mongodb_uri', 'mongo_uri', 'connection_string', 'conn_str', 'jdbc', 'jdbc_url', 'db_host', 'db_name', 'db_user', 'db_username',
        'db_port', 'redis_url'
    ],
    
    config_files: [
        '.env', 'env', 'config', 'configuration', 'settings', 'properties', 'ini', 'yaml', 'yml', 'env_file'
    ],
    
    sql_statement: [
        "' or '' = '", 'or 1=1', 'select * from', '"select * from users where id = " + userinput', 'select', 'insert', 'insert into', 'delete', 'delete from',
        'update', 'update set', 'drop table', 'information_schema', 'sysobjects', 'xp_cmdshell', 'query', 'rawquery', 'raw_sql', 'sql_query', 'db.query',
        'mysql.query', 'sequelize.query', 'knex.raw', 'exec_sql', 'sql'
    ],
    
    command_execution: [
        'exec(', 'system(', 'child_process', 'nc -e', 'netcat', 'subprocess', 'cmd', '--', 'curl -x', 'wget http', 'eval(', 'document.write', 'innerhtml =',
        'window.name', 'unescaped', 'unsafe_query', 'unsanitized', 'userinput', 'new buffer.+.+.+', 'eval.+.+.+', 'exec.+.+.+', 'system.+.+.+', 'query.+.+.+',
        'exec(`|\s'
    ],
    
    cryptography: [
        'aes', 'aes_key', 'rsa', 'rsa_key', 'des', 'rc2', 'rc4', 'chacha', 'poly', 'md5', 'sha', 'hmac', 'hmac_key', 'iv', 'salt', 'encryption_salt', 'hash',
        'signing_key', 'pgp_key', 'master_key', 'vault_key', 'license_key', 'billing_key', 'network_key', 'key', 'keystore', 'truststore'
    ],
    
    authentication: [
        'auth', 'authentication', 'authorization', 'basic_auth', 'bearer', 'bearerauth', 'oauth', 'oauth2', 'csrf', 'csrf_token', 'xsrf_token', 'access',
        'access_code', 'login'
    ],
    
    endpoints_urls: [
        'api_url', 'base_url', 'callback_url', 'webhook_url', 'discord_webhook', 'slack_webhook', 'server_url', 'proxy_url', 'redirect', 'url', 'endpoint',
        'sentry_dsn'
    ],
    
    server_config: [
        'host', 'hostname', 'port', 'domain', 'dns_name', 'dns_zone', 'ssh_config', 'ssh-dss', 'ssh_key', 'sshpass', 'ssh-rsa', 'ssl', 'ssl_cert', 'tls',
        'bastion_host', 'bastion_user', 'remote_host', 'localhost'
    ],
    
    certificates: [
        'certificate', 'begin certificate', 'begin dsa private key', 'begin openssh private key', 'begin private key', 'begin rsa private key', '-----end'
    ],
    
    aws_resources: [
        's3_bucket', 'subnet_id', 'vpc_id', 'gcp_service_account'
    ],
    
    identifiers: [
        'id', 'identification'
    ],
    
    misc_sensitive: [
        'action', 'address', 'admin', 'admin_email', 'administration', 'authentication_header', 'auth_user', 'azure_storage_key', 'base64_decode',
        'base64_encoded', 'callbacks', 'client_id', 'cve-20', 'debug', 'driver', 'email', 'environment', 'environment_type', 'import os', 'invite_code',
        'node_env', 'odbc', 'os.environ', 'phone', 'prod_env', 'test_mode', 'user', 'username', 'verbose', 'localstorage.setitem',
        'localstorage.setitem("token", rawtoken)', 'sessionstorage.setitem'
    ]
}

$pattern_to_category = {}

PATTERN_CATEGORIES.each do |category, patterns|
    patterns.each do |pattern|
        pattern_str = pattern.is_a?(String) ? pattern : pattern.inspect
        $pattern_to_category[pattern_str] = category
    end
end

def find_category_for_pattern(pattern)
    pattern_str = pattern.is_a?(String) ? pattern : pattern.inspect
    
    if $pattern_to_category[pattern_str]
        return $pattern_to_category[pattern_str]
    end
    
    if pattern.is_a?(String)
        $pattern_to_category.each do |p_str, cat|
            if p_str.is_a?(String) && pattern.downcase.include?(p_str.downcase)
                return cat
            end
        end
    end
    
    return :other
end

def write_output(message, console: true)
    if console
        puts message
    end
    if $output_file
        clean_message = message.gsub(/\e\[[0-9;]*[mG]/, '')
        $output_file.puts clean_message
    end
end

def add_to_report(file_path, line_num, pattern, matched_text, category)
    $scan_report[:total_findings] += 1
    $scan_report[:findings_by_category][category] += 1
    
    $scan_report[:findings_by_file][file_path] ||= {
        total: 0,
        findings: []
    }
    
    $scan_report[:findings_by_file][file_path][:total] += 1
    $scan_report[:findings_by_file][file_path][:findings] << {
        line: line_num,
        pattern: pattern.is_a?(String) ? pattern : pattern.inspect[1..-2],
        matched: matched_text,
        category: category
    }
    
    pattern_str = pattern.is_a?(String) ? pattern : pattern.inspect
    unless $scan_report[:patterns_detected].include?(pattern_str)
        $scan_report[:patterns_detected] << pattern_str
    end
end

def print_banner
    banner = <<~BANNER
    
    #{COLORS[:orange]} ███████ ███████  ██████ ██████  ███████ ████████     ███████  ██████  █████  ███    ██ ███    ██ ███████ ██████  
    #{COLORS[:orange]} ██      ██      ██      ██   ██ ██         ██        ██      ██      ██   ██ ████   ██ ████   ██ ██      ██   ██ 
    #{COLORS[:orange]} ███████ █████   ██      ██████  █████      ██        ███████ ██      ███████ ██ ██  ██ ██ ██  ██ █████   ██████  
    #{COLORS[:orange]}      ██ ██      ██      ██   ██ ██         ██             ██ ██      ██   ██ ██  ██ ██ ██  ██ ██ ██      ██   ██ 
    #{COLORS[:orange]} ███████ ███████  ██████ ██   ██ ███████    ██        ███████  ██████ ██   ██ ██   ████ ██   ████ ███████ ██   ██  #{COLORS[:reset]}
    
      #{COLORS[:calypso]}Static scanner that detects sensitive patterns in source code#{COLORS[:reset]}
      #{COLORS[:calypso]}Version 2.0#{COLORS[:reset]}
      #{COLORS[:blue]}Made by iTrox (Javier González)#{COLORS[:reset]}
      #{COLORS[:gray]}Use -h for help#{COLORS[:reset]}
    BANNER
    write_output(banner)
    write_output("")
end

trap("INT") do
    write_output("\n\n#{COLORS[:yellow]}[!] Process interrupted#{COLORS[:reset]}\n")
    $output_file.close if $output_file
    exit 1
end

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
    write_output("=" * 120)
    write_output("#{COLORS[:blue]}➜ Scanning file #{file_path}#{COLORS[:reset]}")
    write_output("=" * 120)
    
    file_findings = 0
    file_categories = Hash.new(0)

    begin
        File.foreach(file_path).with_index(1) do |line, line_num|
            STRINGS_SENSIBLES.each do |pattern|
                if pattern.is_a?(Regexp)
                    line.scan(pattern).each do |match|
                        matched_text = match.is_a?(Array) ? match[0] : match
                        highlighted_line = line.strip.gsub(pattern) { |m| "#{COLORS[:red]}#{m}#{COLORS[:reset]}" }
                        
                        category = find_category_for_pattern(pattern)
                        category_name = category.to_s.gsub('_', ' ').upcase
                        
                        write_output("#{COLORS[:yellow]}[!] #{category_name} in line #{line_num}:#{COLORS[:reset]}" + " #{COLORS[:orange]}[#{matched_text}]#{COLORS[:reset]}" + " | #{highlighted_line}")
                        
                        add_to_report(file_path, line_num, pattern, matched_text, category)
                        file_findings += 1
                        file_categories[category] += 1
                        sleep(delay) if delay > 0
                    end
                else
                    regex_pattern = Regexp.new(Regexp.escape(pattern), Regexp::IGNORECASE)
                    if line.match(regex_pattern)
                        matched_text = line.match(regex_pattern)[0]
                        highlighted_line = line.strip.gsub(regex_pattern) { |m| "#{COLORS[:red]}#{m}#{COLORS[:reset]}" }
                        
                        category = find_category_for_pattern(pattern)
                        category_name = category.to_s.gsub('_', ' ').upcase
                        
                        write_output("#{COLORS[:yellow]}[!] #{category_name} in line #{line_num}:#{COLORS[:reset]}" + 
                                   " #{COLORS[:orange]}[#{pattern}]#{COLORS[:reset]}" + 
                                   " | #{highlighted_line}")
                        
                        add_to_report(file_path, line_num, pattern, matched_text, category)
                        file_findings += 1
                        file_categories[category] += 1
                        sleep(delay) if delay > 0
                    end
                end
            end
        end
        
        if file_findings > 0
            write_output("\n")
            write_output("=" * 120)
            write_output("#{COLORS[:green]}[✔] FILE SUMMARY#{COLORS[:reset]}")
            write_output("=" * 120)
            write_output("\n➜ Total findings: #{file_findings}")
            file_categories.sort_by { |cat, count| -count }.each do |category, count|
                category_name = category.to_s.gsub('_', ' ').capitalize
                write_output("    • #{category_name}: #{count}")
            end
            write_output("\n")
        end
        
        write_output("=" * 120)
        file_findings
        
    rescue => e
        write_output("\n#{COLORS[:red]}[✘] Error reading #{file_path}: #{e.message}#{COLORS[:reset]}\n")
        0
    end
end

def scan_directory(directory, delay: DEFAULT_DELAY)
    write_output("=" * 120)
    write_output("#{COLORS[:blue]}➜ Scanning directory #{directory}#{COLORS[:reset]}\n")
    write_output("=" * 120)
    
    total_findings = 0

    begin
        Find.find(directory) do |path|
            next unless File.file?(path)
            
            if File.extname(path).downcase =~ /\.(asp|aspx|bash|bat|cfg|cfm|cgi|cjs|conf|css|csv|cts|db|do|dsx|dtsx|env|go|htaccess|html|ini|java|js|json|jsp|jsx|log|mjs|mts|php|pl|ps1|py|rb|rpg|rs|sh|sql|svc|svg|ts|tsx|txt|vue|xml|yaml|yml)/i
                $scan_report[:total_files_scanned] += 1
                write_output("#{COLORS[:blue]}➜ Processing file #{$scan_report[:total_files_scanned]}: #{path}#{COLORS[:reset]}")
                findings = scan_file(path, delay: delay)
                total_findings += findings
            else
                write_output("\n#{COLORS[:yellow]}[!] Skipping incompatible file: #{path}#{COLORS[:reset]}\n")
            end
        end
        
        generate_detailed_report()
        
    rescue Errno::ENOENT => e
        write_output("\n#{COLORS[:red]}[✘] ERROR: directory not found - #{e.message}#{COLORS[:reset]}\n")
    rescue Errno::EACCES => e
        write_output("\n#{COLORS[:red]}[✘] Permission error #{e.message}#{COLORS[:reset]}\n")
    rescue => e
        write_output("\n#{COLORS[:red]}[✘] Unexpected error #{e.message}#{COLORS[:reset]}\n")
    end
end

def generate_detailed_report
    write_output("=" * 120)
    write_output("#{COLORS[:green]}[✔] DETAILED SCAN REPORT#{COLORS[:reset]}")
    write_output("=" * 120)
    
    write_output("\n#{COLORS[:blue]}➜ GENERAL SUMMARY:#{COLORS[:reset]}")
    write_output("    • Total files scanned: #{$scan_report[:total_files_scanned]}")
    write_output("    • Total findings: #{$scan_report[:total_findings]}")
    
    if $scan_report[:total_findings] > 0
        write_output("\n#{COLORS[:blue]}➜ FINDINGS BY CATEGORY:#{COLORS[:reset]}")
        sorted_categories = $scan_report[:findings_by_category].sort_by { |cat, count| -count }
        
        if sorted_categories.any?
            max_count = sorted_categories.first[1]
            sorted_categories.each do |category, count|
                category_name = category.to_s.gsub('_', ' ').capitalize
                percentage = ($scan_report[:total_findings] > 0) ? 
                            (count.to_f / $scan_report[:total_findings] * 100).round(2) : 0
                
                bar_length = 30
                filled = max_count > 0 ? (count.to_f / max_count * bar_length).to_i : 0
                bar = "#{COLORS[:green]}#{'█' * filled}#{COLORS[:gray]}#{'░' * (bar_length - filled)}#{COLORS[:reset]}"
                
                write_output("    • #{category_name.ljust(25)}: #{count.to_s.rjust(4)} (#{percentage.to_s.rjust(5)}%) #{bar}")
            end
        end
        
        write_output("\n#{COLORS[:blue]}➜ TOP FILES WITH FINDINGS:#{COLORS[:reset]}")
        if $scan_report[:findings_by_file].any?
            top_files = $scan_report[:findings_by_file].sort_by { |file, data| -data[:total] }.first(10)
            
            top_files.each do |file_path, data|
                write_output("    #{COLORS[:green]}• #{file_path}#{COLORS[:reset]}")
                write_output("      #{COLORS[:yellow]}➤ Total findings: #{data[:total]}#{COLORS[:reset]}")
                
                file_categories = data[:findings].group_by { |f| f[:category] }
                file_categories.each do |category, findings|
                    category_name = category.to_s.gsub('_', ' ').capitalize
                    write_output("        #{COLORS[:violet]}├─ #{category_name}: #{findings.count}#{COLORS[:reset]}")
                end
            end
        else
            write_output("#{COLORS[:red]}[✘] No files with findings#{COLORS[:reset]}")
        end
        
        write_output("\n#{COLORS[:blue]}➜ PATTERN COVERAGE:#{COLORS[:reset]}")
        total_patterns = STRINGS_SENSIBLES.count
        detected_patterns = $scan_report[:patterns_detected].count
        
        coverage_percentage = (detected_patterns.to_f / total_patterns * 100).round(2)
        write_output("    • Patterns detected: #{detected_patterns}/#{total_patterns} (#{coverage_percentage}%)")
        
    else
        write_output("\n#{COLORS[:green]}[✔] No sensitive patterns found!#{COLORS[:reset]}")
    end

    write_output("\n" + "=" * 120)   
    write_output("#{COLORS[:green]}[✔] REPORT GENERATED SUCCESSFULLY#{COLORS[:reset]}")
    write_output("=" * 120)
end

def show_help
    print_banner
    help_text = <<~HELP
    #{COLORS[:blue]}USAGE:#{COLORS[:reset]}
        ruby #{__FILE__} [options]
    
    #{COLORS[:blue]}OPTIONS:#{COLORS[:reset]}
        -f <FILE>         Scan a specific file
        -d <DIRECTORY>    Scan all files in a directory
        -t <THREADS>      Control the threads (1-10, default: #{DEFAULT_THREADS})
        -o <OUTPUT_FILE>  Save output to file (with colors stripped)
        -h                Show this help menu
    
    #{COLORS[:blue]}EXAMPLES:#{COLORS[:reset]}
        ruby #{__FILE__} -f app.js
        ruby #{__FILE__} -d ./src -t 4 -o scan_results.txt
        ruby #{__FILE__} -f config.yaml -o report.txt
    
    #{COLORS[:gray]}Note: Threads control affects delay between findings to avoid overwhelming the system#{COLORS[:reset]}
    HELP
    write_output(help_text)
    exit
end

if ARGV.empty? || ARGV.include?('-h')
    show_help
    exit
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
        is_directory = false
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
    exit 1
end

print_banner

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
    $scan_report[:total_files_scanned] = 1
    findings = scan_file(target, delay: delay)
    
    generate_detailed_report()
end

write_output("", console: false)
write_output("\n#{COLORS[:green]}[✔] Scanning complete...#{COLORS[:reset]}\n\n")

$output_file.close if $output_file
