#!/usr/bin/env ruby
# Author: iTrox (Javier González)

require 'openssl'
require 'optparse'
require 'base64'

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
        
        #{COLORS[:orange]}  █████  ███████ ███████      ██████ ██ ██████  ██   ██ ███████ ██████
        #{COLORS[:orange]} ██   ██ ██      ██          ██      ██ ██   ██ ██   ██ ██      ██   ██ 
        #{COLORS[:orange]} ███████ █████   ███████     ██      ██ ██████  ███████ █████   ██████   
        #{COLORS[:orange]} ██   ██ ██           ██     ██      ██ ██      ██   ██ ██      ██   ██ 
        #{COLORS[:orange]} ██   ██ ███████ ███████      ██████ ██ ██      ██   ██ ███████ ██   ██ #{COLORS[:reset]}
        
          #{COLORS[:calypso]}AES-256 encryption and decryption tool#{COLORS[:reset]}
          #{COLORS[:calypso]}Version 1.0#{COLORS[:reset]}
          #{COLORS[:green]}Made by iTrox (Javier González)#{COLORS[:reset]}
          #{COLORS[:gray]}Use -h for help#{COLORS[:reset]}
    BANNER
    puts
end

class AESCipher
    MODES = {
        'ECB' => { iv: false, auth: false, padding: true },
        'CBC' => { iv: true, iv_size: 16, auth: false, padding: true },
        'CTR' => { iv: true, iv_size: 16, auth: false, padding: false },
        'OFB' => { iv: true, iv_size: 16, auth: false, padding: false },
        'CFB' => { iv: true, iv_size: 16, auth: false, padding: false },
        'GCM' => { iv: true, iv_size: 12, auth: true, padding: false },
        #'CCM' => { iv: true, iv_size: 12, auth: true, padding: false }
    }.freeze

    def initialize(mode, hex_key, hex_iv = nil, auth_data = nil)
        @mode = mode.upcase
        validate_mode!
        @key = validate_hex_key(hex_key)
        @iv = validate_hex_iv(hex_iv, @mode) if MODES[@mode][:iv]
        @auth_data = auth_data
    end

    def encrypt(plaintext)
        cipher = OpenSSL::Cipher.new("AES-256-#{@mode}").encrypt
        cipher.key = @key
        cipher.iv = @iv if MODES[@mode][:iv]
        cipher.auth_data = @auth_data if MODES[@mode][:auth] && @auth_data

        plaintext = add_padding(plaintext) if MODES[@mode][:padding] && plaintext.bytesize % 16 != 0

        encrypted = cipher.update(plaintext) + cipher.final

        {
            mode: @mode,
            ciphertext_hex: encrypted.unpack('H*').first,
            ciphertext_b64: Base64.strict_encode64(encrypted),
            auth_tag: MODES[@mode][:auth] ? cipher.auth_tag.unpack('H*').first : nil,
            padding_added: MODES[@mode][:padding] ? (16 - (plaintext.bytesize % 16)) % 16 : 0,
            key_used: @key.unpack('H*').first,
            iv_used: @iv ? @iv.unpack('H*').first : nil
        }
    end

    def decrypt(ciphertext, auth_tag = nil)
        cipher = OpenSSL::Cipher.new("AES-256-#{@mode}").decrypt
        cipher.key = @key
        cipher.iv = @iv if MODES[@mode][:iv]
        
        if MODES[@mode][:auth]
            unless auth_tag
                raise "Mode #{@mode} requires auth_tag to decrypt"
            end
            cipher.auth_tag = [auth_tag].pack('H*')
            cipher.auth_data = @auth_data if @auth_data
        end

        decrypted = cipher.update(ciphertext) + cipher.final

        if MODES[@mode][:padding]
            pad_len = decrypted.bytes.last
            if pad_len <= 16
                decrypted = decrypted[0...-pad_len]
            end
        end

        {
            mode: @mode,
            plaintext: decrypted,
            key_used: @key.unpack('H*').first,
            iv_used: @iv ? @iv.unpack('H*').first : nil
        }
    end

    private

    def add_padding(data)
        pad_len = 16 - (data.bytesize % 16)
        data + (pad_len.chr * pad_len)
    end

    def validate_mode!
        return if MODES.key?(@mode)

        puts "#{COLORS[:yellow]}[!] Invalid mode. Supported modes:#{COLORS[:reset]}"
        MODES.each_key { |m| puts "  - #{COLORS[:blue]}#{m}#{COLORS[:reset]}" }
        exit 1
    end

    def validate_hex_key(hex_key)
        hex_key = hex_key.to_s.strip
        unless hex_key.size == 64 && hex_key.match?(/\A[a-f0-9]+\z/i)
            puts "#{COLORS[:red]}[✘] ERROR: Invalid key - Length: #{hex_key.size}#{COLORS[:reset]}"
            puts "#{COLORS[:yellow]}Received: #{hex_key}#{COLORS[:reset]}"
            puts "#{COLORS[:yellow]}64 hexadecimal characters were expected (0-9, a-f)#{COLORS[:reset]}"
            exit 1
        end
        
        begin
            [hex_key].pack('H*').tap do |key|
                unless key.bytesize == 32
                    raise ArgumentError, "Incorrect key size"
                end
            end
        rescue ArgumentError => e
            puts "#{COLORS[:red]}[✘] ERROR: Hexadecimal conversion failed - #{e.message}#{COLORS[:reset]}"
            exit 1
        end
    end

    def validate_hex_iv(hex_iv, mode)
        expected_bytes = MODES[mode][:iv_size]
        hex_iv = hex_iv.to_s.strip
        expected_hex_size = expected_bytes * 2

        unless hex_iv.size == expected_hex_size && hex_iv.match?(/\A[a-f0-9]+\z/i)
            puts "#{COLORS[:red]}[✘] ERROR: Invalid IV/Nonce for #{mode}#{COLORS[:reset]}"
            puts "#{COLORS[:yellow]}Must be #{expected_hex_size} hexadecimal characters (#{expected_bytes} bytes)#{COLORS[:reset]}"
            puts "#{COLORS[:yellow]}Example: #{'a' * expected_hex_size}#{COLORS[:reset]}"
            exit 1
        end

        begin
            [hex_iv].pack('H*')
        rescue ArgumentError
            puts "#{COLORS[:red]}[✘] ERROR: Hexadecimal IV is invalid#{COLORS[:reset]}"
            exit 1
        end
    end
end

def safe_decode_plaintext(plaintext)
    utf8_text = plaintext.dup.force_encoding('UTF-8')
    if utf8_text.valid_encoding?
        if utf8_text.match?(/\A[\p{Print}\s\r\n\t]*\z/)
            return utf8_text
        else
            return "#{COLORS[:yellow]}(Binary data - hex): #{plaintext.unpack('H*').first}#{COLORS[:reset]}"
        end
    end
    
    ascii_text = plaintext.dup.force_encoding('ASCII-8BIT')
    if ascii_text.match?(/\A[\x20-\x7E\r\n\t]*\z/)
        return ascii_text.force_encoding('UTF-8')
    else
        return "#{COLORS[:yellow]}(Binary data - hex): #{plaintext.unpack('H*').first}#{COLORS[:reset]}"
    end
rescue => e
    "#{COLORS[:yellow]}(Binary data - hex): #{plaintext.unpack('H*').first}#{COLORS[:reset]}"
end

def print_help
    puts <<~HELP
        #{COLORS[:green]}Use:#{COLORS[:reset]} aes-cipher [flags]

        #{COLORS[:yellow]}Operations:#{COLORS[:reset]}
          -E, --encrypt         Encrypt message (requires -M, -k, -m)
          -D, --decrypt         Decrypt message (requires -M, -k, -i, -c)

        #{COLORS[:yellow]}Mandatory options:#{COLORS[:reset]}
          -M, --mode MODE       Encryption mode (#{AESCipher::MODES.keys.join(', ')})
          -k, --key HEX_KEY     AES-256 key (64 hexadecimal characters)

        #{COLORS[:yellow]}Options for encrypt (-E):#{COLORS[:reset]}
          -m, --message MSG     Message to be encrypted (plain text)
          -i, --iv HEX_IV       IV/Nonce in hexadecimal(#{AESCipher::MODES.select { |_, v| v[:iv] }.map { |k, v| "#{k}: #{v[:iv_size]*2} chars" }.join(', ')})
          -a, --auth-data DATA  Additional data for authentication (GCM/CCM)
        
        #{COLORS[:yellow]}Options for decrypting (-D):#{COLORS[:reset]}
          -c, --ciphertext B64  Base64-encoded text
          -i, --iv HEX_IV       IV/Nonce in hexadecimal
          -t, --auth-tag HEX    Auth Tag in hexadecimal (required for GCM/CCM)

        #{COLORS[:yellow]}General options:#{COLORS[:reset]}
          -h, --help            Show this message

        #{COLORS[:yellow]}Examples::#{COLORS[:reset]}
          #{COLORS[:blue]}Encryption:#{COLORS[:reset]}
            aes-cipher -E -M CBC -k "4a7e5d6c3f8a9b0e1d2c3b4a5968770a1b2c3d4e5f60718293a4b5c6d7e8f901" -i "a1b2c3d4e5f60718293a4b5c6d7e8f90" -m "Mensaje secreto"

          #{COLORS[:blue]}Decrypted:#{COLORS[:reset]}
            aes-cipher -D -M CBC -k "4a7e5d6c3f8a9b0e1d2c3b4a5968770a1b2c3d4e5f60718293a4b5c6d7e8f901" -i "a1b2c3d4e5f60718293a4b5c6d7e8f90" -c "base64_encryption"
    HELP
    exit
end

print_banner

options = { operation: nil }
OptionParser.new do |opts|
    opts.banner = "Use: aes-cipher [options]"

    opts.on("-E", "--encrypt", "Encryption mode") { options[:operation] = :encrypt }
    opts.on("-D", "--decrypt", "Decrypted mode") { options[:operation] = :decrypt }
    opts.on("-M", "--mode MODE", "Encryption mode") { |m| options[:mode] = m }
    opts.on("-k", "--key HEX_KEY", "AES-256 key (64 hex characters)") { |k| options[:key] = k }
    opts.on("-m", "--message MSG", "Message to encrypt (plain text)") { |m| options[:message] = m }
    opts.on("-c", "--ciphertext B64", "Base64-encoded text") { |c| options[:ciphertext] = c }
    opts.on("-i", "--iv HEX_IV", "IV/Nonce in hexadecimal") { |i| options[:iv] = i }
    opts.on("-t", "--auth-tag HEX", "Auth Tag in hexadecimal") { |t| options[:auth_tag] = t }
    opts.on("-a", "--auth-data DATA", "Authentication data") { |a| options[:auth_data] = a }
    opts.on("-h", "--help", "Show help") { print_help }
end.parse!

unless [:encrypt, :decrypt].include?(options[:operation])
    puts "#{COLORS[:yellow]}[!] You must specify -E (encrypt) or -D (decrypt)#{COLORS[:reset]}"
    print_help
end

unless options[:mode] && options[:key]
    puts "#{COLORS[:yellow]}[!] Required parameters missing (mode and key)#{COLORS[:reset]}"
    print_help
end

begin
    cipher = AESCipher.new(
        options[:mode],
        options[:key],
        options[:iv],
        options[:auth_data]
    )

    case options[:operation]
    when :encrypt
        unless options[:message]
            puts "#{COLORS[:yellow]}[!] Missing message to encrypt (-m)#{COLORS[:reset]}"
            exit 1
        end
        
        result = cipher.encrypt(options[:message])

        puts "\n#{COLORS[:green]}[✔︎] AES-256 encryption result #{options[:mode]}:#{COLORS[:reset]}"
        puts "#{COLORS[:blue]}➜ Original message:#{COLORS[:reset]} #{options[:message]}"
        puts "#{COLORS[:blue]}➜ Key used (hex):#{COLORS[:reset]} #{result[:key_used]}"
        puts "#{COLORS[:blue]}➜ IV/Nonce used (hex):#{COLORS[:reset]} #{result[:iv_used] || 'N/A'}"
        puts "#{COLORS[:blue]}➜ Ciphertext (hex):#{COLORS[:reset]} #{result[:ciphertext_hex]}"
        puts "#{COLORS[:blue]}➜ Ciphertext (Base64):#{COLORS[:reset]} #{result[:ciphertext_b64]}"
        puts "#{COLORS[:blue]}➜ Auth Tag:#{COLORS[:reset]} #{result[:auth_tag] || 'N/A'}" if result[:auth_tag]
        puts "#{COLORS[:blue]}➜ Additional padding:#{COLORS[:reset]} #{result[:padding_added]} bytes" if result[:padding_added] > 0

    when :decrypt
        unless options[:ciphertext]
            puts "#{COLORS[:yellow]}[!] Base64-encoded text is missing (-c)#{COLORS[:reset]}"
            exit 1
        end

        if AESCipher::MODES[options[:mode]][:iv] && !options[:iv]
            puts "#{COLORS[:yellow]}[!] Mode #{options[:mode]} requires IV/Nonce (-i)#{COLORS[:reset]}"
            exit 1
        end

        if AESCipher::MODES[options[:mode]][:auth] && !options[:auth_tag]
            puts "#{COLORS[:yellow]}[!] Mode #{options[:mode]} requires the Auth tag (-t)#{COLORS[:reset]}"
            exit 1
        end

        ciphertext = Base64.strict_decode64(options[:ciphertext])
        result = cipher.decrypt(ciphertext, options[:auth_tag])

        puts "\n#{COLORS[:green]}[✔︎] AES-256 decryption result-#{options[:mode]}:#{COLORS[:reset]}"
        puts "#{COLORS[:blue]}➜ Key used (hex):#{COLORS[:reset]} #{result[:key_used]}"
        puts "#{COLORS[:blue]}➜ IV/Nonce used (hex):#{COLORS[:reset]} #{result[:iv_used] || 'N/A'}"
        
        # Use safe decoding for the plaintext
        decoded_plaintext = safe_decode_plaintext(result[:plaintext])
        puts "#{COLORS[:blue]}➜ Decrypted message:#{COLORS[:reset]} #{decoded_plaintext}"
    end

rescue => e
    puts "#{COLORS[:red]}[✘] Error: #{e.message}#{COLORS[:reset]}"
    exit 1
end
