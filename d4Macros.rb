# Author: iTrox (Javier González)
# Versión 1.0

require 'win32ole'
require 'fiddle/import'
require 'fiddle/types'
require 'optparse'

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

TARGET_PROCESS_NAME = "Diablo IV.exe"
DEFAULT_KEYS = ['1', '2', '3', '4']
DEFAULT_DELAY = 0.1
DEFAULT_INTERVAL = 1

$config = {
  keys: DEFAULT_KEYS,
  delay: DEFAULT_DELAY,
  interval: DEFAULT_INTERVAL,
  mouse_chaos: false,
  verbose: false
}

module Sys
  extend Fiddle::Importer
  dlload 'user32.dll'
  include Fiddle::Win32Types

  extern 'void* GetForegroundWindow()'
  extern 'unsigned long GetWindowThreadProcessId(void*, void*)'
  
  def self.get_active_pid
    hwnd = GetForegroundWindow()
    return 0 if hwnd.nil? || hwnd.null?
    
    pid_ptr = Fiddle::Pointer.malloc(4)
    GetWindowThreadProcessId(hwnd, pid_ptr)
    pid_ptr[0, 4].unpack1('L')
  rescue Fiddle::DLError
    0 
  end
end

def write_out(msg, type=:info)
  prefix = case type
           when :error then "#{COLORS[:red]}[✘]"
           when :success then "#{COLORS[:green]}[✔]"
           when :warn then "#{COLORS[:yellow]}[!]"
           else "#{COLORS[:blue]}[*]"
           end
  puts "#{prefix} #{msg}#{COLORS[:reset]}"
end

def print_banner
  banner = <<~BANNER
  #{COLORS[:red]}
    ██████  ██  █████  ██████  ██       ██████      ██ ██    ██     ███    ███  █████   ██████ ██████   ██████  ███████ 
    ██   ██ ██ ██   ██ ██   ██ ██      ██    ██     ██ ██    ██     ████  ████ ██   ██ ██      ██   ██ ██    ██ ██      
    ██   ██ ██ ███████ ██████  ██      ██    ██     ██ ██    ██     ██ ████ ██ ███████ ██      ██████  ██    ██ ███████ 
    ██   ██ ██ ██   ██ ██   ██ ██      ██    ██     ██  ██  ██      ██  ██  ██ ██   ██ ██      ██   ██ ██    ██      ██ 
    ██████  ██ ██   ██ ██████  ███████  ██████      ██   ████       ██      ██ ██   ██  ██████ ██   ██  ██████  ███████
  #{COLORS[:reset]}
      #{COLORS[:orange]}Intento de macros para Diablo IV#{COLORS[:reset]}
      #{COLORS[:gray]}Target: #{TARGET_PROCESS_NAME}#{COLORS[:reset]}
  BANNER
  puts banner
end

def show_help
  help_text = <<~HELP
  #{COLORS[:blue]}USAGE:#{COLORS[:reset]}
      ruby #{File.basename(__FILE__)} [options]

  #{COLORS[:blue]}OPTIONS:#{COLORS[:reset]}
      -k, --keys LISTA          Lista de teclas a emular separadas por coma (Teclas por defecto: 1,2,3,4)
                                Ejemplo: -k "1,2,Q,R,SPACE"
                                Ejemplo: --keys "1,2,2,4"
      
      -d, --delay SEGUNDOS      Delay entre teclas (Delay por defecto: 0.1 segundos)
                                Ejemplo: -d 0.1
                                Ejemplo: --delay 2.3
      
      -i, --interval SEGUNDOS   Intervalo de rotación entre bloques de teclas (Intervalo por defecto: cada 1 segundo)
                                Ejemplo: -i 0.1
                                Ejemplo: --interval 0.1
                                
      -h, --help                Ver menú de ayuda

  #{COLORS[:blue]}Ejemplos:#{COLORS[:reset]}
      ruby #{File.basename(__FILE__)} -k "1,2,3,4"
      ruby #{File.basename(__FILE__)} --keys "1,Q,2,W,SPACE" --delay 0.1
      

  HELP
  puts help_text
  exit
end

def get_diablo_pid
  output = `tasklist /FI "IMAGENAME eq #{TARGET_PROCESS_NAME}" /FO CSV /NH 2>NUL`
  return nil if output.strip.empty? || output.include?("No tasks")
  parts = output.split(",")
  return nil unless parts[1]
  parts[1].gsub('"', '').to_i
rescue
  nil
end

options = {}
OptionParser.new do |opts|
  opts.banner = "Uso: d4_macro.rb [opciones]"

  opts.on("-k", "--keys KEYS") do |k|
    $config[:keys] = k.scan(/\{[^}]+\}|[^,]+/).map(&:strip)
  end

  opts.on("-d", "--delay N", Float, "Delay entre teclas") do |d|
    $config[:delay] = d
  end

  opts.on("-i", "--interval N", Float, "Intervalo de rotación entre bloques de teclas") do |i|
    $config[:interval] = i
  end

  opts.on("-h", "--help", "Prints this help") do
    print_banner
    show_help
  end
end.parse!

trap("INT") do
  puts "\n" + "=" * 60
  write_out("Proceso finalizado por el usuario...", :warn)
  write_out("Saliendo...", :info)
  exit 0
end

system("title D4 MACRO [PID: #{Process.pid}]")
system("cls")
print_banner

puts ""
write_out("Configuración en carga:", :success)
puts "    #{COLORS[:gray]}Keys:#{COLORS[:reset]}     #{$config[:keys].join(' -> ')}"
puts "    #{COLORS[:gray]}Delay:#{COLORS[:reset]}    #{$config[:delay]}s"
puts "    #{COLORS[:gray]}Interval:#{COLORS[:reset]} #{$config[:interval]}s"
puts "\n"

begin
  wsh = WIN32OLE.new('WScript.Shell')
rescue WIN32OLERuntimeError => e
  write_out("Error fatal: no se puede cargar el módulo WScript.Shell", :error)
  puts(e.message)
  exit 1
end

target_pid = nil

loop do
  target_pid = get_diablo_pid
  if target_pid
    write_out("Diablo 4 detectado...", :success)
    write_out("PID: #{target_pid}", :success)
    break
  end
  print("\r#{COLORS[:yellow]}[!] Esperando que el proceso de Diablo IV arranque o sea detectado...#{COLORS[:reset]}")
  sleep 3
end

puts("\n" + ("#" * 99))
write_out("Monitoreo activo. Poner el juego en primer plano para que los macros se comiencen a ejecutar...", :blue)
puts("#" * 99)

loop do
  begin
    active_pid = Sys.get_active_pid

    if active_pid == target_pid
      print("\r#{COLORS[:green]}[➤] En ejecución:#{COLORS[:reset]} ")
      
      $config[:keys].each do |key|
        if Sys.get_active_pid == target_pid
          wsh.SendKeys(key)
          print("#{COLORS[:cyan]}#{key}#{COLORS[:reset]} ")
          sleep($config[:delay])
        else
          print("#{COLORS[:red]}(lost focus)#{COLORS[:reset]}")
          break 
        end
      end
      print("              ")
    else
      print("\r#{COLORS[:gray]}[!] En pausa: (Diablo IV se puso en segundo plano)           #{COLORS[:reset]}")
    end

  rescue WIN32OLERuntimeError
    print("\r#{COLORS[:red]}[!] Entrada del sistema bloqueada...#{COLORS[:reset]}")
    print("\r#{COLORS[:red]}[!] Revisar permisos contra el UAC#{COLORS[:reset]}")
  rescue => e
    print("\r#{COLORS[:red]}[!] Error: #{e.class}#{COLORS[:reset]}")
  end

  sleep($config[:interval] + rand(0.1..0.2))
end
