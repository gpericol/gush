package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
)

var (
	port *string
	psk  [32]byte
)

func init() {
	port = flag.String("port", "", "Listening port (required)")
	flag.Parse()
}

// generatePSK creates a random 32-byte pre-shared key.
func generatePSK() ([32]byte, error) {
	var key [32]byte
	_, err := rand.Read(key[:])
	return key, err
}

// initializeEncryption sets up AES encryption for a connection.
func initializeEncryption(conn net.Conn, key [32]byte) (cipher.StreamReader, cipher.StreamWriter, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return cipher.StreamReader{}, cipher.StreamWriter{}, errors.New("error creating AES cipher: " + err.Error())
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(conn, iv); err != nil {
		return cipher.StreamReader{}, cipher.StreamWriter{}, errors.New("error reading IV from connection: " + err.Error())
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	reader := cipher.StreamReader{S: stream, R: conn}
	writer := cipher.StreamWriter{S: stream, W: conn}

	return reader, writer, nil
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	reader, writer, err := initializeEncryption(conn, psk)
	if err != nil {
		fmt.Println("Failed to initialize encryption:", err)
		return
	}

	// Read from encrypted connection and write to stdout
	go io.Copy(os.Stdout, reader)

	// Read from stdin and write to the encrypted connection
	io.Copy(writer, os.Stdin)
}

func main() {
	if *port == "" {
		fmt.Println("Usage:", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	var err error
	psk, err = generatePSK()
	if err != nil {
		panic("Failed to generate PSK: " + err.Error())
	}
	fmt.Printf("Generated PSK: %x\n", psk)

	listener, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		panic("Failed to start server: " + err.Error())
	}
	defer listener.Close()

	fmt.Printf("Listening on port %s\n", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go handleConnection(conn)
	}
}
