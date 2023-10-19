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
	"strings"
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

func sendFile(filePath string, writer cipher.StreamWriter) error {
	// Apri il file per la lettura
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Ottieni la dimensione del file
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := fileInfo.Size()

	// Invia la dimensione del file come una stringa di 10 caratteri
	header := fmt.Sprintf("%010d", fileSize)
	_, err = writer.Write([]byte(header))
	if err != nil {
		return err
	}

	// Invia il contenuto del file
	_, err = io.Copy(writer, file)
	return err
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

	// Intercept input from stdin
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error reading from stdin:", err)
			}
			break
		}

		// Convert bytes to string and trim space
		line := strings.TrimSpace(string(buf[:n]))

		if strings.HasPrefix(line, "UPLOAD") {
			// Extract the file path
			filePath := strings.TrimSpace(line[len("UPLOAD"):])

			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				// If the file doesn't exist, print "File not found"
				fmt.Println("File not found")
			} else {
				// If the file exists, send the file
				err = sendFile(filePath, writer)
				if err != nil {
					fmt.Printf("Error sending file: %v\n", err)
					continue
				}
				fmt.Println("File sent successfully!")
			}
		} else {
			// Otherwise, write to the encrypted connection
			writer.Write(buf[:n])
		}

	}
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
