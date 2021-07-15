package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"github.com/grandcat/zeroconf"
	"github.com/pkg/sftp"
	"github.com/sethvargo/go-diceware/diceware"
	"golang.org/x/crypto/ssh"
)

func main() {
	var (
		readOnly     bool
		debugStderr  bool
		gitCommit    string // Git hash, set by build pipeline
		buildVersion string // human readable version, set by build pipeline
		password     string
	)

	list, _ := diceware.Generate(2)
	generatedPW := strings.Join(list, "")

	flag.BoolVar(&readOnly, "r", false, "read-only server")
	flag.BoolVar(&debugStderr, "e", false, "debug to stderr")
	flag.StringVar(&password, "p", generatedPW, "set password")
	flag.Parse()
	if len(flag.Args()) >= 1 && flag.Args()[0] == "version" {
		fmt.Println(buildVersion, gitCommit)
		os.Exit(0)
	}

	debugStream := ioutil.Discard
	if debugStderr {
		debugStream = os.Stderr
	}

	signals := make(chan os.Signal, 1)
	//signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		server, err := zeroconf.Register("sftpserver", "_sftp-ssh._tcp", "local.", 2222, []string{"txtv=0", "lo=1", "la=2"}, nil)
		if err != nil {
			panic(err)
		}
		defer server.Shutdown()
		select {
		case <-signals:
			// Exit by user
		}
	}()

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in a production setting.
			fmt.Fprintf(debugStream, "Login: %s\n", c.User())
			if string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	privateBytes := privatePEM()
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatal("failed to listen for connection", err)
	}
	fmt.Println("Listening on port: 2222")
	fmt.Println("Username: any")
	fmt.Printf("Password: %s \n", password)
	fmt.Println("IP address:", GetLocalIP())
	h, _ := os.Hostname()
	fmt.Println("Hostname:", h)

	nConn, err := listener.Accept()
	if err != nil {
		log.Fatal("failed to accept incoming connection", err)
	}

	// Before use, a handshake must be performed on the incoming net.Conn.
	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal("failed to handshake", err)
	}
	fmt.Fprintf(debugStream, "SSH server established\n")

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	go func() {
		for newChannel := range chans {
			// Channels have a type, depending on the application level
			// protocol intended. In the case of an SFTP session, this is "subsystem"
			// with a payload string of "<length=4>sftp"
			fmt.Fprintf(debugStream, "Incoming channel: %s\n", newChannel.ChannelType())
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				fmt.Fprintf(debugStream, "Unknown channel type: %s\n", newChannel.ChannelType())
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Fatal("could not accept channel.", err)
			}
			fmt.Fprintf(debugStream, "Channel accepted\n")

			// Sessions have out-of-band requests such as "shell",
			// "pty-req" and "env".  Here we handle only the "subsystem" request.
			go func(in <-chan *ssh.Request) {
				for req := range in {
					fmt.Fprintf(debugStream, "Request: %v\n", req.Type)
					ok := false
					switch req.Type {
					case "subsystem":
						fmt.Fprintf(debugStream, "Subsystem: %s\n", req.Payload[4:])
						if string(req.Payload[4:]) == "sftp" {
							ok = true
						}
					}
					fmt.Fprintf(debugStream, " - accepted: %v\n", ok)
					req.Reply(ok, nil)
				}
			}(requests)

			serverOptions := []sftp.ServerOption{
				sftp.WithDebug(debugStream),
			}

			if readOnly {
				serverOptions = append(serverOptions, sftp.ReadOnly())
				fmt.Fprintf(debugStream, "Read-only server\n")
			} else {
				fmt.Fprintf(debugStream, "Read write server\n")
			}

			server, err := sftp.NewServer(
				channel,
				serverOptions...,
			)
			if err != nil {
				log.Fatal(err)
			}
			if err := server.Serve(); err == io.EOF {
				server.Close()
				log.Print("sftp client exited session.")
			} else if err != nil {
				log.Fatal("sftp server completed with error:", err)
			}
		}
	}()
	<-signals
}

func privatePEM() []byte {
	// TODO: store in temp folder and reuse
	bitSize := 4096

	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		log.Fatal(err.Error())
	}
	return encodePrivateKeyToPEM(privateKey)
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok {
			if !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}
