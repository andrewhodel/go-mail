package main

import (
    "crypto/rand"
    "crypto/tls"
    "log"
    "fmt"
    "net"
    "crypto/x509"
    "bytes"
    "time"
    "strconv"
    "crypto/md5"
    "encoding/hex"
    "io/ioutil"
    "encoding/json"
    "os"
)

type Config struct {
	PopPort				int64	`json:"popPort"`
	SslKey				string	`json:"sslKey"`
	SslCert				string	`json:"sslCert"`
	SslCa				string	`json:"sslCa"`
}

var config Config

func main() {

	// read the configuration file
	config_file_data, err := ioutil.ReadFile("./config.json")

	if (err != nil) {
		fmt.Printf("Error reading configuration file ./config.json: %s\n", err)
	}

	config_json_err := json.Unmarshal(config_file_data, &config)
	if (config_json_err != nil) {
		fmt.Printf("Error decoding ./config.json: %s\n", config_json_err)
		os.Exit(1)
	}

    cert, err := tls.LoadX509KeyPair(config.SslCert, config.SslKey)

    if err != nil {
        log.Fatalf("server: loadkeys: %s", err)
    }

    srv_config := tls.Config{Certificates: []tls.Certificate{cert}}
    srv_config.Rand = rand.Reader
    service := ":" + strconv.FormatInt(config.PopPort, 10)
    listener, err := tls.Listen("tcp", service, &srv_config)

    if err != nil {
	    log.Fatalf("server: listen: %s", err)
    }

    log.Print("POP (RFC 1939 with 8314) server port " + strconv.FormatInt(config.PopPort, 10) + ": listening")

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("server: accept: %s", err)
            break
        }
        defer conn.Close()
        log.Printf("server: accepted from %s", conn.RemoteAddr())
        tlscon, ok := conn.(*tls.Conn)
        if ok {
            log.Print("ok=true")
            state := tlscon.ConnectionState()
            for _, v := range state.PeerCertificates {
                log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
            }
        }
        go handleClient(conn)
    }

}

// write to the connection
func cw(conn net.Conn, b []byte) {

    n, err := conn.Write(b)

    _ = n
    if err != nil {
	    log.Printf("conn.Write() error: %s", err)
    }

}

// execute and respond to a command
func execCmd(conn net.Conn, c []byte, ss string) {

	// each command can be up to 512 bytes and the buffer is that big
	// they are ended with \r\n so remove everything from that
	c = bytes.Split(c, []byte("\r\n"))[0]

	log.Printf("got command: %s\n", c)

	if (bytes.Index(c, []byte("USER")) == 0) {

		log.Printf("USER command")

		// USER name
		s := bytes.Split(c, []byte(" "))

		if (len(s) != 2) {
			conn.Write([]byte("-ERR invalid USER command\r\n"))
		} else {
			// store the username to test once the password arrives
			//u := s[1]
			conn.Write([]byte("+OK try PASS\r\n"))
		}

	} else if (bytes.Index(c, []byte("PASS")) == 0) {

		log.Printf("PASS command")

		// PASS string
		s := bytes.Split(c, []byte(" "))

		if (len(s) != 2) {
			conn.Write([]byte("-ERR invalid PASS command\r\n"))
		} else {
			// test the stored username and this password
			//u := conn_struct.existing_username
			p := s[1]
			if (string(p) == "asdf") {
				conn.Write([]byte("+OK logged in\r\n"))
			} else {
				conn.Write([]byte("-ERR invalid credentialsr\n"))
			}
		}

	} else if (bytes.Index(c, []byte("AUTH")) == 0) {

		log.Printf("AUTH command")
		conn.Write([]byte("-ERR need credentials and login type\r\n"))

	} else if (bytes.Index(c, []byte("APOP")) == 0) {

		log.Printf("APOP command")
		// APOP login password
		// split by space character
		s := bytes.Split(c, []byte(" "))

		if (len(s) != 3) {
			conn.Write([]byte("-ERR invalid APOP command\r\n"))
		} else {

			//log.Printf("%q\n", s)

			u := s[1]
			p := s[2]

			// the password should be the stored users password and the ss (shared secret)
			// md5sum(ss + password)
			m := md5.New()
			m.Write([]byte(ss + "asdf"))
			valid_sum := hex.EncodeToString(m.Sum(nil))
			fmt.Printf("valid string for md5sum: %s\n", ss + "asdf")
			fmt.Printf("valid md5sum: %s\n", valid_sum)

			fmt.Printf("login: %s\npass: %s\n", u, p)

			// validate credentials

			if (string(p) == valid_sum) {
				conn.Write([]byte("+OK logged in\r\n"))
			} else {
				conn.Write([]byte("-ERR invalid credentials\r\n"))
			}

		}

	} else if (bytes.Index(c, []byte("CAPA")) == 0) {

		log.Printf("CAPA command")
		// respond with capabilities line by line, ended with a .
		conn.Write([]byte("+OK\r\nCAPA\r\nAPOP\r\nUSER\r\n.\r\n"))

	} else if (bytes.Index(c, []byte("STAT")) == 0) {

		log.Printf("STAT command")
		// respond with number of messages and collective size in bytes
		conn.Write([]byte("+OK 0 0\r\n"))

	} else if (bytes.Index(c, []byte("LIST")) == 0) {

		log.Printf("LIST command")
		// returns a list of all messages in the inbox, their message number (identifier) and size in bytes
		// if LIST has a parameter that is an integer, LIST 1 then only return that message
		// +OK 1 4444
		conn.Write([]byte("+OK 1 messages:\r\n1 4444\r\n.\r\n"))

	} else if (bytes.Index(c, []byte("RETR")) == 0) {

		log.Printf("RETR command")
		/*
RETR 2
+OK 4787 octets
Return-Path: <gmailuser@gmail.com>
Delivered-To: someuser@example.atmailcloud.com
<snip>
Content-Type: text/plain; charset=us-ascii
Subject: Test message 1
Date: Wed, 3 Oct 2018 11:01:29 +1000
To: someuser@example.atmailcloud.com

This is just a test message for the POP blog post for atmail.
.
		*/
		conn.Write([]byte("+OK 0 octets\r\n.\r\n"))

	} else if (bytes.Index(c, []byte("DELE")) == 0) {

		log.Printf("DELE command")
		// DELE N
		// delete message N, pending pop session end
		conn.Write([]byte("+OK will be deleted\r\n"))

	} else if (bytes.Index(c, []byte("NOOP")) == 0) {

		log.Printf("NOOP command")
		// this is similar to a keep-alive
		conn.Write([]byte("+OK\r\n"))

	} else if (bytes.Index(c, []byte("RSET")) == 0) {

		log.Printf("RSET command")
		// reset all pending delete operations
		// no messages will be deleted
		conn.Write([]byte("+OK\r\n"))

	} else if (bytes.Index(c, []byte("QUIT")) == 0) {

		log.Printf("QUIT command")
		// logout, client should close the connection
		// the server might as well also
		conn.Write([]byte("+OK logging out\r\n"))
		conn.Close()

	} else {

		conn.Write([]byte("-ERR unknown command\r\n"))

	}

}

func handleClient(conn net.Conn) {

    defer conn.Close()

    /*
    	     A POP3 server which implements the APOP command will
             include a timestamp in its banner greeting.  The syntax of
             the timestamp corresponds to the `msg-id' in [RFC822], and
             MUST be different each time the POP3 server issues a banner
             greeting.  For example, on a UNIX implementation in which a
             separate UNIX process is used for each instance of a POP3
             server, the syntax of the timestamp might be:

                <process-ID.clock@hostname>

             where `process-ID' is the decimal value of the process's
             PID, clock is the decimal value of the system clock, and
             hostname is the fully-qualified domain-name corresponding
             to the host where the POP3 server is running.
    */
    ss := "<1896." + strconv.FormatInt(time.Now().Unix(), 10) + "@asdf.com>"
    log.Printf("client connected")
    s := "+OK POP3 server ready " + ss  + "\r\n"
    cw(conn, []byte(s))

    buf := make([]byte, 512)

    for {

        fmt.Print("\nserver: conn: waiting\n")

        n, err := conn.Read(buf)
	_ = n
        if err != nil {
            if err != nil {
                log.Printf("server: conn: read: %s", err)
            }
            break
        }

	// execute the command, each a maximum of 512 bytes with the final \r\n
	execCmd(conn, buf, ss)

    }

    log.Println("server: conn: closed")

}
