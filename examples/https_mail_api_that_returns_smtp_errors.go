package main

import (
	"io/ioutil"
	"fmt"
	"encoding/json"
	"time"
	"net/mail"
	"strings"
	"os"
	"bytes"
	"github.com/andrewhodel/go-ip-ac"
	"github.com/andrewhodel/go-mail"
	"strconv"
	"crypto/tls"
	"crypto/rand"
	"net"
	"net/url"
	"encoding/pem"
	"encoding/base64"
	"errors"
	"crypto/x509"
)

var config gomail.Config
var ip_ac ipac.Ipac

var pk []byte

func main() {

	// dkim private key
	pk_data, pk_err := os.ReadFile("../domain-dkim/private.key")

	if (pk_err != nil) {
		fmt.Println(pk_err)
		os.Exit(1)
	}

	pk = pk_data

	ipac.Init(&ip_ac)

	// read the configuration file
	cwd, cwd_err := os.Getwd()
	if (cwd_err != nil) {
		fmt.Println(cwd_err)
		os.Exit(1)
	}
	config_file_data, err := ioutil.ReadFile(cwd + "/config.json")

	if (err != nil) {
		fmt.Printf("Error reading configuration file ./config.json (" + cwd + "/config.json): %s\n", err)
	}

	config_json_err := json.Unmarshal(config_file_data, &config)
	if (config_json_err != nil) {
		fmt.Printf("Error decoding ./config.json: %s\n", config_json_err)
		os.Exit(1)
	}

	// https server
	var httpsPort int64 = 444
	var cert tls.Certificate
	var tls_err error
	var rootca []byte
	if (config.LoadCertificatesFromFiles == true) {
		cert, tls_err = tls.LoadX509KeyPair(config.SslCert, config.SslKey)
		rootca, _ = os.ReadFile(config.SslCa)
	} else {
		cert, tls_err = tls.X509KeyPair([]byte(config.SslCert), []byte(config.SslKey))
		rootca = []byte(config.SslCa)
	}

	if err != nil {
		fmt.Printf("HTTPS server did not load TLS certificates: %s\n", tls_err)
		os.Exit(1)
	}

	rootcert, rootcert_err := CertFromPemBytes(rootca, "")
	if (rootcert_err == nil) {
		// add the CA to the certificate chain (as NodeJS does by default)
		for l := range(rootcert.Certificate) {
			cert.Certificate = append(cert.Certificate, rootcert.Certificate[l])
		}
		cert.Leaf = rootcert.Leaf
	}

	tls_config := tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS12, ServerName: config.Fqdn}
	tls_config.Rand = rand.Reader

	// listen on tcp socket
	ln, err := tls.Listen("tcp", ":" + strconv.FormatInt(httpsPort, 10), &tls_config)
	if err != nil {
		fmt.Printf("HTTPS server listen failed: %s\n", err.Error())
		os.Exit(1)
	}
	defer ln.Close()

	// HTTPS server
	// start a subroutine
	go func() {

		for {

			conn, err := ln.Accept()
			if err != nil {
				// handle error
				continue
			}
			defer conn.Close()

			// take the port number off the address
			var ip, port, iperr = net.SplitHostPort(conn.RemoteAddr().String())
			_ = port
			_ = iperr

			if (ipac.TestIpAllowed(&ip_ac, ip) == false) {
				conn.Close()
				continue
			}

			// set the idle timeout
			conn.SetDeadline(time.Now().Add(time.Second * 5))

			go handle_http_request(conn)

		}

	}()

	fmt.Println("HTTPS server started on port " + strconv.FormatInt(httpsPort, 10))

	// keep main thread open
	select {}

}

type EmailJson struct {
	To		[]string	`json:"to"`
	From		string		`json:"from"`
	Subject		string		`json:"subject"`
	Body		string		`json:"body"`
	Html		bool		`json:"html"`
}

func CertFromPemBytes(bytes []byte, password string) (tls.Certificate, error) {
	var cert tls.Certificate
	var block *pem.Block
	for {
		block, bytes = pem.Decode(bytes)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, errors.New("no certificate")
	}
	if c, e := x509.ParseCertificate(cert.Certificate[0]); e == nil {
		cert.Leaf = c
	}
	return cert, nil
}

func handle_http_request(conn net.Conn) {

	// parse HTTP/S request
	var tlen = 0
	var header_data []byte
	var body_data []byte
	var end_of_header = false
	var content_length = -1
	var read_body_data = false

	// read header data
	for true {

		// set the read timeout for each read
		conn.SetReadDeadline(time.Now().Add(time.Second * 2))

		buf := make([]byte, 1500)
		l, err := conn.Read(buf)

		if (err != nil) {
			// error reading request data
			//fmt.Println("http/s server read error:", err)
			break
		}

		tlen += l

		if (tlen > 2000) {
			// headers too long
			conn.Write([]byte("HTTP/1.1 400 headers too long\r\n\r\n"))
			conn.Close()
			return
		}

		if (end_of_header == false) {

			// add to header_data
			for b := range buf {
				header_data = append(header_data, buf[b])
			}

			// find the end of the headers
			var header_end_index = bytes.Index(header_data, []byte("\r\n\r\n"))

			if (header_end_index > -1) {

				// end of header is in header_data
				end_of_header = true

				if (bytes.Index(header_data, []byte("GET ")) == 0) {
					// no body data sent in a GET request
					header_data = header_data[0:header_end_index]
					// no more data allowed
					break
				} else if (header_end_index + 4 < len(header_data)) {

					// this is a request type other than GET
					read_body_data = true

					// avoid waiting for the read deadline
					// that could be caused by no content-length header being sent in the request
					// if there is a content-length header
					var content_length_header_start = bytes.Index(bytes.ToLower(header_data), []byte("content-length:"))

					if (content_length_header_start > -1) {

						var content_length_header_end = bytes.Index(header_data[content_length_header_start:], []byte("\r\n"))

						if (content_length_header_end > -1) {

							var content_length_header = header_data[content_length_header_start:content_length_header_start + content_length_header_end]

							content_length, _ = strconv.Atoi(string(content_length_header[len("content-length: "):len(content_length_header)]))

						}
					}

					// there is body data in header_data
					//fmt.Println("body data in header_data")

					body_data = header_data[header_end_index + 4:]
					header_data = header_data[0:header_end_index]

				}

			}

		}

	}

	// get request URL
	var first_line_end = bytes.Index(header_data, []byte("\r\n"))

	if (first_line_end == -1) {
		// invalid request
		conn.Close()
		return
	}

	var first_line_space_split = bytes.Split(header_data[:first_line_end], []byte(" "))
	var request_path string
	if (len(first_line_space_split) < 3) {
		// invalid request
		// should be similar to GET / HTTP/1.1
		conn.Close()
		return
	} else {
		// the second item is the path
		request_path = string(first_line_space_split[1])
	}

	// parse the url
	urlp, urlp_err := url.Parse(request_path)

	if (urlp_err != nil) {
		conn.Write([]byte("HTTP/1.1 404\r\n"))
		conn.Write([]byte("\r\n"))
		conn.Write([]byte("not found"))
		conn.Close()
		return
	}

	// process URL authentication before reading body data

	var response_headers []byte

	var key = urlp.Query().Get("key")
	if (key != "yourkeyhere") {

		// invalid authentication

		var response = []byte("{\"error\": \"authentication failed, invalid key\"}")

		response_headers = bytes.Join([][]byte{response_headers, []byte("Content-Length: " + strconv.Itoa(len(response)) + "\r\n")}, nil)
		conn.Write([]byte("HTTP/1.1 200\r\n"))
		conn.Write(response_headers)
		conn.Write([]byte("\r\n"))

		// write JSON response with SMTP server response
		conn.Write(response)

		return

	}

	if (read_body_data == true) {

		// read body data
		tlen = 0
		for true {

			if (content_length > -1) {

				if (len(body_data) >= content_length) {
					// do not wait for the read deadline
					// all the data has been sent
					body_data = body_data[:content_length]
					break
				}

			}

			// set the read timeout for each read
			conn.SetReadDeadline(time.Now().Add(time.Second * 2))

			buf := make([]byte, 1500)
			l, err := conn.Read(buf)

			if (err != nil) {
				// error reading request data
				//fmt.Println("http/s server read error:", err)
				break
			}

			tlen += l

			if (tlen > 1000 * 1000 * 10) {
				// body is too long
				conn.Write([]byte("HTTP/1.1 400 body too long\r\n\r\n"))
				conn.Close()
				return
			}

			// add to body_data
			for b := range(buf) {
				body_data = append(body_data, buf[b])
			}

		}

	}

	if (strings.Index(request_path, "/sendmail") == 0) {

		response_headers = bytes.Join([][]byte{response_headers, []byte("Content-Type: application/json\r\n")}, nil)

		// parse JSON containing email data
		var email_json EmailJson

		err := json.Unmarshal(body_data, &email_json)
		if (err != nil) {

			var response = []byte("{\"error\": \"" + err.Error() + "\"}")

			response_headers = bytes.Join([][]byte{response_headers, []byte("Content-Length: " + strconv.Itoa(len(response)) + "\r\n")}, nil)
			conn.Write([]byte("HTTP/1.1 200\r\n"))
			conn.Write(response_headers)
			conn.Write([]byte("\r\n"))

			// write JSON response with SMTP server response
			conn.Write(response)

		} else {

			// send the email
			fmt.Printf("request to send email: %+V\n", email_json)

			var response = []byte("{}")

			// send via SMTP
			var om gomail.OutboundMail
			om.DkimPrivateKey = pk
			om.DkimDomain = "fgkhdgsfgdds._domainkey.xyzbots.com"

			if (email_json.Html == true) {
				// set the content-type header in the email to text/html
				om.Headers = make(map[string]string, 0)
				om.Headers["content-type"] = "text/html; charset=utf-8"
			}

			parsed_from, parsed_from_err := mail.ParseAddress(email_json.From)
			if (parsed_from_err != nil) {

				response = []byte("{\"error\": \"" + base64.StdEncoding.EncodeToString([]byte(err.Error())) + "\"}")

			} else {

				om.From = *parsed_from
				om.Subj = email_json.Subject
				om.Body = []byte(email_json.Body)
				// email will not send unless the server provides TLS or STARTTLS
				om.RequireTLS = true

				// add to addresses
				om.To = []mail.Address{}
				for a := range(email_json.To) {

					// add each to address
					tf, tf_err := mail.ParseAddress(email_json.To[a])

					if tf_err == nil {

						already_exists := false
						for e := range(om.To) {
							if (om.To[e] == *tf) {
								// already in send_addresses
								already_exists = true
								break
							}
						}

						if (already_exists == false) {
							om.To = append(om.To, *tf)
						}

					}

				}

				err, return_code, _ := gomail.SendMail(om)

				if (err != nil) {
					response = []byte("{\"error\": \"" + base64.StdEncoding.EncodeToString([]byte(err.Error())) + "\"}")
				} else {
					response = []byte("{\"smtp_response\": \"" + base64.StdEncoding.EncodeToString([]byte("email received by SMTP server with reply code: " + strconv.Itoa(return_code) + ".")) + "\"}")
					//fmt.Println(email)
					//fmt.Println(string(email))
				}

			}

			response_headers = bytes.Join([][]byte{response_headers, []byte("Content-Length: " + strconv.Itoa(len(response)) + "\r\n")}, nil)
			conn.Write([]byte("HTTP/1.1 200\r\n"))
			conn.Write(response_headers)
			conn.Write([]byte("\r\n"))

			// write JSON response with SMTP server response
			conn.Write(response)

		}

	}

	conn.Close()

}
