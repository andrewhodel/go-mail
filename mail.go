/*
Copyright 2023 Andrew Hodel
	andrew@xyzbots.com, andrewhodel@gmail.com, andrew@ispapp.co

LICENSE MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package gomail

import (
	"crypto/rsa"
	"crypto/x509"
	"time"
	"encoding/pem"
	"crypto/sha256"
	"crypto/rand"
	"crypto/tls"
	"crypto"
	"hash"
	"errors"
	"context"
	"fmt"
	"net"
	"net/mail"
	"bytes"
	"strings"
	"strconv"
	"io"
	"encoding/base64"
	"mime/quotedprintable"
	"os"
	"github.com/andrewhodel/go-ip-ac"
)

type mail_from_func func(string, string, string, string, *bool) bool
type rcpt_to_func func(string, string, *bool) bool
type headers_func func(map[string]string, string, *bool) bool
type full_message_func func(*[]byte, *map[string]string, *[]map[string]string, *[][]byte, *bool, *string, *bool)
type pop3_auth_func func(string, string, string, string) bool
type pop3_stat_func func(string) (int, int)
type pop3_list_func func(string) (int, []int, []int)
type pop3_retr_func func(string, int) string
type pop3_dele_func func(string, int) (bool, string)
type imap4_auth_func func(string, string, string) (bool)
type imap4_list_func func(string, []string, string, string) ([]string)
type imap4_select_func func(string, string) (int, []string, int, int, int)
type imap4_fetch_func func(string, []string, []string) ([]Email)
type imap4_store_func func(string, string, string, string, string) (bool)
type imap4_close_func func(string) (bool)
type imap4_search_func func(string, string) (string)

type Config struct {
	SmtpTLSPorts			[]int64	`json:"smtpTLSPorts"`
	SmtpNonTLSPorts			[]int64	`json:"smtpNonTLSPorts"`
	SmtpMaxEmailSize		uint64	`json:"smtpMaxEmailSize"`
	Imap4Port			int64	`json:"imap4Port"`
	Pop3Port			int64	`json:"pop3Port"`
	SslKey				string	`json:"sslKey"`
	SslCert				string	`json:"sslCert"`
	SslCa				string	`json:"sslCa"`
	LoadCertificatesFromFiles	bool	`json:"loadCertificatesFromFiles"`
	Fqdn				string	`json:"fqdn"`
}

type Email struct {
	Uid				int
	InternalDate			time.Time
	Flags				[]string
	Body				[]byte
	Headers				map[string]string
	Rfc822Size			int
	Mailbox				string
}

type OutboundMail struct {
	SendingHost			string
	Username			string
	Password			string
	ReceivingHostTlsConfig		*tls.Config
	ReceivingHost			string
	Port				int
	From				mail.Address
	To				[]mail.Address
	Cc				[]mail.Address
	Bcc				[]mail.Address
	Subj				string
	Body				[]byte
	DkimPrivateKey			[]byte
	DkimDomain			string
	DkimSigningAlgo			string
	DkimExpireSeconds		int
	Headers				map[string]string
	FirstSendFailure		time.Time
}

type Esmtp struct {
	Name				string
	Parts				[]string

}

func ParseTags(b []byte) (map[string]string, []string) {

	// converts "   a=asdf;  b=afsdf" to
	// v["a"] = "asdf"
	// v["b"] = "afsdf"

	// all the values, out of order
	var tags = make(map[string]string, 0)
	// the order of the tags
	var order = make([]string, 0)

	var tag_found = false
	var tag []byte
	var value []byte
	i := 0
	for {

		if (i == len(b)) {
			break
		}

		if (tag_found == true) {

			// add to the value

			if (b[i] == ';' || i == len(b)-1) {
				// value end or end of data found

				if (b[i] != ';') {
					// last character is part of the value
					value = append(value, b[i])
				}

				//fmt.Println("tag", string(tag), string(value))

				// add the tag to tags
				tags[string(tag)] = string(value)
				order = append(order, string(tag))

				tag_found = false
				tag = nil
				value = nil
				i = i + 1
				continue
			} else {
				value = append(value, b[i])
			}

		} else {

			// add to the tag

			if (b[i] == '=') {
				// separator found
				tag_found = true
				i = i + 1
				continue
			} else {
				// do not add tabs or spaces in the tag name
				if (b[i] != 9 && b[i] != ' ') {
					tag = append(tag, b[i])
				}
			}

		}

		i = i + 1

	}

	return tags, order

}

// execute and respond to a command
func smtpExecCmd(ip_ac ipac.Ipac, using_tls bool, conn net.Conn, tls_config tls.Config, config Config, c []byte, auth_login *string, auth_password *string, login_status *int, authed *bool, esmtp_authed *bool, mail_from *string, to_address *string, parse_data *bool, sent_cmds *int, login *[]byte, ip string, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) {

	//fmt.Printf("smtp smtpExecCmd: %s\n", c)

	if (!*authed) {
		*sent_cmds += 1
	}

	if (*login_status == 1) {

		// decode base64 encoded password
		dec, dec_err := base64.StdEncoding.DecodeString(string(c))

		if (dec_err == nil) {

			// split the parts by a null character
			var null_delimited_parts = bytes.Split(dec, []byte{0})

			if (len(null_delimited_parts) == 1) {
				*auth_password = string(dec)
			} else if (len(null_delimited_parts) == 2) {
				*auth_login = string(null_delimited_parts[0])
				*auth_password = string(null_delimited_parts[1])
			} else if (len(null_delimited_parts) == 3) {
				*auth_login = string(null_delimited_parts[0])
				*auth_password = string(null_delimited_parts[2])
			}

		}

		// set login_status to 0
		*login_status = 0

		// send a 235 response
		conn.Write([]byte("235\r\n"))

	} else if (bytes.Index(c, []byte("STARTTLS")) == 0 && using_tls == false) {

		conn.Write([]byte("220 Ready to start TLS\r\n"))

		// upgrade to TLS
		var tlsConn *tls.Conn
		tlsConn = tls.Server(conn, &tls_config)
		// run a handshake
		tlsConn.Handshake()
		// convert tlsConn to a net.Conn type
		conn = net.Conn(tlsConn)

		//fmt.Println("upgraded to TLS with STARTTLS")

		// the upgraded conn object is only available in the local scope
		// start a new smtpHandleClient in the existing go subroutine
		smtpHandleClient(ip_ac, false, true, conn, tls_config, ip, config, mail_from_func, rcpt_to_func, headers_func, full_message_func)

	} else if (bytes.Index(c, []byte("EHLO")) == 0 || bytes.Index(c, []byte("HELO")) == 0) {

		//fmt.Printf("EHLO command\n")

		// respond with 250-
		// supported SMTP extensions
		conn.Write([]byte("250-" + config.Fqdn + "\r\n"))
		conn.Write([]byte("250-SIZE 14680064\r\n"))
		conn.Write([]byte("250-8BITMIME\r\n"))
		conn.Write([]byte("250-AUTH PLAIN\r\n"))

		if (using_tls == false) {
			// start tls
			conn.Write([]byte("250-STARTTLS\r\n"))
		}

		conn.Write([]byte("250-ENHANCEDSTATUSCODES\r\n"))
		conn.Write([]byte("250-PIPELINING\r\n"))
		//conn.Write([]byte("250-CHUNKING\r\n")) // this is BDAT CHUNKING, the BDAT command must be supported
		conn.Write([]byte("250-SMTPUTF8\r\n"))

		// respond without the - to request the next command
		conn.Write([]byte("250\r\n"))

	} else if (bytes.Index(c, []byte("AUTH PLAIN")) == 0) {

		var auth_parts = bytes.Split(c, []byte(" "))

		if (len(auth_parts) == 3) {

			// password sent in this command as the third parameter

			// decode the base64 password
			dec, dec_err := base64.StdEncoding.DecodeString(string(auth_parts[2]))

			if (dec_err == nil) {

				// split the parts by a null character
				var null_delimited_parts = bytes.Split(dec, []byte{0})

				if (len(null_delimited_parts) == 1) {
					*auth_password = string(dec)
				} else if (len(null_delimited_parts) == 2) {
					*auth_login = string(null_delimited_parts[0])
					*auth_password = string(null_delimited_parts[1])
				} else if (len(null_delimited_parts) == 3) {
					*auth_login = string(null_delimited_parts[0])
					*auth_password = string(null_delimited_parts[2])
				}

			}

			// respond with 235
			conn.Write([]byte("235\r\n"))

		} else {

			// password sent as next command (on next line)

			// set login_status to 1 to parse that next line
			*login_status = 1

			// respond with 334
			conn.Write([]byte("334\r\n"))

		}

	} else if (bytes.Index(c, []byte("MAIL FROM:")) == 0) {

		//fmt.Printf("MAIL FROM command\n")

		i1 := bytes.Index(c, []byte("<"))
		i2 := bytes.Index(c, []byte(">"))
		s := make([]byte, 0)
		if (i1 > -1 && i2 > -1) {
			s = c[i1+1:i2]
		}

		//fmt.Printf("send address (between %d and %d): %s\n", i1, i2, s)

		*mail_from = string(s)

		var mail_from_authed = mail_from_func(string(s), ip, *auth_login, *auth_password, esmtp_authed)

		if (mail_from_authed == false) {

			// invalid auth
			ipac.ModifyAuth(&ip_ac, 1, ip)

			// return 221
			conn.Write([]byte("221 not authorized\r\n"))
			conn.Close()
		} else {
			conn.Write([]byte("250 AUTH\r\n"))
			//conn.Write([]byte("250 OK\r\n"))
		}

	} else if (bytes.Index(c, []byte("RCPT TO:")) == 0) {

		//fmt.Printf("RCPT TO:\n")

		i1 := bytes.Index(c, []byte("<"))
		i2 := bytes.Index(c, []byte(">"))
		s := make([]byte, 0)
		if (i1 > -1 && i2 > -1) {
			//fmt.Printf("found < and > in: '%s'\n", c)
			s = c[i1+1:i2]
		}

		_ = s

		//fmt.Printf("rcpt address (between %d and %d): %s\n", i1, i2, s)

		*to_address = string(s)

		*authed = rcpt_to_func(string(s), ip, esmtp_authed)

		if (*authed == true) {
			conn.Write([]byte("250 OK\r\n"))
		} else {

			// invalid auth
			ipac.ModifyAuth(&ip_ac, 1, ip)

			// 221 <domain>
			// service closing transmission channel
			conn.Write([]byte("221 not authorized\r\n"))
			conn.Close()
		}

	} else if (bytes.Index(c, []byte("DATA")) == 0) {

		//fmt.Printf("DATA command\n")

		if (*authed) {

			// valid auth
			ipac.ModifyAuth(&ip_ac, 2, ip)

			*parse_data = true
			conn.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
			//fmt.Println("DATA received, replied with 354")
		} else {

			// invalid auth
			ipac.ModifyAuth(&ip_ac, 1, ip)

			// 221 <domain>
			// service closing transmission channel
			conn.Write([]byte("221 not authorized\r\n"))
			conn.Close()
		}

	} else if (bytes.Index(c, []byte("RSET")) == 0) {

		//fmt.Printf("RSET command\n")

		conn.Write([]byte("250 OK\r\n"))

		//fmt.Println("RSET received, replied with 250")

	} else if (bytes.Index(c, []byte("QUIT")) == 0) {

		//fmt.Printf("QUIT command\n")

		conn.Write([]byte("221 Bye\r\n"))
		conn.Close()

	} else {

		// 502 command not implemented
		conn.Write([]byte("502\r\n"))

	}

}

func smtpHandleClient(ip_ac ipac.Ipac, is_new bool, using_tls bool, conn net.Conn, tls_config tls.Config, ip string, config Config, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) {

	//fmt.Printf("new SMTP connection from %s\n", ip)

	if (is_new == true) {
		conn.Write([]byte("220 " + config.Fqdn + " go-mail\r\n"))
	}

	authed := false
	esmtp_authed := false
	auth_login := ""
	auth_password := ""
	login_status := 0

	parse_data := false

	mail_from := ""
	to_address := ""

	login := make([]byte, 0)
	var parts_headers = make([]map[string]string, 0)
	var parts = make([][]byte, 0)

	sent_cmds := 0
	sent_bytes := 0

	smtp_data := make([]byte, 0)
	last_parse_data_block_position := 0

	for {

		if (authed == false && sent_cmds > 3) {
			// should be authorized
			conn.Write([]byte("221 unauthenticated send limit exceeded\r\n"))
			conn.Close()
			break
		}

		if (authed == false && sent_bytes > 400) {
			// disconnect unauthed connections that have sent more than N bytes
			conn.Write([]byte("221 unauthenticated send limit exceeded\r\n"))
			conn.Close()
			break
		}

		buf := make([]byte, 1400)
		n, err := conn.Read(buf)
		sent_bytes += n
		if err != nil {
			//fmt.Printf("server: conn: read: %s\n", err)
			// close connection
			conn.Close()
			break
		}

		//fmt.Printf("smtp read length: %d\n", n)
		//fmt.Print(string(buf))

		// set buf to read length
		buf = buf[:n]

		// add buf to smtp_data
		for l := range buf {
			smtp_data = append(smtp_data, buf[l])
		}

		if (uint64(len(smtp_data)) > config.SmtpMaxEmailSize) {
			//fmt.Println("smtp data too big from ", ip)
			conn.Write([]byte("221 send limit exceeded\r\n"))
			conn.Close()
			break
		}

		if (parse_data == false) {

			if (bytes.Index(smtp_data, []byte("\r\n")) == -1) {
				// not a valid command
				//fmt.Println("no valid command, waiting for more data")
				continue
			}

			// commands end with \r\n and can be at most 512 bytes
			// remove each and send to smtpExecCmd()
			var s = bytes.Split(smtp_data, []byte("\r\n"))

			for r := range s {

				if (parse_data == true) {
					// time to parse the data
					break
				}

				var line = s[r]

				if (len(line) > 0) {
					// do not send an empty line to smtpExecCmd()
					smtpExecCmd(ip_ac, using_tls, conn, tls_config, config, line, &auth_login, &auth_password, &login_status, &authed, &esmtp_authed, &mail_from, &to_address, &parse_data, &sent_cmds, &login, ip, mail_from_func, rcpt_to_func, headers_func, full_message_func)
				}

				if (len(smtp_data) + 2 >= len(line) && len(smtp_data) >= 2 && len(line) + 2 <= len(smtp_data)) {
					// remove the line from smtp_data
					smtp_data = smtp_data[len(line) + 2:len(smtp_data)]
				}

			}

		}

		if (parse_data == true) {
			// connection has already been authenticated
			// this is data sent after the client sends DATA and the server responds with 354

			// to make fast modifications
			// instead of iterating through 500MB of data each time 1400 bytes is added
			var lp_start = last_parse_data_block_position - 10

			if (lp_start < 0) {
				// the start position is 0 at least
				lp_start = 0
			}

			smtp_data_edit_block := smtp_data[lp_start:len(smtp_data)]

			// RFC-5321 section 4.5.2. Transparency
			// Before sending a line of mail text, the SMTP client checks the first character of the line. If it is a period, one additional period is inserted at the beginning of the line.
			smtp_data_edit_block = bytes.ReplaceAll(smtp_data_edit_block, []byte("\r\n.."), []byte("\r\n."))

			smtp_data = smtp_data[0:lp_start]
			for db := range(smtp_data_edit_block) {
				smtp_data = append(smtp_data, smtp_data_edit_block[db])
			}

			// gather data until <CR><LF>.<CR><LF>
			// indicating the end of this email (body, attachments and anything else received already)
			data_block_end := bytes.Index(smtp_data_edit_block, []byte("\r\n.\r\n"))
			if (data_block_end > -1) {
				// if the data_block_end was found, set the offset position
				data_block_end += lp_start
			}
			//fmt.Println("data_block_end", data_block_end)

			// keep track of the previous/last position in smtp_data
			last_parse_data_block_position = len(smtp_data)-1

			if (data_block_end > -1) {
				// this is the end of all the DATA

				//fmt.Printf("smtp parse_data: (%d)\n######\n%s\n######\n", len(smtp_data), smtp_data[0:data_block_end])
				//fmt.Printf("<CR><LF>.<CR><LF> found at: %d of %d\n", data_block_end, len(smtp_data))

				// validate DKIM without the \r\n.\r\n
				smtp_data = smtp_data[0:data_block_end]

				boundary := ""

				// parse the headers
				headers := make(map[string]string)
				// keep an ordered list also
				real_headers := make([]string, 0)
				var headers_sent = false

				// decode quoted-printable body parts
				var decode_qp = false

				// limit the number of DKIM lookups
				var dkim_lookups = 0
				var validate_dkim = false
				var dkim_public_key = ""
				var dkim_valid = false
				var dkim_done = false
				var dkim_hp map[string]string

				v := make([]byte, 0)
				i := -1
				for {

					i = i + 1

					if (i >= len(smtp_data)) {
						break
					}

					//fmt.Printf("i=%d, c=%c\n", i, smtp_data[i])

					if (smtp_data[i] == []byte("\n")[0] && smtp_data[i-1] == []byte("\r")[0]) {

						// this is at \r\n
						// remove the \r from v
						v = v[:len(v)-1]

						//fmt.Println("LINE:", len(v), string(v))

						if (len(v) == 0) {

							// empty line indicates body or new block start

							if (headers_sent == false) {
								// send the headers for validation
								authed = headers_func(headers, ip, &esmtp_authed)

								if (authed == false) {
									conn.Write([]byte("221 not authorized\r\n"))
									conn.Close()
									return
								}

								// only send them once
								headers_sent = true
							}

							//fmt.Printf("email body or new block start at %d\n", i)

							// skip the newline
							i = i + 1

							if (validate_dkim == true && dkim_done == false) {

								// this needs to happen once the email is fully processed and only once
								// the email is in smtp_data
								dkim_done = true

								//fmt.Println("DKIM signing algorithm:", dkim_hp["a"])

								var dkim_expired = false
								if (dkim_hp["x"] != "") {
									// make sure header is not expired
									i, err := strconv.ParseInt(dkim_hp["x"], 10, 64)
									if err != nil {
										// invalid data in x tag
										dkim_expired = true
									} else {
										expire_time := time.Unix(i, 0)
										if (expire_time.Unix() < time.Now().Unix()) {
											dkim_expired = true
										}
									}
								}

								//fmt.Println("dkim_expired", dkim_expired)

								// the domain in the from header
								var valid_domain_1 = ""

								var d1p = strings.Split(headers["from"], "@")
								if (len(d1p) == 2) {
									valid_domain_1 = strings.TrimRight(d1p[1], ">")
								}

								// the domain in the MAIL FROM command
								var valid_domain_2 = ""

								var d2p = strings.Split(mail_from, "@")
								if (len(d2p) == 2) {
									valid_domain_2 = d2p[1]
								}

								if (dkim_expired == true) {
									//fmt.Println("DKIM header is expired")
									headers["dkim-validation-errors"] = headers["dkim-validation-errors"] + "(header is expired)"
								} else if (dkim_hp["a"] != "rsa-sha256") {
									//fmt.Println("unsupported DKIM signing algorithm", dkim_hp["a"])
									headers["dkim-validation-errors"] = headers["dkim-validation-errors"] + "(unsupported signing algorithm)"

								} else {

									if (dkim_hp["d"] != valid_domain_1 && dkim_hp["d"] != valid_domain_2) {
										// the d= tag value (domain specified in the DKIM header) is not the same domain as the reply-to address
										//fmt.Println("DKIM d= domain", dkim_hp["d"], "does not match the from address", headers["from"], "or the MAIL FROM address", mail_from)
										headers["dkim-validation-warnings"] = headers["dkim-validation-warnings"] + "(d= domain does not match the from header domain or the SMTP MAIL FROM domain)"
									}

									// finish parsing the DKIM headers
									// replace whitespace in b= and bh=
									// space, tab, \r and \n
									dkim_hp["b"] = strings.ReplaceAll(dkim_hp["b"], " ", "")
									dkim_hp["b"] = strings.ReplaceAll(dkim_hp["b"], string(9), "")
									dkim_hp["b"] = strings.ReplaceAll(dkim_hp["b"], string(10), "")
									dkim_hp["b"] = strings.ReplaceAll(dkim_hp["b"], string(13), "")
									dkim_hp["bh"] = strings.ReplaceAll(dkim_hp["bh"], " ", "")
									dkim_hp["bh"] = strings.ReplaceAll(dkim_hp["bh"], string(9), "")
									dkim_hp["bh"] = strings.ReplaceAll(dkim_hp["bh"], string(10), "")
									dkim_hp["bh"] = strings.ReplaceAll(dkim_hp["bh"], string(13), "")

									// bh= is the body hash, if the l= field exists it specifies the length of the body that was hashed
									//fmt.Println("DKIM header bh=", dkim_hp["bh"])

									// make sure the bh tag from the DKIM headers is the same as the actual body hash (only the length specified if l= exists)

									/*
									rfc6376 - DKIM

									3.5.  The DKIM-Signature Header Field
									c= Message canonicalization (plain-text; OPTIONAL, default is
									"simple/simple").  This tag informs the Verifier of the type of
									canonicalization used to prepare the message for signing.  It
									consists of two names separated by a "slash" (%d47) character,
									corresponding to the header and body canonicalization algorithms,
									respectively.  These algorithms are described in Section 3.4.  If
									only one algorithm is named, that algorithm is used for the header
									and "simple" is used for the body.  For example, "c=relaxed" is
									treated the same as "c=relaxed/simple".

										In better explanation, `header_canon_algorith/body_canon_algorithm` with `simple/simple` being default
									*/

									var canon_algos = strings.Split(dkim_hp["c"], "/")
									if (len(canon_algos) == 0) {
										// is no algorithms are defined, use simple for the header and body
										canon_algos = append(canon_algos, "simple")
										canon_algos = append(canon_algos, "simple")
									} else if (len(canon_algos) == 1) {
										// if only one algorithm is defined, it is used for the header and simple is used for the body
										canon_algos = append(canon_algos, "simple")
									}

									var canonicalized_body []byte
									var canonicalized_body_hash_base64 string

									if (canon_algos[1] == "simple") {

										// simple body canonicalization

										/*
										3.4.3.  The "simple" Body Canonicalization Algorithm
										The "simple" body canonicalization algorithm ignores all empty lines
										at the end of the message body.  An empty line is a line of zero
										length after removal of the line terminator.  If there is no body or
										no trailing CRLF on the message body, a CRLF is added.  It makes no
										other changes to the message body.  In more formal terms, the
										"simple" body canonicalization algorithm converts "*CRLF" at the end
										of the body to a single "CRLF".

											remove all \r\n at the end then add \r\n (\r\n is CRLF)
										*/

										if (dkim_hp["l"] != "") {
											// length specified
											optional_body_length, optional_body_length_err := strconv.ParseInt(dkim_hp["l"], 10, 64)
											if (optional_body_length >= 0 && int(optional_body_length) <= data_block_end && optional_body_length_err == nil) {
												// valid length
												canonicalized_body = bytes.TrimRight(smtp_data[i:data_block_end], "\r\n")
											} else {
												// invalid optional body length
												// dkim will not validate unless the bh= tag hash was created with an empty canonicalized body
											}
										} else {
											// no length specified
											canonicalized_body = bytes.TrimRight(smtp_data[i:data_block_end], "\r\n")
										}

										canonicalized_body = append(canonicalized_body, '\r')
										canonicalized_body = append(canonicalized_body, '\n')

									} else if (canon_algos[1] == "relaxed") {

										// relaxed body canonicalization

										/*
										3.4.4.  The "relaxed" Body Canonicalization Algorithm

										   The "relaxed" body canonicalization algorithm MUST apply the
										   following steps (a) and (b) in order:

										   a.  Reduce whitespace:

										       *  Ignore all whitespace at the end of lines.  Implementations
											  MUST NOT remove the CRLF at the end of the line.

										       *  Reduce all sequences of WSP within a line to a single SP
											  character.

										   b.  Ignore all empty lines at the end of the message body.  "Empty
										       line" is defined in Section 3.4.3.  If the body is non-empty but
										       does not end with a CRLF, a CRLF is added.  (For email, this is
										       only possible when using extensions to SMTP or non-SMTP transport
										       mechanisms.)

										*/

										canonicalized_body = smtp_data[i:data_block_end]

										// remove whitespace at the end of lines
										for true {
											if (bytes.Index(canonicalized_body, []byte("\t\r\n")) > -1) {
												// replace trn with rn
												canonicalized_body = bytes.Replace(canonicalized_body, []byte("\t\r\n"), []byte("\r\n"), 1)
											} else if (bytes.Index(canonicalized_body, []byte(" \r\n")) > -1) {
												// replace nrn with rn
												canonicalized_body = bytes.Replace(canonicalized_body, []byte(" \r\n"), []byte("\r\n"), 1)
											} else {
												break
											}
										}

										// replace wsp sequences with a single space
										for true {
											if (bytes.Index(canonicalized_body, []byte("\t")) > -1) {
												// replace all \t with space
												canonicalized_body = bytes.ReplaceAll(canonicalized_body, []byte("\t"), []byte(" "))
											} else if (bytes.Index(canonicalized_body, []byte("  ")) > -1) {
												// replace "  " with space
												canonicalized_body = bytes.Replace(canonicalized_body, []byte("  "), []byte(" "), 1)
											} else {
												// no more wsp characters
												break
											}
										}

										// 3.4.4 step b
										if (len(canonicalized_body) > 0) {
											// the body is non-empty
											if (len(canonicalized_body) >= 2) {
												if (canonicalized_body[len(canonicalized_body)-2] != '\r' && canonicalized_body[len(canonicalized_body)-1] != '\n') {
													// the body does not end with a CRLF
													// add a CRLF
													canonicalized_body = append(canonicalized_body, '\r')
													canonicalized_body = append(canonicalized_body, '\n')

												}
											} else {
												// the body is not long enough to end with a CRLF
												// add a CRLF
												canonicalized_body = append(canonicalized_body, '\r')
												canonicalized_body = append(canonicalized_body, '\n')
											}
										}

									}

									// get the checksum from the canonicalized body
									var canonicalized_body_sha256_sum = sha256.Sum256(canonicalized_body)
									// convert [32]byte to []byte
									var formatted_canonicalized_body_sha256_sum []byte
									for b := range canonicalized_body_sha256_sum {
										formatted_canonicalized_body_sha256_sum = append(formatted_canonicalized_body_sha256_sum, canonicalized_body_sha256_sum[b])
									}

									// as base64
									canonicalized_body_hash_base64 = base64.StdEncoding.EncodeToString(formatted_canonicalized_body_sha256_sum)

									if (canonicalized_body_hash_base64 != dkim_hp["bh"]) {

										/*
										fmt.Println("DKIM canonicalized_body_hash_base64 does not equal the bh= tag value")
										fmt.Println("canonicalization algorithms", canon_algos)
										fmt.Println("bh=", dkim_hp["bh"])
										fmt.Println("canonicalized_body_hash_base64", canonicalized_body_hash_base64)
										*/

										headers["dkim-validation-errors"] = headers["dkim-validation-errors"] + "(canonicalized body hash encoded as base64 does not equal the bh= tag value)"

									} else {

										// body hash in the headers is the same as the calculated body hash
										// valid

										//fmt.Println("DKIM bh= tag matches hash of body content with length optionally specified by l= tag")

										// the DKIM public key of the sending domain is in dkim_public_key

										// b= is the signature of the headers and body
										//fmt.Println("signature base64 b=", dkim_hp["b"])

										// get the public key as an x509 object
										var dkim_public_x509_key rsa.PublicKey
										un64, un64_err := base64.StdEncoding.DecodeString(dkim_public_key)
										if (un64_err == nil) {
											pk, pk_err := x509.ParsePKIXPublicKey(un64)
											if (pk_err == nil) {
												if pk, ok := pk.(*rsa.PublicKey); ok {
													dkim_public_x509_key = *pk
												}
											}
										}

										//fmt.Println("dkim_public_x509_key", dkim_public_x509_key)

										// create the canonicalized header string based on the field specified in the h= tag
										// remove spaces from each field
										dkim_hp["h"] = strings.ReplaceAll(dkim_hp["h"], " ", "")
										// lowercase all field names
										dkim_hp["h"] = strings.ToLower(dkim_hp["h"])
										var canon_h = strings.Split(dkim_hp["h"], ":")

										// remove duplicates
										var d = 0
										for {

											if (d >= len(canon_h)) {
												// last entry
												break
											}

											for dd := len(canon_h)-1; dd >= 0; dd-- {
												if (canon_h[dd] == canon_h[d] && dd != d) {
													// remove duplicate value
													//fmt.Println("remove duplicate", dd, canon_h[dd])
													copy(canon_h[dd:], canon_h[dd+1:])
													canon_h = canon_h[:len(canon_h)-1]
												}
											}

											d += 1

										}

										//fmt.Println("header fields to be canonicalized", canon_h)

										var canonicalized_header_string = ""

										if (canon_algos[0] == "simple") {

											// simple header canonicalization

										} else if (canon_algos[0] == "relaxed") {

											// relaxed header canonicalization

											for h := range canon_h {

												var h_name = canon_h[h]
												//fmt.Println("h_name", h_name)

												var is_real = false
												for r := range real_headers {
													if (real_headers[r] == h_name) {
														is_real = true
														break
													}
												}

												if (is_real == true) {
													// add each header specified in the h= tag with the valid format
													// lowercase key values and no spaces on either side of :
													canonicalized_header_string = canonicalized_header_string + h_name + ":" + headers[h_name] + "\r\n"
												}
											}

											//fmt.Println("\n\ncanonicalized_header_string", canonicalized_header_string)

											// add the DKIM header that was used
											// with no newlines, an empty b= tag and a space for each wsp sequence
											// in the original header's order
											dkim_tags, dkim_order := ParseTags([]byte(headers["dkim-signature"]))
											var canonicalized_dkim_header_string = ""

											for dh := range dkim_order {
												var tag_name = dkim_order[dh]
												if (tag_name != "b") {
													canonicalized_dkim_header_string = canonicalized_dkim_header_string + tag_name + "=" + dkim_tags[tag_name] + "; "
												}
											}

											// add the empty b= at the end with no ; at the end
											canonicalized_dkim_header_string = canonicalized_dkim_header_string + "b=";

											canonicalized_header_string = canonicalized_header_string + "dkim-signature:" + canonicalized_dkim_header_string

										}

										//fmt.Println("canonicalized_header_string", []byte(canonicalized_header_string))
										//fmt.Println("canonicalized_header_string", canonicalized_header_string)

										// verify the signature
										var h1 hash.Hash
										var h2 crypto.Hash
										h1 = sha256.New()
										h2 = crypto.SHA256

										h1.Write([]byte(canonicalized_header_string))
										sig, sig_err := base64.StdEncoding.DecodeString(dkim_hp["b"])
										if (sig_err == nil) {
											if (rsa.VerifyPKCS1v15(&dkim_public_x509_key, h2, h1.Sum(nil), sig) == nil) {

												// the dkim data is valid
												dkim_valid = true

											} else {
												headers["dkim-validation-errors"] = headers["dkim-validation-errors"] + "(canonicalized headers hash did not equal the b= tag signature decoded from base64 using rsa.VerifyPKCS1v15())"
											}
										}

									}

								}

							}

							var nb = make([]byte, 0)
							nb_headers := make(map[string]string)

							var boundary_len = len("--" + boundary)

							if (string(smtp_data[i:i + boundary_len]) == "--" + boundary) {

								// there is a boundary, parse the new block headers
								//fmt.Println("boundary found in email body, parsing new block")

								// parse until next boundary
								var nb_size = 0
								for {

									if (i >= len(smtp_data)) {
										break
									}

									nb = append(nb, smtp_data[i])

									// find next boundary
									//if (bytes.Contains(nb, []byte("--" + boundary))) {
									// same thing but faster
									if (len(nb) >= 2+2+len(boundary)) {
										if (bytes.Compare(nb[len(nb)-2-2-len(boundary):len(nb)], []byte("\r\n--" + boundary)) == 0) {
											// set where to start processing after this nb
											i = i - (2 + 2 + len(boundary))
											// remove the boundary string from nb
											nb = nb[0:len(nb) - (2 + 2 + len(boundary))]
											break
										}
									}

									i = i + 1
									nb_size = nb_size + 1

								}

								//fmt.Println("nb_size", nb_size, "boundary_len", boundary_len)

								if (nb_size == boundary_len + 7) {
									// nb == --boundary--\r\n.\r\n
									// and is empty
									//fmt.Println("empty block")
									break
								}

								// get the headers from this nb
								vv := make([]byte, 0)
								last_header_end_pos := 0
								for l := range nb {
									vv = append(vv, nb[l])

									//fmt.Printf("l: %d c: %c\n", l, nb[l])

									if (len(vv) > 3) {

										if (nb[l] == []byte("\n")[0] && nb[l-1] == []byte("\r")[0] && nb[l+1] == []byte("\r")[0] && nb[l+2] == []byte("\n")[0]) {

											//fmt.Printf("last header found: %s\n", vv)
											ss := bytes.Split(vv, []byte(":"))
											for ssc := range ss {
												// trim spaces
												ss[ssc] = bytes.Trim(ss[ssc], " ")
											}

											if (len(ss) > 1) {

												// remove any newlines from ss[1]
												ss[1] = bytes.ReplaceAll(ss[1], []byte("\r"), []byte(""))
												ss[1] = bytes.ReplaceAll(ss[1], []byte("\n"), []byte(""))

												// add header
												nb_headers[string(bytes.ToLower(ss[0]))] = string(bytes.ToLower(ss[1]))

												last_header_end_pos = l + 3

											}

											// the headers ended
											//fmt.Printf("\\r\\n\\r\\n END OF NB HEADERS, %d total.\n", len(nb_headers))

											break
										} else if (nb[l] == []byte("\n")[0] && nb[l-1] == []byte("\r")[0]) {

											ml := false
											if (len(nb) > l + 1) {
												// check for multiline header
												if (nb[l+1] == []byte(" ")[0] || nb[l+1] == []byte("\t")[0]) {
													//fmt.Printf("multiline header found\n")
													ml = true
												}
											}

											if (!ml) {

												//fmt.Printf("header found: %s\n", vv)
												ss := bytes.Split(vv, []byte(":"))
												for ssc := range ss {
													// trim spaces
													ss[ssc] = bytes.Trim(ss[ssc], " ")
												}

												if (len(ss) > 1) {

													// remove any newlines from ss[1]
													ss[1] = bytes.ReplaceAll(ss[1], []byte("\r"), []byte(""))
													ss[1] = bytes.ReplaceAll(ss[1], []byte("\n"), []byte(""))

													// add header
													nb_headers[string(bytes.ToLower(ss[0]))] = string(bytes.ToLower(ss[1]))

													last_header_end_pos = l + 3

												}

												// reset test string
												vv = make([]byte, 0)
											}

										}

									}

								}

								//fmt.Printf("nb_headers: %+v\n", nb_headers)
								//fmt.Printf("last_header_end_pos: %d\n", last_header_end_pos)

								// remove the headers from nb
								nb = nb[last_header_end_pos:len(nb)]

							} else {

								// there is only body content, add it to nb
								//fmt.Println("email body does not have boundaries")
								for {

									if (i >= len(smtp_data)) {
										break
									}

									nb = append(nb, smtp_data[i])

									i = i + 1

								}

								// remove the end of body text
								// if it was received
								if (len(nb) >= 3) {
									if (nb[len(nb)-3] == 46 && nb[len(nb)-2] == 13 && nb[len(nb)-1] == 10) {
										// last 3 characters exist and are
										// 46 13 10
										// . \r \n
										//fmt.Println(nb[len(nb)-3], nb[len(nb)-2], nb[len(nb)-1])
										nb = nb[:len(nb)-3]
									}
								}

							}

							//fmt.Printf("##NB##%s##ENDNB##\n", nb)

							// add each part and the nb_headers for each part
							parts_headers = append(parts_headers, nb_headers)

							if (decode_qp == true) {
								// decode quoted-printable data
								qp, qp_err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(nb)))
								if (qp_err == nil) {
									nb = qp
								}
							}

							parts = append(parts, nb)

							// reset v
							v = make([]byte, 0)
							continue

						} else if (string(v) == "--" + boundary + "--") {

							// RFC 1341 (a multipart RFC, none are defined in RFC 5321)
							// Because encapsulation boundaries must not appear in the body parts being encapsulated, a user agent must exercise care to choose a unique boundary.
							// The simplest boundary possible is something like "---", with a closing boundary of "-----".

							// also says:
							// Encapsulation boundaries must not appear within the encapsulations, and must be no longer than 70 characters, not counting the two leading hyphens.

							// that means the protocol is invalid, you can include every possible boundary of 68 characters in an email

							// RFC 5321 should require a content length header that is a utf8 string
							// lines in the data of an email are not required to be less than 512 bytes, only the commands are

							// final boundary reached
							// who names this an epilogue
							//fmt.Printf("final boundary reached at %d\n", i)
							break

						}

						if (len(smtp_data) > i+1) {
							// test if the next character is a space
							// indicating a continued header
							//fmt.Printf("next character after \r\n in this header: %s\n", smtp_data[i+1])
							if (smtp_data[i+1] == []byte(" ")[0] || smtp_data[i+1] == []byte("\t")[0]) {
								// continue adding to this header, without resetting v
								//fmt.Println("Header is continued on another line:", string(v))
								continue
							}
						}

						if (len(v) > 0) {
							// check if this line is a header
							//fmt.Println("testing if line is a header", string(v))

							ss := bytes.Split(v, []byte(":"))

							if (len(ss) > 1) {

								// ss[0] is the header name, store it in lowercase
								header_name := bytes.ToLower(ss[0])
								// remove all spaces
								header_name = bytes.Trim(header_name, " ")
								// remove the header name from the ss slice
								ss = ss[1:len(ss)]

								// put all the rest of the parts back together for the header value
								header_value := bytes.Join(ss, []byte(":"))

								// if part of the header_value is 8 spaces or a tab, remove that
								if (bytes.Index(header_value, []byte("        ")) > -1) {
									header_value = bytes.ReplaceAll(header_value, []byte("        "), []byte(""))
								} else if (bytes.Index(header_value, []byte("\t")) > -1) {
									header_value = bytes.ReplaceAll(header_value, []byte("\t"), []byte(""))
								}

								// if the first character is a space, remove that
								header_value = bytes.TrimLeft(header_value, " ")

								//fmt.Printf("smtp data header: %s: %s\n", header_name, header_value)

								// add header if not DKIM
								if (string(header_name) != "dkim-signature") {
									headers[string(header_name)] = string(header_value)
									real_headers = append(real_headers, string(header_name))
								}

								if (string(header_name) == "content-type") {
									// add boundary from content-type

									// find the string boundary in lower case, because it may be spelled bOUndary or any other way
									bb := bytes.Index(bytes.ToLower(header_value), []byte("boundary=\""))

									//fmt.Printf("boundary=\" found at: %d in: %s\n", bb, header_value)

									if (bb > -1) {
										// set boundary to the original header value because that's what is in the email body
										bbb := header_value[bb + len("boundary=\""):len(header_value)]
										boundary = string(bytes.Trim(bbb, "\""))
										//fmt.Printf("boundary: %s\n", boundary)
									}

								} else if (string(header_name) == "content-transfer-encoding" && string(bytes.ToLower(header_value)) == "quoted-printable") {
									// if content-transfer-encoding is quoted-printable
									// lines ending with =\r\n need to remove =\r\n
									//fmt.Println("decoding content-transfer-encoding", string(header_value))
									decode_qp = true
								} else if (string(header_name) == "dkim-signature" && dkim_lookups <= 3 && dkim_public_key == "") {

									// the dkim_public_key has not been found yet

									// only allow 3 DKIM lookups to prevent a sending client from making the server perform many DNS requests
									//fmt.Println("\nDKIM Validation")

									// validate DKIM using the 6 required fields
									// v, a, d, s, bh, b
									// and possibly the optional field
									// l
									temp, _ := ParseTags(header_value)
									dkim_hp = temp

									if (dkim_hp["v"] == "" || dkim_hp["a"] == "" || dkim_hp["d"] == "" || dkim_hp["s"] == "" || dkim_hp["bh"] == "" || dkim_hp["b"] == "") {
										//fmt.Println("incomplete dkim header")
									} else {

										// required DKIM header tags
										// v= is the version
										// a= is the signing algorithm
										// d= is the domain
										// s= is the selector (subdomain)

										// get the DKIM public key from DNS
										// it should be looked up from many physical locations on the planet
										// and they should all be the same or DKIM is invalid (smtp TLS validation from server to client per client TLS domain is not in SMTP, TLS validation of the from domain would make SMTP perfect.  TLS validation of the MAIL FROM sender would make SMTP better.)
										// make a TXT dns query to selector._domainkey.domain to get the key
										var query_domain = dkim_hp["s"] + "._domainkey." + dkim_hp["d"]
										//fmt.Println("DKIM DNS Query TXT:", query_domain)

										// keep track of the number of dkim lookups
										dkim_lookups = dkim_lookups + 1

										l_txts, l_err := net.LookupTXT(query_domain)
										if (l_err == nil) {

											for t := range l_txts {
												// get the last non empty p= value in the string results
												pp, _ := ParseTags([]byte(l_txts[t]))
												if (pp["p"] != "") {
													dkim_public_key = pp["p"]
												}
											}

											//fmt.Println("TXT Response base64 p=", dkim_public_key)
											validate_dkim = true

											// add the dkim-signature header that was used to headers
											headers[string(header_name)] = string(header_value)
											real_headers = append(real_headers, string(header_name))

										} else {
											headers["dkim-validation-errors"] = headers["dkim-validation-errors"] + "(DNS TXT record not found " + query_domain + ")"
										}

									}

								}

							}

						}

						v = make([]byte, 0)
						continue
					}

					v = append(v, smtp_data[i])

				}

				// set parse_data back to false
				parse_data = false

				// write 250 OK
				conn.Write([]byte("250 OK\r\n"))

				// now the client may send another email or disconnect

				// add the end of transmission sequence that was removed back to smtp_data
				// []byte("\r\n.\r\n"))
				smtp_data = append(smtp_data, '\r')
				smtp_data = append(smtp_data, '\n')
				smtp_data = append(smtp_data, '.')
				smtp_data = append(smtp_data, '\r')
				smtp_data = append(smtp_data, '\n')

				// full email received
				// none of the data passed in the pointers should be accessed after this
				// because it is sent in a pointer to a user level closure of a module
				full_message_func(&smtp_data, &headers, &parts_headers, &parts, &dkim_valid, &ip, &esmtp_authed)

				// reset values
				smtp_data = nil
				last_parse_data_block_position = 0

			}

		}

	}

	//fmt.Println("server: conn: closed\n")

}

func smtpListenNoEncrypt(ip_ac ipac.Ipac, lport int64, config Config, tls_config tls.Config, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) {

	ln, err := net.Listen("tcp", ":" + strconv.FormatInt(lport, 10))
	if err != nil {
		// handle error
		fmt.Printf("server: listen: %s\n", err)
		os.Exit(1)
	}

	fmt.Print("SMTP (RFC 5321 plus ESMTP extensions) listening on port " + strconv.FormatInt(lport, 10) + " with STARTTLS\n")

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

		//fmt.Printf("smtp server: accepted connection from %s on port %d\n", ip, lport)

		go smtpHandleClient(ip_ac, true, false, conn, tls_config, ip, config, mail_from_func, rcpt_to_func, headers_func, full_message_func)

	}

}

func smtpListenTLS(ip_ac ipac.Ipac, lport int64, config Config, tls_config tls.Config, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) {

	service := ":" + strconv.FormatInt(lport, 10)
	listener, err := tls.Listen("tcp", service, &tls_config)

	if err != nil {
		fmt.Printf("server: listen: %s\n", err)
		os.Exit(1)
	}

	fmt.Print("SMTP (RFC 5321 plus ESMTP extensions with RFC 8314) listening on port " + strconv.FormatInt(lport, 10) + " with TLS\n")

	for {

		conn, err := listener.Accept()
		if err != nil {
			// error with socket
			//fmt.Printf("smtp server socket error: : %s\n", err)
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

		//fmt.Printf("smtp server: accepted connection from %s on port %d\n", ip, lport)

		go smtpHandleClient(ip_ac, true, true, conn, tls_config, ip, config, mail_from_func, rcpt_to_func, headers_func, full_message_func)

	}

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

func SmtpServer(ip_ac ipac.Ipac, config Config, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) {

	var cert tls.Certificate
	var err error
	var rootca []byte
	if (config.LoadCertificatesFromFiles == true) {
		cert, err = tls.LoadX509KeyPair(config.SslCert, config.SslKey)
		rootca, _ = os.ReadFile(config.SslCa)
	} else {
		cert, err = tls.X509KeyPair([]byte(config.SslCert), []byte(config.SslKey))
		rootca = []byte(config.SslCa)
	}

	if err != nil {
		fmt.Printf("SMTP server did not load TLS certificates: %s\n", err)
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

	for p := range config.SmtpNonTLSPorts {
		// start a server without TLS on every defined non TLS port
		go smtpListenNoEncrypt(ip_ac, config.SmtpNonTLSPorts[p], config, tls_config, mail_from_func, rcpt_to_func, headers_func, full_message_func)
	}
	for p := range config.SmtpTLSPorts {
		// start a server with TLS on every defined TLS port
		go smtpListenTLS(ip_ac, config.SmtpTLSPorts[p], config, tls_config, mail_from_func, rcpt_to_func, headers_func, full_message_func)
	}

}

func Pop3Server(config Config, ip_ac ipac.Ipac, pop3_auth_func pop3_auth_func, pop3_stat_func pop3_stat_func, pop3_list_func pop3_list_func, pop3_retr_func pop3_retr_func, pop3_dele_func pop3_dele_func) {

	var cert tls.Certificate
	var err error
	var rootca []byte
	if (config.LoadCertificatesFromFiles == true) {
		cert, err = tls.LoadX509KeyPair(config.SslCert, config.SslKey)
		rootca, _ = os.ReadFile(config.SslCa)
	} else {
		cert, err = tls.X509KeyPair([]byte(config.SslCert), []byte(config.SslKey))
		rootca = []byte(config.SslCa)
	}

	if err != nil {
		fmt.Printf("POP3 server did not load TLS certificates: %s\n", err)
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

	service := ":" + strconv.FormatInt(config.Pop3Port, 10)
	listener, err := tls.Listen("tcp", service, &tls_config)

	if err != nil {
		fmt.Printf("POP3 server error: %s", err)
		os.Exit(1)
	}

	fmt.Println("POP3 (RFC 1939 with RFC 8314) listening on port " + strconv.FormatInt(config.Pop3Port, 10))

	for {

		conn, err := listener.Accept()
		if err != nil {
			//fmt.Printf("POP3 server: %s", err)
			break
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

		//fmt.Printf("POP3 server: connection from %s\n", conn.RemoteAddr())

		go pop3HandleClient(ip_ac, ip, conn, config, pop3_auth_func, pop3_stat_func, pop3_list_func, pop3_retr_func, pop3_dele_func)

	}

}

// write to the connection
func pop3Cw(conn net.Conn, b []byte) {

	n, err := conn.Write(b)

	_ = n
	if err != nil {
		//fmt.Printf("POP3 conn.Write() error: %s\n", err)
	}

}

// execute and respond to a command
func pop3ExecCmd(ip_ac ipac.Ipac, ip string, conn net.Conn, c []byte, ss string, authed *bool, auth_login *string, auth_password *string, pop3_auth_func pop3_auth_func, pop3_stat_func pop3_stat_func, pop3_list_func pop3_list_func, pop3_retr_func pop3_retr_func, pop3_dele_func pop3_dele_func) {

	// each command can be up to 512 bytes
	// remove all characters at \r\n
	var end_pos = bytes.Index(c, []byte("\r\n"))
	c = c[0:end_pos]

	//fmt.Printf("POP3 command: %s\n", c)

	if (bytes.Index(c, []byte("USER")) == 0) {

		// USER name
		s := bytes.Split(c, []byte(" "))

		if (len(s) != 2) {
			conn.Write([]byte("-ERR invalid USER command\r\n"))
		} else {
			// store the username
			*auth_login = string(s[1])
			// respond with request for password
			conn.Write([]byte("+OK try PASS\r\n"))
		}

	} else if (bytes.Index(c, []byte("PASS")) == 0) {

		// PASS string
		s := bytes.Split(c, []byte(" "))

		if (len(s) != 2) {
			conn.Write([]byte("-ERR invalid PASS command\r\n"))
		} else {
			// validate the login credentials
			*auth_password = string(s[1])
			*authed = pop3_auth_func(ip, *auth_login, *auth_password, "")

			if (*authed == true) {

				// invalid auth
				ipac.ModifyAuth(&ip_ac, 2, ip)

				conn.Write([]byte("+OK logged in\r\n"))

			} else {

				// invalid auth
				ipac.ModifyAuth(&ip_ac, 1, ip)

				conn.Write([]byte("-ERR invalid credentialsr\n"))
				conn.Close()

			}

		}

	} else if (bytes.Index(c, []byte("AUTH")) == 0) {

		conn.Write([]byte("-ERR need credentials and login type\r\n"))

	} else if (bytes.Index(c, []byte("APOP")) == 0) {

		// APOP login password
		// split by space character
		s := bytes.Split(c, []byte(" "))

		if (len(s) != 3) {
			conn.Write([]byte("-ERR invalid APOP command\r\n"))
		} else {

			*auth_login = string(s[1])
			*auth_password = string(s[2])

			// validate credentials with closure
			*authed = pop3_auth_func(ip, *auth_login, *auth_password, ss)

			if (*authed == true) {

				//fmt.Println("POP3 APOP authenticated")

				// valid auth
				ipac.ModifyAuth(&ip_ac, 2, ip)

				conn.Write([]byte("+OK logged in\r\n"))

			} else {

				//fmt.Println("POP3 APOP not authenticated")

				// invalid auth
				ipac.ModifyAuth(&ip_ac, 1, ip)

				conn.Write([]byte("-ERR invalid credentials\r\n"))
				conn.Close()

			}

		}

	} else if (bytes.Index(c, []byte("CAPA")) == 0) {

		// respond with capabilities line by line, ended with a .
		conn.Write([]byte("+OK\r\nCAPA\r\nAPOP\r\nUSER\r\n.\r\n"))

	} else if (bytes.Index(c, []byte("STAT")) == 0 && *authed == true) {

		// respond with number of messages and total size of all messages in bytes
		n_messages, messages_size := pop3_stat_func(*auth_login)
		conn.Write([]byte("+OK " + strconv.Itoa(n_messages) + " " + strconv.Itoa(messages_size) + "\r\n"))

	} else if (bytes.Index(c, []byte("LIST")) == 0 && *authed == true) {

		// returns a list of all messages in the inbox
		// each with the message identifier (must be whole numbers starting with 1) and the size
		// +OK 2 messages (250 octets)
		// 1 200
		// 2 50
		// .
		//
		// all message ids are strings to allow larger than the uint64 maximum value as message ids
		total_size, msg_ids, msg_lengths := pop3_list_func(*auth_login)

		if (len(msg_ids) != len(msg_lengths)) {
			fmt.Println("POP3 LIST response []string values for message identifiers and lengths are not the same length")
			os.Exit(1)
		}

		// build the response
		var s = "+OK " + strconv.FormatUint(uint64(len(msg_lengths)), 10) + " messages (" + strconv.Itoa(total_size) + " octets)"

		for m := range msg_lengths {
			// message identifiers must be whole numbers
			s += "\r\n" + strconv.Itoa(msg_ids[m]) + " " + strconv.Itoa(msg_lengths[m])
		}

		s += "\r\n.\r\n"

		conn.Write([]byte(s))

	} else if (bytes.Index(c, []byte("RETR")) == 0 && *authed == true) {

		//fmt.Println("RETR", string(c))

		// RETR ID
		s := bytes.Split(c, []byte(" "))
		if (len(s) == 2) {
			// send message
			mid, _ := strconv.Atoi(string(s[1]))
			msg := pop3_retr_func(*auth_login, mid)
			conn.Write([]byte("+OK " + strconv.FormatUint(uint64(len(msg)), 10) + " octets\r\n" + msg + "\r\n.\r\n"))
		} else {
			conn.Write([]byte("-ERR invalid RETR command\r\n"))
		}

	} else if (bytes.Index(c, []byte("DELE")) == 0 && *authed == true) {

		// DELE ID
		s := bytes.Split(c, []byte(" "))
		if (len(s) == 2) {
			// delete message N
			mid, _ := strconv.Atoi(string(s[1]))
			msg_deleted, delete_error := pop3_dele_func(*auth_login, mid)
			if (msg_deleted == true) {
				conn.Write([]byte("+OK deleted\r\n"))
			} else {
				conn.Write([]byte("-ERR deleting message: " + delete_error + "\r\n"))
			}
		} else {
			conn.Write([]byte("-ERR invalid DELE command\r\n"))
		}

	} else if (bytes.Index(c, []byte("NOOP")) == 0) {

		// this is similar to a keep-alive
		conn.Write([]byte("+OK\r\n"))

	} else if (bytes.Index(c, []byte("RSET")) == 0 && *authed == true) {

		// reset all pending delete operations
		conn.Write([]byte("+OK\r\n"))

	} else if (bytes.Index(c, []byte("QUIT")) == 0) {

		// end connection
		conn.Write([]byte("+OK logging out\r\n"))
		conn.Close()

	} else {

		conn.Write([]byte("-ERR unknown command\r\n"))

	}

}

func pop3HandleClient(ip_ac ipac.Ipac, ip string, conn net.Conn, config Config, pop3_auth_func pop3_auth_func, pop3_stat_func pop3_stat_func, pop3_list_func pop3_list_func, pop3_retr_func pop3_retr_func, pop3_dele_func pop3_dele_func) {

	defer conn.Close()

	// create the shared secret or timestamp banner
	ss := pop3TimestampBanner(config.Fqdn)

	//fmt.Println("POP3 client connected")

	// send the first connection message
	pop3Cw(conn, []byte("+OK POP3 server ready " + ss + "\r\n"))

	sent_cmds := 0
	sent_bytes := 0

	authed := false
	auth_login := ""
	auth_password := ""

	buf := make([]byte, 512)

	for {

		if (sent_cmds > 5 && authed == false) {
			// too many commands while not authenticated
			conn.Write([]byte("-ERR unauthenticated send limit exceeded\r\n"))
			conn.Close()
			break
		}

		n, n_err := conn.Read(buf)
		sent_bytes += n

		if (sent_bytes > 1024 * 1000 * 3) {
			// client sent too much data
			conn.Write([]byte("-ERR unauthenticated send limit exceeded\r\n"))
			conn.Close()
			break
		}

		if (n_err != nil) {
			//fmt.Printf("POP3 server: %s\n", n_err)
			break
		}

		sent_cmds += 1

		// execute the command, each a maximum of 512 bytes with the final \r\n
		pop3ExecCmd(ip_ac, ip, conn, buf, ss, &authed, &auth_login, &auth_password, pop3_auth_func, pop3_stat_func, pop3_list_func, pop3_retr_func, pop3_dele_func)

	}

	//fmt.Println("POP3 server connection closed")

}

func pop3TimestampBanner(fqdn string) (string) {

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

	// create the timestamp banner
	timestamp_banner := "<1896." + strconv.FormatInt(time.Now().Unix(), 10) + "@" + fqdn + ">"

	return timestamp_banner

}

func Imap4Server(config Config, ip_ac ipac.Ipac, imap4_auth_func imap4_auth_func, imap4_list_func imap4_list_func, imap4_select_func imap4_select_func, imap4_fetch_func imap4_fetch_func, imap4_store_func imap4_store_func, imap4_close_func imap4_close_func, imap4_search_func imap4_search_func) {

	var cert tls.Certificate
	var err error
	var rootca []byte
	if (config.LoadCertificatesFromFiles == true) {
		cert, err = tls.LoadX509KeyPair(config.SslCert, config.SslKey)
		rootca, _ = os.ReadFile(config.SslCa)
	} else {
		cert, err = tls.X509KeyPair([]byte(config.SslCert), []byte(config.SslKey))
		rootca = []byte(config.SslCa)
	}

	if err != nil {
		fmt.Printf("IMAP4 server did not load TLS certificates: %s\n", err)
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

	service := ":" + strconv.FormatInt(config.Imap4Port, 10)
	listener, err := tls.Listen("tcp", service, &tls_config)

	if err != nil {
		fmt.Printf("IMAP4 server error: %s", err)
		os.Exit(1)
	}

	fmt.Println("IMAP4 listening on port " + strconv.FormatInt(config.Imap4Port, 10))

	for {

		conn, err := listener.Accept()
		if err != nil {
			//fmt.Printf("IMAP4 server: %s", err)
			break
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

		//fmt.Printf("IMAP4 server: connection from %s\n", conn.RemoteAddr())

		go imap4HandleClient(ip_ac, ip, conn, config, imap4_auth_func, imap4_list_func, imap4_select_func, imap4_fetch_func, imap4_store_func, imap4_close_func, imap4_search_func)

	}

}

// write to the connection
func imap4Cw(conn net.Conn, b []byte) {

	n, err := conn.Write(b)

	_ = n
	if err != nil {
		//fmt.Printf("IMAP4 conn.Write() error: %s\n", err)
	}

}

// execute and respond to a command
func imap4ExecCmd(ip_ac ipac.Ipac, ip string, conn net.Conn, c []byte, authed *bool, auth_login *string, auth_password *string, imap4_auth_func imap4_auth_func, imap4_list_func imap4_list_func, imap4_select_func imap4_select_func, imap4_fetch_func imap4_fetch_func, imap4_store_func imap4_store_func, imap4_close_func imap4_close_func, imap4_search_func imap4_search_func) {

	// remove \r\n from the command
	c = bytes.TrimRight(c, "\r\n")

	fmt.Printf("IMAP4 command: %s\n", c)

	// get the sequence number position
	seq_pos := bytes.Index(c, []byte(" "))

	if (seq_pos == -1) {
		// no sequence number exists
		conn.Write([]byte("* BAD no sequence number\r\n"))
		return
	}

	// get the sequence number
	seq := c[0:seq_pos]
	// remove the sequence number from the command
	c = c[seq_pos+1:]

	// remove seq UID from command
	// thunderbird sends this incorrectly per RFC 3501
	// and RFC 9051 allows it to work with COPY, MOVE, FETCH, or STORE
	var is_uid_command = false
	if (bytes.Index(c, []byte("UID ")) == 0) {
		is_uid_command = true
		c = bytes.TrimLeft(c, "UID ")
	}

	// some IMAP4 clients send commands in uppercase characters
	// and the RFC requires casing of characters but does not specify casing of command names
	upper_c := bytes.ToUpper(c)

	//fmt.Printf("IMAP4 command (%s): %s\n", seq, c)

	if (bytes.Index(upper_c, []byte("LOGIN")) == 0) {

		// USER name
		s := bytes.Split(c, []byte(" "))

		if (len(s) != 3) {
			conn.Write([]byte(string(seq) + " NO invalid credentials\r\n"))
		} else {

			// remove " from start and end of login and password
			s[1] = bytes.TrimLeft(s[1], "\"")
			s[1] = bytes.TrimRight(s[1], "\"")
			s[2] = bytes.TrimLeft(s[2], "\"")
			s[2] = bytes.TrimRight(s[2], "\"")

			// store the credentials
			*auth_login = string(s[1])
			*auth_password = string(s[2])

			// validate credentials with closure
			*authed = imap4_auth_func(ip, *auth_login, *auth_password)

			if (*authed == true) {

				//fmt.Println("IMAP4 authenticated")

				// valid auth
				ipac.ModifyAuth(&ip_ac, 2, ip)

				conn.Write([]byte(string(seq) + " OK LOGIN completed\r\n"))

			} else {

				//fmt.Println("IMAP4 not authenticated")

				// invalid auth
				ipac.ModifyAuth(&ip_ac, 1, ip)

				conn.Write([]byte(string(seq) + " NO invalid credentials\r\n"))
				conn.Close()

			}

		}

	} else if (bytes.Index(upper_c, []byte("CAPABILITY")) == 0) {

		// return IMAP capabilities of the server
		conn.Write([]byte("* CAPABILITY IMAP4rev2 CHILDREN UNSELECT BINARY ID\r\n"))
		conn.Write([]byte(string(seq) + " OK CAPABILITY completed\r\n"))

	} else if (bytes.Index(upper_c, []byte("ID")) == 0) {

		// return IMAP server info
		conn.Write([]byte("* ID (\"name\" \"Go-Mail\" \"vendor\" \"XYZBots\" \"support-url\" \"https://xyzbots.com\")\r\n"))
		conn.Write([]byte(string(seq) + " OK CAPABILITY completed\r\n"))

	} else if (bytes.Index(upper_c, []byte("LIST")) == 0) {

		// a slice with each response line is returned
		// the * LIST () "" "" lines

		/*
		C: A101 LIST "" ""
		S: * LIST (\Noselect) "/" ""
		S: A101 OK LIST Completed
		C: A102 LIST #news.comp.mail.misc ""
		S: * LIST (\Noselect) "." #news.
		S: A102 OK LIST Completed
		C: A103 LIST /usr/staff/jones ""
		S: * LIST (\Noselect) "/" /
		S: A103 OK LIST Completed
		C: A202 LIST ~/Mail/ %
		S: * LIST (\Noselect) "/" ~/Mail/foo
		S: * LIST () "/" ~/Mail/meetings
		S: A202 OK LIST completed
		*/

		// remove command name
		c = c[5:]

		// arguments are: flags, reference, mailbox_name
		// flags is optional
		var flags []string
		var reference string
		var mailbox_name string
		if (bytes.Index(c, []byte("(")) > -1) {
			// has flags argument
			flags = append(flags, "")
		} else {
			// does not have flags argument
			var args = bytes.Split(c, []byte(" "))
			if (len(args) != 2) {
				conn.Write([]byte(string(seq) + " BAD invalid command\r\n"))
				return
			}

			reference = string(args[0])
			reference = strings.TrimLeft(reference, "\"")
			reference = strings.TrimRight(reference, "\"")

			mailbox_name = string(args[1])
			mailbox_name = strings.TrimLeft(mailbox_name, "\"")
			mailbox_name = strings.TrimRight(mailbox_name, "\"")
		}

		// InBoX is case-insensitive
		// always return INBOX
		if (strings.Index(strings.ToLower(mailbox_name), "inbox") == 0) {
			// mailbox_name starts with case-insensitive InBoX
			// return INBOX as uppercase
			mailbox_name = "INBOX" + mailbox_name[5:len(mailbox_name)]
		}

		list_response := imap4_list_func(*auth_login, flags, reference, mailbox_name)

		for l := range(list_response) {
			conn.Write([]byte(string(list_response[l]) + "\r\n"))
		}

		conn.Write([]byte(string(seq) + " OK LIST completed\r\n"))

	} else if (bytes.Index(upper_c, []byte("UNSELECT")) == 0) {

		conn.Write([]byte(string(seq) + " OK UNSELECT completed\r\n"))

	} else if (bytes.Index(upper_c, []byte("SELECT")) == 0) {

		/*
		C:   a002 select inbox
		S:   * 18 EXISTS
		S:   * FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
		S:   * 2 RECENT
		S:   * OK [UNSEEN 17] Message 17 is the first unseen message
		S:   * OK [UIDVALIDITY 3857529045] UID value that is unique to the mailbox
		S:   a002 OK [READ-WRITE] SELECT completed
		*/

		// remove command name
		c = c[7:]

		// remove start and end " if they exist
		c = bytes.TrimLeft(c, "\"")
		c = bytes.TrimRight(c, "\"")

		// InBoX is case-insensitive
		// always return INBOX
		if (bytes.Index(bytes.ToLower(c), []byte("inbox")) == 0) {
			// mailbox name starts with case-insensitive InBoX
			// return INBOX as uppercase
			c = []byte("INBOX" + string(c[5:len(c)]))
		}

		// returns int, []string, int, string, string
		// total messages
		// slice of flags
		// count of unseen messages
		// first unseen message id
		// uid validity string (this is forever unique to the mailbox and must increment if the mailbox is deleted)
		total_messages, flags, recent_messages, first_unseen_message_id, uid_validity := imap4_select_func(*auth_login, string(c))

		flags_string := ""
		for f := range(flags) {
			flags_string += flags[f] + " "
		}
		strings.TrimRight(flags_string, " ")

		conn.Write([]byte("* FLAGS (" + flags_string + ")\r\n"))
		conn.Write([]byte("* " + strconv.Itoa(total_messages) + " EXISTS\r\n"))
		conn.Write([]byte("* " + strconv.Itoa(recent_messages) + " RECENT\r\n"))
		conn.Write([]byte("* OK [UNSEEN " + strconv.Itoa(first_unseen_message_id) + "]\r\n"))
		conn.Write([]byte("* OK [PERMANENTFLAGS \\Answered \\Seen \\Draft \\Flagged \\Deleted \\Recent] Ok\r\n"))
		conn.Write([]byte("* OK [UIDNEXT " + strconv.Itoa(total_messages + 1) + "] Ok\r\n"))
		conn.Write([]byte("* OK [UIDVALIDITY " + strconv.Itoa(uid_validity) + "] Ok\r\n"))

		conn.Write([]byte(string(seq) + " OK [READ-WRITE] SELECT completed\r\n"))

	} else if (bytes.Index(upper_c, []byte("SEARCH")) == 0) {

		mids := imap4_search_func(*auth_login, string(c))

		// required by many IMAP4 clients
		// return list of message ids matching the search query
		conn.Write([]byte("* SEARCH " + mids + "\r\n"))
		conn.Write([]byte(string(seq) + " OK SEARCH completed\r\n"))

	} else if (bytes.Index(upper_c, []byte("FETCH")) == 0) {

		/*
		FETCH 1:2 (INTERNALDATE UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (date subject from to cc message-id in-reply-to references content-type x-priority x-uniform-type-identifier x-universally-unique-identifier list-id list-unsubscribe bimi-indicator bimi-location x-bimi-indicator-hash authentication-results dkim-signature)])
		*/

		// remove command name
		c = c[6:]

		fetch_arguments := bytes.SplitN(c, []byte(" ("), 2)
		var item_names []string

		if (len(fetch_arguments) != 2) {

			// item_names is a macro

			/*
			FULL
			Macro equivalent to: (FLAGS INTERNALDATE RFC822.SIZE ENVELOPE
			BODY)
			*/

			// split by space character, not " (" sequence
			fetch_arguments := bytes.SplitN(c, []byte(" "), 2)

			if (len(fetch_arguments) != 2) {
				// invalid command
				conn.Write([]byte(string(seq) + " BAD unknown command\r\n"))
				return
			}

			// add macro to item_names
			item_names = append(item_names, string(fetch_arguments[1]))

		} else {
			// parse item_names

			// remove last ) from second argument
			fetch_arguments[1] = bytes.TrimRight(fetch_arguments[1], ")")

			// get item names
			var last_item []byte
			inner_set := false
			for l := range(fetch_arguments[1]) {

				ch := fetch_arguments[1][l]

				if (ch == ']') {
					// add close of inner_set
					last_item = append(last_item, ch)
					inner_set = false
					continue
				}

				if (ch == '[') {
					inner_set = true
				}

				if (ch == ' ' && inner_set == false) {

					// add last_item to item_names
					item_names = append(item_names, string(last_item))
					last_item = nil
					continue
				}

				last_item = append(last_item, ch)

			}

			if (last_item != nil) {
				// add last_item to item_names
				item_names = append(item_names, string(last_item))
			}

		}

		// get sequence set
		seq_set := strings.Split(string(fetch_arguments[0]), ":")

		if (len(seq_set) != 2) {
			// one message id in the string
			seq_set = nil
			// add it from fetch_arguments
			seq_set = append(seq_set, string(fetch_arguments[0]))
		}

		// returns []Email
		messages := imap4_fetch_func(*auth_login, seq_set, item_names)

		// parse messages and send the data per the IMAP4 protocol

		/*
		C:   a003 fetch 12 full
		S:   * 12 FETCH (FLAGS (\Seen) INTERNALDATE "17-Jul-1996 02:44:25 -0700"
		      RFC822.SIZE 4286 ENVELOPE ("Wed, 17 Jul 1996 02:23:25 -0700 (PDT)"
		      "IMAP4rev1 WG mtg summary and minutes"
		      (("Terry Gray" NIL "gray" "cac.washington.edu"))
		      (("Terry Gray" NIL "gray" "cac.washington.edu"))
		      (("Terry Gray" NIL "gray" "cac.washington.edu"))
		      ((NIL NIL "imap" "cac.washington.edu"))
		      ((NIL NIL "minutes" "CNRI.Reston.VA.US")
		      ("John Klensin" NIL "KLENSIN" "MIT.EDU")) NIL NIL
		      "<B27397-0100000@cac.washington.edu>")
		      BODY ("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 3028
		      92))
		S:   a003 OK FETCH completed
		*/

		/*
		C:   a004 fetch 12 body[header]
		S:   * 12 FETCH (BODY[HEADER] {342}
		S:   Date: Wed, 17 Jul 1996 02:23:25 -0700 (PDT)
		S:   From: Terry Gray <gray@cac.washington.edu>
		S:   Subject: IMAP4rev1 WG mtg summary and minutes
		S:   To: imap@cac.washington.edu
		S:   Cc: minutes@CNRI.Reston.VA.US, John Klensin <KLENSIN@MIT.EDU>
		S:   Message-Id: <B27397-0100000@cac.washington.edu>
		S:   MIME-Version: 1.0
		S:   Content-Type: TEXT/PLAIN; CHARSET=US-ASCII
		S:
		S:   )
		S:   a004 OK FETCH completed
		*/

		// respond with each requested value
		for msg := range(messages) {

			m := messages[msg]

			fmt.Println("FETCH sending email with UID", strconv.Itoa(m.Uid))

			conn.Write([]byte("* " + strconv.Itoa(m.Uid) + " FETCH ("))
			fmt.Print(string([]byte("* " + strconv.Itoa(m.Uid) + " FETCH (")))

			// convert FULL, ALL and FAST macros
			for i := range(item_names) {
				if (item_names[i] == "FULL") {
					item_names = nil

					item_names = append(item_names, "FLAGS")
					item_names = append(item_names, "INTERNALDATE")
					item_names = append(item_names, "RFC822.SIZE")
					item_names = append(item_names, "ENVELOPE")
					item_names = append(item_names, "BODY")

					break
				} else if (item_names[i] == "ALL") {
					item_names = nil

					item_names = append(item_names, "FLAGS")
					item_names = append(item_names, "INTERNALDATE")
					item_names = append(item_names, "RFC822.SIZE")
					item_names = append(item_names, "ENVELOPE")

					break
				} else if (item_names[i] == "FAST") {
					item_names = nil

					item_names = append(item_names, "FLAGS")
					item_names = append(item_names, "INTERNALDATE")
					item_names = append(item_names, "RFC822.SIZE")

					break
				}
			}

			var add_space = false
			for i := range(item_names) {

				if (item_names[i] == "INTERNALDATE") {

					continue

					if (add_space == true) {
						conn.Write([]byte(" "))
						fmt.Print(string([]byte(" ")))
					}

					// send the date as specified by RFC 9051
					conn.Write([]byte("INTERNALDATE \"17-Jul-2023 02:44:25 -0700\""))
					fmt.Print(string([]byte("INTERNALDATE \"17-Jul-2023 02:44:25 -0700\"")))
					//conn.Write([]byte("INTERNALDATE \"" + m.InternalDate.String() + "\""))
					//fmt.Print(string([]byte("INTERNALDATE \"" + m.InternalDate.String() + "\"")))

				} else if (item_names[i] == "UID") {

					if (add_space == true) {
						conn.Write([]byte(" "))
						fmt.Print(string([]byte(" ")))
					}

					// send the unique identifier of the message as specified by RFC 9051
					conn.Write([]byte("UID " + strconv.Itoa(m.Uid)))
					fmt.Print(string([]byte("UID " + strconv.Itoa(m.Uid))))

				} else if (item_names[i] == "FLAGS") {

					if (add_space == true) {
						conn.Write([]byte(" "))
						fmt.Print(string([]byte(" ")))
					}

					f_string := ""
					for f := range(m.Flags) {
						f_string += m.Flags[f] + " "
					}
					// remove last space character
					f_string = strings.TrimRight(f_string, " ")

					// write flags
					conn.Write([]byte("FLAGS (" + f_string + ")"))
					fmt.Print(string([]byte("FLAGS (" + f_string + ")")))

				} else if (item_names[i] == "RFC822.SIZE") {

					if (add_space == true) {
						conn.Write([]byte(" "))
						fmt.Print(string([]byte(" ")))
					}

					// send the size as specified by RFC 822
					conn.Write([]byte("RFC822.SIZE " + strconv.Itoa(m.Rfc822Size)))
					fmt.Print(string([]byte("RFC822.SIZE " + strconv.Itoa(m.Rfc822Size))))

				} else if (item_names[i] == "ENVELOPE") {

					continue

					if (add_space == true) {
						conn.Write([]byte(" "))
						fmt.Print(string([]byte(" ")))
					}

					/*
					The envelope structure of the message.  This is computed by the
					server by parsing the [RFC-2822] header into the component
					parts, defaulting various fields as necessary.
					*/

				} else if (item_names[i] == "BODY" || item_names[i] == "BODYSTRUCTURE") {

					if (add_space == true) {
						conn.Write([]byte(" "))
						fmt.Print(string([]byte(" ")))
					}

					/*
					The [MIME-IMB] body structure of the message.  This is computed
					by the server by parsing the [MIME-IMB] header fields in the
					[RFC-2822] header and [MIME-IMB] headers.
					*/

					conn.Write([]byte("BODYSTRUCTURE (\"text\" \"html\" (\"charset\" \"utf-8\") NIL NIL \"base64\" 27654 355 NIL NIL NIL NIL)"))
					fmt.Print(string([]byte("BODYSTRUCTURE (\"text\" \"html\" (\"charset\" \"utf-8\") NIL NIL \"base64\" 27654 355 NIL NIL NIL NIL)")))

				} else if (strings.Index(item_names[i], "BODY.PEEK[") == 0) {

					if (add_space == true) {
						conn.Write([]byte(" "))
						fmt.Print(string([]byte(" ")))
					}

					/*
					BODY.PEEK[<section>]<<partial>>
					An alternate form of BODY[<section>] that does not implicitly
					set the \Seen flag.
					*/

					// only write the headers for now
					var header_string = ""
					for h := range(m.Headers) {
						header_string += h + ": " + m.Headers[h] + "\r\n"
					}

					conn.Write([]byte(item_names[i] + " {" + strconv.Itoa(len(header_string)) + "}\r\n" + header_string + "\r\n"))
					fmt.Print(string([]byte(item_names[i] + " {" + strconv.Itoa(len(header_string)) + "}\r\n" + header_string + "\r\n")))

				} else if (strings.Index(item_names[i], "BODY[") == 0) {

					continue

					if (add_space == true) {
						conn.Write([]byte(" "))
						fmt.Print(string([]byte(" ")))
					}

					/*
					The text of a particular body section.  The section
					specification is a set of zero or more part specifiers
					delimited by periods.  A part specifier is either a part number
					or one of the following: HEADER, HEADER.FIELDS,
					HEADER.FIELDS.NOT, MIME, and TEXT.  An empty section
					specification refers to the entire message, including the
					header.
					*/

				}

				if (i + 1 < len(item_names)) {
					// send space character between each item
					add_space = true

				}

			}

			// send end of message character sequence
			conn.Write([]byte(")\r\n"))
			fmt.Print(string([]byte(")\r\n")))

		}

		if (is_uid_command == true) {
			conn.Write([]byte(string(seq) + " OK UID FETCH completed\r\n"))
			fmt.Print(string([]byte(string(seq) + " OK UID FETCH completed\r\n")))
		} else {
			conn.Write([]byte(string(seq) + " OK FETCH completed\r\n"))
			fmt.Print(string([]byte(string(seq) + " OK FETCH completed\r\n")))
		}

	} else if (bytes.Index(upper_c, []byte("NOOP")) == 0) {

		/*
		Since any command can return a status update as untagged data, the
		NOOP command can be used as a periodic poll for new messages or
		message status updates during a period of inactivity (this is the
		preferred method to do this).  The NOOP command can also be used
		to reset any inactivity autologout timer on the server.

		Example:
		C: a002 NOOP
		S: a002 OK NOOP completed
		  . . .
		C: a047 NOOP
		S: * 22 EXPUNGE
		S: * 23 EXISTS
		S: * 3 RECENT
		S: * 14 FETCH (FLAGS (\Seen \Deleted))
		S: a047 OK NOOP completed
		*/

		conn.Write([]byte(string(seq) + " OK NOOP completed\r\n"))

	} else if (bytes.Index(upper_c, []byte("LSUB")) == 0) {

		conn.Write([]byte(string(seq) + " BAD LSUB not implemented\r\n"))

	} else if (bytes.Index(upper_c, []byte("STORE")) == 0) {

		// not implemented
		// add RFC 9051 UID prefix when STORE is implemented using is_uid_command as used in FETCH
		//conn.Write([]byte(string(seq) + " OK STORE completed\r\n"))
		conn.Write([]byte(string(seq) + " BAD\r\n"))

	} else if (bytes.Index(upper_c, []byte("CLOSE")) == 0) {

		conn.Write([]byte(string(seq) + " OK CLOSE completed\r\n"))

	} else if (bytes.Index(upper_c, []byte("LOGOUT")) == 0) {

		conn.Write([]byte("* BYE IMAP4rev2 server terminating connection\r\n"))
		conn.Write([]byte(string(seq) + " OK LOGOUT completed\r\n"))
		conn.Close()

	} else {

		fmt.Println("IMAP4 unknown command", string(c))
		conn.Write([]byte(string(seq) + " BAD unknown command\r\n"))

	}

}

func imap4HandleClient(ip_ac ipac.Ipac, ip string, conn net.Conn, config Config, imap4_auth_func imap4_auth_func, imap4_list_func imap4_list_func, imap4_select_func imap4_select_func, imap4_fetch_func imap4_fetch_func, imap4_store_func imap4_store_func, imap4_close_func imap4_close_func, imap4_search_func imap4_search_func) {

	defer conn.Close()

	fmt.Println("IMAP4 client connected")

	// send the first connection message
	imap4Cw(conn, []byte("* OK IMAP4rev2 Service Ready\r\n"))

	sent_cmds := 0
	sent_bytes := 0

	authed := false
	auth_login := ""
	auth_password := ""

	/*
	RFC 9051
	Unless otherwise specified in an IMAP extension, non-synchronizing literals MUST NOT be larger than 4096 octets. Any literal larger than 4096 bytes MUST be sent as a synchronizing literal.
	*/
	// max command length
	max_command_length := 4096
	buf := make([]byte, 0)

	for {

		b := make([]byte, 1024)

		n, n_err := conn.Read(buf)
		sent_bytes += n

		if (n_err != nil) {
			//fmt.Printf("IMAP4 server: %s\n", n_err)
			break
		}

		if (sent_bytes > 1024 * 1000 * 3) {
			// client sent too much data
			conn.Write([]byte("* NO unauthenticated send limit exceeded\r\n"))
			conn.Close()
			break
		}

		if (sent_cmds > 5 && authed == false) {
			// too many commands while not authenticated
			conn.Write([]byte("* NO unauthenticated send limit exceeded\r\n"))
			conn.Close()
			break
		}

		if (len(b) + len(buf) > max_command_length) {
			conn.Write([]byte("* NO exceeds max command length in RFC 9051\r\n"))
			buf = nil
			continue
		}

		// add b to buf
		for l := range b {
			buf = append(buf, b[l])
		}
		// clear b
		b = nil

		var cmd_end_pos = bytes.Index(buf, []byte("\r\n"))

		if (cmd_end_pos != -1) {

			sent_cmds += 1

			// execute the command
			imap4ExecCmd(ip_ac, ip, conn, buf[0:cmd_end_pos], &authed, &auth_login, &auth_password, imap4_auth_func, imap4_list_func, imap4_select_func, imap4_fetch_func, imap4_store_func, imap4_close_func, imap4_search_func)

			// clear buf
			buf = nil

		}

	}

	//fmt.Println("IMAP4 server connection closed")

}

func SendMail(outbound_mail OutboundMail) (error, []byte) {

	if (outbound_mail.From.String() == "") {
		return errors.New("requires a from address"), nil
	}

	// Setup headers
	headers := make(map[string]string)

	// copy defined headers to headers that are sent
	for k,v := range outbound_mail.Headers {
		headers[strings.ToLower(k)] = v
	}

	if (len(outbound_mail.DkimPrivateKey) > 0 && outbound_mail.DkimDomain != "") {

		var dkim_header = bytes.Buffer{}
		dkim_header.Write([]byte("DKIM-Signature: v=1;"))

		if (outbound_mail.DkimSigningAlgo == "") {
			// use default
			outbound_mail.DkimSigningAlgo = "rsa-sha256"
		}

		if (outbound_mail.DkimSigningAlgo != "rsa-sha256") {
			return errors.New("invalid DkimSigningAlgo"), nil
		}

		if (outbound_mail.DkimExpireSeconds == 0) {
			// set to 60 minutes by default
			outbound_mail.DkimExpireSeconds = 3600
		}

		var l = strings.Split(outbound_mail.DkimDomain, "._domainkey.")
		if (len(l) != 2) {
			return errors.New("invalid DkimDomain, must be selector._domainkey.domain.tld"), nil
		}
		var selector = l[0]
		var domain = l[1]

		// write to dkim_header
		// t = timestamp
		// x = expire time
		now := int(time.Now().Unix())
		dkim_header.Write([]byte(" a=rsa-sha256; q=dns/txt; c=relaxed/simple;\r\n s=" + selector + "; d=" + domain + "; t=" + strconv.Itoa(now) + "; x=" + strconv.Itoa(now + outbound_mail.DkimExpireSeconds) + "; h=from;"))

		// create DKIM header
		var privateKey *rsa.PrivateKey

		d, _ := pem.Decode(outbound_mail.DkimPrivateKey)
		if (d == nil) {
			return errors.New("error parsing DKIM private key"), nil
		}

		// try to parse it as PKCS1 otherwise try PKCS8
		if key, err := x509.ParsePKCS1PrivateKey(d.Bytes); err != nil {
			if key, err := x509.ParsePKCS8PrivateKey(d.Bytes); err != nil {
				return err, nil
			} else {
				privateKey = key.(*rsa.PrivateKey)
			}
		} else {
			privateKey = key
		}

		var canonicalized_body []byte
		var canonicalized_body_hash_base64 string

		// simple body canonicalization

		/*
		3.4.3.  The "simple" Body Canonicalization Algorithm
		The "simple" body canonicalization algorithm ignores all empty lines
		at the end of the message body.  An empty line is a line of zero
		length after removal of the line terminator.  If there is no body or
		no trailing CRLF on the message body, a CRLF is added.  It makes no
		other changes to the message body.  In more formal terms, the
		"simple" body canonicalization algorithm converts "*CRLF" at the end
		of the body to a single "CRLF".

			remove all \r\n at the end then add \r\n (\r\n is CRLF)
		*/

		canonicalized_body = bytes.TrimRight(outbound_mail.Body, "\r\n")

		canonicalized_body = append(canonicalized_body, '\r')
		canonicalized_body = append(canonicalized_body, '\n')

		//fmt.Println("canonicalized_body", string(canonicalized_body))

		// get the checksum from the canonicalized body
		var canonicalized_body_sha256_sum = sha256.Sum256(canonicalized_body)
		// convert [32]byte to []byte
		var formatted_canonicalized_body_sha256_sum []byte
		for b := range canonicalized_body_sha256_sum {
			formatted_canonicalized_body_sha256_sum = append(formatted_canonicalized_body_sha256_sum, canonicalized_body_sha256_sum[b])
		}

		// as base64
		canonicalized_body_hash_base64 = base64.StdEncoding.EncodeToString(formatted_canonicalized_body_sha256_sum)

		//fmt.Println("canonicalized_body_hash_base64", canonicalized_body_hash_base64)

		// write to dkim_header
		dkim_header.Write([]byte("\r\n bh=" + canonicalized_body_hash_base64 + ";\r\n b="))

		// create the canonicalized header string using the from header
		var canonicalized_header_string = ""

		// relaxed header canonicalization
		// lowercase key names
		// no spaces on either side of :
		canonicalized_header_string = "from:" + outbound_mail.From.String() + "\r\n"

		// add dkim_header with b= and an empty value to canonicalized_header_string
		// replacing each header key with the same with lower case values and 
		canonicalized_header_string += strings.ReplaceAll(strings.ReplaceAll(dkim_header.String(), "\r\n", ""), "DKIM-Signature: ", "dkim-signature:")

		//fmt.Println("canonicalized_header_string", []byte(canonicalized_header_string))
		//fmt.Println("canonicalized_header_string", canonicalized_header_string)

		// create the signature of headers to send in b=
		var h1 hash.Hash
		var h2 crypto.Hash
		h1 = sha256.New()
		h2 = crypto.SHA256

		// sign
		h1.Write([]byte(canonicalized_header_string))
		sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, h2, h1.Sum(nil))
		if err != nil {
			return err, nil
		}
		var b_value = base64.StdEncoding.EncodeToString(sig)

		// every 70 characters, add "\r\n "
		var lined []byte
		for ch := range(b_value) {
			lined = append(lined, b_value[ch])
			if (ch % 70 == 0 && ch != 0) {
				lined = append(lined, '\r')
				lined = append(lined, '\n')
				lined = append(lined, ' ')
			}
		}

		dkim_header.Write(lined)

		headers["DKIM-Signature"] = string(dkim_header.Bytes()[16:])

	}

	headers["from"] = outbound_mail.From.String()

	if (len(outbound_mail.To) > 0) {
		var th = ""
		for i := range outbound_mail.To {
			th += outbound_mail.To[i].String() + ","
		}
		th = strings.TrimRight(th, ",")
		headers["to"] = th
	}

	if (len(outbound_mail.Cc) > 0) {
		var cch = ""
		for i := range outbound_mail.Cc {
			cch += outbound_mail.Cc[i].String() + ","
		}
		cch = strings.TrimRight(cch, ",")
		headers["cc"] = cch
	}

	if (len(outbound_mail.Bcc) > 0) {
		var bcch = ""
		for i := range outbound_mail.Bcc {
			bcch += outbound_mail.Bcc[i].String() + ","
		}
		bcch = strings.TrimRight(bcch, ",")
		headers["bcc"] = bcch
	}


	headers["subject"] = outbound_mail.Subj

	if (outbound_mail.SendingHost == "") {
		// set to localhost
		outbound_mail.SendingHost = "localhost"
	}
	if (outbound_mail.Port == 0) {
		// set to 25
		outbound_mail.Port = 25
	}
	if (outbound_mail.ReceivingHost == "") {
		// set from to address
		if (len(outbound_mail.To) > 0) {
			p := strings.Split(outbound_mail.To[0].Address, "@")
			outbound_mail.ReceivingHost = p[1]

			// get mx record to get address of SMTP server
			var r net.Resolver
			ctx, cancel := context.WithTimeout(context.Background(), time.Second * 10)
			defer cancel()
			mx, mx_err := r.LookupMX(ctx, p[1])

			if (mx_err == nil) {
				if (len(mx) > 0) {
					outbound_mail.ReceivingHost = mx[0].Host
				} else {
					return errors.New("No MX records found for " + outbound_mail.To[0].String()), nil
				}
			} else {
				return mx_err, nil
			}
		} else {
			return errors.New("No To address or ReceivingHost set."), nil
		}
	}

	// Connect to the SMTP Server
	servername := outbound_mail.ReceivingHost + ":" + strconv.FormatInt(int64(outbound_mail.Port), 10)

	var conn net.Conn
	var tlsconfig *tls.Config

	if (outbound_mail.Port == 25) {

		// port 25 never uses TLS without STARTTLS
		nconn, err := net.Dial("tcp", servername)
		if err != nil {
			//fmt.Println(err)
			return err, nil
		}
		conn = nconn

	} else {

		// port 465 and 587 should only accept TLS connections, so should any non standard port

		if (outbound_mail.ReceivingHostTlsConfig == nil) {

			// OS TLS config
			tlsconfig = &tls.Config {
				InsecureSkipVerify: false,
				ServerName: outbound_mail.ReceivingHost,
			}

		} else {
			// supplied tls config
			tlsconfig = outbound_mail.ReceivingHostTlsConfig
		}

		nconn, err := tls.Dial("tcp", servername, tlsconfig)
		if err != nil {
			//fmt.Println(err)
			return err, nil
		}
		conn = nconn

	}

	// read server greeting
	read_err, _, read_data := smtp_client_read_command_response(conn)

	if (read_err != nil) {
		return read_err, nil
	}

	// send EHLO command and read response
	conn.Write([]byte("EHLO " + outbound_mail.SendingHost + "\r\n"))

	// after EHLO the server may respond with ESMTP extensions
	var esmtps []Esmtp

	for (true) {

		read_err, _, read_data = smtp_client_read_command_response(conn)

		if (read_err != nil) {
			return read_err, nil
		}

		if (bytes.Index(read_data, []byte("250-")) == 0) {
			// the server responded with a ESTMP extension
			// add it to esmtps and read the next command

			// get extension name
			var e = string(bytes.Split(read_data, []byte("250-"))[1])
			// get extension parts
			var p = strings.Split(e, " ")

			var supported_extension Esmtp
			supported_extension.Name = p[0]
			supported_extension.Parts = p[1:len(p)]

			esmtps = append(esmtps, supported_extension)

		} else if (bytes.Index(read_data, []byte("250")) == 0) {
			// this command completes the EHLO response
			// per SMTP it must be 250
			break
		}

	}

	if (len(esmtps) > 0) {

		//fmt.Println("SMTP Extensions Found:", esmtps)

		if (tlsconfig == nil) {

			// use STARTTLS if supported and connection is not already using TLS

			var starttls = false
			for i := range esmtps {
				if (esmtps[i].Name == "STARTTLS") {
					starttls = true
					break
				}
			}

			if (starttls == true) {

				//fmt.Println("STARTTLS supported and TLS not currently in use on conn")
				//fmt.Println("Upgrading to TLS")

				// send STARTTLS command and read response
				conn.Write([]byte("STARTTLS\r\n"))

				read_err, _, read_data = smtp_client_read_command_response(conn)

				if (read_err != nil) {
					return read_err, nil
				}

				// 250 returned per SMTP

				if (outbound_mail.ReceivingHostTlsConfig == nil) {

					// OS TLS config
					tlsconfig = &tls.Config {
						InsecureSkipVerify: true,
						ServerName: outbound_mail.ReceivingHost,
					}

				} else {
					// supplied tls config
					tlsconfig = outbound_mail.ReceivingHostTlsConfig
				}

				var tlsConn *tls.Conn
				tlsConn = tls.Client(conn, tlsconfig)
				// run a handshake
				tlsConn.Handshake()
				// convert tlsConn to a net.Conn type
				conn = net.Conn(tlsConn)

			}

		}

	}

	// send username and password if not nil via a supported ESMTP method provided by the server
	if (outbound_mail.Username != "" || outbound_mail.Password != "") {

		var auths_allowed Esmtp
		for i := range esmtps {
			if (esmtps[i].Name == "AUTH") {
				auths_allowed = esmtps[i]
				break
			}
		}

		//fmt.Println("username or password provided, AUTH types allowed by server", auths_allowed)

		for i := range auths_allowed.Parts {
			if (auths_allowed.Parts[i] == "PLAIN") {

				// use AUTH PLAIN
				// send username + null character + password base64 encoded
				var login_string = make([]byte, len(outbound_mail.Username) + 1 + len(outbound_mail.Password))
				for c := range outbound_mail.Username {
					login_string[c] = outbound_mail.Username[c]
				}
				login_string[len(outbound_mail.Username)] = 0
				for c := range outbound_mail.Password {
					login_string[len(outbound_mail.Username) + 1 + c] = outbound_mail.Password[c]
				}

				b64_string := base64.StdEncoding.EncodeToString(login_string)
				conn.Write([]byte("AUTH PLAIN " + b64_string + "\r\n"))

				// 235 response expected
				read_err, _, read_data = smtp_client_read_command_response(conn)

				if (read_err != nil) {
					return read_err, nil
				}

				//fmt.Println("AUTH PLAIN response (235 means authorized)")
				//fmt.Println(string(read_data))

				break

			}
		}

	}

	// send MAIL FROM command and read response
	conn.Write([]byte("MAIL FROM:<" + outbound_mail.From.Address + ">\r\n"))

	read_err, _, read_data = smtp_client_read_command_response(conn)

	if (read_err != nil) {
		return read_err, nil
	}

	for i := range outbound_mail.To {

		// send RCPT TO command and read response
		conn.Write([]byte("RCPT TO:<" + outbound_mail.To[i].Address + ">\r\n"))

		read_err, _, read_data = smtp_client_read_command_response(conn)

		if (read_err != nil) {
			return read_err, nil
		}

	}

	for i := range outbound_mail.Cc {

		// send RCPT TO command and read response
		conn.Write([]byte("RCPT TO:<" + outbound_mail.Cc[i].Address + ">\r\n"))

		read_err, _, read_data = smtp_client_read_command_response(conn)

		if (read_err != nil) {
			return read_err, nil
		}

	}

	for i := range outbound_mail.Bcc {

		// send RCPT TO command and read response
		conn.Write([]byte("RCPT TO:<" + outbound_mail.Bcc[i].Address + ">\r\n"))

		read_err, _, read_data = smtp_client_read_command_response(conn)

		if (read_err != nil) {
			return read_err, nil
		}

	}

	// send DATA command and read response
	conn.Write([]byte("DATA\r\n"))

	read_err, _, read_data = smtp_client_read_command_response(conn)

	if (read_err != nil) {
		return read_err, nil
	}

	if (bytes.Index(read_data, []byte("354")) != 0) {
		// error
		return errors.New("smtp server did not respond with 354 after DATA command, " + string(read_data)), nil
	}

	buf := bytes.Buffer{}

	// write from header first
	// required in this order for DKIM validation, often
	buf.Write([]byte("from: " + headers["from"] + "\r\n"))
	conn.Write([]byte("from: " + headers["from"] + "\r\n"))
	delete(headers, "from")

	// send DATA and read response
	for k,v := range headers {
		buf.Write([]byte(k + ": " + v + "\r\n"))
		conn.Write([]byte(k + ": " + v + "\r\n"))
	}

	conn.Write([]byte("\r\n"))
	conn.Write(outbound_mail.Body)
	conn.Write([]byte("\r\n.\r\n"))

	// do not write \r\n.\r\n to the output, only to the server
	buf.Write([]byte("\r\n"))
	buf.Write(outbound_mail.Body)

	var error_string = ""

	for (true) {

		// shorten the read deadline as this is after the DATA has been sent
		conn.SetReadDeadline(time.Now().Add(time.Second * 10))

		read_err, _, read_data = smtp_client_read_command_response(conn)

		if (read_err != nil) {
			break
		}

		if (bytes.Index(read_data, []byte("250")) == 0) {
			// finished
			break
		} else if (bytes.Index(read_data, []byte("5")) == 0) {
			// error
			error_string += string(read_data) + "\n"
		}

	}

	conn.Write([]byte("QUIT\r\n"))
	conn.Close()

	if (error_string == "") {
		return nil, buf.Bytes()
	} else {
		// return error
		return errors.New(error_string), buf.Bytes()
	}

}

func smtp_client_read_command_response(conn net.Conn) (error, uint64, []byte) {

	var data []byte
	var rlen uint64 = 0
	var max_read_size = 1024 * 1000 * 1000
	seq := 0
	for true {

		var read_buf = make([]byte, 1)

		// read 1 byte
		n, read_err := conn.Read(read_buf)

		if (read_err != nil) {
			return read_err, rlen, data
		}

		rlen += 1

		for c := range read_buf {

			if (c > max_read_size) {
				// max command response size
				return errors.New("max SMTP command response size"), rlen, data
			}

			if (c > n) {
				break
			} else if (seq == 1) {
				if (read_buf[c] == '\n') {
					// sequence completed
					seq += 1
					break
				}
			} else if (seq == 0) {
				if (read_buf[c] == '\r') {
					seq += 1
				} else {
					data = append(data, read_buf[c])
				}
			}
		}

		if (seq == 2) {
			// command in data
			break
		}

		if (rlen > uint64(max_read_size)) {
			// max command response size
			return errors.New("max SMTP command response size"), rlen, data
		}

	}

	return nil, rlen, data

}
