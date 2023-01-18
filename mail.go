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
	"crypto/sha256"
	"crypto/rand"
	"crypto/tls"
	"crypto"
	"hash"
	"fmt"
	"net"
	"bytes"
	"strings"
	"strconv"
	"io"
	"encoding/base64"
	"mime/quotedprintable"
	"os"
	"github.com/andrewhodel/go-ip-ac"
)

type mail_from_func func(string, string, string, string) bool
type rcpt_to_func func(string, string, string, string) bool
type headers_func func(map[string]string, string, string, string) bool
type full_message_func func(*[]byte, *map[string]string, *[]map[string]string, *[][]byte, *bool, *string, *string, *string)
type pop3_auth_func func(string, string, string, string) bool
type pop3_stat_func func(string) (string, string)
type pop3_list_func func(string) (string, []string, []string)
type pop3_retr_func func(string, string) string
type pop3_dele_func func(string, string) (bool, string)

type Config struct {
	SmtpTLSPorts			[]int64	`json:"smtpTLSPorts"`
	SmtpNonTLSPorts			[]int64	`json:"smtpNonTLSPorts"`
	SmtpMaxEmailSize		uint64	`json:"smtpMaxEmailSize"`
	Pop3Port			int64	`json:"pop3Port"`
	SslKey				string	`json:"sslKey"`
	SslCert				string	`json:"sslCert"`
	SslCa				string	`json:"sslCa"`
	LoadCertificatesFromFiles	bool	`json:"loadCertificatesFromFiles"`
	Fqdn				string	`json:"fqdn"`
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
func smtpExecCmd(ip_ac ipac.Ipac, using_tls bool, conn net.Conn, tls_config tls.Config, config Config, c []byte, auth_login *string, auth_password *string, login_status *int, authed *bool, mail_from *string, to_address *string, parse_data *bool, sent_cmds *int, login *[]byte, ip string, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) {

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
		if (i1 >= 0 || i2 >= 0 || i2 < i1) {
			s = c[i1+1:i2]
		}

		//fmt.Printf("send address (between %d and %d): %s\n", i1, i2, s)

		*mail_from = string(s)

		var mail_from_authed = mail_from_func(string(s), ip, *auth_login, *auth_password)

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
		if (i1 >= 0 || i2 >= 0 || i2 < i1) {
			//fmt.Printf("found < and > in: '%s'\n", c)
			s = c[i1+1:i2]
		}

		_ = s

		//fmt.Printf("rcpt address (between %d and %d): %s\n", i1, i2, s)

		*to_address = string(s)

		*authed = rcpt_to_func(string(s), ip, *auth_login, *auth_password)

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
		//fmt.Println(string(buf))

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
					smtpExecCmd(ip_ac, using_tls, conn, tls_config, config, line, &auth_login, &auth_password, &login_status, &authed, &mail_from, &to_address, &parse_data, &sent_cmds, &login, ip, mail_from_func, rcpt_to_func, headers_func, full_message_func)
				}

				if (len(smtp_data) + 2 >= len(line) && len(smtp_data) >= 2 && len(line) + 2 <= len(smtp_data)) {
					// remove the line from smtp_data
					smtp_data = smtp_data[len(line) + 2:len(smtp_data)]
				}

			}

		}

		if (parse_data == true) {
			// connection has already been authenticated
			// and parsed to the body and attachment blocks that use boundaries

			// RFC-5321 section 4.5.2. Transparency
			// Before sending a line of mail text, the SMTP client checks the first character of the line. If it is a period, one additional period is inserted at the beginning of the line.

			// gather data until <CR><LF>.<CR><LF>
			// indicating the end of this email (body, attachments and anything else received already)
			data_block_end := bytes.Index(smtp_data, []byte("\r\n.\r\n"))

			if (data_block_end > -1) {

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
								authed = headers_func(headers, ip, auth_login, auth_password)

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
									i, err := strconv.ParseInt("1405544146", 10, 64)
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
								} else if (dkim_hp["d"] != valid_domain_1 && dkim_hp["d"] != valid_domain_2) {
									// the d= tag value (domain specified in the DKIM header) is not the same domain as the reply-to address
									//fmt.Println("DKIM d= domain", dkim_hp["d"], "does not match the from address", headers["from"], "or the MAIL FROM address", mail_from)
									headers["dkim-validation-errors"] = headers["dkim-validation-errors"] + "(d= domain does not match the from header domain or the SMTP MAIL FROM domain)"
								} else {

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
									//fmt.Println("body hash base64 bh=", dkim_hp["bh"])

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

											In better explanation, remove \r\n.\r\n, then remove all \r\n at the end then add \r\n (\r\n is CRLF)
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
										var canon_h = strings.Split(dkim_hp["h"], ":")

										// empty duplicates
										for d := range canon_h {
											for dd := range canon_h {
												if (canon_h[dd] == canon_h[d] && dd != d) {
													// empty duplicate value
													canon_h[dd] = ""
												}
											}
										}

										//fmt.Println("header fields to be canonicalized", canon_h)

										var canonicalized_header_string = ""

										if (canon_algos[0] == "simple") {

											// simple header canonicalization

										} else if (canon_algos[0] == "relaxed") {

											// relaxed header canonicalization

											for h := range canon_h {
												var h_name = strings.ToLower(canon_h[h])

												var is_real = false
												for r := range real_headers {
													if (real_headers[r] == h_name) {
														is_real = true
														break
													}
												}

												if (is_real == true) {
													// add each header specified in the h= tag with the valid format
													canonicalized_header_string = canonicalized_header_string + h_name + ":" + headers[h_name] + "\r\n"
												}
											}

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

										//fmt.Println("canonicalized_header_string", sha256.Sum256([]byte(canonicalized_header_string)), []byte(canonicalized_header_string), canonicalized_header_string)

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
				full_message_func(&smtp_data, &headers, &parts_headers, &parts, &dkim_valid, &ip, &auth_login, &auth_password)

				smtp_data = nil

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

func SmtpServer(ip_ac ipac.Ipac, config Config, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) {

	var cert tls.Certificate
	var err error
	if (config.LoadCertificatesFromFiles == true) {
		cert, err = tls.LoadX509KeyPair(config.SslCert, config.SslKey)
	} else {
		cert, err = tls.X509KeyPair([]byte(config.SslCert), []byte(config.SslKey))
	}

	if err != nil {
		fmt.Printf("SMTP server did not load TLS certificates: %s\n", err)
		os.Exit(1)
	}

	tls_config := tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.VerifyClientCertIfGiven, ServerName: config.Fqdn}
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
	if (config.LoadCertificatesFromFiles == true) {
		cert, err = tls.LoadX509KeyPair(config.SslCert, config.SslKey)
	} else {
		cert, err = tls.X509KeyPair([]byte(config.SslCert), []byte(config.SslKey))
	}

	if err != nil {
		fmt.Printf("POP3 server did not load TLS certificates: %s\n", err)
		os.Exit(1)
	}

	srv_config := tls.Config{Certificates: []tls.Certificate{cert}}
	srv_config.Rand = rand.Reader
	service := ":" + strconv.FormatInt(config.Pop3Port, 10)
	listener, err := tls.Listen("tcp", service, &srv_config)

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

	// each command can be up to 512 bytes and the buffer is that big
	// they are ended with \r\n so remove everything from that
	c = bytes.Split(c, []byte("\r\n"))[0]

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
		conn.Write([]byte("+OK " + n_messages + " " + messages_size + "\r\n"))

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
		var s = "+OK " + strconv.FormatUint(uint64(len(msg_lengths)), 10) + " messages (" + total_size + " octets)"

		for m := range msg_lengths {
			// message identifiers must be whole numbers
			s += "\r\n" + msg_ids[m] + " " + msg_lengths[m]
		}

		s += "\r\n.\r\n"

		conn.Write([]byte(s))

	} else if (bytes.Index(c, []byte("RETR")) == 0 && *authed == true) {

		// RETR ID
		s := bytes.Split(c, []byte(" "))
		if (len(s) == 2) {
			// send message
			msg := pop3_retr_func(*auth_login, string(s[1]))
			conn.Write([]byte("+OK " + strconv.FormatUint(uint64(len(msg)), 10) + " octets\r\n" + msg + "\r\n.\r\n"))
		} else {
			conn.Write([]byte("-ERR invalid RETR command\r\n"))
		}

	} else if (bytes.Index(c, []byte("DELE")) == 0 && *authed == true) {

		// DELE ID
		s := bytes.Split(c, []byte(" "))
		if (len(s) == 2) {
			// delete message N
			msg_deleted, delete_error := pop3_dele_func(*auth_login, string(s[1]))
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
