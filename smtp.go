package main

import (
	"time"
	"crypto/sha256"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"bytes"
	"strings"
	"strconv"
	"io"
	"io/ioutil"
	"encoding/json"
	"encoding/base64"
	"mime/quotedprintable"
	"os"
	"github.com/andrewhodel/go-ip-ac"
	dkim "github.com/toorop/go-dkim"
)

type Config struct {
	SmtpTLSPorts			[]int64	`json:"smtpTLSPorts"`
	SmtpNonTLSPorts			[]int64	`json:"smtpNonTLSPorts"`
	SslKey				string	`json:"sslKey"`
	SslCert				string	`json:"sslCert"`
	SslCa				string	`json:"sslCa"`
	Fqdn				string	`json:"fqdn"`
}

var config Config
var ip_ac ipac.Ipac
type mail_from_func func(string) bool
type rcpt_to_func func(string) bool
type headers_func func(map[string]string) bool
type full_message_func func([]map[string]string, [][]byte, bool)

func main() {

	ipac.Init(&ip_ac)

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

	smtpServer(ip_ac, config, func(from_address string) bool {

		// MAIL FROM
		fmt.Println("mail from", from_address)

		//creds := strings.Split(from_address, "@")
		//fmt.Println(creds)

		// return true if allowed, false if not
		return true

	}, func(to_address string) bool {

		// RCPT TO
		fmt.Println("mail to", to_address)

		// return true if allowed, false if not
		return true

	}, func(headers map[string]string) bool {

		// HEADERS
		// you can use smtpParseTags() to parse strings with key=value; parts into a map[string]string
		fmt.Println("headers")
		for h := range headers {
			fmt.Println(h, headers[h])
		}

		// return true if allowed, false if not
		return true

	}, func(parts_headers []map[string]string, parts [][]byte, dkim_valid bool) {

		fmt.Println("full email received")
		fmt.Println("dkim valid:", dkim_valid)

		// email is in parts
		// a part can be an attachment or a body with a different content-type
		// there is a parts_headers item for each part

		fmt.Println("parts:", len(parts))
		for p := range parts {
			fmt.Println("###### part:", p)
			fmt.Println("part headers:", parts_headers[p])
			if (len(parts[p]) > 1000) {
				fmt.Println("email part is too long to print")
			} else {
				fmt.Println(string(parts[p]))
			}
		}

	})

}

func smtpParseTags(b []byte) map[string]string {

	// converts "   a=asdf;  b=afsdf" to
	// v["a"] = "asdf"
	// v["b"] = "afsdf"

	var tags = make(map[string]string, 0)

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

	return tags

}

// execute and respond to a command
func smtpExecCmd(using_tls bool, conn net.Conn, tls_config tls.Config, config Config, c []byte, authed *bool, to_address *string, parse_data *bool, total_cmds *int, login *[]byte, ip string, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) {

	//fmt.Printf("smtp smtpExecCmd: %s\n", c)

	if (!*authed) {
		*total_cmds += 1
	}

	if (bytes.Index(c, []byte("STARTTLS")) == 0 && using_tls == false) {

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
		smtpHandleClient(false, true, conn, tls_config, ip, config, mail_from_func, rcpt_to_func, headers_func, full_message_func)

	} else if (bytes.Index(c, []byte("EHLO")) == 0 || bytes.Index(c, []byte("HELO")) == 0) {

		//fmt.Printf("EHLO command\n")

		// respond with 250 and supported SMTP extensions
		conn.Write([]byte("250-" + config.Fqdn + "\r\n"))
		conn.Write([]byte("250-SIZE 14680064\r\n"))
		conn.Write([]byte("250-8BITMIME\r\n"))

		if (using_tls == false) {
			// start tls
			conn.Write([]byte("250-STARTTLS\r\n"))
		}

		conn.Write([]byte("250-ENHANCEDSTATUSCODES\r\n"))
		conn.Write([]byte("250-PIPELINING\r\n"))
		//conn.Write([]byte("250-CHUNKING\r\n")) // this is BDAT CHUNKING, the BDAT command must be supported
		// this has to be sent without a - to allow the other extensions to be specified with the per EHLO
		conn.Write([]byte("250 SMTPUTF8\r\n"))

	} else if (bytes.Index(c, []byte("MAIL FROM:")) == 0) {

		//fmt.Printf("MAIL FROM command\n")

		i1 := bytes.Index(c, []byte("<"))
		i2 := bytes.Index(c, []byte(">"))
		s := make([]byte, 0)
		if (i1 >= 0 || i2 >= 0 || i2 < i1) {
			s = c[i1+1:i2]
		}

		//fmt.Printf("send address (between %d and %d): %s\n", i1, i2, s)

		var mail_from_authed = mail_from_func(string(s))

		if (mail_from_authed == false) {
			// return 221
			conn.Write([]byte("221\r\n"))
			conn.Close()
		} else {
			conn.Write([]byte("250 OK\r\n"))
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

		*authed = rcpt_to_func(string(s))

		if (*authed == true) {
			conn.Write([]byte("250 OK\r\n"))
		} else {
			// 221 <domain>
			// service closing transmission channel
			conn.Write([]byte("221\r\n"))
			conn.Close()
		}

	} else if (bytes.Index(c, []byte("DATA")) == 0) {

		//fmt.Printf("DATA command\n")

		if (*authed) {
			*parse_data = true
			conn.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
			//fmt.Println("DATA received, replied with 354")
		} else {
			// 221 <domain>
			// service closing transmission channel
			conn.Write([]byte("221\r\n"))
			conn.Close()
		}

	} else if (bytes.Index(c, []byte("RSET")) == 0) {

		//fmt.Printf("RSET command\n")

		conn.Write([]byte("250 OK\r\n"))

		fmt.Println("RSET received, replied with 250")

	} else if (bytes.Index(c, []byte("QUIT")) == 0) {

		//fmt.Printf("QUIT command\n")

		conn.Write([]byte("221 Bye\r\n"))
		conn.Close()

	} else {

		// 502 command not implemented
		conn.Write([]byte("502\r\n"))

	}

}

func smtpHandleClient(is_new bool, using_tls bool, conn net.Conn, tls_config tls.Config, ip string, config Config, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) {

	//fmt.Printf("new SMTP connection from %s\n", ip)

	if (is_new == true) {
		conn.Write([]byte("220 " + config.Fqdn + " go-mail\r\n"))
	}

	authed := false
	parse_data := false
	to_address := ""

	login := make([]byte, 0)
	var parts_headers = make([]map[string]string, 0)
	var parts = make([][]byte, 0)

	total_cmds := 0
	total_bytes := 0

	smtp_data := make([]byte, 0)

	for {

		if (authed == false && total_cmds > 3) {
			// should be authorized
			conn.Write([]byte("221 unauthenticated send limit exceeded\r\n"))
			conn.Close()
			break
		}

		if (authed == false && total_bytes > 400) {
			// disconnect unauthed connections that have sent more than N bytes
			conn.Write([]byte("221 unauthenticated send limit exceeded\r\n"))
			conn.Close()
			break
		}

		buf := make([]byte, 1400)
		n, err := conn.Read(buf)
		total_bytes += n
		if err != nil {
		    //fmt.Printf("server: conn: read: %s\n", err)
		    // close connection
		    conn.Close()
		    break
		}

		//fmt.Printf("smtp read length: %d\n", n)
		//fmt.Println(string(buf))

		if (total_bytes > 1024 * 1000 * 3) {
			//fmt.Println("smtp data too big from ", ip)
			conn.Write([]byte("221 send limit exceeded\r\n"))
			conn.Close()
			break
		}

		// set buf to read length
		buf = buf[:n]

		// add buf to smtp_data
		for l := range buf {
			smtp_data = append(smtp_data, buf[l])
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
					smtpExecCmd(using_tls, conn, tls_config, config, line, &authed, &to_address, &parse_data, &total_cmds, &login, ip, mail_from_func, rcpt_to_func, headers_func, full_message_func)
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

				fmt.Printf("smtp parse_data: (%d)\n######\n%s\n######\n", len(smtp_data), smtp_data[0:data_block_end])
				fmt.Printf("<CR><LF>.<CR><LF> found at: %d of %d\n", data_block_end, len(smtp_data))

				// validate DKIM without the \r\n.\r\n
				smtp_data = smtp_data[0:data_block_end]
				dkim_status, dkim_err := dkim.Verify(&smtp_data)
				fmt.Println("dkim, 1==valid:", dkim_status, dkim_err)

				boundary := ""

				// parse the headers
				headers := make(map[string]string)
				var headers_sent = false

				// decode quoted-printable body parts
				var decode_qp = false

				// limit the number of DKIM lookups
				var dkim_lookups = 0
				var validate_dkim = false
				var dkim_valid = false
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
								authed = headers_func(headers)

								if (authed == false) {
									conn.Write([]byte("221\r\n"))
									conn.Close()
									return
								}

								// only send them once
								headers_sent = true
							}

							//fmt.Printf("email body or new block start at %d\n", i)

							// skip the newline
							i = i + 1

							if (validate_dkim == true) {

								fmt.Println("DKIM signing algorithm:", dkim_hp["a"])

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

								if (dkim_expired == true) {
									fmt.Println("DKIM header is expired")
								} else if (dkim_hp["a"] != "rsa-sha256") {
									fmt.Println("unsupported DKIM signing algorithm", dkim_hp["a"])
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
									fmt.Println("body hash base64 bh=", dkim_hp["bh"])

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
										var canonicalized_body_sha256_sum = sha256.Sum256(canonicalized_body)
										// convert [32]byte to []byte
										var formatted_canonicalized_body_sha256_sum []byte
										for b := range canonicalized_body_sha256_sum {
											formatted_canonicalized_body_sha256_sum = append(formatted_canonicalized_body_sha256_sum, canonicalized_body_sha256_sum[b])
										}

										canonicalized_body_hash_base64 = base64.StdEncoding.EncodeToString(formatted_canonicalized_body_sha256_sum)

									} else if (strings.Index(dkim_hp["c"], "relaxed") > -1) {

										// relaxed body canonicalization

									}

									if (canonicalized_body_hash_base64 == dkim_hp["bh"]) {

										// body hash in the headers is the same as the calculated body hash
										// valid

										fmt.Println("DKIM bh= tag matches hash of body content with length optionally specified by l= tag")

										// the DKIM public key of the sending domain is in p_value

										// b= is the signature of the headers and body
										fmt.Println("signature base64 b=", dkim_hp["b"])

										// the dkim data is valid
										//dkim_valid = true

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
							//fmt.Println("testing if line is a header")

							ss := bytes.Split(v, []byte(":"))
							for ssc := range ss {
								// trim spaces
								ss[ssc] = bytes.Trim(ss[ssc], " ")
							}

							if (len(ss) > 1) {

								// ss[0] is the header name, store it in lowercase
								header_name := bytes.ToLower(ss[0])
								// remove the header name from the ss slice
								ss = ss[1:len(ss)]

								// put all the rest of the parts back together for the header value
								header_value := bytes.Join(ss, []byte(":"))

								//fmt.Printf("smtp data header: %s: %s\n", header_name, header_value)

								// add header
								headers[string(header_name)] = string(header_value)

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
								} else if (string(header_name) == "dkim-signature" && dkim_lookups <= 3) {

									// only allow 3 DKIM lookups to prevent a sending client from making the server perform many DNS requests
									fmt.Println("\nDKIM Validation")

									// validate DKIM using the 6 required fields
									// v, a, d, s, bh, b
									// and possibly the optional field
									// l
									dkim_hp = smtpParseTags(header_value)

									if (dkim_hp["v"] == "" || dkim_hp["a"] == "" || dkim_hp["d"] == "" || dkim_hp["s"] == "" || dkim_hp["bh"] == "" || dkim_hp["b"] == "") {
										fmt.Println("incomplete dkim header")
									} else {

										// required DKIM header tags
										// v= is the version
										// a= is the signing algorithm
										// d= is the domain
										// s= is the selector (subdomain)

										// get the DKIM public key from DNS
										// it should be looked up from many physical locations on the planet
										// and they should all be the same or DKIM is invalid (smtp TLS validation from server to client per client TLS domain is not in SMTP, that would make SMTP perfect)
										// make a TXT dns query to selector._domainkey.domain to get the key
										var query_domain = dkim_hp["s"] + "._domainkey." + dkim_hp["d"]
										fmt.Println("DKIM DNS Query TXT:", query_domain)

										// keep track of the number of dkim lookups
										dkim_lookups = dkim_lookups + 1

										l_txts, l_err := net.LookupTXT(query_domain)
										if (l_err == nil) {

											var p_value = ""
											for t := range l_txts {
												// get the last non empty p= value in the string results
												var pp = smtpParseTags([]byte(l_txts[t]))
												if (pp["p"] != "") {
													p_value = pp["p"]
												}
											}

											fmt.Println("TXT Response base64 p=", p_value)
											validate_dkim = true

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

				// empty smtp_data
				smtp_data = nil

				// set parse_data back to false
				parse_data = false

				// full email received, handle it
				full_message_func(parts_headers, parts, dkim_valid)

				// free the memory
				parts = nil
				parts_headers = nil

				// write 250 OK
				conn.Write([]byte("250 OK\r\n"))

				// now the client may send another email or disconnect

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

	fmt.Print("SMTP listening on " + strconv.FormatInt(lport, 10) + " with STARTTLS\n")

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

		go smtpHandleClient(true, false, conn, tls_config, ip, config, mail_from_func, rcpt_to_func, headers_func, full_message_func)

	}

}

func smtpListenTLS(ip_ac ipac.Ipac, lport int64, config Config, tls_config tls.Config, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) {

	service := ":" + strconv.FormatInt(lport, 10)
	listener, err := tls.Listen("tcp", service, &tls_config)

	if err != nil {
		fmt.Printf("server: listen: %s\n", err)
		os.Exit(1)
	}

	fmt.Print("SMTP listening on " + strconv.FormatInt(lport, 10) + " with TLS\n")

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

		go smtpHandleClient(true, true, conn, tls_config, ip, config, mail_from_func, rcpt_to_func, headers_func, full_message_func)

	}

}

func smtpServer(ip_ac ipac.Ipac, config Config, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) {

	cert, err := tls.LoadX509KeyPair(config.SslCert, config.SslKey)

	if err != nil {
		fmt.Printf("server: loadkeys: %s\n", err)
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

	// keep main thread open
	select {}

}
