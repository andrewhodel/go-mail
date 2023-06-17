# go-mail

Email in a Go module.

Include the module and easily integrate an email client or a server with closures (callbacks).

```
* SMTP Client and Server {RFC 5321} (with {RFC 8314} and without TLS)
* ESTMP Extensions (8BITMIME, AUTH, STARTTLS, ENHANCEDSTATUSCODE, PIPELINING, SMTPUTF8)
* DKIM {RFC 6376}

* POP3 {RFC 1939} (with {RFC 8314} TLS)
```

# Functions

```go
SendMail()
	SMTP Client that supports DKIM, ESMTP AUTH and STARTTLS

SmtpServer()
	Start SMTP Server(s) with or without TLS

PopServer()
	Start POP Server with TLS

ParseTags()
	Parse string with key=value tags to map[string]string
```

# SMTP Client SendMail()

Read `examples/send_mail.go`

```go
type OutboundMail struct {
	SendingHost			string			fqdn or hostname of the client (sending) host
	Username			string			ESMTP AUTH username
	Password			string			ESMTP AUTH password
	ReceivingHostTlsConfig		*tls.Config		TLS Config of the server
	ReceivingHost			string			server address
	Port				int			server port, 25 does not use TLS by default
	From				mail.Address
	To				[]mail.Address		list of addresses sent to and in the to header
	Cc				[]mail.Address		list of addresses sent to and in the cc header
	Bcc				[]mail.Address		list of addresses sent to and in the bcc header
	Subj				string
	Body				[]byte
	DkimPrivateKey			[]byte			DKIM private key (private key to use to sign the DKIM headers in the email)
	DkimDomain			string			DKIM domain (address of DKIM public key TXT record)
	DkimSigningAlgo			string			DKIM signing algorithm (rsa-sha256 supported)
	DkimExpireSeconds		int			DKIM seconds from send time to expire (default 3600)
}
```

# Server Configuration Struct

Passed as an argument to `SmtpServer()` and `Pop3Server()`.

`LoadCertificatesFromFiles = false` will load the certificate data from `SslKey, SslCert and SslCa`.

`LoadCertificatesFromFiles = true` will load the certificate data from the file paths specified in `SslKey, SslCert and SslCa`.

`Fqdn` is the fully qualified domain name of the email server.

```go
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
```

# SMTP Server

Read `examples/mail_server.go`

```go
gomail.SmtpServer(ip_ac, config, func(from_address string, ip string, auth_login string, auth_password string) bool {

	// from_address		MAIL FROM value
	// ip			ip address of the sending client
	// auth_login		ESTMP AUTH login
	// auth_password	ESTMP AUTH password

	// MAIL FROM
	fmt.Println("mail from", from_address)
	fmt.Println("AUTH login", auth_login)
	fmt.Println("AUTH password", auth_password)

	// get the email local-part and domain
	//address_parts := strings.Split(from_address, "@")
	//fmt.Println(address_parts)

	// return true if allowed
	// return false to ignore the email, disconnect the socket and add an invalid auth to ip_ac
	return true

}, func(to_address string, ip string, auth_login string, auth_password string) bool {

	// to_address		RCPT TO value
	// ip			ip address of the sending client
	// auth_login		ESTMP AUTH login
	// auth_password	ESTMP AUTH password

	// RCPT TO
	fmt.Println("mail to", to_address)

	// return true if allowed
	// return false to ignore the email, disconnect the socket and add an invalid auth to ip_ac
	return true

}, func(headers map[string]string, ip string, auth_login string, auth_password string) bool {

	// headers		parsed headers
	// ip			ip address of the sending client
	// auth_login		ESTMP AUTH login
	// auth_password	ESTMP AUTH password

	// headers
	// verify the message-id with stored messages to the same address to prevent duplicates

	// you can use ParseTags() to parse strings with key=value; parts into a map[string]string
	fmt.Println("headers")
	for h := range headers {
		fmt.Println(h, headers[h])
	}

	// return true if allowed
	// return false to ignore the email, disconnect the socket and add an invalid auth to ip_ac
	return true

}, func(email_data *[]byte, headers *map[string]string, parts_headers *[]map[string]string, parts *[][]byte, dkim_valid *bool, ip *string, auth_login *string, auth_password *string) {

	// email_data		raw email data as received (headers and body)
	// headers		parsed headers
	// parts_headers	headers of each body block
	// parts		each body block
	// dkim_valid		true if DKIM validated by the domain's public key
	// ip			ip address of the sending client
	// auth_login		ESTMP AUTH login
	// auth_password	ESTMP AUTH password

	fmt.Println("full email received, length", len(*email_data))
	fmt.Println("dkim valid:", *dkim_valid)
	fmt.Println("ip of smtp client", *ip)

	// email is in parts
	// a part can be an attachment or a body with a different content-type
	// there is a parts_headers item for each part

	fmt.Println("parts:", len(*parts))
	for p := range *parts {
		fmt.Println("###### part:", p)
		fmt.Println("part headers:", (*parts_headers)[p])
		if (len((*parts)[p]) > 10000) {
			fmt.Println(string((*parts)[p][0:10000]))
		} else {
			fmt.Println(string((*parts)[p]))
		}
	}

})
```

# POP3 Server

Read `examples/mail_server.go`

```go
gomail.Pop3Server(config, ip_ac, func(ip string, auth_login string, auth_password string, shared_secret string) bool {

	// ip			ip address
	// auth_login		login
	// auth_password	password

	fmt.Println("POP3 server auth login", auth_login, "password", auth_password, "shared_secret", shared_secret)

	if (shared_secret != "") {
		// if there is a shared secret, the APOP command is being used

		// validate the username and get the known password

		// prepend shared_secret to the known password and the md5sum as a hex value will match auth_password if the sent password is valid
		m := md5.New()
		m.Write([]byte(shared_secret + "asdf"))
		valid_sum := hex.EncodeToString(m.Sum(nil))

		fmt.Println("valid_sum", valid_sum)

		if (valid_sum == auth_password) {
			return true
		} else {
			return false
		}

	}

	// there is no shared secret, validate auth_login and auth_password

	// return true if allowed
	// return false to disconnect the socket and add an invalid auth to ip_ac
	return true

}, func(auth_login string) (string, string) {

	// STAT
	// auth_login		login

	fmt.Println("POP3 STAT", auth_login)

	// return the total message count and size of all messages in bytes
	// strings allow larger than uint64 max values
	return "1", "5"

}, func(auth_login string) (string, []string, []string) {

	// LIST
	// auth_login		login

	fmt.Println("POP3 LIST", auth_login)

	// each message needs an identifier that is a whole number, beginning with 1
	// the message identifiers are used to identify messages in the RETR and DELE commands by POP3 clients

	// return total size in bytes of all messages, the message identifiers and the size of each message in bytes
	// strings allow larger than uint64 max values
	return "5", []string{"1"}, []string{"5"}

}, func(auth_login string, msg_id string) string {

	// RETR retrieve message by id
	// auth_login		login
	// msg_id		message identifier

	fmt.Println("POP3 RETR", auth_login, "message identifier", msg_id)

	// get the message and return it as a string
	return "12345"

}, func(auth_login string, msg_id string) (bool, string) {

	// DELE
	// auth_login		login
	// msg_id		message identifier

	fmt.Println("POP3 DELE", auth_login, "message identifier", msg_id)

	// delete the message and return the message deleted status and error message if the message was not deleted
	return true, ""

})
```

# Installation

```
GO111MODULE=off go get github.com/andrewhodel/go-ip-ac
GO111MODULE=off go get github.com/andrewhodel/go-mail
```

Run with `GO111MODULE=off go run program.go` or `sudo GOPATH=/home/ec2-user/go GO111MODULE=off go run program.go` for port numbers lower than 1024.

# License

MIT
