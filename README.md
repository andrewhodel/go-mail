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
	SMTP Client that supports DKIM, ESMTP AUTH and STARTTLS.

SmtpServer()
	Start SMTP Server(s) with or without TLS, there are closures for each step of the SMTP process.

Pop3Server()
	Start POP3 Server with TLS, there are closures for each step of the POP3 process.

ParseTags()
	Parse string with key=value tags to map[string]string.
```

# Examples

Read the programs in `examples/`.

# Installation

```
GO111MODULE=off go get github.com/andrewhodel/go-ip-ac
GO111MODULE=off go get github.com/andrewhodel/go-mail
```

Run with `GO111MODULE=off go run program.go` or `sudo GOPATH=/home/ec2-user/go GO111MODULE=off go run program.go` for port numbers lower than 1024.

# License

MIT
