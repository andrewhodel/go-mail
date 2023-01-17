# go-mail

Email in a go module

* SMTP {RFC 5321} (with {RFC 8314} and without TLS)
* ESTMP Extensions (8BITMIME, AUTH, STARTTLS, ENHANCEDSTATUSCODE, PIPELINING, SMTPUTF8)
* DKIM {RFC 6376}

* POP3 {RFC 1939} (with {RFC 8314} TLS)

# functions

```go
SmtpServer()
	Start SMTP Server(s) with or without TLS

PopServer()
	Start POP Server with TLS

ParseTags()
	Parse string with key=value tags to map[string]string
```

# example

```go

```

# install

```
GO111MODULE=off go get github.com/andrewhodel/go-ip-ac
```

Run your Go program with `GO111MODULE=off go run program.go` or `sudo GOPATH=/home/ec2-user/go GO111MODULE=off go run program.go` if you need `sudo` access for port numbers lower than 1024.
