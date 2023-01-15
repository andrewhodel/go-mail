# go-mail

email in a go module

* SMTP (with and without TLS)
* ESTMP Extensions (8BITMIME, AUTH, STARTTLS, ENHANCEDSTATUSCODE, PIPELINING, SMTPUTF8)
* POP (TLS)
* DKIM

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
