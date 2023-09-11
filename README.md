# go-mail

Email in a Go module.

Include the module and easily integrate an email client or a server with closures (callbacks).

```
* SMTP Client and Server {RFC 5321} (with {RFC 8314} and without TLS)
* ESTMP Extensions (8BITMIME, AUTH, STARTTLS, ENHANCEDSTATUSCODE, PIPELINING, SMTPUTF8)
* DKIM {RFC 6376}

* POP3 {RFC 1939} (with {RFC 8314} TLS)
* IMAP4 {RFC 3501} (INCOMPLETE, WIP, BETA)
```

# Functions

```go
SendMail()
	SMTP Client that supports DKIM, ESMTP AUTH and STARTTLS.

SmtpServer()
	Start SMTP Server(s) with or without TLS, there are closures for each step of the SMTP process.

Pop3Server()
	Start POP3 Server with TLS, there are closures for each step of the POP3 process.

Imap4Server()
	Start IMAP4 Server with TLS, there are closures for each step of the IMAP4 process.

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

# SendMail() and TLS

If `outbound_mail.RequireTLS` is true, TLS or STARTTLS must be used on the connection.

## Absolutely secure Email via SMTP with TLS

Without `outbound_mail.RequireServerNameOfReceivingAddresses = true` any router in the network path between the SMTP client and the receiving SMTP server can modify the DNS MX response and steal or copy the email being sent.

That means that email hosting as provided by Google Workspaces (looks like Gmail) for domains other than gmail.com fail to receive email with `outbound_mail.RequireServerNameOfReceivingAddresses = true` because Google Workspaces does not require their customers to upload a TLS certificate.

This is the `SendMail()` logic that explains how to use SMTP email securely.

```go
if (outbound_mail.RequireServerNameOfReceivingAddresses == true) {

        if (outbound_mail.ReceivingHostTlsConfig != nil) {

                // the ServerName can be set in ReceivingHostTlsConfig
                // it is not possible to use RequireServerNameOfReceivingAddresses and ReceivingHostTlsConfig with the same email
                return errors.New("it is not possible to use RequireServerNameOfReceivingAddresses and ReceivingHostTlsConfig with the same email because ServerName can be set in ReceivingHostTlsConfig"), 0, nil

        }               
                        
        if (all_same_receiving_domain == true) {
                // all the receiving email addresses are the same domain
        
                if (servername_from_receiving_addresses == outbound_mail.ReceivingHost) {

                        // the email addresses domain matches ReceivingHost exactly
                        // keep the servername from ReceivingHost

                } else if (strings.Index(outbound_mail.ReceivingHost, servername_from_receiving_addresses) == len(outbound_mail.ReceivingHost) - len(servername_from_receiving_addresses)) {

                        // the email addresses domain matches ReceivingHost's major domain (*.domain.tld) regardless of having a subdomain
                        // keep the servername from ReceivingHost

                        // allowing hosts that are subdomains of the receiving domain and using TLS to be validated

                        // also allowing 3rd party hosting of email by setting the MX record of domain.tld to unused-subdomain.domain.tld and creating an A record of unused-subdomain.domain.tld
                        // with the IP address of the 3rd party host, then providing the third party host with the TLS certificate of unused-subdomain.domain.tld

                } else {

                        // use the servername from the receiving email addresses if it does not match ReceivingHost or a subdomain of ReceivingHost
                        // this will work with any DNS MX record while STARTTLS returns the valid TLS certificate with ServerName of the receiving email addresses
                        outbound_mail.STARTTLS_ServerName = servername_from_receiving_addresses

                        // allowing 3rd party hosting of email by providing SMTP and requiring STARTTLS that uses the TLS certificate and servername of the receiving email addresses

                }       
                                
        } else if (all_same_receiving_domain == false) {
                
                return errors.New("Receiving email addresses (TO, CC and BCC) must all be the same if RequireServerNameOfReceivingAddresses is true"), 0, nil
        
        }
}
```

# License

MIT

# bitcoin OP_RETURN validation of authorship

bitcoin transaction ID: ff269df685d94d176e107fc8c4d0d2e819d9f5b20ca9b5833bb3edad15d429df
https://www.blockstream.info/nojs/tx/ff269df685d94d176e107fc8c4d0d2e819d9f5b20ca9b5833bb3edad15d429df?expand

The github URL with the commit identifier is forever recorded in the bitcoin transaction ff269df685d94d176e107fc8c4d0d2e819d9f5b20ca9b5833bb3edad15d429df.  The git commit identifiers prove all prior commits in the repository and the bitcoin transaction proves the date and time of the validation.
