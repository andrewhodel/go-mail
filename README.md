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

Without `outbound_mail.RequireServerNameOfReceivingAddresses = true` any router in the network path between the SMTP origin and the SMTP destination can steal or copy the email being sent.

The routers between the mail servers can steal emails by acting as the destination IP address.  Although verification of origin is achieved by DKIM, the destination server is only verified if the origin server requires the TLS servernname of the destination server and validates that it is the same as the destination domain in the email address.

That means that email hosting as provided by Google Workspaces (looks like Gmail) for domains other than gmail.com will fail to receive email with `outbound_mail.RequireServerNameOfReceivingAddresses = true` if Google Workspaces does not require their customers to upload a TLS certificate and the destination domain of the email address does not match that of the server.

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

`SendMail()` returns a `TLSInfo` string in the second response argument that tells the TLS ServerName, Hostname and IP Address.

# License

MIT

# Verification of Authorship

The OP_RETURN data in this BTC transaction provides a sha256 checksum of the project file.  The BTC transaction provides a transaction date.  The file contains the author and the work.

https://blockstream.info/tx/0914c23220712ff2eb96b4c49b7c2df3a128be04a5abd67ed3831d680a70c4a4?expand

mail.go

        commit                  3fade57d4b48c4910e39be46036e6bea3629ec73
        sha256                  f74ef27f51929dce6aa70d6519addf87ff7a642980fe62dad5c2e738ae6ad137
        op_return               7368613235362066373465663237663531393239646365366161373064363531396164646638376666376136343239383066653632646164356332653733386165366164313337
        bitcoin transaction     0914c23220712ff2eb96b4c49b7c2df3a128be04a5abd67ed3831d680a70c4a4
        date                    4/9/2024
