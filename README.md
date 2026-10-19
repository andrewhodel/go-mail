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
SendMail(outbound_mail *OutboundMail)
	SMTP Client that supports DKIM, ESMTP AUTH and STARTTLS.

SmtpServer(ip_ac *ipac.Ipac, config Config, mail_from_func mail_from_func, rcpt_to_func rcpt_to_func, headers_func headers_func, full_message_func full_message_func) ([]error)
	Start TLS and non TLS servers on multiple ports based on configuration.

Pop3Server(config Config, ip_ac *ipac.Ipac, pop3_auth_func pop3_auth_func, pop3_stat_func pop3_stat_func, pop3_list_func pop3_list_func, pop3_retr_func pop3_retr_func, pop3_dele_func pop3_dele_func) (error)
	Start POP3 Server with TLS.

Imap4Server(config Config, ip_ac *ipac.Ipac, imap4_auth_func imap4_auth_func, imap4_list_func imap4_list_func, imap4_select_func imap4_select_func, imap4_fetch_func imap4_fetch_func, imap4_store_func imap4_store_func, imap4_close_func imap4_close_func, imap4_search_func imap4_search_func) (error)
	Start IMAP4 Server with TLS.

ParseTags(input string) (map[string]string, []string)
	Parse string with key=value tags to map[string]string.
```

# Examples

Read the examples in `examples/`.

Read the config file in `examples/`, the maximum inbound email size is important.

Set the DkimDomain in `examples/mail_server.go`.

# Installation

```
cd go/src
git clone github.com/andrewhodel/go-ip-ac
git clone github.com/andrewhodel/go-mail
```

# SendMail() and TLS

If `outbound_mail.RequireTLS` is true, TLS or STARTTLS must be used on the connection.

## Absolutely secure outbound Email via SMTP with TLS

Set `outbound_mail.RequireServerNameOfReceivingAddresses = true` or any router in the network path between the SMTP origin and the SMTP destination can steal or copy the email being sent.

The routers between the mail servers can steal emails by acting as the destination IP address.  Although verification of origin is achieved by DKIM, the destination server is only verified if the origin server requires the TLS servernname of the destination server and validates that it is the same as the destination domain in the email address.

That means that email hosting as provided by Google Workspaces (looks like Gmail) for domains other than gmail.com will fail to receive email with `outbound_mail.RequireServerNameOfReceivingAddresses = true` if Google Workspaces does not require their customers to upload a TLS certificate and the destination domain of the email address does not match that of the server.

`SendMail()` returns a `TLSInfo` string of each server connected to that tells the TLS ServerName, Hostname and IP Address.  The Hostname and ServerName can be proven to match.

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
