package main

import (
	"fmt"
	"net/mail"
	"github.com/andrewhodel/go-mail"
)

func main() {

	/*
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
		Headers				map[string]string	Headers to send, these overwrite: OutboundMail.From, OutboundMail.To, OutboundMail.Cc, OutboundMail.Bcc, OutboundMail.Subj when defined in the Headers map[string]string
	}
	*/

	var om gomail.OutboundMail
	om.SendingHost = "localhost"
	om.Username = "user"
	om.Password = "pass"
	om.ReceivingHost = "xyzbots.com"
	om.Port = 25
	om.From = mail.Address{"", "newuser@unknown.unknown_tld"}
	om.Subj = "New go-mail user"
	om.Body = []byte("New go-mail user")

	var to []mail.Address
	to = append(to, mail.Address{"Andrew Hodel", "andrew@xyzbots.com"})
	om.To = to

	// the data as sent to the server is in em
	err, send_resp, em := gomail.SendMail(om)
	_ = em

	if (err != nil) {
		fmt.Println("gomail.SendMail() error:", err)
	} else {
		fmt.Println("email received by server", send_resp.ReplyCode, send_resp.TLSInfo, em)
	}

}
