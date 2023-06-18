package main

import (
	"os"
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
		MessageId                       string			Some SMTP servers require a message-id header for each email
	}
	*/

	pk, pk_err := os.ReadFile("../xyzbots-dkim/private.key")

	if (pk_err != nil) {
		fmt.Println(pk_err)
		os.Exit(1)
	}

	var om gomail.OutboundMail
	om.DkimPrivateKey = pk
	om.DkimDomain = "fgkhdgsfgdds._domainkey.xyzbots.com"
	om.From = mail.Address{"", "andrew@xyzbots.com"}
	om.Subj = "New go-mail user"
	om.Body = []byte("New go-mail user")

	var to []mail.Address
	to = append(to, mail.Address{"Andrew Hodel", "andrewhodel@gmail.com"})
	om.To = to

	// the data as sent to the server is in em
	err, em := gomail.SendMail(om)
	_ = em

	if (err != nil) {
		fmt.Println("gomail.SendMail() error:", err)
	} else {
		fmt.Println("email received by server")
	}

}
