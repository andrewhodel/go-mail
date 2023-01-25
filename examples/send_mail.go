package main

import (
	"fmt"
	"net/mail"
	"github.com/andrewhodel/go-mail"
)

func main() {

	var to []mail.Address
	to = append(to, mail.Address{"Andrew Hodel", "andrew@xyzbots.com"})

	// func SendMail()
	//
	// arguments in order
	//
	// sending_host_string		string			fqdn or hostname of the client (sending) host
	// username			string			ESMTP AUTH username
	// password			string			ESMTP AUTH password
	// receiving_host_tls_config	*tls.Config		TLS Config of the server
	// receiving_host		string			server address
	// port				int			server port, 25 does not use TLS by default
	// from				mail.Address
	// to				[]mail.Address		list of addresses sent to and in the to header
	// cc				[]mail.Address		list of addresses sent to and in the cc header
	// bcc				[]mail.Address		list of addresses sent to and in the bcc header
	// subj				string
	// body				string
	// dkim_private_key		string			DKIM private key (private key to use to sign the DKIM headers in the email)
	// dkim_domain			string			DKIM domain (address of DKIM public key TXT record)
	// dkim_signing_algo		string			DKIM signing algorithm (rsa-sha256 supported)
	err := gomail.SendMail("localhost", "user", "pass", nil, "xyzbots.com", 25, nil, mail.Address{"", "newuser@unknown.unknown_tld"}, to, nil, nil, "New go-mail user", "New go-mail user.", "", "", "")

	if (err != nil) {
		fmt.Println("gomail.SendMail() error:", err)
	} else {
		fmt.Println("email received by server")
	}

}
