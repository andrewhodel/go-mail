package main

import (
	"os"
	"fmt"
	"net/mail"
	"go-mail"
)

func main() {

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

	// returns gomail.SentMail
	var sent_mail = gomail.SendMail(&om)

	if (sent_mail.Error != nil) {

		fmt.Println("gomail.SendMail() error:", sent_mail.Error.Error())

	} else {

		// the email may be sent to multiple servers

		for hostname := range sent_mail.ReceivingServers {

			var rs = sent_mail.ReceivingServers[hostname]

			if ((*rs).Error != nil) {
				fmt.Println("email not received by server", hostname, (*rs).Error.Error())
			} else {
				fmt.Println("email received by server", hostname, (*rs).ReplyCode, (*rs).TLSInfo)
			}

		}

	}

}
