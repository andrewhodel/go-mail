package main

import (
	"fmt"
	"net/mail"
	"go-mail"
)

func main() {

	var om gomail.OutboundMail
	om.Username = "user"
	om.Password = "pass"
	om.Port = 25
	om.From = mail.Address{"", "newuser@unknown.unknown_tld"}
	om.Subj = "New go-mail user"
	om.Body = []byte("New go-mail user")

	var to []mail.Address
	to = append(to, mail.Address{"Andrew Hodel", "andrew@xyzbots.com"})
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
