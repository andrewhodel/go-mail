package main

import (
	"fmt"
	"net/mail"
	"go-mail"
)

func main() {

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
