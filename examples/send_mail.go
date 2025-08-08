package main

import (
	"fmt"
	"net/mail"
	"go-mail"
)

func main() {

	var om gomail.OutboundMail
	om.From = mail.Address{"", "newuser@unknown.unknown_tld"}
	om.Subj = "New go-mail user"
	om.Body = []byte("New go-mail user")

	// if you have not setup a server yet, you can send an email directly to an IP address
	om.ReceivingHost = "172.16.10.24"
	// this works insecurely without TLS
	// unless om.RequireServerNameOfReceivingAddresses = true or the TLS certificate has a Subject Alternative Name (SAN) list with the IP address of om.ReceivingHost

	var to []mail.Address
	to = append(to, mail.Address{"Andrew Hodel", "andrew@xyzbots.com"})
	om.To = to

	// the data as sent to the server is in em
	err, send_resp, em := gomail.SendMail(om)

	if (err != nil) {
		fmt.Println("gomail.SendMail() error:", err)
	} else {
		fmt.Println("email received by server", send_resp.ReplyCode, send_resp.TLSInfo, em)
	}

}
