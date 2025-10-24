package main

import (
	"fmt"
	"net/mail"
	"go-mail"
)

func main() {

	var om gomail.OutboundMail
	om.From = &mail.Address{"", "newuser@unknown.unknown_tld"}
	om.Subj = "New go-mail user"

	var body = []byte("there is a new go-mail user.")
	om.Body = &body

	var html_body = []byte("<div>there is a new go-mail user.</div>")
	om.HtmlBody = &html_body

	var attachment_file = []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	var attachment gomail.Attachment
	attachment.File = &attachment_file
	attachment.Name = "text.txt"
	attachment.Type = "text/plain"
	om.Attachments = append(om.Attachments, &attachment)

	// if you have not setup a server yet, you can send an email directly to an IP address
	om.ReceivingHost = "172.16.10.24"
	// this works insecurely without TLS
	// unless om.RequireServerNameOfReceivingAddresses = true or the TLS certificate has a Subject Alternative Name (SAN) list with the IP address of om.ReceivingHost

	var to []*mail.Address
	to = append(to, &mail.Address{"Andrew Hodel", "andrew@xyzbots.com"})
	om.To = to

	// returns gomail.SentMail
	var sent_mail = gomail.SendMail(&om)

	if (sent_mail.Error != nil) {

		// email did not even attempt to send to servers, invalid email

		fmt.Println("gomail.SendMail error:", sent_mail.Error.Error())

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
