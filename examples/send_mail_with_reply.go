package main

import (
	"fmt"
	"net/mail"
	"go-mail"
	"xyzdb"
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

	om.Headers = make(map[string] string)

	var first_message_id = xyzdb.CreateId(xyzdb.IdByteLength)
	om.Headers["message-id"] = "<" + first_message_id + ">"

	var to []*mail.Address
	to = append(to, &mail.Address{"Andrew Hodel", "andrew@xyzbots.com"})
	om.To = to

	// if you have not setup a server yet, you can send an email directly to an IP address
	// this works insecurely without TLS
	// unless om.RequireServerNameOfReceivingAddresses = true or the TLS certificate has a Subject Alternative Name (SAN) list with the IP address of om.ReceivingHost
	om.ReceivingHost = "172.16.10.24"

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

	var om1 gomail.OutboundMail
	om1.From = &mail.Address{"", "newuser@unknown.unknown_tld"}
	om1.Subj = "New go-mail user"

	var body1 = []byte("reply to new go-mail user.")
	var html_body1 = []byte("<div>reply to new go-mail user.</div>")

	om1.Body = &body1
	om1.HtmlBody = &html_body1

	om1.Headers = make(map[string] string)

	var second_message_id = xyzdb.CreateId(xyzdb.IdByteLength)
	om1.Headers["message-id"] = "<" + second_message_id + ">"
	om1.Headers["in-reply-to"] = "<" + first_message_id + ">"
	om1.Headers["references"] = "<" + first_message_id + ">"

	// if you have not setup a server yet, you can send an email directly to an IP address
	om1.ReceivingHost = "172.16.10.24"
	// this works insecurely without TLS
	// unless om.RequireServerNameOfReceivingAddresses = true or the TLS certificate has a Subject Alternative Name (SAN) list with the IP address of om.ReceivingHost

	var to1 []*mail.Address
	to1 = append(to1, &mail.Address{"Andrew Hodel", "andrew@xyzbots.com"})
	om1.To = to1

	// returns gomail.SentMail
	var sent_mail1 = gomail.SendMail(&om1)

	if (sent_mail1.Error != nil) {

		fmt.Println("gomail.SendMail() error:", sent_mail1.Error.Error())

	} else {

		// the email may be sent to multiple servers

		for hostname := range sent_mail1.ReceivingServers {

			var rs = sent_mail1.ReceivingServers[hostname]

			if ((*rs).Error != nil) {
				fmt.Println("email not received by server", hostname, (*rs).Error.Error())
			} else {
				fmt.Println("email received by server", hostname, (*rs).ReplyCode, (*rs).TLSInfo)
			}

		}

	}

}
