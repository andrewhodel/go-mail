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

	// the data as sent to the server is in em
	err, send_resp, em := gomail.SendMail(om)
	_ = em

	if (err != nil) {
		fmt.Println("gomail.SendMail() error:", err)
	} else {
		fmt.Println("email received by server", send_resp.ReplyCode, send_resp.TLSInfo, em)
	}

}
