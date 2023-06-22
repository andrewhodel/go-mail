package main

import (
	"io/ioutil"
	"fmt"
	"encoding/json"
	"crypto/md5"
	"encoding/hex"
	"os"
	"github.com/andrewhodel/go-ip-ac"
	"github.com/andrewhodel/go-mail"
)

var config gomail.Config
var ip_ac ipac.Ipac

func main() {

	ipac.Init(&ip_ac)

	// read the configuration file
	cwd, cwd_err := os.Getwd()
	if (cwd_err != nil) {
		fmt.Println(cwd_err)
		os.Exit(1)
	}
	config_file_data, err := ioutil.ReadFile(cwd + "/config.json")

	if (err != nil) {
		fmt.Printf("Error reading configuration file ./config.json (" + cwd + "/config.json): %s\n", err)
	}

	config_json_err := json.Unmarshal(config_file_data, &config)
	if (config_json_err != nil) {
		fmt.Printf("Error decoding ./config.json: %s\n", config_json_err)
		os.Exit(1)
	}

	gomail.SmtpServer(ip_ac, config, func(from_address string, ip string, auth_login string, auth_password string, esmtp_authed *bool) bool {

		// from_address		MAIL FROM value
		// ip			ip address of the sending client
		// auth_login		ESTMP AUTH login
		// auth_password	ESTMP AUTH password
		// esmtp_authed		ESTMP authed status (set in this closure)

		// MAIL FROM
		fmt.Println("mail from", from_address)
		fmt.Println("AUTH login", auth_login)
		fmt.Println("AUTH password", auth_password)

		// get the email local-part and domain
		//address_parts := strings.Split(from_address, "@")
		//fmt.Println(address_parts)

		// return true if allowed
		// return false to ignore the email, disconnect the socket and add an invalid auth to ip_ac
		return true

	}, func(to_address string, ip string, esmtp_authed *bool) bool {

		// to_address		RCPT TO value
		// ip			ip address of the sending client
		// esmtp_authed		ESTMP authed status

		// RCPT TO
		fmt.Println("mail to", to_address)

		// return true if allowed
		// return false to ignore the email, disconnect the socket and add an invalid auth to ip_ac
		return true

	}, func(headers map[string]string, ip string, esmtp_authed *bool) bool {

		// headers		parsed headers
		// ip			ip address of the sending client
		// esmtp_authed		ESTMP authed status

		// headers
		// verify the message-id with stored messages to the same address to prevent duplicates

		// you can use ParseTags() to parse strings with key=value; parts into a map[string]string
		fmt.Println("headers")
		for h := range headers {
			fmt.Println(h, headers[h])
		}

		// return true if allowed
		// return false to ignore the email, disconnect the socket and add an invalid auth to ip_ac
		return true

	}, func(email_data *[]byte, headers *map[string]string, parts_headers *[]map[string]string, parts *[][]byte, dkim_valid *bool, ip *string, esmtp_authed *bool) {

		// email_data		raw email data as received (headers and body)
		// headers		parsed headers
		// parts_headers	headers of each body block
		// parts		each body block
		// dkim_valid		true if DKIM validated by the domain's public key
		// ip			ip address of the sending client
		// esmtp_authed		ESTMP authed status

		fmt.Println("full email received, length", len(*email_data))
		fmt.Println("dkim valid:", *dkim_valid)
		fmt.Println("ip of smtp client", *ip)

		// email is in parts
		// a part can be an attachment or a body with a different content-type
		// there is a parts_headers item for each part

		fmt.Println("parts:", len(*parts))
		for p := range *parts {
			fmt.Println("###### part:", p)
			fmt.Println("part headers:", (*parts_headers)[p])
			if (len((*parts)[p]) > 10000) {
				fmt.Println(string((*parts)[p][0:10000]))
			} else {
				fmt.Println(string((*parts)[p]))
			}
		}

	})

	gomail.Pop3Server(config, ip_ac, func(ip string, auth_login string, auth_password string, shared_secret string) bool {

		// ip			ip address
		// auth_login		login
		// auth_password	password
		// shared_secret	auth shared secret

		fmt.Println("POP3 server auth login", auth_login, "password", auth_password, "shared_secret", shared_secret)

		if (shared_secret != "") {
			// if there is a shared secret, the APOP command is being used

			// validate the username and get the known password

			// prepend shared_secret to the known password and the md5sum as a hex value will match auth_password if the sent password is valid
			m := md5.New()
			m.Write([]byte(shared_secret + "asdf"))
			valid_sum := hex.EncodeToString(m.Sum(nil))

			fmt.Println("valid_sum", valid_sum)

			if (valid_sum == auth_password) {
				return true
			} else {
				return false
			}

		}

		// there is no shared secret, validate auth_login and auth_password

		// return true if allowed
		// return false to disconnect the socket and add an invalid auth to ip_ac
		return true

	}, func(auth_login string) (string, string) {

		// STAT
		// auth_login		login

		fmt.Println("POP3 STAT", auth_login)

		// return the total message count and size of all messages in bytes
		// strings allow larger than uint64 max values
		return "1", "5"

	}, func(auth_login string) (string, []string, []string) {

		// LIST
		// auth_login		login

		fmt.Println("POP3 LIST", auth_login)

		// each message needs an identifier that is a whole number, beginning with 1
		// the message identifiers are used to identify messages in the RETR and DELE commands by POP3 clients

		// return total size in bytes of all messages, the message identifiers and the size of each message in bytes
		// strings allow larger than uint64 max values
		return "5", []string{"1"}, []string{"5"}

	}, func(auth_login string, msg_id string) string {

		// RETR retrieve message by id
		// auth_login		login
		// msg_id		message identifier

		fmt.Println("POP3 RETR", auth_login, "message identifier", msg_id)

		// get the message and return it as a string
		return "12345"

	}, func(auth_login string, msg_id string) (bool, string) {

		// DELE
		// auth_login		login
		// msg_id		message identifier

		fmt.Println("POP3 DELE", auth_login, "message identifier", msg_id)

		// delete the message and return the message deleted status and error message if the message was not deleted
		return true, ""

	})

	gomail.Imap4Server(config, ip_ac, func(ip string, auth_login string, auth_password string) bool {

		// ip			ip address
		// auth_login		login
		// auth_password	password

		fmt.Println("IMAP4 server auth login", auth_login, "password", auth_password)

		// get the email local-part and domain
		address_parts := strings.Split(auth_login, "@")
		//fmt.Println(address_parts)

		if (len(address_parts) != 2) {
			// login must be in the form local-part@domain.tld
			return false
		}

		if (address_parts[1] == config.Fqdn) {
			// this user is from this domain

			// authenticate the session
			if (auth_login == "") {
			} else if (users[auth_login] == auth_password) {
				// authenticated
				return true
			}

		}

		// return true if allowed
		// return false to disconnect the socket and add an invalid auth to ip_ac
		return false

	}, func(auth_login string, mailbox_name string) []string {

		// LIST
		// auth_login		login
		// mailbox_name		mailbox name with possible wildcards

		fmt.Println("IMAP4 LIST", auth_login, "mailbox_name", mailbox_name)

		/*
		C: A101 LIST "" ""
		S: * LIST (\Noselect) "/" ""
		S: A101 OK LIST Completed
		C: A102 LIST #news.comp.mail.misc ""
		S: * LIST (\Noselect) "." #news.
		S: A102 OK LIST Completed
		C: A103 LIST /usr/staff/jones ""
		S: * LIST (\Noselect) "/" /
		S: A103 OK LIST Completed
		C: A202 LIST ~/Mail/ %
		S: * LIST (\Noselect) "/" ~/Mail/foo
		S: * LIST () "/" ~/Mail/meetings
		S: A202 OK LIST completed
		*/

		// return slice of strings to respond with
		// if empty, IMAP4 server will instruct the client to use SELECT with a "* LIST" response
		return []string{}

	}, func(auth_login string, mailbox_name string) (int, []string, int, string, string) {

		// SELECT
		// auth_login		login
		// mailbox_name		name of mailbox

		fmt.Println("IMAP4 SELECT", auth_login)

		/*
		C:   a002 select inbox
		S:   * 18 EXISTS
		S:   * FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
		S:   * 2 RECENT
		S:   * OK [UNSEEN 17] Message 17 is the first unseen message
		S:   * OK [UIDVALIDITY 3857529045] UIDs valid
		S:   a002 OK [READ-WRITE] SELECT completed
		*/

		// return
		// total messages
		// slice of flags
		// count of unseen messages
		// first unseen message id
		// uid validity string (this is forever unique to the mailbox and must increment if the mailbox is deleted)
		return 2, []string{}, 2, "1", "1"

	}, func(auth_login string, sequence_set []string, item_names []string) ([]gomail.Imap4Message) {

		// FETCH
		// auth_login		login
		// sequence_set		messages to return
		//			one item means one message
		//			two items means a range
		// item_names		item names or macro

		fmt.Println("IMAP4 FETCH", auth_login, "sequence set", sequence_set, "item_names", item_names)

		/*
		C:   a003 fetch 12 full
		S:   * 12 FETCH (FLAGS (\Seen) INTERNALDATE "17-Jul-1996 02:44:25 -0700"
		      RFC822.SIZE 4286 ENVELOPE ("Wed, 17 Jul 1996 02:23:25 -0700 (PDT)"
		      "IMAP4rev1 WG mtg summary and minutes"
		      (("Terry Gray" NIL "gray" "cac.washington.edu"))
		      (("Terry Gray" NIL "gray" "cac.washington.edu"))
		      (("Terry Gray" NIL "gray" "cac.washington.edu"))
		      ((NIL NIL "imap" "cac.washington.edu"))
		      ((NIL NIL "minutes" "CNRI.Reston.VA.US")
		      ("John Klensin" NIL "KLENSIN" "MIT.EDU")) NIL NIL
		      "<B27397-0100000@cac.washington.edu>")
		      BODY ("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 3028
		      92))
		S:   a003 OK FETCH completed
		*/

		/*
		C:   a004 fetch 12 body[header]
		S:   * 12 FETCH (BODY[HEADER] {342}
		S:   Date: Wed, 17 Jul 1996 02:23:25 -0700 (PDT)
		S:   From: Terry Gray <gray@cac.washington.edu>
		S:   Subject: IMAP4rev1 WG mtg summary and minutes
		S:   To: imap@cac.washington.edu
		S:   Cc: minutes@CNRI.Reston.VA.US, John Klensin <KLENSIN@MIT.EDU>
		S:   Message-Id: <B27397-0100000@cac.washington.edu>
		S:   MIME-Version: 1.0
		S:   Content-Type: TEXT/PLAIN; CHARSET=US-ASCII
		S:
		S:   )
		S:   a004 OK FETCH completed
		*/

		// return a slice of Imap4Message
		// the Body field only needs to be set if requested

		/*
		type Imap4Message struct {
			Uid				string
			InternalDate			time.Time
			Flags				[]string
			Body				[]byte
			Headers				map[string]string
			Rfc822Size			int
		}
		*/

		var one gomail.Imap4Message
		var oneh map[string]string
		oneh = make(map[string] string)
		oneh["subject"] = "message one"
		oneh["date"] = "Thu, 27 Jun 2023 08:29:16 -0700"
		one.Headers = oneh
		one.Uid = "1"
		one.InternalDate = time.Now()
		one.Rfc822Size = 1000

		var two gomail.Imap4Message
		var twoh map[string]string
		twoh = make(map[string] string)
		twoh["subject"] = "message two"
		twoh["date"] = "Thu, 27 Jun 2023 08:29:16 -0700"
		two.Headers = twoh
		two.Uid = "2"
		two.InternalDate = time.Now()
		two.Rfc822Size = 1000

		return []gomail.Imap4Message{one, two}

	}, func(auth_login string, msg_id string, sequence_set string, item_name string, item_value string) bool {

		// STORE
		// auth_login		login
		// msg_id		message identifier
		// sequence_set		messages to modify items of
		//			space delimiter means individual messages
		//			: delimiter means a range
		// item_name		item name
		//			+flags (add to flags)
		//			-flags (remove from flags)
		// item_value		values of item that must be set
		//			\Seen \Deleted

		fmt.Println("IMAP4 STORE", auth_login, "message identifier", msg_id, "sequence set", sequence_set, "item name", item_name, "item value", item_value)

		/*
		C    a005 store 12 +flags \deleted
		S:   * 12 FETCH (FLAGS (\Seen \Deleted))
		S:   a005 OK +FLAGS completed
		*/

		// return true if all messages were updated
		// return false if no messages were modified
		return true

	}, func(auth_login string) bool {

		// CLOSE
		// auth_login		login

		fmt.Println("IMAP4 CLOSE", auth_login)

		// delete all messages with the /Deleted flag

		// return true on success or false on failure
		return true

	})

	// keep main thread open
	select {}

}
