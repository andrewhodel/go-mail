package main

import (
	"io/ioutil"
	"fmt"
	"encoding/json"
	"time"
	"net/mail"
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
	"os"
	"sync"
	"bytes"
	"github.com/andrewhodel/go-ip-ac"
	"github.com/andrewhodel/go-mail"
)

type Mailbox struct {
	Name			string
	LastMessageId		int
	TotalSize		int
	// must always be the same for each mailbox or all clients end all pending operations and resync
	UidValidity		int
}

var config gomail.Config
var ip_ac ipac.Ipac

var users map[string] string

var mailboxes map[string] []Mailbox
var mailboxes_mutex = &sync.Mutex{}

var message_store map[string] []gomail.Email
var message_store_mutex = &sync.Mutex{}

var resend_queue map[string] gomail.OutboundMail

func main() {

	// init users
	users = make(map[string] string)
	users["andrew@xyzbots.com"] = "aaaaaaaaaaaaaaa"
	users["no-reply@xyzbots.com"] = "aaaaaaaaaaaaaaaaaaaa"
	users["billing@cobianet.com"] = "aaaaaaaaaaaaaaaaa"

	// initialize the message store
	message_store = make(map[string] []gomail.Email)

	var one gomail.Email
	var oneh map[string]string
	oneh = make(map[string] string)
	oneh["subject"] = "message one"
	oneh["date"] = "Thu, 27 Jun 2023 08:29:16 -0700"
	oneh["to"] = "andrew@xyzbots.com"
	oneh["from"] = "andrewhodel@gmail.com"
	oneh["message-id"] = "20230623044816.85E937380062@gmail.com"
	one.Headers = oneh
	//one.Flags = []string{"\\Recent"}
	one.Uid = 1
	one.InternalDate = time.Now()
	one.Rfc822Size = 1000
	one.Mailbox = "INBOX"
	one.Body = []byte("data of body")
	message_store["andrew@xyzbots.com"] = append(message_store["andrew@xyzbots.com"], one)

	var two gomail.Email
	var twoh map[string]string
	twoh = make(map[string] string)
	twoh["subject"] = "message two"
	twoh["date"] = "Thu, 27 Jun 2023 08:29:16 -0700"
	twoh["to"] = "andrew@xyzbots.com"
	twoh["from"] = "andrewhodel@gmail.com"
	twoh["message-id"] = "20230623044816.85E737380011@gmail.com"
	two.Headers = twoh
	//two.Flags = []string{"\\Recent"}
	two.Uid = 2
	two.InternalDate = time.Now()
	two.Rfc822Size = 1000
	two.Mailbox = "INBOX"
	two.Body = []byte("data of body")
	message_store["andrew@xyzbots.com"] = append(message_store["andrew@xyzbots.com"], two)

	// initialize the mailboxes
	mailboxes = make(map[string] []Mailbox)
	for a := range(users) {
		emails := message_store[a]

		// create the mailboxes of each account
		for mid := range(emails) {

			// test if the mailbox exists
			var mailbox_found = false
			for m := range(mailboxes[a]) {
				if (mailboxes[a][m].Name == emails[mid].Mailbox) {
					mailbox_found = true
					break
				}
			}

			if (mailbox_found == false) {
				// create the mailbox
				fmt.Println("creating mailbox", emails[mid].Mailbox, a)
				mailboxes[a] = append(mailboxes[a], Mailbox{Name: emails[mid].Mailbox, UidValidity: 1})
			}

		}

		// set the last message id of each email for each mailbox for each account from the message store
		for mb := range(mailboxes[a]) {

			var last_message_id = 0
			for mid := range(emails) {
				email := emails[mid]

				if (email.Uid > last_message_id && email.Mailbox == mailboxes[a][mb].Name) {
					// set the last_message_id
					last_message_id = email.Uid
				}

				if (email.Mailbox == mailboxes[a][mb].Name) {
					// increase the total size
					mailboxes[a][mb].TotalSize += email.Rfc822Size
				}

			}
			// set the highest message id for this mailbox of this account
			mailboxes[a][mb].LastMessageId = last_message_id

		}

	}

	// dkim private key
	pk, pk_err := os.ReadFile("../xyzbots-dkim/private.key")

	if (pk_err != nil) {
		fmt.Println(pk_err)
		os.Exit(1)
	}

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

	// init resend queue
	resend_queue = make(map[string] gomail.OutboundMail)
	go resend_loop()

	go gomail.SmtpServer(ip_ac, config, func(from_address string, ip string, auth_login string, auth_password string, esmtp_authed *bool) (bool, string) {

		// from_address		MAIL FROM value
		// ip			ip address of the sending client
		// auth_login		ESTMP AUTH login
		// auth_password	ESTMP AUTH password
		// esmtp_authed		ESTMP authed status (set in this closure)

		// MAIL FROM
		//fmt.Println("mail from", from_address)
		//fmt.Println("AUTH login", auth_login)
		//fmt.Println("AUTH password", auth_password)

		// get the email local-part and domain
		address_parts := strings.Split(from_address, "@")
		//fmt.Println(address_parts)

		if (len(address_parts) != 2) {
			// from_address must be in the form local-part@domain.tld
			return false, ""
		}

		// authenticate the session with esmtp
		if (from_address == "" || auth_password == "") {
		} else if (users[from_address] == auth_password) {
			// authenticated
			*esmtp_authed = true
			return true, ""
		}

		// only allow esmtp_authed == true
		// the 2nd argument can be set to something other than the default "221 not authorized"
		// like "221 your IP address is spamming too much, 5000 emails in the last 15 seconds"
		// like "221 your domain is spamming too much, 5000 emails in the last 15 seconds"
		return false, ""

	}, func(to_address string, ip string, esmtp_authed *bool) (bool, string) {

		// to_address		RCPT TO value
		// ip			ip address of the sending client
		// esmtp_authed		ESTMP authed status

		// RCPT TO
		//fmt.Println("mail to", to_address)

		// return true if allowed
		// return false to ignore the email, disconnect the socket and add an invalid auth to ip_ac

		if (*esmtp_authed == true) {
			// allow sending emails to other servers if the session is esmtp authenticated
			return true, ""
		} else if (users[to_address] != "") {
			// local account exists
			return true, ""
		}

		// this email is invalid
		// the 2nd argument can be set to something other than the default "550 mailbox not found"
		// like "450 RCPT TO address is being rate limited"
		return false, ""

	}, func(headers map[string]string, ip string, esmtp_authed *bool) bool {

		// headers		parsed headers
		// ip			ip address of the sending client
		// esmtp_authed		ESTMP authed status

		// headers
		// verify the message-id with stored messages to the same address to prevent duplicates

		// return true if allowed
		// return false to ignore the email, disconnect the socket and add an invalid auth to ip_ac
		return true

	}, func(email_data *[]byte, headers *map[string]string, parts_headers *[]map[string]string, parts *[][]byte, dkim_valid *bool, ip *string, esmtp_authed *bool, mail_from *string, rcpt_to_addresses *[]string) {

		// email_data		raw email data as received (headers and body)
		// headers		parsed headers
		// parts_headers	headers of each body block
		// parts		each body block
		// dkim_valid		true if DKIM validated by the domain's public key
		// ip			ip address of the sending client
		// esmtp_authed		ESTMP authed status
		// mail_from		email address sent in MAIL FROM SMTP command
		// rcpt_to_addresses	email addresses sent in RCPT TO SMTP commands (sometimes used instead of BCC headers)

		//fmt.Println(string((*email_data)))
		var dkim_string = "false"
		if (*dkim_valid == true) {
			dkim_string = "true"
		}
		var console_output = "full email received, length: " + strconv.Itoa(len(*email_data)) + "\nDKIM valid: " + dkim_string + "\nIP Address: " + *ip

		// get list of each address to send to
		// send to external servers
		// send to local domain inboxes
		var send_addresses []mail.Address

		// add addresses from the RCPT TO SMTP commands
		for a := range((*rcpt_to_addresses)) {

			rcpt_tf, rcpt_tf_err := mail.ParseAddress((*rcpt_to_addresses)[a])
			if rcpt_tf_err == nil {

				already_exists := false
				for e := range(send_addresses) {
					if (send_addresses[e] == *rcpt_tf) {
						// already in send_addresses
						already_exists = true
						break
					}
				}

				if (already_exists == false) {
					send_addresses = append(send_addresses, *rcpt_tf)
				}

			}

		}

		// add addresses from the to: header
		var tos = strings.Split((*headers)["to"], ",")
		for a := range(tos) {

			// add each bcc address
			tf, tf_err := mail.ParseAddress(tos[a])

			if tf_err == nil {

				already_exists := false
				for e := range(send_addresses) {
					if (send_addresses[e] == *tf) {
						// already in send_addresses
						already_exists = true
						break
					}
				}

				if (already_exists == false) {
					send_addresses = append(send_addresses, *tf)
				}

			}

		}

		// add addresses from the bcc: header
		var bcc_header = (*headers)["bcc"]
		// remove the BCC headers to not reveal the bcc addresses
		delete((*headers), "bcc")
		var bccs = strings.Split(bcc_header, ",")
		for a := range(bccs) {

			// add each bcc address
			tf, tf_err := mail.ParseAddress(bccs[a])

			if tf_err == nil {

				already_exists := false
				for e := range(send_addresses) {
					if (send_addresses[e] == *tf) {
						// already in send_addresses
						already_exists = true
						break
					}
				}

				if (already_exists == false) {
					send_addresses = append(send_addresses, *tf)
				}

			}

		}

		// add addresses from the cc: header
		var ccs = strings.Split((*headers)["cc"], ",")
		for a := range(ccs) {

			// add each cc address
			tf, tf_err := mail.ParseAddress(bccs[a])
			if tf_err == nil {

				already_exists := false
				for e := range(send_addresses) {
					if (send_addresses[e] == *tf) {
						// already in send_addresses
						already_exists = true
						break
					}
				}

				if (already_exists == false) {
					send_addresses = append(send_addresses, *tf)
				}

			}

		}

		// get the raw body as bytes
		var h_split_pos = bytes.Index((*email_data), []byte("\r\n\r\n"))
		var end_split_pos = bytes.Index((*email_data), []byte("\r\n.\r\n"))

		if (h_split_pos == -1) {
			h_split_pos = 0
		} else {
			h_split_pos += 4
		}
		if (end_split_pos == -1) {
			end_split_pos = len((*email_data)) - 1
		}

		pf, pf_err := mail.ParseAddress((*headers)["from"])
		if pf_err == nil {

			for a := range(send_addresses) {

				if (users[send_addresses[a].Address] != "") {
					// send to local domain
					console_output += "\nstoring at local domain:\n" + string(*email_data)
				} else {

					if (*esmtp_authed == false) {
						// never send to external domains unless esmtp authed
						console_output += "\nnot sending to external domain, not esmtp authed"
						continue
					}

					// send via SMTP
					var om gomail.OutboundMail
					om.DkimPrivateKey = pk
					om.DkimDomain = "aaaaaaaaaaaaaaaaaa._domainkey.domain.tld"
					om.From = *pf
					om.Subj = (*headers)["subject"]
					om.Body = (*email_data)[h_split_pos:end_split_pos]
					// email will not send unless the server provides TLS or STARTTLS
					om.RequireTLS = true

					// add headers
					om.Headers = (*headers)

					// add to address
					om.To = []mail.Address{send_addresses[a]}

					console_output += "\nsending email\n" + "to: " + om.To[0].Address + "\nfrom: " + om.From.Address + "\nsubject: " + om.Subj

					err, return_code, _ := gomail.SendMail(om)

					if (err != nil) {
						console_output += "\ngomail.SendMail() error: " + err.Error()

						if (return_code == 550 || return_code == 551) {
							// 550 is mailbox not found, no access or command rejected for policy reasons
							// 551 is user not local; please try <forward-path>
							// do not add to resend_queue
						} else {

							// add to resend_queue
							om.FirstSendFailure = time.Now()
							resend_queue[gomail.RandStringBytesMaskImprSrcUnsafe(107)] = om

						}

					} else {

						console_output += "\nemail received by server\n"
						//fmt.Println(email)
						//fmt.Println(string(email))
					}

				}

			}

		}

		fmt.Println("*****\n" + console_output + "\n*****")

	})

	go gomail.Pop3Server(config, ip_ac, func(ip string, auth_login string, auth_password string, shared_secret string) bool {

		// ip			ip address
		// auth_login		login
		// auth_password	password
		// shared_secret	auth shared secret

		fmt.Println("POP3 server auth login", auth_login, "password", auth_password, "shared_secret", shared_secret)

		if (auth_login == "") {
			// auth_login must be set
			return false
		}

		// get the email local-part and domain
		address_parts := strings.Split(auth_login, "@")
		//fmt.Println(address_parts)

		if (len(address_parts) != 2) {
			// from_address must be in the form local-part@domain.tld
			return false
		}

		if (address_parts[1] != config.Fqdn) {
			// this user is not from this domain
			return false
		}

		if (shared_secret != "") {
			// if there is a shared secret, the APOP command is being used

			// validate the username and get the known password

			// prepend shared_secret to the known password and the md5sum as a hex value will match auth_password if the sent password is valid
			m := md5.New()
			m.Write([]byte(shared_secret + users[auth_login]))
			valid_sum := hex.EncodeToString(m.Sum(nil))

			fmt.Println("valid_sum", valid_sum)

			if (valid_sum == auth_password) {
				// the shared secret was used to validate the password
				return true
			}

		}

		// not APOP
		// authenticate the session
		if (users[auth_login] == auth_password) {
			// authenticated
			return true
		}

		// return true if allowed
		// return false to disconnect the socket and add an invalid auth to ip_ac
		return false

	}, func(auth_login string) (int, int) {

		// STAT
		// auth_login		login

		fmt.Println("POP3 STAT", auth_login)

		mailboxes_mutex.Lock()
		var total_messages = 0
		var total_size = 0
		// add all the mailboxes together
		// POP3 treats the mailbox as a single store, and has no concept of folders
		for mb := range(mailboxes[auth_login]) {
			var mailbox = mailboxes[auth_login][mb]
			total_messages += mailbox.LastMessageId
			total_size += mailbox.TotalSize
		}
		mailboxes_mutex.Unlock()

		// return the total message count and size of all messages in bytes
		return total_messages, total_size

	}, func(auth_login string) (int, []int, []int) {

		// LIST
		// auth_login		login

		fmt.Println("POP3 LIST", auth_login)

		// each message needs an identifier that is a whole number, beginning with 1
		// the message identifiers are used to identify messages in the RETR and DELE commands by POP3 clients

		// return emails from all mailboxes
		// POP3 treats the mailbox as a single store, and has no concept of folders
		var total_size = 0
		var mids []int
		var m_sizes []int
		message_store_mutex.Lock()
		for m := range(message_store[auth_login]) {
			email := message_store[auth_login][m]
			total_size += email.Rfc822Size
			mids = append(mids, email.Uid)
			m_sizes = append(m_sizes, email.Rfc822Size)
		}
		message_store_mutex.Unlock()

		// return total size in bytes of all messages, the message identifiers and the size of each message in bytes
		return total_size, mids, m_sizes

	}, func(auth_login string, msg_id int) string {

		// RETR retrieve message by id
		// auth_login		login
		// msg_id		message identifier

		fmt.Println("POP3 RETR", auth_login, "message identifier", msg_id)

		// get the message and return it as a string
		var h = ""
		message_store_mutex.Lock()
		for m := range(message_store[auth_login]) {
			email := message_store[auth_login][m]
			if (email.Uid == msg_id) {
				for k, v := range(email.Headers) {
					h += k + ": " + v + "\r\n"
				}
				h += "\r\n" + string(email.Body)
				break
			}
		}
		message_store_mutex.Unlock()

		return h

	}, func(auth_login string, msg_id int) (bool, string) {

		// DELE
		// auth_login		login
		// msg_id		message identifier

		fmt.Println("POP3 DELE", auth_login, "message identifier", msg_id)

		// delete the message and return the message deleted status and error message if the message was not deleted
		var deleted = false
		message_store_mutex.Lock()
		for m := range(message_store[auth_login]) {
			if (message_store[auth_login][m].Uid == msg_id) {
				// delete the message
				message_store[auth_login] = nil
				deleted = true
				break
			}
		}
		message_store_mutex.Unlock()

		if (deleted == true) {
			return true, ""
		} else {
			return false, "not found"
		}

	})

	go gomail.Imap4Server(config, ip_ac, func(ip string, auth_login string, auth_password string) bool {

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

	}, func(auth_login string, flags []string, reference string, mailbox_name string) []string {

		// LIST
		// auth_login		login
		// flags		[]string of flags
		// reference		reference is prepended to the mailbox
		// mailbox_name		mailbox name

		// mailbox_name InBoX is case-insensitive and always returned as INBOX

		fmt.Println("IMAP4 LIST", auth_login, "flags", flags, "reference", reference, "mailbox", mailbox_name)

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
		if (mailbox_name == "*") {
			// return all mailboxes

			mailboxes_mutex.Lock()
			var mbs []string
			// find the mailbox
			for mb := range(mailboxes[auth_login]) {
				var mailbox = mailboxes[auth_login][mb]
				mbs = append(mbs, "* LIST () \"\" " + mailbox.Name)
			}
			mailboxes_mutex.Unlock()
			return mbs

		} else {
			// return that mailbox
			return []string{"* LIST () \"\" " + mailbox_name}
		}

	}, func(auth_login string, mailbox_name string) (int, []string, int, int, int) {

		// SELECT
		// auth_login		login
		// mailbox_name		name of mailbox

		// mailbox_name InBoX is case-insensitive and always returned as INBOX

		fmt.Println("IMAP4 SELECT", auth_login, "mailbox", mailbox_name)

		/*
		C:   a002 select inbox
		S:   * 18 EXISTS
		S:   * FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
		S:   * 2 RECENT
		S:   * OK [UNSEEN 17] Message 17 is the first unseen message
		S:   * OK [UIDVALIDITY 3857529045] UIDs valid
		S:   a002 OK [READ-WRITE] SELECT completed
		*/

		var total_messages = 0
		var mailbox_uid_validity = 0
		var unseen_messages = 0
		var first_unseen_message = 0
		// find the mailbox
		mailboxes_mutex.Lock()
		for mb := range(mailboxes[auth_login]) {
			var mailbox = mailboxes[auth_login][mb]
			if (mailbox.Name == mailbox_name) {
				total_messages = mailbox.LastMessageId
				// set the number of unseen messages to all messages
				unseen_messages = total_messages
				// set the first unseen message to the first message (1)
				first_unseen_message = 1
				mailbox_uid_validity = mailbox.UidValidity
			}
		}
		mailboxes_mutex.Unlock()

		fmt.Println("IMAP4 SELECT returning", total_messages, "total messages in", mailbox_name, "with mailbox_uid_validity", mailbox_uid_validity, "messages without \\Seen flag", unseen_messages, "first unseen message", first_unseen_message)

		// return
		// total messages
		// slice of flags
		// count of unseen messages (messages without the \Seen flag
		// first unseen message id
		// uid validity string (this is forever unique to the mailbox and must increment if the mailbox is deleted)
		return total_messages, []string{}, unseen_messages, first_unseen_message, mailbox_uid_validity

	}, func(auth_login string, sequence_set []string, item_names []string) ([]gomail.Email) {

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

		// return []Email
		// the Body field only needs to be set if requested

		var return_all_in_mailbox = false
		if (sequence_set[len(sequence_set)-1] == "*") {
			return_all_in_mailbox = true
		}

		// return emails from selected mailbox
		var selected_mailbox = "INBOX"
		var emails []gomail.Email
		message_store_mutex.Lock()
		for m := range(message_store[auth_login]) {
			if (message_store[auth_login][m].Mailbox == selected_mailbox) {

				email := message_store[auth_login][m]

				if (return_all_in_mailbox == false) {
					var skip = true
					for s := range(sequence_set) {
						sci, sci_err := strconv.Atoi(sequence_set[s])
						if (sci_err != nil) {
							// go to next
							continue
						}
						if (sci == email.Uid) {
							skip = false
							break
						}
					}
					if (skip == true) {
						continue
					}
				} else {
					// do not remove body if returning all messages
					email.Body = nil
				}

				emails = append(emails, email)
			}
		}
		message_store_mutex.Unlock()

		return emails

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

	}, func(auth_login string, search_query string) string {

		// SEARCH
		// auth_login		login
		// query		search query

		fmt.Println("IMAP4 SEARCH", auth_login)

		// search messages

		// return emails from selected mailbox
		var selected_mailbox = "INBOX"
		var mids = ""
		message_store_mutex.Lock()
		for m := range(message_store[auth_login]) {
			if (message_store[auth_login][m].Mailbox == selected_mailbox) {
				email := message_store[auth_login][m]
				mids += strconv.Itoa(email.Uid) + " "
			}
		}
		message_store_mutex.Unlock()

		// remove last space character
		mids = strings.TrimRight(mids, " ")

		// return "mid mid mid" list of email message ids matching search query
		return mids

	})

	// keep main thread open
	select {}

}

func resend_loop() {

	// attempt SMTP resends every hour
	time.Sleep(time.Minute * 60)

	var console_output = ""

	for m := range(resend_queue) {

		now := time.Now()

		console_output += "\nemail resend\n" + "to: " + resend_queue[m].To[0].Address + "\nfrom: " + resend_queue[m].From.Address + "\nsubject: " + resend_queue[m].Subj

		if (now.Sub(resend_queue[m].FirstSendFailure).Hours() > 144) {
			// delete after 6 days
			console_output += "\nemail resend failed for 144 hours, REMOVING from resend queue"
			delete(resend_queue, m)
			continue
		}

		err, _, _ := gomail.SendMail(resend_queue[m])

		if (err != nil) {
			console_output += "\ngomail.SendMail() error: " + err.Error()
		} else {
			console_output += "\nemail received by server"
			//fmt.Println(email)
			//fmt.Println(string(email))
			delete(resend_queue, m)
		}

	}

	if (console_output != "") {
		fmt.Println("*\nSMTP RESEND(S)\n" + console_output + "\n*\n")
	}

	go resend_loop()

}
