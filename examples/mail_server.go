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

	gomail.SmtpServer(ip_ac, config, func(from_address string, ip string, auth_login string, auth_password string) bool {

		// from_address		MAIL FROM value
		// ip			ip address of the sending client
		// auth_login		ESTMP AUTH login
		// auth_password	ESTMP AUTH password

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

	}, func(to_address string, ip string, auth_login string, auth_password string) bool {

		// to_address		RCPT TO value
		// ip			ip address of the sending client
		// auth_login		ESTMP AUTH login
		// auth_password	ESTMP AUTH password

		// RCPT TO
		fmt.Println("mail to", to_address)

		// return true if allowed
		// return false to ignore the email, disconnect the socket and add an invalid auth to ip_ac
		return true

	}, func(headers map[string]string, ip string, auth_login string, auth_password string) bool {

		// headers		parsed headers
		// ip			ip address of the sending client
		// auth_login		ESTMP AUTH login
		// auth_password	ESTMP AUTH password

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

	}, func(email_data *[]byte, headers *map[string]string, parts_headers *[]map[string]string, parts *[][]byte, dkim_valid *bool, ip *string, auth_login *string, auth_password *string) {

		// email_data		raw email data as received (headers and body)
		// headers		parsed headers
		// parts_headers	headers of each body block
		// parts		each body block
		// dkim_valid		true if DKIM validated by the domain's public key
		// ip			ip address of the sending client
		// auth_login		ESTMP AUTH login
		// auth_password	ESTMP AUTH password

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

	}, func(auth_login string) (uint64, uint64) {

		// STAT
		// auth_login		login

		// return the total message count and size of all messages in bytes
		return 0, 0

	}, func(auth_login string) (uint64, []string, []uint64) {

		// LIST
		// auth_login		login

		// return number of messages, each message id and size
		return 0, []string{}, []uint64{}

	}, func(auth_login string, msg_id string) string {

		// RETR retrieve message by id
		// auth_login		login
		// msg_id		message identifier

		// get the message and return it as a string
		return ""

	}, func(auth_login string, msg_id string) (bool, string) {

		// DELE
		// auth_login		login
		// msg_id		message identifier

		// delete the message and return the message deleted status and error message if the message was not deleted
		return false, ""

	})

	// keep main thread open
	select {}

}
