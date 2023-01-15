package main

import (
	"io/ioutil"
	"fmt"
	"encoding/json"
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

		// you can use smtpParseTags() to parse strings with key=value; parts into a map[string]string
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

}
