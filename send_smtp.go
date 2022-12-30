package main

import (
  "net/smtp"
)

func main() {
  err := smtp.SendMail(
    "127.0.0.1:25",
    nil,
    "src@test.local",
    []string{"dst@test.local"},
    []byte("Hello! Just testing."),
  )
  if err != nil {
    panic(err)
  }
}
