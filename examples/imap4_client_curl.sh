# how to use curl as an IMAP4 client

# LIST mailboxes
curl --user andrew@xyzbots.com:aaa "imaps://xyzbots.com/INBOX"
* LIST () "" INBOX

# SEARCH INBOX and return all email UIDs
curl --user andrew@xyzbots.com:aaa "imaps://xyzbots.com/INBOX" -X "SEARCH"
* SEARCH 1 2

# FETCH email by UID
curl --user andrew@xyzbots.com:aaa "imaps://xyzbots.com/INBOX;UID=2"
subject: message two
date: Thu, 27 Jun 2023 08:29:16 -0700
to: andrew@xyzbots.com
from: andrewhodel@gmail.com
message-id: 20230623044816.85E737380011@gmail.com

data of body
