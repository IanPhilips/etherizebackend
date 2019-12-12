# Etherize backend


## Installation

Install [go](https://golang.org/doc/install)

install dependencies for this project:   

`go get -d ./...`

## Configure

create a `config.toml` file and add your credentials:

openLawUsername = "you@email.com"  
openLawPassword = "supersecret"  
coinPaymentsPublic = "xxx"  
coinPaymentsPrivate = "xxx"  
coinPaymentsIPN = "xxx"  
coinPaymentsMerchantId = "xxx"  
testEmail = "xxx"  
kaleidoInstanceURL = "xxx"



## Usage

If you want callbacks from coinpayments/stripe and you're running this locally, use `ngrok` for an accessible ip address.  

`go run *.go -ip YOUR_CALLBACK_IP`

If you're on the server, make sure your `bash_aliases` has the alias:  
`alias eth="sudo /usr/local/go/bin/go run ./*.go -ip https://api.etherize.io -mode production"`
and in the application directory type: `eth` 

