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



## Usage

If you want callbacks from coinpayments/stripe and you're running this locally, use `ngrok` for an accessible ip address.  

`go run *.go -ip YOUR_CALLBACK_IP`
