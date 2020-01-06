package main

import "github.com/BurntSushi/toml"


var config = Config{}

// Represents database server and credentials
type Config struct {
	OpenLawUsername string
	OpenLawPassword string
	CoinPaymentsPublic string
	CoinPaymentsPrivate string
	CoinPaymentsIPN string
	CoinPaymentsMerchantId string
	TestEmail string
	BasicAuthUser string
	BasicAuthPass string
	StripePublic string
	StripePrivate string
	StripeWebHookSecret string
	MailGunPrivate string
	MailGunPublic string
	OpenLawInstance string
}

// Read and parse the configuration file
func (c *Config) Read() {
	if _, err := toml.DecodeFile("config.toml", &c); err != nil {
		log.Fatal().Msg(err.Error())
	}
}