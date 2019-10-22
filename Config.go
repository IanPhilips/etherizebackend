package main

import "github.com/BurntSushi/toml"

// Represents database server and credentials
type Config struct {
	Username string
	Password string
	CoinPaymentsPublic string
	CoinPaymentsPrivate string
	CoinPaymentsIPN string
	CoinPaymentsMerchantId string
	TestEmail string
}

// Read and parse the configuration file
func (c *Config) Read() {
	if _, err := toml.DecodeFile("config.toml", &c); err != nil {
		log.Fatal().Msg(err.Error())
	}
}