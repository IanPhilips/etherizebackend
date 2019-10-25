package main


type OpenlawJWT struct {
	Jwt string `json:"jwt"`
	Error string `json:"error"`
}

type TransactionCallback struct{
	Id string `schema:"txn_id"`
	StatusText string `schema:"status_text"`
	ReceivedConfirms int `schema:"received_confirms"`
	Status int `schema:"status"`
	ReceivedAmount float64 `schema:"received_amount"`
	Merchant string `schema:"merchant"`
	IpnVersion string `schema:"ipn_version"`
	IpnType string `schema:"ipn_type" `
	IpnMode string `schema:"ipn_mode"`
	IpnId string `schema:"ipn_id"`
	Fee float64 `schema:"fee"`
	Email string `schema:"email"`
	Currency1 string `schema:"currency1"`
	Currency2 string `schema:"currency2"`
	BuyerName string `schema:"buyer_name"`
	Amount1 float64 `schema:"amount1"`
	Amount2 float64 `schema:"amount2"`
}
