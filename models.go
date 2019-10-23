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

//{"level":"info","time":"2019-10-21T17:53:02-06:00","caller":"/Users/iansp/go/src/github.com/ianphilips/etherizeBackend" +
//	"/main.go:239","message":"POST /cryptoPaymentCallback HTTP/1.1\r\nHost: c47f3acb.ngrok.io\r\nAccept: */*\r" +
//	"\nContent-Length: 414\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\n" +
//	"Hmac: e0320ed393cc7dae5bd87016168aa8c141cad3dbd9577f51b12d93a831ec662269b7ee7df6f2d9ed3ae449662fd61d886ab25424bf033650db6e6229890c8dfa\r\n" +
//	"User-Agent: CoinPayments.net IPN Generator\r\nX-Forwarded-For: 149.56.241.110\r\n\r\n" +
//	"amount1=0.01&amount2=0.00018432&buyer_name=CoinPayments+API&currency1=USD&currency2=LTCT&" +
//	"email=iansphilips%40gmail.com&fee=1.0E-5&ipn_id=471b49e971f40cee9160c5b0d70b005f&ipn_mode=hmac&" +
//	"ipn_type=api&ipn_version=1.0&merchant=88ccc46f3b200561ac32a23c18cbf3f9&received_amount=0.00018432&" +
//	"received_confirms=0&status=1&status_text" +
//	"=Funds+received+and+confirmed%2C+sending+to+you+shortly...&txn_id=CPDJ2O1RS7OWO27IW3FCKWOKYZ"}