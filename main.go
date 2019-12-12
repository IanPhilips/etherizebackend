package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/ianphilips/coinpayments-go/coinpayments"
	"github.com/stripe/stripe-go"
	sessionStripe "github.com/stripe/stripe-go/checkout/session"
	"github.com/stripe/stripe-go/webhook"
	"golang.org/x/crypto/acme/autocert"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)


// SSL for HTTPS
var hostName = "api.etherize.io"
var sslDir = "certs"
var currentIP url.URL


// CoinPayments
var coinPaymentsCallbackResource = "/cryptoPaymentCallback"

// debugging
var runningDevelopmentServer = false

// default client with timeout
var netClient = &http.Client{
	Timeout: time.Second * 8,
}

// Called on start - parses CL args and starts the server
func main() {

	// Parse command line arguments
	mode := flag.String("mode", "debug", " 'debug' or 'production' - http or https + production logging")
	callbackIP := flag.String("ip", "http://localhost", " callback url for payments - for " +
		"local dev use ngrok")
	flag.Parse()

	currentIP, parseErr := url.ParseRequestURI(*callbackIP)
	if parseErr != nil{
		log.Info().Msg( "callback ip parse error: " + parseErr.Error())
		return
	}

	log.Info().Msg( "payment callbacks ip: " + currentIP.String())


	// setup
	config.Read()
	r := mux.NewRouter()
	registerHandlers(r)
	r.Use(loggingMiddleware)


	// debug mode
	if *mode == "debug" {
		runningDevelopmentServer = true
		log.Info().Msg("running in debug mode on port 80")

		if err := http.ListenAndServe(":80", handlers.CORS()(r)); err != nil {
			log.Fatal().Msg(err.Error())
		}

		// production mode
	} else if *mode == "production" {
		runningDevelopmentServer = false
		runProductionServer(r)
	}


}


// match endpoints to functions
func registerHandlers(r *mux.Router){

	// payments
	r.HandleFunc("/generateCryptoTransaction", generateCryptoTransaction)
	r.HandleFunc(coinPaymentsCallbackResource, cryptoPaymentCallback)
	r.HandleFunc("/generateFiatTransaction", getFiatPayment)
	r.HandleFunc("/fiatPaymentCallback", fiatPaymentCallback)

	// openlaw
	r.HandleFunc("/getOpenlawJWT", getOpenlawJWT)

	// unused
	//r.PathPrefix("/passThroughGETWithBasicAuthToOpenLaw/").HandlerFunc(passThroughGETWithBasicAuthToOpenLaw)

}



// Gets a JWT from the Openlaw hosted instance using our credentials from the config.toml (not included in OS repo)
// REST api details from https://docs.openlaw.io/api-client/#authentication
func getOpenlawJWT(w http.ResponseWriter, r *http.Request){
	// dashboard is here: https://console.kaleido.io/consortia/u0vvwcatsl
	resource := "/app/login"
	u, _ := url.ParseRequestURI(config.KaleidoInstanceURL)
	u.Path = resource
	urlStr := u.String()

	data := url.Values{}
	data.Set("userId", config.OpenLawUsername)
	data.Set("password", config.OpenLawPassword)


	r, _ = http.NewRequest("POST", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	r.SetBasicAuth(config.BasicAuthUser,config.BasicAuthPass)
	response := OpenlawJWT{}
	code:= http.StatusAccepted

	resp, err := netClient.Do(r)

	// assign error
	if err!= nil {
		response.Error = err.Error()
		log.Error().Msg("openlaw request time out or failure!")
	}

	// assign jwt and response code
	if resp!= nil{
		code = resp.StatusCode
		response.Jwt = resp.Header.Get("OPENLAW_JWT")
	}

	respondWithJson(w,code,response)
}


// Called with payment updates from CoinPayments
func cryptoPaymentCallback(w http.ResponseWriter, r *http.Request) {

	// Read the content from body
	var bodyBytes []byte
	bodyBytes, _ = ioutil.ReadAll(r.Body)
	// replace the content
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	err := r.ParseForm()
	if err != nil {
		log.Error().Msg("couldn't parse form: " + err.Error())
		return
	}

	// get Hmac
	suppliedHmac := r.Header.Get("Hmac")
	if suppliedHmac == ""{
		log.Error().Msg("no HMAC signature set")
		return
	}

	// compute our own hmac
	mac := hmac.New(sha512.New, []byte(config.CoinPaymentsIPN))
	mac.Write([]byte(bodyBytes))
	computedHmac := hex.EncodeToString(mac.Sum(nil))

	// verify supplied hmac matches computed
	if suppliedHmac != computedHmac {
		log.Info().Msg("hmacs don't match!")
		return
	}

	// decode form to callback struct
	transactionCallback := new(TransactionCallback)
	decoder := schema.NewDecoder()
	err = decoder.Decode(transactionCallback, r.Form)
	if err != nil {
		log.Error().Msg("couldn't decode callback: " + err.Error())
		return
	}

	// verify correct merchant id
	suppliedMerchantId := transactionCallback.Merchant
	if suppliedMerchantId != config.CoinPaymentsMerchantId{
		log.Error().Msg("merchant id doesn't match")
		return
	}

	paymentStatus := transactionCallback.Status
	log.Info().Msg("callback successfully processed with status: " + transactionCallback.StatusText)
	log.Info().Msg("Coinpayments update for transaction id: " + transactionCallback.Id)



	paymentComplete := false
	switch paymentStatus {
	case 0:
		log.Info().Msg("waiting for payment")
		break
	case 1:
		log.Info().Msg("coins received!")
		break
	case 2:
		log.Info().Msg("coins queued for payout!")
		paymentComplete = true
		break
	case -1:
		log.Info().Msg("payment cancelled or timed out")
		break
	case -2:
		log.Info().Msg("Paypal refund or reversal")
		break
	case 3:
		log.Info().Msg("Paypal pending!")
		break
	case 100:
		log.Info().Msg("Payment Complete!")
		paymentComplete = true
		break
	}


	if paymentComplete{
		// TODO notify user of completed payment and that we're working on creating their entity
		// TODO notify any other parties of completed payment other than ian (default email on coinpayments)
	}


}


// Generates a crypto transaction via CoinPayments
func generateCryptoTransaction(w http.ResponseWriter, r *http.Request) {


	// amount is in default USD
	amount := .01
	// client specifies crypto currency
	cryptoCurrency := r.URL.Query()["crypto"][0]

	// generate our full url for payment callbacks to make sure url works
	coinPaymentsCallbackURL := currentIP
	coinPaymentsCallbackURL.Path = coinPaymentsCallbackResource


	// Ask coinpayments for a crypto transaction
	coinClient := coinpayments.NewClient(config.CoinPaymentsPublic,config.CoinPaymentsPrivate, http.DefaultClient)
	newTransaction := coinpayments.TransactionParams{
		Amount:     amount,
		Currency1:  "USD",
		Currency2:  cryptoCurrency,
		BuyerEmail: config.TestEmail,
		IPNUrl: coinPaymentsCallbackURL.String(),
	}
	trans, _, err := coinClient.Transactions.NewTransaction(&newTransaction)


	if err!= nil {
		log.Error().Msg(err.Error())
		return
	}

	if trans.Error!="ok"{
		log.Error().Msg(trans.Error)
		return
	}

	log.Info().Msg("transaction created!")

	// TODO show customer where to send crypto

	respondWithJson(w,http.StatusAccepted, trans)
}


// TODO
func fiatPaymentCallback (w http.ResponseWriter, req *http.Request){
	const MaxBodyBytes = int64(65536)
	req.Body = http.MaxBytesReader(w, req.Body, MaxBodyBytes)
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Error().Msg("Error reading request body: " + err.Error())
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// Pass the request body & Stripe-Signature header to ConstructEvent, along with the webhook signing key
	// You can find your endpoint's secret in your webhook settings
	endpointSecret := "whsec_...";
	event, err := webhook.ConstructEvent(body, req.Header.Get("Stripe-Signature"), endpointSecret)

	if err != nil {
		log.Error().Msg("Error verifying webhook signature: "+ err.Error())
		w.WriteHeader(http.StatusBadRequest) // Return a 400 error on a bad signature
		return
	}

	// Handle the checkout.session.completed event
	if event.Type == "checkout.session.completed" {
		var session stripe.CheckoutSession
		err := json.Unmarshal(event.Data.Raw, &session)
		if err != nil {
			log.Error().Msg( "Error parsing webhook JSON: "+ err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// TODO Fulfill the purchase...
		// handleCheckoutSession(session)
	}

	w.WriteHeader(http.StatusOK)
}


// TODO
func getFiatPayment(w http.ResponseWriter, r *http.Request) {
	// Set your secret key: remember to change this to your live secret key in production
	// See your keys here: https://dashboard.stripe.com/account/apikeys
	stripe.Key = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
	params := &stripe.CheckoutSessionParams{
		PaymentMethodTypes: stripe.StringSlice([]string{
			"card",
		}),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			&stripe.CheckoutSessionLineItemParams{
				Name: stripe.String("T-shirt"),
				Description: stripe.String("Comfortable cotton t-shirt"),
				Amount: stripe.Int64(500),
				Currency: stripe.String(string(stripe.CurrencyUSD)),
				Quantity: stripe.Int64(1),
			},
		},
		SuccessURL: stripe.String("https://example.com/success?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL: stripe.String("https://example.com/cancel"),
	}


	session, err := sessionStripe.New(params)
	if err!=nil{
		respondWithError(w,http.StatusBadRequest,err.Error())
		return
	}

	respondWithJson(w,http.StatusAccepted,session)
}


// TODO
func runProductionServer( r *mux.Router){
	//create your file with desired read/write permissions
	f, err := os.OpenFile(logName, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Error().Msg("Could not open logfile")
		log.Fatal().Msg(err.Error())
	}

	// close file on method finish
	defer func() {
		closed := f.Close()
		if err == nil {
			err = closed
		}
	}()

	SetupProductionLogger(f)

	// Ian gets a text if we have a fatal error
	//log = AttachErrorMessaging(avalogging.Log)

	//Key and cert are coming from Let's Encrypt
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hostName), //Your domain here
		Cache:      autocert.DirCache(sslDir),             //Folder for storing certificates
	}


	// Allow autocert handle Let's Encrypt auth callbacks over HTTP.
	// it'll pass all other urls to our hanlder
	go func() {
		err :=http.ListenAndServe(":http", certManager.HTTPHandler(nil))
		if err != nil {
			log.Fatal().Str("CertBot http.ListenAndServe() failed with: ", err.Error())
		}
	}()

	// configure https server
	server := &http.Server{
		Addr: ":https",
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
		Handler:  handlers.CORS()(r),
	}

	log.Info().Msg("running on https")
	// HTTPS Production server:
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal().Msg(err.Error())
	}
}


// prints out a formatted webrequest
func PrettyPrintRequest(r *http.Request) {
	// Save a copy of this request for debugging.
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Error().Msg(err.Error())
	}

	log.Info().Msg(string(requestDump))

}


// utility for http response with an error
func respondWithError(w http.ResponseWriter, code int, msg string) {
	log.Info().Msg("Responding with error: " + msg )
	respondWithJson(w, code, map[string]string{"error": msg})
}


// utility for http response with json
func respondWithJson(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}



// Unused:

// this function translated get requests to our server to get requests with basic auth attached
// and made the request to our openlaw instance on Kaleido. For the sake of dev speed we're just going
// to store the basic auth on the front-end and hope for the best for the time being!
// TODO: when Kaleido introduces role-based basic auth, use that for users
func passThroughGETWithBasicAuthToOpenLaw(w http.ResponseWriter, r *http.Request){
	// dashboard: https://console.kaleido.io/dashboard/openlaw/u0vvwcatsl/u0ztgr50os/u0gzl2r9pj/u0flnq9hwd
	// TODO: make the auth code modular
	resource := "/app/login"
	ur, _ := url.ParseRequestURI(config.KaleidoInstanceURL)
	ur.Path = resource
	urlStr := ur.String()

	data := url.Values{}
	data.Set("userId", config.OpenLawUsername)
	data.Set("password", config.OpenLawPassword)


	newR, _ := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	newR.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	newR.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	newR.SetBasicAuth(config.BasicAuthUser,config.BasicAuthPass)
	respon := OpenlawJWT{}

	resp, err := netClient.Do(newR)

	// assign error
	if err!= nil {
		respon.Error = err.Error()
		log.Error().Msg("openlaw request time out or failure!")
	}

	// assign jwt and response code
	if resp!= nil{
		respon.Jwt = resp.Header.Get("OPENLAW_JWT")
	}



	// TODO; support more than just GET

	newURL := r.URL.String()
	newURL = strings.Replace(newURL, "/passThroughGETWithBasicAuthToOpenLaw", "",1)
	u, _ := url.ParseRequestURI(config.KaleidoInstanceURL + newURL)
	log.Info().Msg("new url: " + u.String())

	req, _ := http.NewRequest("GET",u.String(), nil)
	req.Header.Add("OPENLAW_JWT", respon.Jwt)

	//req, _ := http.NewRequest("GET",u.String(), nil)
	req.SetBasicAuth(config.BasicAuthUser,config.BasicAuthPass)
	req.Header.Add("Cookie","OPENLAW_SESSION=xx")
	response, err := netClient.Do(req)

	if err!=nil{
		respondWithError(w,http.StatusBadRequest, err.Error())
		return
	}
	body, _ := ioutil.ReadAll(response.Body)
	w.WriteHeader(response.StatusCode)
	w.Write(body)

}


