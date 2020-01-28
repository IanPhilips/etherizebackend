package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/ianphilips/coinpayments-go/coinpayments"
	"github.com/mailgun/mailgun-go"
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


var (
	// CoinPayments
	coinPaymentsCallbackResource = "/cryptoPaymentCallback"

	// Stripe
	fiatPaymentCallbackResource = "/fiatPaymentCallback"

	// SSL for HTTPS
	serverHostARecord = "api"
	sslDir              = "certs"
	currentCallbackHost url.URL

	// debugging
	runningDevelopmentServer = false

	// default client with timeout
	netClient = &http.Client{
		Timeout: time.Second * 5,
	}
)


// Called on start - parses CL args and starts the server
func main() {

	// Parse command line arguments
	mode := flag.String("mode", "debug", " 'debug' or 'production' - http or https + production logging")
	callbackIP := flag.String("ip", "http://localhost", " callback url for payments - for " +
		"local dev use ngrok")
	flag.Parse()

	// make sure the ip passed is a url
	currentCallbackIP, parseErr := url.ParseRequestURI(*callbackIP)
	if parseErr != nil{
		log.Info().Msg( "callback ip parse error: " + parseErr.Error())
		return
	}

	log.Info().Msg( "payment callbacks ip: " + currentCallbackIP.String())
	currentCallbackHost = *currentCallbackIP


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
	r.HandleFunc(fiatPaymentCallbackResource, fiatPaymentCallback)

	// openlaw
	r.HandleFunc("/getOpenlawJWT", getOpenlawJWT)
	r.HandleFunc("/inviteNewUser", inviteNewUser)
	r.HandleFunc("/checkUserExists", checkUserExists)


	// misc
	r.HandleFunc("/sendAdminsEmail", sendAdminsEmail)


	// unused
	//r.PathPrefix("/passThroughGETWithBasicAuthToOpenLaw/").HandlerFunc(passThroughGETWithBasicAuthToOpenLaw)

}


func checkUserExists(w http.ResponseWriter, r *http.Request) {
	type userExists struct {
		UserExists bool `json:"userExists"`
		//Error string `json:"error"`
	}
	// client specifies email
	email, err1:= getQueryValueOrError("email", r)
	if err1 != nil {
		respondWithError(w,http.StatusBadRequest, err1.Error())
		return
	}

	openLawJWT, code := getOpenLawJWTForUser(config.OpenLawUsernameAdmin, config.OpenLawPasswordAdmin)
	if  openLawJWT.Error != "" {
		respondWithError(w,code, openLawJWT.Error)
		return
	}

	urlStr := config.GetOpenLawUrl("/users/search")

	req, _ := http.NewRequest("GET",urlStr, nil)
	req.Header.Add("OPENLAW_JWT", openLawJWT.Jwt)

	q := req.URL.Query()
	q.Add("keyword", email)
	q.Add("page", "1")
	q.Add("pageSize", "25")
	req.URL.RawQuery = q.Encode()

	resp, err := netClient.Do(req)

	if err != nil{
		respondWithError(w,resp.StatusCode,err.Error())
		return
	}

	type OLUserExistsResponse struct {
		NbHits int `json:"nbHits"`
		Data   []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Name  string `json:"name"`
			Role  string `json:"role"`
		} `json:"data"`
	}
	var bodyBytes []byte
	bodyBytes, _ = ioutil.ReadAll(resp.Body)
	olResp :=  OLUserExistsResponse{}

	errParse := json.Unmarshal(bodyBytes,&olResp)
	if errParse != nil {
		respondWithError(w,http.StatusBadRequest,errParse.Error())
		return
	}

	userExistsResp := userExists{
		UserExists:olResp.NbHits>0,
	}

	respondWithJson(w,resp.StatusCode,userExistsResp)

}

func sendAdminsEmail(w http.ResponseWriter, r *http.Request) {
	message, err1:= getQueryValueOrError("message", r)
	if err1 != nil {
		respondWithError(w,http.StatusBadRequest, err1.Error())
		return
	}
	id, err := sendEmail("IMPORTANT",message, config.AdminEmail)
	if err!=nil{
		log.Error().Msg("email couldn't send to admins with error: " + err.Error())
		respondWithError(w,http.StatusBadRequest, err.Error())
		return
	}
	log.Info().Msg("email sent to admins with id: " + id)
	respondWithJson(w,http.StatusAccepted,"")

}



func inviteNewUser(w http.ResponseWriter, r *http.Request){
	// client specifies email
	newUserEmail, err1:= getQueryValueOrError("newUserEmail", r)
	if err1 != nil {
		respondWithError(w,http.StatusBadRequest, err1.Error())
		return
	}

	openLawJWT, code := getOpenLawJWTForUser(config.OpenLawUsernameAdmin, config.OpenLawPasswordAdmin)
	if  openLawJWT.Error != "" {
		respondWithError(w,code, openLawJWT.Error)
		return
	}
	urlStr := config.GetOpenLawUrl("/user/emailMultipleNewUsers/user")

	type newUserReq struct {
		Emails []string `json:"emails"`
		InstanceName string `json:"instanceName"`
	}

	newUserEmails:= []string{newUserEmail}
	emails := newUserReq{newUserEmails, config.OpenLawInstanceName }

	json, _ := json.Marshal(emails)

	req, _ := http.NewRequest("POST", urlStr, bytes.NewBuffer(json))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("OPENLAW_JWT", openLawJWT.Jwt)

	resp, err := netClient.Do(req)

	if err != nil{
		respondWithError(w,resp.StatusCode,err.Error())
		return
	}

	respondWithJson(w,resp.StatusCode,resp.Status)
}


func getOpenLawJWTForUser(user string, pass string) (OpenlawJWT, int){
	urlStr := config.GetOpenLawUrl("/app/login")
	//log.Info().Msg(urlStr)

	data := url.Values{}
	data.Set("userId", user)
	data.Set("password", pass)


	r, _ := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	openLawJWT := OpenlawJWT{}
	code:= http.StatusAccepted
	resp, err := netClient.Do(r)

	// assign error
	if err!= nil {
		openLawJWT.Error = err.Error()
		log.Error().Msg("openlaw request time out or failure!")
	}

	// assign jwt and openLawJWT code
	if resp!= nil{
		code = resp.StatusCode
		openLawJWT.Jwt = resp.Header.Get("OPENLAW_JWT")
		if code>=300{
			openLawJWT.Error = resp.Status
		}
	}

	return openLawJWT, code
}


// Gets a JWT from the Openlaw hosted instance using our credentials from the config.toml (not included in OS repo)
// REST api details from https://docs.openlaw.io/api-client/#authentication
func getOpenlawJWT(w http.ResponseWriter, r *http.Request){

	openLawJWT, code := getOpenLawJWTForUser(config.OpenLawUsername, config.OpenLawPassword)

	respondWithJson(w,code, openLawJWT)
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
	decoder.IgnoreUnknownKeys(true)
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

	log.Info().Msg( "transaction email: " + transactionCallback.Email)


	paymentComplete := false
	switch paymentStatus {
	case 0:
		log.Info().Msg("waiting for payment")
		break
	case 1:
		log.Info().Msg("coins received!")
		//TODO: we will want to be more stringent in the future, wait for confirmation
		//paymentComplete = true
		break
	case 2:
		log.Info().Msg("coins queued for payout!")
		//paymentComplete = true
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
		sendEmail("Payment Complete!", "We'll be in touch as we summon your " +
			"Entity from the Ether. See: https://" + config.ServerLocation + "/paid?email=" +
			transactionCallback.Email +
			" for your next steps. ", transactionCallback.Email)

		sendEmail("Payment Complete!", transactionCallback.Email + " completed their payment",
			config.AdminEmail)


	}


}


// Generates a crypto transaction via CoinPayments
func generateCryptoTransaction(w http.ResponseWriter, r *http.Request) {

	// client specifies crypto currency
	buyerEmail, err1:= getQueryValueOrError("buyerEmail", r)
	if err1 != nil {
		respondWithError(w,http.StatusBadRequest, err1.Error())
		return
	}

	// client specifies crypto currency
	cryptoCurrency, err1:= getQueryValueOrError("crypto", r)
	if err1 != nil {
		respondWithError(w,http.StatusBadRequest, err1.Error())
		return
	}

	// price is in default USD
	price, err2:= getQueryValueOrError("price", r)
	if err2 != nil {
		respondWithError(w,http.StatusBadRequest, err2.Error())
		return
	}

	amount, err := strconv.ParseFloat(price,  64)
	if err!=nil{
		badInt := "price as int not formatted correctly"
		log.Error().Msg(badInt)
		respondWithError(w,http.StatusBadRequest, badInt)
		return
	}

	// generate our full url for payment callbacks to make sure url works
	coinPaymentsCallbackURL := currentCallbackHost
	coinPaymentsCallbackURL.Path = coinPaymentsCallbackResource


	// Ask coinpayments for a crypto transaction
	coinClient := coinpayments.NewClient(config.CoinPaymentsPublic,config.CoinPaymentsPrivate, http.DefaultClient)
	newTransaction := coinpayments.TransactionParams{
		Amount:     amount,
		Currency1:  "USD",
		Currency2:  cryptoCurrency,
		BuyerEmail: buyerEmail,
		IPNUrl: coinPaymentsCallbackURL.String(),
	}
	trans, _, err := coinClient.Transactions.NewTransaction(&newTransaction)

	if err!= nil {
		log.Error().Msg(err.Error())
		respondWithError(w,http.StatusInternalServerError, err.Error())
		return
	}

	if trans.Error!="ok"{
		log.Error().Msg(trans.Error)
		respondWithError(w,http.StatusInternalServerError, trans.Error)
		return
	}

	log.Info().Msg("transaction created!")
	respondWithJson(w,http.StatusAccepted, trans)
}


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
	endpointSecret := config.StripeWebHookSecret
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


		log.Info().Msg("Payment Callback Complete - User successfully completed payment!")
		sendEmail("Payment Complete",
			"Fiat Payment Completed! Time to file those papers.",
			config.AdminEmail)

	}

	w.WriteHeader(http.StatusOK)
}

// TODO: if the user cancels a fiat payment, how do we make sure their openlaw form is saved?
func getFiatPayment(w http.ResponseWriter, r *http.Request) {

	email, err1:= getQueryValueOrError("email", r)
	if err1 != nil {
		respondWithError(w,http.StatusBadRequest, err1.Error())
		return
	}
	price, err2:= getQueryValueOrError("price", r)
	if err2 != nil {
		respondWithError(w,http.StatusBadRequest, err2.Error())
		return
	}

	priceInt, err := strconv.ParseInt(price, 10, 64)
	if err!=nil{
		badInt := "price as int not formatted correctly"
		log.Error().Msg(badInt)
		respondWithError(w,http.StatusBadRequest, badInt)
		return
	}

	product, err3:= getQueryValueOrError("product", r)
	if err3 != nil {
		respondWithError(w,http.StatusBadRequest, err3.Error())
		return
	}

	// Set your secret key: remember to change this to your live secret key in production
	// See your keys here: https://dashboard.stripe.com/account/apikeys
	// live key:
	stripe.Key = config.StripePrivate

	// test key:
	//stripe.Key = "sk_test_fPVOpS8a0NQr7cJ1bF2GpKCw00C7ru06xe"

	log.Info().Msg("stripe callback url: " + currentCallbackHost.String() + fiatPaymentCallbackResource)

	params := &stripe.CheckoutSessionParams{
		PaymentMethodTypes: stripe.StringSlice([]string{
			"card",
		}),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			&stripe.CheckoutSessionLineItemParams{
				Name: stripe.String(config.ServerLocation),
				Description: stripe.String(product),
				Amount: stripe.Int64(priceInt),
				Currency: stripe.String(string(stripe.CurrencyUSD)),
				Quantity: stripe.Int64(1),

			},

		},

		SuccessURL: stripe.String("https://www." + config.ServerLocation + "/paid" +
			"?session_id={CHECKOUT_SESSION_ID}" +
			"&email=" + email),
		CancelURL: stripe.String("https://www." + config.ServerLocation + "/create"),
	}


	session, err := sessionStripe.New(params)
	if err!=nil{
		respondWithError(w,http.StatusInternalServerError,err.Error())
		return
	}

	respondWithJson(w,http.StatusAccepted,session)
}


func getQueryValueOrError(key string, r *http.Request) (string, error){
	keyValue := r.FormValue(key)
	if keyValue == "" {
		missingParam :="Url Param " + key +" is missing"
		log.Error().Msg(missingParam)
		return "", errors.New(missingParam)
	}
	return keyValue, nil

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
	serverHostName := serverHostARecord + "." + config.ServerLocation

	// Ian gets a text if we have a fatal error
	//log = AttachErrorMessaging(avalogging.Log)

	//Key and cert are coming from Let's Encrypt
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(serverHostName), //Your domain here
		Cache:      autocert.DirCache(sslDir),              //Folder for storing certificates
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


func sendEmail(title string, msg string, recipient string) (string, error) {
	domain := "mg." + config.ServerLocation
	mg := mailgun.NewMailgun(domain, config.MailGunPrivate)
	m := mg.NewMessage(
		config.ServerLocation + " <noreply@"+config.ServerLocation+">",
		title,
		msg,
		recipient,
	)

	_, id, err := mg.Send(context.Background(), m)
	return id, err
}




// Unused:

// this function translated get requests to our server to get requests with basic auth attached
// and made the request to our openlaw instance on Kaleido. For the sake of dev speed we're just going
// to store the basic auth on the front-end and hope for the best for the time being!
func passThroughGETWithBasicAuthToOpenLaw(w http.ResponseWriter, r *http.Request){
	// dashboard: https://console.kaleido.io/dashboard/openlaw/u0vvwcatsl/u0ztgr50os/u0gzl2r9pj/u0flnq9hwd
	// TODO: make the auth code modular
	resource := "/app/login"
	ur, _ := url.ParseRequestURI("kaleidoInstance")
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
	u, _ := url.ParseRequestURI("kaleidoInstance" + newURL)
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



// kaleido pauses free instances after inactivity: https://docs.kaleido.io/faqs/why-is-my-environment-paused/
func pingKaleidoRecurrently(){
	// wait for server to come online
	time.Sleep(3 * time.Second)

	for {
		r, _ := http.NewRequest("GET", currentCallbackHost.String() + "/getOpenlawJWT", nil) // URL-encoded payload
		//r, _ := http.NewRequest("GET", config.KaleidoInstanceURL + "/", nil) // URL-encoded payload

		resp, err := netClient.Do(r)
		if err !=nil{
			log.Error().Msg("Kaleido ping error: " + err.Error())
		} else {
			log.Info().Msg("Kaleido ping response: " + resp.Status)
		}
		time.Sleep(70 * time.Hour)
	}
}

