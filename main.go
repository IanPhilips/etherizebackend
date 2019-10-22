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
	"golang.org/x/crypto/acme/autocert"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
)


// SSL for HTTPS
var hostName = "etherize.io"
var sslDir = "certs"

// CoinPayments
var coinPaymentsCallbackResource = "/cryptoPaymentCallback"
var coinPaymentsCallbackURL string

// debugging
var runningOnLocalHost = false


// Called on start - parses CL args and starts the server
func main() {

	// Parse command line arguments
	mode := flag.String("mode", "debug", " 'debug' or 'production' - http or https + production logging")
	callbackIP := flag.String("ip", "CALLBACK IP NOT SET", " callback url for coinpayments - for debugging use ngrok")
	flag.Parse()
	log.Info().Msg( "callaback ip set to: " + *callbackIP)

	// generate our full url for payment callbacks
	resource := coinPaymentsCallbackResource
	u, _ := url.ParseRequestURI(*callbackIP)
	u.Path = resource
	coinPaymentsCallbackURL = u.String()


	// setup
	config.Read()
	r := mux.NewRouter()
	registerHandlers(r)
	r.Use(loggingMiddleware)


	// debug mode
	if *mode == "debug" {
		runningOnLocalHost = true
		log.Info().Msg("running in debug more on port 80")

		if err := http.ListenAndServe(":80", handlers.CORS()(r)); err != nil {
			log.Fatal().Msg(err.Error())
		}

		// production mode
	} else if *mode == "production" {
		runningOnLocalHost = false
		runProductionServer(r)
	}


}


// match endpoints to functions
func registerHandlers(r *mux.Router){

	// payments
	r.HandleFunc("/generateCryptoTransaction", generateCryptoTransaction)
	r.HandleFunc(coinPaymentsCallbackResource, cryptoPaymentCallback)
	r.HandleFunc("/fiatPayment", getFiatPayment)
	r.HandleFunc("/getOpenlawJWT", getOpenlawJWT)

}


// Gets a JWT from the Openlaw hosted instance using our credentials from the config.toml (not included in OS repo)
// REST api details from https://docs.openlaw.io/api-client/#authentication
func getOpenlawJWT(w http.ResponseWriter, r *http.Request){
	apiUrl := "https://etherizeit.openlaw.io"
	resource := "/app/login"
	u, _ := url.ParseRequestURI(apiUrl)
	u.Path = resource
	urlStr := u.String()

	data := url.Values{}
	data.Set("userId", config.OpenLawUsername)
	data.Set("password", config.OpenLawPassword)


	client := &http.Client{}
	r, _ = http.NewRequest("POST", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, err := client.Do(r)
	if err!= nil {
		respondWithError(w, resp.StatusCode, err.Error())
		return
	}

	response := OpenlawJWT{
		Jwt: resp.Header.Get("OPENLAW_JWT"),
		Error:"",
	}

	respondWithJson(w,http.StatusAccepted,response)

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


	log.Info().Msg("callback successfully processed with status: " + transactionCallback.StatusText)
	log.Info().Msg("Coinpayments update for transaction id: " + transactionCallback.Id)

	// TODO: determine difference between successful payments and still pending ones

}


// Generates a crypto transaction via CoinPayments
func generateCryptoTransaction(w http.ResponseWriter, r *http.Request) {

	// amount is in default USD
	amount := .01
	cryptoCurrency := "LTCT"

	// Ask coinpayments for a crypto transaction
	coinClient := coinpayments.NewClient(config.CoinPaymentsPublic,config.CoinPaymentsPrivate, http.DefaultClient)
	newTransaction := coinpayments.TransactionParams{
		Amount:     amount,
		Currency1:  "USD",
		Currency2:  cryptoCurrency,
		BuyerEmail: config.TestEmail,
		IPNUrl:     coinPaymentsCallbackURL,
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
	respondWithJson(w,http.StatusAccepted, trans)
}


// TODO
func getFiatPayment(w http.ResponseWriter, r *http.Request) {

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
		Handler: r,
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

