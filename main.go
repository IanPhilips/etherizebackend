package main

import (
	"bytes"
	"crypto/sha512"
	"crypto/tls"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"flag"
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


var log = Log
var runningOnLocalHost = false
var logName = "Etherize.log"
var hostName = "etherize.io"
var sslDir = "certs"
var config = Config{}
var coinClient *coinpayments.Client
var callbackIP *string
var callbackEndpoint = "/cryptoPaymentCallback"

func main() {

	config.Read()

	r := mux.NewRouter()
	mode := flag.String("mode", "debug", " 'debug' or 'production' - http or https + production logging")
	callbackIP = flag.String("ip", "CALLBACK IP NOT SET", " callback url for coinpayments - for debugging use ngrok")
	flag.Parse()

	log.Info().Msg( "callaback ip set to: " + *callbackIP)

	registerHandlers(r)
	r.Use(loggingMiddleware)


	// debug mode
	if *mode == "debug" {
		runningOnLocalHost = true
		log.Info().Msg("running in debug more on port 80")

		if err := http.ListenAndServe(":80", r); err != nil {
			log.Fatal().Msg(err.Error())
		}

		// production mode
	} else if *mode == "production" {
		runningOnLocalHost = false
		runProductionServer(r)
	}


}


func registerHandlers(r *mux.Router){

	// payments
	r.HandleFunc("/cryptoPayment", getCryptoPayment)
	r.HandleFunc(callbackEndpoint, cryptoPaymentCallback)
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
	data.Set("userId", config.Username)
	data.Set("password", config.Password)


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

func cryptoPaymentCallback(w http.ResponseWriter, r *http.Request) {

	log.Info().Msg("callback called!")
	// Read the content
	var bodyBytes []byte
	bodyBytes, _ = ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))// Use the content

	err := r.ParseForm()
	if err != nil {
		log.Error().Msg("couldn't parse form: " + err.Error())
	}

	suppliedHmac := r.Header.Get("Hmac")
	if suppliedHmac == ""{
		log.Error().Msg("no HMAC signature set")
	}

	//log.Info().Msg("body: "+ bodyString)


	mac := hmac.New(sha512.New, []byte(config.CoinPaymentsIPN))
	mac.Write([]byte(bodyBytes))
	sha := hex.EncodeToString(mac.Sum(nil))

	//log.Info().Msg("computed sha: " + sha)
	//log.Info().Msg("supplied sha: " + suppliedHmac)

	if suppliedHmac != sha{
		log.Info().Msg("hmacs don't match!")
		return
	}

	transactionCallback := new(TransactionCallback)
	decoder := schema.NewDecoder()


	err = decoder.Decode(transactionCallback, r.Form)
	if err != nil {
		log.Error().Msg("couldn't decode callback: " + err.Error())
	}

	suppliedMerchantId := transactionCallback.Merchant
	if suppliedMerchantId != config.CoinPaymentsMerchantId{
		log.Error().Msg("merchant id doesn't match")
		return
	}


	log.Info().Msg("callback successfully processed with status: " + transactionCallback.StatusText)
	log.Info().Msg("user has successfully paid! id: " + transactionCallback.Id)

}



func getCryptoPayment(w http.ResponseWriter, r *http.Request) {

	coinClient = coinpayments.NewClient(config.CoinPaymentsPublic,config.CoinPaymentsPrivate, http.DefaultClient)

	apiUrl := callbackIP
	resource := callbackEndpoint
	u, _ := url.ParseRequestURI(*apiUrl)
	u.Path = resource
	urlStr := u.String()

	newTransaction := coinpayments.TransactionParams{
		Amount:.01,
		Currency1:"USD",
		Currency2:"LTCT",
		BuyerEmail:config.TestEmail,
		IPNUrl:urlStr,

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
	log.Info().Msg("Status URL:   " + trans.Result.StatusUrl + "    ")
	respondWithJson(w,http.StatusAccepted, trans)
}


func getFiatPayment(w http.ResponseWriter, r *http.Request) {

}


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



// region: logging

// logs all requests to server
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do stuff here
		log.Info().Str("Request made to",r.RequestURI).Msg(r.Method)
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}
//endregion


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

//endregion