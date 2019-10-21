package etherizeBackend

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/acme/autocert"
	"net/http"
	"os"
	"runtime"
)


var log = Log
var runningOnLocalHost = false
var logName = "Etherize.log"
var hostName = "etherize.io"
var sslDir = "certs"
var config = Config{}

func main() {

	config.Read()

	r := mux.NewRouter()
	flag.Parse()

	registerHandlers(r)
	r.Use(loggingMiddleware)


	// debug mode on mac
	if runtime.GOOS == "darwin" {
		runningOnLocalHost = true
		log.Info().Msg("running on port 80")

		if err := http.ListenAndServe(":80", r); err != nil {
			log.Fatal().Msg(err.Error())
		}

		// production mode on linux
	} else if runtime.GOOS == "linux" {
		runningOnLocalHost = false
		runProductionServer(r)
	}

}


func registerHandlers(r *mux.Router){

	// payments
	r.HandleFunc("/cryptoPayment", getCryptoPayment)
	r.HandleFunc("/fiatPayment", getFiatPayment)
	r.HandleFunc("/getOpenlawJWT", getOpenlawJWT)


}


func getOpenlawJWT(w http.ResponseWriter, r *http.Request){
	url := "https://etherizeit.openlaw.io";
	// You can change TEMPLATE_NAME to 'articles-of-organization' to make the code work ...
	// Right now, both deal templates on Etherizeit instance are causing the same issue
	openlawUser := config.Username
	openlawPass := config.Password
	
}


func getCryptoPayment(w http.ResponseWriter, r *http.Request) {

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