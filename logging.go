package main

import (
	zlog "github.com/rs/zerolog/log"
	"io"
	"net/http"
	"os"
)

var logName = "Etherize.log"
var log = zlog.With().Caller().Logger()

// logs all requests to server
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do stuff here
		log.Info().Str("Request made to",r.RequestURI).Msg(r.Method)
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}

func SetupProductionLogger(f *os.File) {
	// create multiwriter to write to std out as well as logfile
	mw := io.MultiWriter(os.Stdout, f)

	//defer to close when you're done with it

	log = zlog.With().Caller().Logger().Output(mw)

}
