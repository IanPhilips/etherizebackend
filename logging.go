package main

import (
zlog "github.com/rs/zerolog/log"
"io"
"os"
)

var Log = zlog.With().Caller().Logger()



func SetupProductionLogger(f *os.File) {
	// create multiwriter to write to std out as well as logfile
	mw := io.MultiWriter(os.Stdout, f)

	//defer to close when you're done with it

	Log = zlog.With().Caller().Logger().Output(mw)

}
