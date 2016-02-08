// Package log implements a wrapper around the Go standard library's
// logging package. Clients should set the current log level; only
// messages below that level will actually be logged. For example, if
// Level is set to LevelWarning, only log messages at the Warning,
// Error, and Critical levels will be logged.
package log

import (
	"flag"
	"fmt"
	golog "log"
	"log/syslog"
	"os"
)

// The following constants represent logging levels in increasing levels of seriousness.
const (
	LevelDebug = iota
	LevelInfo
	LevelWarning
	LevelError
	LevelCritical
	LevelFatal
)

var levelPrefix = [...]string{
	LevelDebug:    "[DEBUG] ",
	LevelInfo:     "[INFO] ",
	LevelWarning:  "[WARNING] ",
	LevelError:    "[ERROR] ",
	LevelCritical: "[CRITICAL] ",
	LevelFatal:    "[FATAL] ",
}

var levelPriority = [...]syslog.Priority{
	LevelDebug:    syslog.LOG_DEBUG,
	LevelInfo:     syslog.LOG_INFO,
	LevelWarning:  syslog.LOG_WARNING,
	LevelError:    syslog.LOG_ERR,
	LevelCritical: syslog.LOG_CRIT,
	LevelFatal:    syslog.LOG_EMERG,
}

// Level stores the current logging level.
var Level = LevelDebug

var (
	//UseSyslog controls if syslog is used instead of stdout/err.
	UseSyslog bool
	//SyslogNetwork controls the network protocol syslog uses.
	SyslogNetwork string
	//SyslogRaddr is the address of a remote syslog instance.
	SyslogRaddr string
	//SyslogTag is the tag to pass to syslog.
	SyslogTag string
)

func init() {
	flag.IntVar(&Level, "loglevel", LevelDebug, "Log level")
	flag.BoolVar(&UseSyslog, "syslog", false, "Whether or not to use syslog logging")
	flag.StringVar(&SyslogNetwork, "syslog-network", "udp", "Syslog network to use.")
	flag.StringVar(&SyslogRaddr, "syslog-remote", "", "Syslog server to use. Defaults to local on empty string.")
	flag.StringVar(&SyslogTag, "syslog-tag", "udp", "Syslog tag to use.")
}

func outputf(l int, format string, v []interface{}) {
	if l >= Level {
		msg := fmt.Sprintf(fmt.Sprint(levelPrefix[l], format), v...)
		if UseSyslog {
			logger, err := syslog.Dial(SyslogNetwork, SyslogRaddr, levelPriority[l], SyslogTag)
			defer logger.Close()
			if err != nil {
				golog.Fatal(err)
			}
			golog.SetOutput(logger)
		} else if l > 2 {
			golog.SetOutput(os.Stderr)
		} else {
			golog.SetOutput(os.Stdout)
		}
		golog.Print(msg)
	}
}

func output(l int, v []interface{}) {
	if l >= Level {
		msg := fmt.Sprint(levelPrefix[l], fmt.Sprint(v...))
		if UseSyslog {
			logger, err := syslog.Dial(SyslogNetwork, SyslogRaddr, levelPriority[l], SyslogTag)
			defer logger.Close()
			if err != nil {
				golog.Fatal(err)
			}
			golog.SetOutput(logger)
		} else if l > 2 {
			golog.SetOutput(os.Stderr)
		} else {
			golog.SetOutput(os.Stdout)
		}
		golog.Print(msg)
	}
}

// Fatalf logs a formatted message at the "fatal" level and then exits. The
// arguments are handled in the same manner as fmt.Printf.
func Fatalf(format string, v ...interface{}) {
	outputf(LevelFatal, format, v)
	os.Exit(1)
}

// Fatal logs its arguments at the "fatal" level and then exits.
func Fatal(v ...interface{}) {
	output(LevelFatal, v)
	os.Exit(1)
}

// Criticalf logs a formatted message at the "critical" level. The
// arguments are handled in the same manner as fmt.Printf.
func Criticalf(format string, v ...interface{}) {
	outputf(LevelCritical, format, v)
}

// Critical logs its arguments at the "critical" level.
func Critical(v ...interface{}) {
	output(LevelCritical, v)
}

// Errorf logs a formatted message at the "error" level. The arguments
// are handled in the same manner as fmt.Printf.
func Errorf(format string, v ...interface{}) {
	outputf(LevelError, format, v)
}

// Error logs its arguments at the "error" level.
func Error(v ...interface{}) {
	output(LevelError, v)
}

// Warningf logs a formatted message at the "warning" level. The
// arguments are handled in the same manner as fmt.Printf.
func Warningf(format string, v ...interface{}) {
	outputf(LevelWarning, format, v)
}

// Warning logs its arguments at the "warning" level.
func Warning(v ...interface{}) {
	output(LevelWarning, v)
}

// Infof logs a formatted message at the "info" level. The arguments
// are handled in the same manner as fmt.Printf.
func Infof(format string, v ...interface{}) {
	outputf(LevelInfo, format, v)
}

// Info logs its arguments at the "info" level.
func Info(v ...interface{}) {
	output(LevelInfo, v)
}

// Debugf logs a formatted message at the "debug" level. The arguments
// are handled in the same manner as fmt.Printf.
func Debugf(format string, v ...interface{}) {
	outputf(LevelDebug, format, v)
}

// Debug logs its arguments at the "debug" level.
func Debug(v ...interface{}) {
	output(LevelDebug, v)
}
