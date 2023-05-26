// Package report contains error reporting functions.
package report

import (
	"fmt"
	"time"

	"github.com/cloudflare/redoctober/config"
	"github.com/getsentry/sentry-go"
)

// useSentry will be set to true if sentry reporting is valid.
var useSentry bool

// sentryTags contains additional tags that can be sent to Sentry.

func configSentry(cfg *config.Config) {
	err := sentry.Init(sentry.ClientOptions{
		Dsn: cfg.Reporting.SentryDSN,
	})

	if err != nil {
		fmt.Printf("Sentry initialization failed: %v\n", err)
		return
	}

	useSentry = true
	var sentryTags = map[string]string{}

	sentryTags["started_at"] = fmt.Sprintf("%d", time.Now().Unix())

	sentryTags["server.systemd"] = fmt.Sprintf("%v", cfg.Server.Systemd)
	if cfg.Server.Addr != "" {
		sentryTags["server.address"] = cfg.Server.Addr
	}

	sentryTags["metrics.host"] = cfg.Metrics.Host
	sentryTags["metrics.port"] = cfg.Metrics.Port

	if cfg.HipChat.ID != "" {
		sentryTags["hipchat.id"] = cfg.HipChat.ID
	}

	sentryTags["persist.enabled"] = fmt.Sprintf("%v", cfg.Delegations.Persist)
	if cfg.Delegations.Persist {
		sentryTags["persist.mechanism"] = cfg.Delegations.Mechanism
		sentryTags["persist.location"] = cfg.Delegations.Location
	}

	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTags(sentryTags)
	})
}

func Init(cfg *config.Config) {
	if cfg.Reporting.SentryDSN != "" {
		configSentry(cfg)
	}
}

// Check will see if err contains an error; if it does, and if
// reporting is configured, it will report the error.
func Check(err error, tags map[string]string) {
	if err == nil {
		return
	}

	if tags == nil {
		tags = map[string]string{}
	}

	if useSentry {
		sentry.ConfigureScope(func(scope *sentry.Scope) {
			scope.SetTags(tags)
		})
		sentry.CaptureException(err)
	}
}

// Recover will wrap the function in a manner that will capture
// panics. If error reporting isn't active, it will just panic. This
// default behaviour allows the stack trace to be capture in the
// system logs and the service management system (e.g. systemd) to
// automatically restart the server.
func Recover(fn func()) {
	if useSentry {
		defer sentry.Recover()
	}
	fn()
}
