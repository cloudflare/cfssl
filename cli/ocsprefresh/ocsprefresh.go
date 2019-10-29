// Package ocsprefresh implements the ocsprefresh command.
package ocsprefresh

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/dbconf"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/gomodule/redigo/redis"
)

// Usage text of 'cfssl ocsprefresh'
var ocsprefreshUsageText = `cfssl ocsprefresh -- refreshes the ocsp_responses table
with new OCSP responses for all known unexpired certificates (with recently changed only as option).

Usage of ocsprefresh:
        cfssl ocsprefresh -db-config db-config -ca cert -responder cert -responder-key key [-interval 96h] [-recent-changes-only 5min] [-redis host:port]

Flags:
`

// Flags of 'cfssl ocsprefresh'
var ocsprefreshFlags = []string{"ca", "responder", "responder-key", "db-config", "interval", "recent-changes-only", "redis"}

// ocsprefreshMain is the main CLI of OCSP refresh functionality.
func ocsprefreshMain(args []string, c cli.Config) error {
	if c.DBConfigFile == "" {
		return errors.New("need DB config file (provide with -db-config)")
	}

	if c.ResponderFile == "" {
		return errors.New("need responder certificate (provide with -responder)")
	}

	if c.ResponderKeyFile == "" {
		return errors.New("need responder key (provide with -responder-key)")
	}

	if c.CAFile == "" {
		return errors.New("need CA certificate (provide with -ca)")
	}

	s, err := SignerFromConfig(c)
	if err != nil {
		log.Critical("Unable to create OCSP signer: ", err)
		return err
	}

	db, err := dbconf.DBFromConfig(c.DBConfigFile)
	if err != nil {
		return err
	}

	ca, err := helpers.ReadBytes(c.CAFile)
	if err != nil {
		return err
	}
	CACert, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return err
	}
	dbAccessor := sql.NewAccessor(db)

	var certs []certdb.CertificateRecord

	if c.RecentChangesOnly != 0 {
		oldestChangeTimestamp := time.Now().Add(-c.RecentChangesOnly).UTC()
		c, err := dbAccessor.GetUnexpiredCertificatesRecentChangesOnlyByAKI(hex.EncodeToString(CACert.SubjectKeyId), oldestChangeTimestamp)
		if err != nil {
			return err
		}
		certs = c
	} else {
		c, err := dbAccessor.GetUnexpiredCertificatesByAKI(hex.EncodeToString(CACert.SubjectKeyId))
		if err != nil {
			return err
		}
		certs = c
	}

	// Open connection to redis service if redis flag present.
	var redisConn redis.Conn
	if c.Redis != "" {
		dialOptions := []redis.DialOption{
			redis.DialReadTimeout(time.Duration(10) * time.Second),
			redis.DialWriteTimeout(time.Duration(10) * time.Second),
			redis.DialConnectTimeout(time.Duration(30) * time.Second),
		}

		if redisConn, err = redis.Dial("tcp", c.Redis, dialOptions...); err != nil {
			log.Critical("Unable to connect to redis service: ", err)
			return err
		}

		defer redisConn.Close()
	}

	// Set an expiry timestamp for all certificates refreshed in this batch
	ocspExpiry := time.Now().Add(c.Interval)
	for _, certRecord := range certs {
		cert, err := helpers.ParseCertificatePEM([]byte(certRecord.PEM))
		if err != nil {
			log.Critical("Unable to parse certificate: ", err)
			return err
		}

		req := ocsp.SignRequest{
			Certificate: cert,
			Status:      certRecord.Status,
		}

		if certRecord.Status == "revoked" {
			req.Reason = int(certRecord.Reason)
			req.RevokedAt = certRecord.RevokedAt
		}

		resp, err := s.Sign(req)
		if err != nil {
			log.Critical("Unable to sign OCSP response: ", err)
			return err
		}

		// Store signed response in redis if enabled; store in SQL db otherwise.
		if redisConn != nil {
			// Use sha1 of cert AKI+SerialNumber for smaller and faster keys in redis; set
			// item expiry in redis (in seconds) same as for OCSP response.
			if _, err := redisConn.Do("SET", sha1.Sum(append(cert.AuthorityKeyId, cert.SerialNumber.Bytes()...)), resp, "EX", int(c.Interval.Seconds())); err != nil {
				log.Critical("Unable to save OCSP response in redis: ", err)
				return err
			}
		} else {
			err = dbAccessor.UpsertOCSP(cert.SerialNumber.String(), hex.EncodeToString(cert.AuthorityKeyId), string(resp), ocspExpiry)
			if err != nil {
				log.Critical("Unable to save OCSP response in SQL database: ", err)
				return err
			}
		}
	}

	return nil
}

// SignerFromConfig creates a signer from a cli.Config as a helper for cli and serve
func SignerFromConfig(c cli.Config) (ocsp.Signer, error) {
	//if this is called from serve then we need to use the specific responder key file
	//fallback to key for backwards-compatibility
	k := c.ResponderKeyFile
	if k == "" {
		k = c.KeyFile
	}
	return ocsp.NewSignerFromFile(c.CAFile, c.ResponderFile, k, time.Duration(c.Interval))
}

// Command assembles the definition of Command 'ocsprefresh'
var Command = &cli.Command{UsageText: ocsprefreshUsageText, Flags: ocsprefreshFlags, Main: ocsprefreshMain}
