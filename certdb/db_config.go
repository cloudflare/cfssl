package certdb

import (
	"encoding/json"
	"errors"
	"io/ioutil"

	"database/sql"

	_ "github.com/lib/pq"           // import just to initialize Postgres
	_ "github.com/mattn/go-sqlite3" // import just to initialize SQLite

	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
)

// DBConfig contains the database driver name and configuration to be passed to Open
type DBConfig struct {
	DriverName     string
	DataSourceName string
}

// LoadFile attempts to load the db configuration file stored at the path
// and returns the configuration. On error, it returns nil.
func LoadFile(path string) (cfg *DBConfig, err error) {
	log.Debugf("loading db configuration file from %s", path)
	if path == "" {
		return nil, cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, errors.New("invalid path"))
	}

	var body []byte
	body, err = ioutil.ReadFile(path)
	if err != nil {
		return nil, cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, errors.New("could not read configuration file"))
	}

	cfg = &DBConfig{}
	err = json.Unmarshal(body, &cfg)
	if err != nil {
		return nil, cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy,
			errors.New("failed to unmarshal configuration: "+err.Error()))
	}

	if cfg.DataSourceName == "" || cfg.DriverName == "" {
		return nil, cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, errors.New("invalid db configuration"))
	}

	log.Info("db configuration ok")
	return
}

// DBFromConfig opens a sql.DB from settings in a db config file
func DBFromConfig(path string) (db *sql.DB, err error) {
	var dbCfg *DBConfig
	dbCfg, err = LoadFile(path)
	if err != nil {
		return nil, err
	}

	return sql.Open(dbCfg.DriverName, dbCfg.DataSourceName)
}
