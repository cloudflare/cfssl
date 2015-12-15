This directory stores [goose](https://bitbucket.org/liamstask/goose/) db migration scripts for various DB backends.
Currently supported:
 - SQLite in sqlite
 - PostgreSQL in pg

## Get goose
'go get https://bitbucket.org/liamstask/goose/'

## Use goose to start and terminate a SQLite DB
To start a SQLite DB using goose:
'goose -path GOPATH/src/github.com/cloudflare/cfssl/certdb/sqlite up'
To tear down a SQLite DB using goose
'goose -path GOPATH/src/github.com/cloudflare/cfssl/certdb/sqlite down'

## Use goose to start and terminate a PostegreSQL DB
To start a PostgreSQL using goose:
'goose -path GOPATH/src/github.com/cloudflare/cfssl/certdb/pg up'
To tear down a PostgreSQL DB using goose
'goose -path GOPATH/src/github.com/cloudflare/cfssl/certdb/pg down'

Note: the administration of PostgreSQL DB is not included. We assume
the databases being connected to are already created and access control
are properly handled.



