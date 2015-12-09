-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE ocsp_responses (
  serial            bytea NOT NULL PRIMARY KEY,
  body              bytea NOT NULL,
  expiry            timestamptz,
  FOREIGN KEY(serial) REFERENCES certificates(serial)
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE ocsp_responses;


