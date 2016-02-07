-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE certificates (
  id                serial,
  serial            bytea NOT NULL UNIQUE,
  ca_label          bytea NOT NULL,
  status            bytea NOT NULL,
  reason            int,
  expiry            timestamptz,
  revoked_at        timestamptz,
  pem               bytea NOT NULL,
  PRIMARY KEY(id, serial)
);

CREATE TABLE ocsp_responses (
  id                serial PRIMARY KEY,
  serial            bytea NOT NULL,
  body              bytea NOT NULL,
  expiry            timestamptz,
  FOREIGN KEY(serial) REFERENCES certificates(serial)
);
-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE ocsp_responses;
DROP TABLE certificates;
