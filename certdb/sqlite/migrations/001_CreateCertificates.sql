-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE certificates (
  serial_number            blob NOT NULL,
  authority_key_identifier blob NOT NULL,
  ca_label                 blob,
  status                   blob NOT NULL,
  reason                   int,
  expiry                   timestamp,
  revoked_at               timestamp,
  pem                      blob NOT NULL,
  PRIMARY KEY(serial_number, authority_key_identifier)
);

CREATE TABLE ocsp_responses (
  serial_number            blob NOT NULL,
  authority_key_identifier blob NOT NULL,
  body                     blob NOT NULL,
  expiry                   timestamp,
  PRIMARY KEY(serial_number, authority_key_identifier),
  FOREIGN KEY(serial_number, authority_key_identifier) REFERENCES certificates(serial_number, authority_key_identifier)
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE ocsp_responses;
DROP TABLE certificates;

