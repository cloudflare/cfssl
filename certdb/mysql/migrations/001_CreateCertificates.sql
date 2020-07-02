-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE certificates (
  serial_number            varbinary(128) NOT NULL,
  subject                  varchar(1024) NOT NULL,
  authority_key_identifier varbinary(128) NOT NULL,
  ca_label                 varbinary(128),
  ca_profile               varbinary(128),
  status                   varbinary(128) NOT NULL,
  reason                   int,
  created_at               timestamp DEFAULT '0000-00-00 00:00:00',
  expiry                   timestamp DEFAULT '0000-00-00 00:00:00',
  revoked_at               timestamp DEFAULT '0000-00-00 00:00:00',
  pem                      varbinary(4096) NOT NULL,
  request                  varbinary(8192),
  PRIMARY KEY(serial_number, authority_key_identifier),
  FULLTEXT INDEX certificates_subject (subject),
  INDEX certificates_created_at (created_at),
  INDEX certificates_revoked_at (revoked_at)
);

CREATE TABLE ocsp_responses (
  serial_number            varbinary(128) NOT NULL,
  authority_key_identifier varbinary(128) NOT NULL,
  body                     varbinary(4096) NOT NULL,
  expiry                   timestamp DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY(serial_number, authority_key_identifier)
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE certificates;
DROP TABLE ocsp_responses;
