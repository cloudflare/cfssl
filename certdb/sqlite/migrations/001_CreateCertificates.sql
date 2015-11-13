-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE certificates (
  id                serial,
  serial            bytea NOT NULL PRIMARY KEY,
  ca_label          bytea NOT NULL,
  status            bytea NOT NULL,
  reason            int,
  expiry            timestamp,
  revoked_at        timestamp,
  pem               bytea NOT NULL
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE certificates;

