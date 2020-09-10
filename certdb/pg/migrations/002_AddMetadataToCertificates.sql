-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE certificates
ADD COLUMN issued_at timestamptz,
    ADD COLUMN not_before timestamptz,
    ADD COLUMN originating_host TEXT,
    ADD COLUMN sans TEXT,
    ADD COLUMN tags TEXT,
    ADD COLUMN common_name TEXT,
    ADD COLUMN filename TEXT,
    ADD COLUMN application_name TEXT;
-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
ALTER TABLE certificates DROP COLUMN issued_at,
    DROP COLUMN not_before,
    DROP COLUMN originating_host,
    DROP COLUMN sans,
    DROP COLUMN tags,
    DROP COLUMN common_name,
    DROP COLUMN filename,
    DROP COLUMN application_name;