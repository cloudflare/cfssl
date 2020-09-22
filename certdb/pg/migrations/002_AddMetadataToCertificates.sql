-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE certificates
ADD COLUMN issued_at timestamptz,
    ADD COLUMN not_before timestamptz,
    ADD COLUMN metadata jsonb,
    ADD COLUMN sans jsonb,
    ADD COLUMN common_name TEXT;
-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
ALTER TABLE certificates DROP COLUMN issued_at,
    DROP COLUMN not_before,
    DROP COLUMN metadata,
    DROP COLUMN sans,
    DROP COLUMN common_name;