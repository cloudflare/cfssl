-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE certificates ADD COLUMN "issued_at" timestamp;
ALTER TABLE certificates ADD COLUMN "not_before" timestamp;
ALTER TABLE certificates ADD COLUMN "metadata" text;
ALTER TABLE certificates ADD COLUMN "sans" text;
ALTER TABLE certificates ADD COLUMN "common_name" text;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

-- can't drop columns in sqlite
