-- following commands will add status col to access, capability and expiry col to access
-- TODO: remove default constraint on all tables once expiry API done
CREATE TYPE consent.access_status_enum AS ENUM ('active', 'deleted');
ALTER TABLE consent.access ADD COLUMN status consent.access_status_enum NOT NULL DEFAULT('active');
ALTER TABLE consent.capability ADD COLUMN status consent.access_status_enum NOT NULL DEFAULT('active');
ALTER TABLE consent.access ADD COLUMN expiry timestamp without time zone NOT NULL DEFAULT(NOW() + interval '1 year');
