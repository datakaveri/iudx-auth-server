SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'SQL_ASCII';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_with_oids = false;

CREATE SCHEMA consent;

GRANT ALL ON SCHEMA consent to postgres;
GRANT USAGE ON SCHEMA consent TO auth;

CREATE TYPE consent.status_enum AS ENUM ('rejected', 'pending', 'approved');
CREATE TYPE consent.role_enum 	AS ENUM ('consumer', 'data ingester', 'onboarder', 'delegate', 'provider', 'admin');
CREATE TYPE consent.access_item AS ENUM ('resourcegroup', 'catalogue', 'provider-caps');
CREATE TYPE consent.capability_enum AS ENUM ('temporal', 'complex', 'subscription');

CREATE TABLE consent.organizations (

	id		integer GENERATED ALWAYS AS IDENTITY	PRIMARY KEY,
	name		character varying			NOT NULL,
	website 	character varying			NOT NULL,
	city		character varying			NOT NULL,
	state		character varying(2)			NOT NULL,
	country		character varying(2)			NOT NULL,
	created_at	timestamp without time zone		NOT NULL,
	updated_at	timestamp without time zone		NOT NULL
);

CREATE UNIQUE INDEX idx_organizations_id ON consent.organizations(id);
CREATE UNIQUE INDEX idx_organizations_website ON consent.organizations(website);

CREATE TABLE consent.users (

	id		integer GENERATED ALWAYS AS IDENTITY		PRIMARY KEY,
	title		character varying				NOT NULL,
	first_name 	character varying				NOT NULL,
	last_name	character varying				NOT NULL,
	email		character varying				NOT NULL,
	phone		character varying(10)				NOT NULL,
	organization_id	integer REFERENCES consent.organizations(id)		,
	created_at	timestamp without time zone			NOT NULL,
	updated_at	timestamp without time zone			NOT NULL
);

CREATE UNIQUE INDEX idx_users_id ON consent.users(id);
CREATE UNIQUE INDEX idx_users_email ON consent.users(email);

CREATE TABLE consent.role (

	id		integer GENERATED ALWAYS AS IDENTITY		PRIMARY KEY,
	user_id		integer NOT NULL REFERENCES consent.users(id)	ON DELETE CASCADE,
	role		consent.role_enum				NOT NULL,
	status		consent.status_enum				NOT NULL,
	created_at	timestamp without time zone			NOT NULL,
	updated_at	timestamp without time zone			NOT NULL
);

CREATE UNIQUE INDEX idx_role_id ON consent.role(id);

CREATE TABLE consent.certificates (

	id		integer GENERATED ALWAYS AS IDENTITY		PRIMARY KEY,
	user_id		integer NOT NULL REFERENCES consent.users(id)	ON DELETE CASCADE,
	csr		character varying				NOT NULL,
	cert		character varying					,
	created_at	timestamp without time zone			NOT NULL,
	updated_at	timestamp without time zone			NOT NULL
);

CREATE TABLE consent.access (

	id			integer GENERATED ALWAYS AS IDENTITY		PRIMARY KEY,
	provider_id		integer NOT NULL REFERENCES consent.users(id) 	ON DELETE CASCADE,
	role_id			integer REFERENCES consent.role(id)		ON DELETE CASCADE,
	policy_text		character varying				NOT NULL,
	access_item_id		integer 						,
	access_item_type	consent.access_item					,
	created_at		timestamp without time zone			NOT NULL,
	updated_at		timestamp without time zone			NOT NULL
);

CREATE UNIQUE INDEX idx_access_id ON consent.access(id);

CREATE TABLE consent.resourcegroup (

	id			integer GENERATED ALWAYS AS IDENTITY			PRIMARY KEY,
	provider_id		integer NOT NULL REFERENCES consent.users(id) 		ON DELETE CASCADE,
	cat_id			character varying					NOT NULL,
	created_at		timestamp without time zone				NOT NULL,
	updated_at		timestamp without time zone				NOT NULL
);

CREATE TABLE consent.capability (

	id			integer GENERATED ALWAYS AS IDENTITY			PRIMARY KEY,
	access_id		integer NOT NULL REFERENCES consent.access(id)		ON DELETE CASCADE,
	capability		consent.capability_enum					NOT NULL,
	created_at		timestamp without time zone				NOT NULL,
	updated_at		timestamp without time zone				NOT NULL,
	UNIQUE (access_id, capability)
);

ALTER TABLE consent.organizations	OWNER TO postgres;
ALTER TABLE consent.users		OWNER TO postgres;
ALTER TABLE consent.role		OWNER TO postgres;
ALTER TABLE consent.certificates	OWNER TO postgres;
ALTER TABLE consent.access		OWNER TO postgres;
ALTER TABLE consent.resourcegroup	OWNER TO postgres;
ALTER TABLE consent.capability		OWNER TO postgres;

GRANT SELECT,INSERT,UPDATE 		ON TABLE consent.organizations	 TO auth;
GRANT SELECT,INSERT,UPDATE,DELETE 	ON TABLE consent.users		 TO auth;
GRANT SELECT,INSERT,UPDATE 		ON TABLE consent.certificates	 TO auth;

GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE consent.role		 TO auth;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE consent.resourcegroup TO auth;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE consent.access	 TO auth;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE consent.capability	 TO auth;
