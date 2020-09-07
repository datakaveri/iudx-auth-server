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

CREATE TYPE consent.status AS ENUM ('rejected', 'pending', 'approved');
CREATE TYPE consent.role AS ENUM ('provider', 'consumer');

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
	type		consent.role					NOT NULL,
	email		character varying				NOT NULL,
	phone		character varying(10)				NOT NULL,
	approved	consent.status					NOT NULL,
	organization_id	integer REFERENCES consent.organizations(id)		,
	created_at	timestamp without time zone			NOT NULL,
	updated_at	timestamp without time zone			NOT NULL
);

CREATE UNIQUE INDEX idx_users_id ON consent.users(id);

CREATE UNIQUE INDEX idx_users_email ON consent.users(email);

CREATE TABLE consent.certificates (

	id		integer GENERATED ALWAYS AS IDENTITY		PRIMARY KEY,
	user_id		integer REFERENCES consent.users(id)		NOT NULL,
	csr		character varying				NOT NULL,
	cert		character varying					,
	created_at	timestamp without time zone			NOT NULL,
	updated_at	timestamp without time zone			NOT NULL
);

ALTER TABLE consent.organizations	OWNER TO postgres;
ALTER TABLE consent.users		OWNER TO postgres;
ALTER TABLE consent.certificates	OWNER TO postgres;

GRANT SELECT,INSERT,UPDATE ON TABLE consent.organizations	 TO auth;
GRANT SELECT,INSERT,UPDATE ON TABLE consent.users		 TO auth;
GRANT SELECT,INSERT,UPDATE ON TABLE consent.certificates	 TO auth;
