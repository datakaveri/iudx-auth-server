--
-- PostgreSQL database dump
--

-- Dumped from database version 11.2
-- Dumped by pg_dump version 11.2

SET TIMEZONE='Asia/Kolkata';

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

--
-- Name: crl; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.crl (
    crl jsonb DEFAULT '[]'::jsonb NOT NULL
);

INSERT INTO public.crl VALUES('[]'::jsonb);

ALTER TABLE public.crl OWNER TO postgres;

--
-- Name: groups; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.groups (
    id character varying NOT NULL,
    consumer character varying NOT NULL,
    group_name character varying NOT NULL,
    valid_till timestamp without time zone NOT NULL
);

CREATE INDEX idx_groups_id ON public.groups(id,group_name);

ALTER TABLE public.groups OWNER TO postgres;

--
-- Name: policy; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.policy (
    id character varying PRIMARY KEY,
    policy character varying(3145728) NOT NULL,
    policy_in_json jsonb NOT NULL,
    previous_policy character varying(3145728),
    last_updated timestamp without time zone NOT NULL
);

CREATE UNIQUE INDEX idx_policy_id ON public.policy(id);

ALTER TABLE public.policy OWNER TO postgres;

--
-- Name: token; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.token (
    id character varying NOT NULL,
    token character varying NOT NULL,
    expiry timestamp without time zone NOT NULL,
    request jsonb NOT NULL,
    cert_serial character varying NOT NULL,
    cert_fingerprint character varying NOT NULL,
    issued_at timestamp without time zone NOT NULL,
    resource_ids jsonb NOT NULL,
    introspected boolean NOT NULL,
    revoked boolean NOT NULL,
    cert_class integer NOT NULL,
    server_token jsonb NOT NULL,
    providers jsonb NOT NULL,
    geo jsonb NOT NULL,
    PRIMARY KEY(id, token)
);

CREATE UNIQUE INDEX idx_token_id ON public.token(id,token);

ALTER TABLE public.token OWNER TO postgres;

--
-- ACCESS CONTROLS 
--

CREATE USER auth with PASSWORD 'XXXauth';

GRANT SELECT ON TABLE public.crl TO auth;
GRANT SELECT,INSERT,UPDATE ON TABLE public.token TO auth;
GRANT SELECT,INSERT,UPDATE ON TABLE public.groups TO auth;
GRANT SELECT,INSERT,UPDATE ON TABLE public.policy TO auth;

CREATE USER update_crl with PASSWORD 'XXXupdate_crl';
GRANT UPDATE ON TABLE public.crl TO update_crl;
