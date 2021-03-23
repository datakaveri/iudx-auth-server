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
	crl	jsonb	NOT NULL
);

INSERT INTO public.crl VALUES('[]'::jsonb);

--
-- ACCESS CONTROLS
--

ALTER TABLE public.crl			OWNER TO postgres;

CREATE USER auth		with PASSWORD 'XXX_auth';

GRANT SELECT				ON TABLE public.crl				TO auth;
