/* vim: set ts=8 sw=4 tw=0 noet : */

"use strict";

const fs			= require("fs");
const os			= require("os");
const dns			= require("dns");
const cors			= require("cors");
const x509			= require('x509');
const Pool			= require("pg").Pool;
const http			= require("http");
const assert			= require("assert").strict;
const forge			= require("node-forge");
const chroot			= require("chroot");
const crypto			= require("crypto");
const logger			= require("node-color-log");
const lodash			= require("lodash");
const cluster			= require("cluster");
const express			= require("express");
const timeout			= require("connect-timeout");
const domain			= require("getdomain");
const aperture			= require("./node-aperture");
const safe_regex		= require("safe-regex");
const nodemailer		= require("nodemailer");
const geoip_lite		= require("geoip-lite");
const bodyParser		= require("body-parser");
const compression		= require("compression");
const http_request		= require("request");
const pgNativeClient		= require("pg-native");

const pg			= new pgNativeClient();

const TOKEN_LEN			= 16;
const TOKEN_LEN_HEX		= 2 * TOKEN_LEN;
const CSR_SIZE			= 2048;

const EUID			= process.geteuid();
const is_openbsd		= os.type() === "OpenBSD";
const pledge			= is_openbsd ? require("node-pledge")	: null;
const unveil			= is_openbsd ? require("openbsd-unveil"): null;

const NUM_CPUS			= os.cpus().length;
const SERVER_NAME		= "auth.iudx.org.in";
const CONSENT_URL		= "cons.iudx.org.in";

const MAX_TOKEN_TIME		= 31536000; // in seconds (1 year)

const MIN_TOKEN_HASH_LEN	= 64;
const MAX_TOKEN_HASH_LEN	= 64;

const MAX_SAFE_STRING_LEN	= 512;
const PG_MAX_INT		= 2147483647;

/* for access API */
const ACCESS_ROLES		= ["consumer", "data ingester", "onboarder"];
const RESOURCE_ITEM_TYPES	= ["resourcegroup"];
const CAT_URL			= "catalogue.iudx.io";
const CAT_API_RULE		= `${CAT_URL}/catalogue/crud`;
const INGEST_API_RULE		= "/iudx/v1/adapter";
const LATEST			= (rsg) => `/ngsi-ld/v1/entities/${rsg}`;
const CAPABILITIES		= {
	"temporal"	: ["/ngsi-ld/v1/temporal/entities", LATEST],
	"complex"	: ["/ngsi-ld/v1/entityOperations/query", LATEST, "/ngsi-ld/v1/entities"],
	"subscription"	: ["/ngsi-ld/v1/subscription"]
};

const MIN_CERT_CLASS_REQUIRED	= Object.freeze ({

/* resource server API */
	"/auth/v1/token/introspect"		: 1,
	"/auth/v1/certificate-info"		: 1,

/* data consumer's APIs */
	"/auth/v1/token"			: 2,

/* data provider's APIs */
	"/auth/v1/audit/tokens"			: 3,

	"/auth/v1/token/revoke"			: 3,
	"/auth/v1/token/revoke-all"		: 3,

	"/auth/v1/acl"				: 3,
	"/auth/v1/acl/set"			: 3,
	"/auth/v1/acl/revert"			: 3,
	"/auth/v1/acl/append"			: 3,

	"/auth/v1/group/add"			: 3,
	"/auth/v1/group/delete"			: 3,
	"/auth/v1/group/list"			: 3,
	"/auth/v1/admin/provider/registrations"		: -Infinity,
	"/auth/v1/admin/provider/registrations/status"	: -Infinity,
	"/auth/v1/admin/organizations"		: -Infinity,
	"/auth/v1/provider/access"			: -Infinity,

/* consent APIs */
	"/consent/v1/provider/registration"	: -Infinity,
	"/consent/v1/organizations"		: -Infinity,
	"/consent/v1/registration"		: -Infinity
});

/* --- environment variables--- */

// process.env.TZ = "Asia/Kolkata";

/* --- dns --- */

dns.setServers ([
	"1.1.1.1",
	"4.4.4.4",
	"8.8.8.8",
	"[2001:4860:4860::8888]",
	"[2001:4860:4860::8844]",
]);

/* --- telegram --- */

const TELEGRAM		= "https://api.telegram.org";

const telegram_apikey	= fs.readFileSync ("telegram.apikey","ascii").trim();
const telegram_chat_id	= fs.readFileSync ("telegram.chatid","ascii").trim();
const admin_list = JSON.parse(fs.readFileSync("passwords/admins.json", "ascii").trim()).admins;
const root_cert = forge.pki.certificateFromPem(fs.readFileSync("passwords/cert.pem"));
const root_key = forge.pki.privateKeyFromPem(fs.readFileSync("passwords/key.pem"));

const telegram_url	= TELEGRAM + "/bot" + telegram_apikey +
				"/sendMessage?chat_id="	+ telegram_chat_id +
				"&text=";
/* --- nodemailer --- */

let transporter;

const mailer_config 	= JSON.parse(fs.readFileSync("mailer_config.json","utf-8"));
const mailer_options 	= {
	host	: mailer_config.host,
	port	: mailer_config.port,
	auth	: {
		user : mailer_config.username,
		pass : mailer_config.password
	},
	tls: {rejectUnauthorized: false}
};

transporter = nodemailer.createTransport(mailer_options);

transporter.verify(function(error, success) {
	if (error)
		log("err", "MAILER_EVENT", true, {}, error.toString());
	else
		log("info", "MAILER_EVENT", false, {}, success.toString());
});

/* --- postgres --- */

const DB_SERVER	= "127.0.0.1";

const password	= {
	"DB"	: fs.readFileSync("passwords/auth.db.password","ascii").trim(),
};

/* --- log file --- */

const log_file = fs.createWriteStream('/var/log/debug.log', {flags : 'a'});

// async postgres connection
const pool = new Pool ({
	host		: DB_SERVER,
	port		: 5432,
	user		: "auth",
	database	: "postgres",
	password	: password.DB,
});

pool.connect();

// sync postgres connection
pg.connectSync (
	"postgresql://auth:"+ password.DB + "@" + DB_SERVER + ":5432/postgres",
		(err) =>
		{
			if (err) {
				throw err;
			}
		}
);

/* --- preload negotiator's encoding module for gzip compression --- */

const Negotiator = require("negotiator");
const negotiator = new Negotiator();

try		{ negotiator.encodings(); }
catch(x)	{ /* ignore */ }

/* --- express --- */

const app = express();

app.disable("x-powered-by");

app.set("trust proxy", true);
app.use(timeout("5s"));
app.use(
	cors ({
		credentials	:	true,
		methods		:	["POST", "GET", "PUT"],
		origin		:	(origin, callback) =>
					{
						callback (
							null,
							!!origin
						);
					}
	})
);

app.use(compression());
app.use(bodyParser.raw({type:"*/*"}));

app.use(parse_cert_header);
app.use(basic_security_check);
app.use(log_conn);
//app.use(dns_check);

/* --- aperture --- */

const apertureOpts = {

	types		: aperture.types,
	typeTable	: {

		ip			: "ip",
		time			: "time",

		tokens_per_day		: "number",	// tokens issued today

		api			: "string",	// the API to be called
		method			: "string",	// the method for API

		"cert.class"		: "number",	// the certificate class
		"cert.cn"		: "string",
		"cert.o"		: "string",
		"cert.ou"		: "string",
		"cert.c"		: "string",
		"cert.st"		: "string",
		"cert.gn"		: "string",
		"cert.sn"		: "string",
		"cert.title"		: "string",

		"cert.issuer.cn"	: "string",
		"cert.issuer.email"	: "string",
		"cert.issuer.o"		: "string",
		"cert.issuer.ou"	: "string",
		"cert.issuer.c"		: "string",
		"cert.issuer.st"	: "string",

		groups			: "string",	// CSV actually

		country			: "string",
		region			: "string",
		timezone		: "string",
		city			: "string",
		latitude		: "number",
		longitude		: "number",
	}
};

const parser	= aperture.createParser		(apertureOpts);
const evaluator	= aperture.createEvaluator	(apertureOpts);

/* --- functions --- */

function print(msg)
{
	logger.color("white").log(msg);
}

function is_valid_token (token, user = null)
{
	if (! is_string_safe(token))
		return false;

	const split = token.split("/");

	if (split.length !== 3)
		return false;

	const issued_by		= split[0];
	const issued_to		= split[1];
	const random_hex	= split[2];

	if (issued_by !== SERVER_NAME)
		return false;

	if (random_hex.length !== TOKEN_LEN_HEX)
		return false;

	if (user && user !== issued_to)
		return false;		// token was not issued to this user

	if (! is_valid_email(issued_to))
		return false;

	return true;
}

function is_valid_tokenhash (token_hash)
{
	if (! is_string_safe(token_hash))
		return false;

	if (token_hash.length < MIN_TOKEN_HASH_LEN)
		return false;

	if (token_hash.length > MAX_TOKEN_HASH_LEN)
		return false;

	return true;
}

function is_valid_servertoken (server_token, hostname)
{
	if (! is_string_safe(server_token))
		return false;

	const split = server_token.split("/");

	if (split.length !== 2)
		return false;

	const issued_to		= split[0];
	const random_hex	= split[1];

	if (issued_to !== hostname)
		return false;

	if (random_hex.length !== TOKEN_LEN_HEX)
		return false;

	return true;
}

function sha1 (string)
{
	return crypto
		.createHash("sha1")
		.update(string)
		.digest("hex");
}

function sha256 (string)
{
	return crypto
		.createHash("sha256")
		.update(string)
		.digest("hex");
}

function base64 (string)
{
	return Buffer
		.from(string)
		.toString("base64");
}

function send_telegram (message)
{
	http_request ( telegram_url + "[ AUTH ] : " + message, (error, response, body) =>
	{
		if (error)
		{
			log ("warn", "EVENT", true, {},
				"Telegram failed ! response = " +
					String(response)	+
				" body = "			+
					String(body)
			);
		}
	});
}

function log(level, type, notify, details, message = null)
{
	//const message = new Date() + " | " + msg;
	const log_msg = {
		"level"		: level,
		"type"      	: type,
		"notify"	: notify,
		"details"   	: details,
	};

	if (message !== null)
		log_msg.message = message;

	if (level === "err")
		send_telegram(message);

	let output = JSON.stringify(log_msg);

        log_file.write(output + '\n');
}

function END_SUCCESS (res, response = null)
{
	// if no response is given, just send success

	if (! response)
		response = {"success":true};

	res.setHeader("Content-Security-Policy",	"default-src 'none'");
	res.setHeader("Content-Type",			"application/json");

	res.status(200).end(JSON.stringify(response) + "\n");
}

function END_ERROR (res, http_status, error, exception = null)
{
	if (exception)
		log("err", "END_ERROR", true, {}, String(exception).replace(/\n/g," "));

	res.setHeader("Content-Security-Policy",	"default-src 'none'");
	res.setHeader("Content-Type",			"application/json");
	res.setHeader("Connection",			"close");

	const response = {};

	if (typeof error === "string")
		response.error = {"message" : error};
	else
	{
		// error is already a JSON

		if (error["invalid-input"])
		{
			response["//"] ="Unsafe characters (if any) in"		+
					" 'invalid-input' field have been"	+
					" replaced with '*'";
		}

		response.error = error;
	}

	res.status(http_status).end(JSON.stringify(response) + "\n");

	res.socket.end();
	res.socket.destroy();

	delete res.socket;
	delete res.locals;
}

function is_valid_email (email)
{
	if (! email || typeof email !== "string")
		return false;

	if (email.length < 5 || email.length > 64)
		return false;

	// reject email ids starting with invalid chars
	const invalid_start_chars = ".-_@";

	if (invalid_start_chars.indexOf(email[0]) !== -1)
		return false;

	/*
		Since we use SHA1 (160 bits) for storing email hashes:

			the allowed chars in the email login is -._a-z0-9
			which is : 1 + 1 + 1 + 26 + 10 = ~40 possible chars

			the worst case brute force attack with 31 chars is
				40**31 > 2**160

			but for 30 chars it is
				40**30 < 2**160

			and since we have a good margin for 30 chars
				(2**160) - (40**30) > 2**157

			hence, as a precaution, limit the login length to 30.

		SHA1 has other attacks though, maybe we should switch to better
		hash algorithm in future.
	*/

	const split = email.split("@");

	if (split.length !== 2)
		return false;

	const user = split[0]; // the login

	if (user.length === 0 || user.length > 30)
		return false;

	let num_dots = 0;

	for (const chr of email)
	{
		if (
			(chr >= "a" && chr <= "z") ||
			(chr >= "A" && chr <= "Z") ||
			(chr >= "0" && chr <= "9")
		)
		{
			// ok;
		}
		else
		{
			switch (chr)
			{
				case "-":
				case "_":
				case "@":
					break;

				case ".":
					++num_dots;
					break;

				default:
					return false;
			}
		}
	}

	return num_dots >= 1;


}

function is_certificate_ok (req, cert, validate_email)
{
	if (! cert || ! cert.subject)
		return "No subject found in the certificate";

	if (! cert.subject.CN)
		return "No CN found in the certificate";

	if (validate_email)
	{
		if (! is_valid_email(cert.subject.emailAddress))
			return "Invalid 'emailAddress' field in the certificate";

		if (! cert.issuer || ! cert.issuer.emailAddress)
			return "Certificate issuer has no 'emailAddress' field";

		const issuer_email = cert.issuer.emailAddress.toLowerCase();

		if (! is_valid_email(issuer_email))
			return "Certificate issuer's emailAddress is invalid";

		if (issuer_email.startsWith("iudx.sub.ca@"))
		{
			const issued_to_domain	= cert.subject.emailAddress
							.toLowerCase()
							.split("@")[1];

			const issuer_domain	= issuer_email
							.toLowerCase()
							.split("@")[1];

			if (issuer_domain !== issued_to_domain)
			{
				// TODO
				// As this could be a fraud commited by a sub-CA
				// maybe revoke the sub-CA certificate

				log ("err", "ERROR", false, {},
					"Invalid certificate: issuer = "+
						issuer_domain		+
					" and issued to = "		+
						cert.subject.emailAddress
				);

				return "Invalid certificate issuer";
			}
		}
	}

	return "OK";
}

function is_secure (req, res, cert, validate_email = true)
{
	res.header("Referrer-Policy",		"no-referrer-when-downgrade");
	res.header("X-Frame-Options",		"deny");
	res.header("X-XSS-Protection",		"1; mode=block");
	res.header("X-Content-Type-Options",	"nosniff");

	/*
	if (req.headers.host && req.headers.host !== SERVER_NAME)
		return "Invalid 'host' field in the header";
	*/

	if (req.headers.origin)
	{
		const origin = req.headers.origin.toLowerCase();

		// e.g Origin = https://www.iudx.org.in:8443/

		if (! origin.startsWith("https://"))
		{
			// allow the server itself to host "http"
			if (origin !== "http://" + SERVER_NAME)
				return "Insecure 'origin' field";
		}

		if ((origin.match(/\//g) || []).length < 2)
			return "Invalid 'origin' field";

		const origin_domain = String (
			origin
				.split("/")[2]	// remove protocol
				.split(":")[0]	// remove port number
		);

		if (
			(! origin_domain.endsWith(".iudx.org.in"))	&&
			(! origin_domain.endsWith(".iudx.io"))
		)
		{
			return "Invalid 'origin' header; this website is not"	+
				" permitted to call this API";
		}

		res.header("Access-Control-Allow-Origin", req.headers.origin);
		res.header("Access-Control-Allow-Methods","POST, PUT, GET");
	}

	const error = is_certificate_ok (req,cert,validate_email);

	if (error !== "OK")
		return "Invalid certificate : " + error;

	return "OK";
}

function has_certificate_been_revoked (socket, cert, CRL)
{
	const cert_fingerprint	= cert.fingerprint
					.replace(/:/g,"")
					.toLowerCase();

	const cert_serial	= cert.serialNumber
					.toLowerCase()
					.replace(/^0+/,"");

	const cert_issuer	= cert.issuer.emailAddress.toLowerCase();

	for (const c of CRL)
	{
		c.issuer	= c.issuer.toLowerCase();
		c.serial	= c.serial.toLowerCase().replace(/^0+/,"");
		c.fingerprint	= c.fingerprint.toLowerCase().replace(/:/g,"");

		if (
			(c.issuer	=== cert_issuer)	&&
			(c.serial	=== cert_serial)	&&
			(c.fingerprint	=== cert_fingerprint)
		)
		{
			return true;
		}
	}

	// If it was issued by a sub-CA then check the sub-CA's cert too
	// Assuming depth is <= 3. ca@iudx.org.in -> sub-CA -> user

	if (cert_issuer.startsWith("iudx.sub.ca@"))
	{
		const ISSUERS = [];

		if (cert.issuerCertificate)
		{
			// both CA and sub-CA are the issuers
			ISSUERS.push(cert.issuerCertificate);

			if (cert.issuerCertificate.issuerCertificate)
			{
				ISSUERS.push (
					cert.issuerCertificate.issuerCertificate
				);
			}
		}
		else
		{
			/*
				if the issuerCertificate is empty,
				then the session must have been reused
				by the browser.

			if (! socket.isSessionReused())
				return true;
			*/
		}

		for (const issuer of ISSUERS)
		{
			if (issuer.fingerprint && issuer.serialNumber)
			{
				issuer.fingerprint = issuer
							.fingerprint
							.replace(/:/g,"")
							.toLowerCase();

				issuer.serialNumber = issuer
							.serialNumber
							.toLowerCase();

				for (const c of CRL)
				{
					if (c.issuer === "ca@iudx.org.in")
					{
						const serial = c.serial
								.toLowerCase()
								.replace(/^0+/,"");

						const fingerprint = c.fingerprint
									.replace(/:/g,"")
									.toLowerCase();

						if (serial === issuer.serial && fingerprint === issuer.fingerprint)
							return true;
					}
				}
			}
			else
			{
				/*
					if fingerprint OR serial is undefined,
					then the session must have been reused
					by the browser.

				if (! socket.isSessionReused())
					return true;
				*/
			}
		}
	}

	return false;
}

function xss_safe (input)
{
	if (typeof input === "string")
		return input.replace(/[^-a-zA-Z0-9:/.@_]/g,"*");
	else
	{
		// we can only change string variables

		return input;
	}
}

function is_string_safe (str, exceptions = "")
{
	if (! str || typeof str !== "string")
		return false;

	if (str.length === 0 || str.length > MAX_SAFE_STRING_LEN)
		return false;

	exceptions = exceptions + "-/.@";

	for (const ch of str)
	{
		if (
			(ch >= "a" && ch <= "z") ||
			(ch >= "A" && ch <= "Z") ||
			(ch >= "0" && ch <= "9")
		)
		{
			// ok
		}
		else
		{
			if (exceptions.indexOf(ch) === -1)
				return false;
		}
	}

	return true;
}

function is_iudx_certificate(cert)
{
	if (! cert.issuer.emailAddress)
		return false;

	const email = cert
			.issuer
			.emailAddress
			.toLowerCase();

	// certificate issuer should be IUDX CA or a IUDX sub-CA

	return (email ==="ca@iudx.org.in" || email.startsWith("iudx.sub.ca@"));
}

function body_to_json (body)
{
	if (! body)
		return {};

	let string_body;

	try
	{
		string_body = Buffer
				.from(body,"utf-8")
				.toString("ascii")
				.trim();

		if (string_body.length === 0)
			return {};
	}
	catch (x)
	{
		return {};
	}

	try
	{
		const json_body = JSON.parse (string_body);

		if (json_body)
			return json_body;
		else
			return {};
	}
	catch (x)
	{
		return null;
	}
}

/* ---
  Check role/privilege of any registered user.
  If user has particular role, return user ID.
  Else return null.
		--- */

async function check_privilege(email, role, callback)
{
	try
	{
		const result = await pool.query(
					" SELECT * FROM consent.users, consent.role" 		+
					" WHERE consent.users.id = consent.role.user_id "	+
					" AND consent.users.email = $1::text "			+
					" AND role = $2::consent.role_enum"			+
					" AND status = $3::consent.status_enum",
			[
				email,				//$1
				role,				//$2
				'approved'			//$3
			]);

		if (result.rows.length === 0)
			throw new Error("Invalid");

		return result.rows[0].user_id;
	}
	catch(error) {
		throw error;
	}
}

/* ---
  Set aperture policies for a specific provider
  provider_id is email address of provider,
  rules is an array of strings.
		--- */

function set_acl(provider_id, rules, callback)
{
	let policy_in_json;

	try
	{
		policy_in_json = rules.map (
			(r) => {
				return (parser.parse(r.trim()));
			}
		);
	}
	catch (x)
	{
		let error = new Error("Syntax error in policy. ");
		log("warn", "APERTURE_ERROR", false, {}, x.message);
		error.http_code = 500;
		callback(error);
		return;
	}

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	const base64policy	= base64(rules.join(";"));

	pool.query (

		"SELECT 1 FROM policy WHERE id = $1::text LIMIT 1",
		[
			provider_id_hash,	// 1
		],

	(error, results) =>
	{
		if (error)
		{
			let error = new Error("Internal error!");
			error.http_code = 500;
			callback(error);
			return;
		}

		let query;
		let params;

		if (results.rows.length > 0)
		{
			query	= "UPDATE policy"			+
					" SET policy = $1::text,"	+
					" policy_in_json = $2::jsonb,"	+
					" previous_policy = policy,"	+
					" last_updated = NOW(),"	+
					" api_called_from = $3::text"	+
					" WHERE id = $4::text";

			params	= [
				base64policy,				// 1
				JSON.stringify(policy_in_json),		// 2
				null,					// 3
				provider_id_hash			// 4
			];
		}
		else
		{
			query	= "INSERT INTO policy VALUES("	+
					"$1::text,"		+
					"$2::text,"		+
					"$3::jsonb,"		+
					"NULL,"			+
					"NOW(),"		+
					"$4::text"		+
			")";

			params	= [
				provider_id_hash,			// 1
				base64policy,				// 2
				JSON.stringify(policy_in_json),		// 3
				null					// 4
			];
		}

		pool.query (query, params, (error_1, results_1) =>
		{
			if (error_1 || results_1.rowCount === 0)
			{
				let error = new Error("Internal error!");
				error.http_code = 500;
				callback(error);
				return;
			}

			const details = {
				"provider"  : provider_id,
				"policy"    : rules
			};

			log("info", "CREATED_POLICY", true, details);
			callback(null);
		});
	});
}

function intersect (array1, array2)
{
	return array1.filter(val => array2.includes(val));
}

function create_consumer_policy_text(accesser_email, resource, resource_name, capability)
{
	let join = "if", index;
	let rule = `${accesser_email} can access ${resource_name}/* for 1 week`;

	let apis = capability.reduce((acc, val) => acc.concat(CAPABILITIES[val]), []);
	apis = [...new Set(apis)];

	/* if latest API is there, then add resource group
	 * to the template */
	if ((index = apis.indexOf(LATEST)) !== -1)
		apis[index] = apis[index](resource);

	for (const i of apis)
	{
		rule = rule + ` ${join} api = "${i}"`;
		join = "or";
	}

	return rule;
}

/* ---
	A variable to indicate if a worker has started serving APIs.

	We will further drop privileges when a worker is about to
	serve its first API.
				--- */

let has_started_serving_apis = false;

/* ---
    functions to change certificate fields to match Node certificate
    object
	--- */

function change_cert_keys(obj)
{
	const newkeys = {
		"countryName"		    : "C",
		"stateOrProvinceName"	    : "ST",
		"localityName"		    : "L",
		"organizationName"	    : "O",
		"organizationalUnitName"    : "OU",
		"commonName"		    : "CN",
		"givenName"		    : "GN",
		"surName"		    : "SN"
	};

	let new_obj = {};

	for( let key in obj )
		new_obj[newkeys[key] || key] = obj[key];

	return new_obj;
}

function parse_cert_header(req, res, next)
{
	let cert;

	if (req.headers.host === CONSENT_URL)
		return next();

	try
	{
		let raw_cert = decodeURIComponent(req.headers['x-forwarded-ssl']);
		cert	     = x509.parseCert(raw_cert);
	}
	catch(error)
	{
		return END_ERROR(res, 403, "Error in parsing certificate");
	}

	cert.subject   = change_cert_keys(cert.subject);
	cert.issuer    = change_cert_keys(cert.issuer);

	cert.fingerprint		= cert.fingerPrint;
	cert.serialNumber		= cert.serial;
	cert.subject['id-qt-unotice']	= cert.subject['Policy Qualifier User Notice'];

	delete(cert.fingerPrint);
	delete(cert.serial);
	delete(cert.subject['Policy Qualifier User Notice']);

	req.certificate = cert;
	return next();

}

/* --- basic security checks to be done at every API call --- */

function basic_security_check (req, res, next)
{
	if (! has_started_serving_apis)
	{
		if (is_openbsd) // drop "rpath" in worker
			pledge.init("error stdio tty prot_exec inet dns recvfd");

		has_started_serving_apis = true;
	}

	// replace all version with "/v1/"

	const endpoint			= req.url.split("?")[0];
	const api			= endpoint.replace(/\/v[1-2]\//,"/v1/");
	const min_class_required	= MIN_CERT_CLASS_REQUIRED[api];

	if (! min_class_required)
	{
		return END_ERROR (
			res, 404,
				"No such page/API. Please visit : "	+
				"<https://authdocs.iudx.org.in> for documentation."
		);
	}

	if (! (res.locals.body = body_to_json(req.body)))
	{
		return END_ERROR (
			res, 400,
			"Body is not a valid JSON"
		);
	}

	// skip checks for consent APIs
	if (req.headers.host === CONSENT_URL)
		return next();

	const cert		= req.certificate;

	cert.serialNumber	= cert.serialNumber.toLowerCase();
	cert.fingerprint	= cert.fingerprint.toLowerCase();

	if ((res.locals.is_iudx_certificate = is_iudx_certificate(cert)))
	{
		// id-qt-unotice is in the format "key1:value1;key2:value2;..."

		const id_qt_notice	= cert.subject["id-qt-unotice"] || "";
		const split		= id_qt_notice.split(";");
		const user_notice	= {};

		for (const s of split)
		{
			const	ss	= s.split(":");	// ss = split of split

			let	key	= ss[0];
			let	value	= ss[1];

			if (key && value)
			{
				key	= key.toLowerCase();
				value	= value.toLowerCase();

				user_notice[key] = value;
			}
		}

		if (user_notice.untrusted)
		{
			res.locals.untrusted = true;
		}

		if (user_notice["delegated-by"])
		{
			return END_ERROR (
				res, 403,
					"Delegated certificates cannot"	+
					" be used to call auth/marketplace APIs"
			);
		}

		const	cert_class		= user_notice["class"];
		let	integer_cert_class	= 0;

		if (cert_class)
			integer_cert_class = parseInt(cert_class,10) || 0;

		if (integer_cert_class < 1)
			return END_ERROR(res, 403, "Invalid certificate class");

		if (integer_cert_class < min_class_required)
		{
			return END_ERROR (
				res, 403,
					"A class-" + min_class_required	+
					" or above certificate "	+
					"is required to call this API"
			);
		}

		if (min_class_required === 1 && integer_cert_class !== 1)
		{
			/*
				class-1 APIs are special,
				user needs a class-1 certificate

				except in case of "/certificate-info"
			*/

			if (! api.endsWith("/certificate-info"))
			{
				return END_ERROR (
					res, 403,
					"A class-1 certificate is required " +
					"to call this API"
				);
			}
		}

		const error = is_secure(req,res,cert,true); // validate emails

		if (error !== "OK")
			return END_ERROR (res, 403, error);

		pool.query("SELECT crl FROM crl LIMIT 1", [], (error, results) =>
		{
			if (error || results.rows.length === 0)
			{
				return END_ERROR (
					res, 500,
					"Internal error!", error
				);
			}

			const CRL = results.rows[0].crl;

			if (has_certificate_been_revoked(req.socket,cert,CRL))
			{
				return END_ERROR (
					res, 403,
					"Certificate has been revoked"
				);
			}

			res.locals.cert		= cert;
			res.locals.cert_class	= integer_cert_class;
			res.locals.email	= cert
							.subject
							.emailAddress
							.toLowerCase();

			if (user_notice["can-access"])
			{
				res.locals.can_access_regex	= [];

				const can_access_regex		= user_notice["can-access"]
									.split(";");
				let regex_number		= 0;

				for (const r of can_access_regex)
				{
					++regex_number;

					const regex = r.trim();

					if (regex === "")
						continue;

					/*
						allow '^' '*' and '$' characters
						but not unsafe RegEx
					*/

					if (! is_string_safe(regex,"^*$"))
					{
						const error_response = {
							"message"	: "Unsafe 'can-access' RegEx in certificate",
							"invalid-input"	: "RegEx no. " + regex_number,
						};

						return END_ERROR (
							res, 400,
								error_response
						);
					}

					/*
						We don't support ".", replace:
							"."	with	"\."
							"*"	with	".*"
					*/

					const final_regex = regex
								.replace(/\./g,"\\.")
								.replace(/\*/g,".*");

					if (! safe_regex(final_regex))
					{
						const error_response = {
							"message"	: "Unsafe 'can-access' RegEx in certificate",
							"invalid-input"	: "RegEx no. " + regex_number,
						};

						return END_ERROR (
							res, 400,
								error_response
						);
					}

					res.locals.can_access_regex.push (
						new RegExp(final_regex)
					);
				}
			}

			Object.freeze(res.locals);
			Object.freeze(res.locals.body);
			Object.freeze(res.locals.cert);

			return next();
		});
	}
	else
	{
		/*
			Certificates issued by other CAs
			may not have an "emailAddress" field.
			By default consider them as a class-1 certificate
		*/

		const error = is_secure(req,res,cert,false);

		if (error !== "OK")
			return END_ERROR (res, 403, error);

		res.locals.cert_class	= 1;
		res.locals.email	= "";
		res.locals.cert		= cert;

		/*
			But if the certificate has a valid "emailAddress"
			field then we consider it as a class-2 certificate
		*/

		if (is_valid_email(cert.subject.emailAddress))
		{
			res.locals.cert_class	= 2;
			res.locals.email	= cert
							.subject
							.emailAddress
							.toLowerCase();
		}

		/*
			class-1 APIs are special,
			user needs a class-1 certificate

			except in case of "/certificate-info"

			if user is trying to call a class-1 API,
			then downgrade his certificate class
		*/

		if (min_class_required === 1)
		{
			if (! api.endsWith("/certificate-info"))
			{
				res.locals.cert_class = 1;
			}
		}

		if (res.locals.cert_class < min_class_required)
		{
			return END_ERROR (
				res, 403,
				"A class-" + min_class_required	+
				" or above certificate is"	+
				" required to call this API"
			);
		}

		Object.freeze(res.locals);
		Object.freeze(res.locals.body);
		Object.freeze(res.locals.cert);

		return next();
	}
}

/* Log all API calls */

function log_conn (req, res, next)
{
	const endpoint			= req.url.split("?")[0];
	const api			= endpoint.replace(/\/v[1-2]\//,"/v1/");
	const api_details 		= api.split('/').slice(3).join('_');
	let id, cert_issuer;

	// if marketplace APIs called, api_details will be empty
	if( api_details == "")
		return next();

	/* if provider/consumer, id is email
	 * if rs, id is hostname
	 * if consent API, id is null? */

	if (res.locals.cert)
	{
		id = res.locals.email || res.locals.cert.subject.CN.toLowerCase();
		cert_issuer = res.locals.cert.issuer.CN;
	}
	else
	{
		id	    = null;
		cert_issuer = "none";
	}

	const type	= api_details.toUpperCase() + "_REQUEST";
	const details	=
	{
		"ip"  		 : req.ip,
		"authentication" : "certificate " + cert_issuer,
		"id"		 : id
	};

	log("info", type, false, details);

	return next();
}

function dns_check (req, res, next)
{
	const cert		= res.locals.cert;
	const cert_class	= res.locals.cert_class;

	// No dns check required if certificate is class-2 or above

	if (cert_class > 1)
		return next();

	if (! cert.subject || ! is_string_safe(cert.subject.CN))
		return END_ERROR (res, 400, "Invalid 'CN' in the certificate");

	const	ip			= req.ip;
	let	ip_matched		= false;
	const	hostname_in_certificate	= cert.subject.CN.toLowerCase();

	dns.lookup (hostname_in_certificate, {all:true}, (error, ip_addresses) =>
	{
		/*
			No dns checks for "example.com"
			this for developer's testing purposes.
		*/

		if (hostname_in_certificate === "example.com")
		{
			error		= null;
			ip_matched	= true;
			ip_addresses	= [];
		}

		if (error)
		{
			const error_response = {
				"message"	: "Invalid 'hostname' in certificate",
				"invalid-input"	: xss_safe(hostname_in_certificate)
			};

			return END_ERROR (res, 400, error_response);
		}

		for (const a of ip_addresses)
		{
			if (a.address === ip)
			{
				ip_matched = true;
				break;
			}
		}

		if (! ip_matched)
		{
			return END_ERROR (res, 403,
				"Your certificate's hostname in CN "	+
				"and your IP does not match!"
			);
		}

		return next();  // dns check passed
	});
}

function to_array (o)
{
	if (o instanceof Object)
	{
		if (o instanceof Array)
			return o;
		else
			return [o];
	}
	else
	{
		return [o];
	}
}

function sign_csr(raw_csr, user)
{
	const cert_class = user.role === "provider" ? "class:3" : "class:2";
	forge.pki.oids['id-qt-unotice'] = '1.3.6.1.5.5.7.2.2';
	const csr = forge.pki.certificationRequestFromPem(raw_csr);
	if (!csr.verify()) { return null; }
	let cert = forge.pki.createCertificate();
	cert.publicKey = csr.publicKey;
	cert.setIssuer(root_cert.subject.attributes);
	cert.serialNumber = crypto.randomBytes(20).toString('hex');
	cert.validity.notBefore = new Date();
	cert.validity.notAfter = new Date();
	cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
	let attrs = [
		{
			name: "commonName",
			value: "IUDX Provider",
		},
		{
			name: "emailAddress",
			value: user.email,
		},
		{
			name: "id-qt-unotice",
			value: cert_class,
		},
	];
	cert.setSubject(attrs);
	cert.sign(root_key, forge.md.sha256.create());
	if (root_cert.verify(cert)) {
		return forge.pki.certificateToPem(cert);
	}
	return null;
}

/* --- Auth APIs --- */

app.post("/auth/v[1-2]/token", (req, res) => {

	const cert				= res.locals.cert;
	const cert_class			= res.locals.cert_class;
	const body				= res.locals.body;
	const consumer_id			= res.locals.email;

	const resource_id_dict			= {};
	const resource_server_token		= {};
	const sha256_of_resource_server_token	= {};

	const request_array			= to_array(body.request);
	const processed_request_array		= [];

	if (! request_array || request_array.length < 1)
	{
		return END_ERROR (
			res, 400,
				"'request' must be a valid JSON array " +
				"with at least 1 element"
		);
	}

	let requested_token_time;		// as specified by the consumer
	let token_time = MAX_TOKEN_TIME;	// to be sent along with token

	if (body["token-time"])
	{
		requested_token_time = parseInt(body["token-time"],10);

		if (
			isNaN(requested_token_time)		||
			requested_token_time < 1		||
			requested_token_time > MAX_TOKEN_TIME
		)
		{
			return END_ERROR (
				res, 400,
				"'token-time' should be > 0 and < " +
				MAX_TOKEN_TIME
			);
		}
	}

	const rows = pg.querySync (

		"SELECT COUNT(*)/60.0"		+
		" AS rate"			+
		" FROM token"			+
		" WHERE id = $1::text"		+
		" AND issued_at >= (NOW() - interval '60 seconds')",
		[
			consumer_id,		// 1
		]
	);

	// in last 1 minute
	const tokens_rate_per_second = parseFloat (rows[0].rate);

	if (tokens_rate_per_second > 1) // tokens per second
	{
		log ("err", "HIGH_TOKEN_RATE", true, {},
			"Too many requests from user : " + consumer_id +
			", from ip : " + String (req.ip)
		);

		return END_ERROR (res, 429, "Too many requests");
	}

	const ip	= req.ip;
	const issuer	= cert.issuer;

	const geoip	= geoip_lite.lookup(ip) || {ll:[]};

	// these fields are not necessary

	delete geoip.eu;
	delete geoip.area;
	delete geoip.metro;
	delete geoip.range;

	Object.freeze(geoip);

	const context = {

		principal	: consumer_id,
		action		: "access",

		conditions	: {
			ip			: ip,
			time			: new Date(),

			"cert.class"		: cert_class,
			"cert.cn"		: cert.subject.CN	|| "",
			"cert.o"		: cert.subject.O	|| "",
			"cert.ou"		: cert.subject.OU	|| "",
			"cert.c"		: cert.subject.C	|| "",
			"cert.st"		: cert.subject.ST	|| "",
			"cert.gn"		: cert.subject.GN	|| "",
			"cert.sn"		: cert.subject.SN	|| "",
			"cert.title"		: cert.subject.title	|| "",

			"cert.issuer.cn"	: issuer.CN		|| "",
			"cert.issuer.email"	: issuer.emailAddress	|| "",
			"cert.issuer.o"		: issuer.O		|| "",
			"cert.issuer.ou"	: issuer.OU		|| "",
			"cert.issuer.c"		: issuer.C		|| "",
			"cert.issuer.st"	: issuer.ST		|| "",

			country			: geoip.country		|| "",
			region			: geoip.region		|| "",
			timezone		: geoip.timezone	|| "",
			city			: geoip.city		|| "",
			latitude		: geoip.ll[0]		|| 0,
			longitude		: geoip.ll[1]		|| 0,
		}
	};

	const providers			= {};

	let num_rules_passed		= 0;

	const can_access_regex = res.locals.can_access_regex;

	for (let r of request_array)
	{
		let resource;

		if (typeof r === "string")
		{
			resource = r;

			// request is a string, make it an object

			r = {
				"id" : resource,
			};
		}
		else if (r instanceof Object)
		{
			if (! r.id)
			{
				const error_response = {
					"message"	: "no resource 'id' found in request",
					"invalid-input"	: xss_safe(r),
				};

				return END_ERROR (res, 400, error_response);
			}

			resource = r.id;
		}
		else
		{
			const error_response = {
				"message"	: "Invalid resource 'id' found in request",
				"invalid-input"	: xss_safe(String(r)),
			};

			return END_ERROR (res, 400, error_response);
		}

		// allow some chars but not ".."

		if (! is_string_safe(resource, "*_") || resource.indexOf("..") >= 0)
		{
			const error_response = {
				"message"	: "'id' contains unsafe characters",
				"invalid-input"	: xss_safe(resource),
			};

			return END_ERROR (res, 400, error_response);
		}

		if (typeof r.method === "string")
			r.methods = [r.method];

		if (! r.methods)
			r.methods = ["*"];

		if (! (r.methods instanceof Array))
		{
			const error_response = {
				"message"	: "'methods' must be a valid JSON array",
				"invalid-input"	: {
					"id"		: xss_safe(resource),
					"methods"	: xss_safe(r.methods)
				}
			};

			return END_ERROR (res, 400, error_response);
		}

		if (r.api && typeof r.api === "string")
			r.apis = [r.api];

		if (! r.apis)
			r.apis = ["/*"];

		if (! r.body)
			r.body = null;

		if ( ! (r.apis instanceof Array))
		{
			const error_response = {
				"message"	: "'apis' must be a valid JSON array",
				"invalid-input"	: {
					"id"	: xss_safe(resource),
					"apis"	: xss_safe(r.apis)
				}
			};

			return END_ERROR (res, 400, error_response);
		}

		if ((resource.match(/\//g) || []).length < 3)
		{
			const error_response = {
				"message"	: "'id' must have at least 3 '/' characters.",
				"invalid-input"	: xss_safe(resource)
			};

			return END_ERROR (res, 400, error_response);
		}

		// if body is given but is not a valid object
		if (r.body && (! (r.body instanceof Object)))
		{
			const error_response = {
				"message"	: "'body' must be a valid JSON object",
				"invalid-input"	: {
					"id"	: xss_safe(resource),
					"body"	: xss_safe(r.body)
				}
			};

			return END_ERROR (res, 400, error_response);
		}

		if (can_access_regex)
		{
			let access_denied = true;

			for (const regex of can_access_regex)
			{
				if (resource.match(regex))
				{
					access_denied = false;
					break;
				}
			}

			if (access_denied)
			{
				const error_response = {
					"message"	: "Your certificate does not allow access to this 'id'",
					"invalid-input"	: {
						"id"	: xss_safe(resource),
					}
				};

				return END_ERROR (res, 403, error_response);
			}
		}

		const split			= resource.split("/");

		const email_domain		= split[0].toLowerCase();
		const sha1_of_email		= split[1].toLowerCase();

		const provider_id_hash		= email_domain + "/" + sha1_of_email;

		const resource_server		= split[2].toLowerCase();
		const resource_name		= split.slice(3).join("/");

		providers			[provider_id_hash]	= true;

		// to be generated later
		resource_server_token		[resource_server]	= true;

		// to be generated later
		sha256_of_resource_server_token	[resource_server]	= true;

		const rows = pg.querySync (

			"SELECT policy,policy_in_json"	+
			" FROM policy"			+
			" WHERE id = $1::text"		+
			" LIMIT 1",
			[
				provider_id_hash,	// 1
			]
		);

		if (rows.length === 0)
		{
			const error_response = {

				"message"	:"Invalid 'id'; no access"	+
						" control policies have been"	+
						" set for this 'id'"		+
						" by the data provider",

				"invalid-input"	: xss_safe(resource)
			};

			return END_ERROR (res, 400, error_response);
		}

		const policy_lowercase = Buffer.from (
						rows[0].policy, "base64"
					)
					.toString("ascii")
					.toLowerCase();

		const policy_in_json	= rows[0].policy_in_json;

		// full name of resource eg: bangalore.domain.com/streetlight-1
		context.resource = resource_server + "/" + resource_name;

		context.conditions.groups = "";

		if (policy_lowercase.search(" consumer-in-group") >= 0)
		{
			const rows = pg.querySync (

				"SELECT DISTINCT group_name"	+
				" FROM groups"			+
				" WHERE id = $1::text"		+
				" AND consumer = $2::text"	+
				" AND valid_till > NOW()",
				[
					provider_id_hash,	// 1
					consumer_id		// 2
				]
			);

			const group_array = [];
			for (const g of rows)
				group_array.push(g.group_name);

			context.conditions.groups = group_array.join();
		}

		context.conditions.tokens_per_day = 0;

		if (policy_lowercase.search(" tokens_per_day ") >= 0)
		{
			const resource_true = {};
				resource_true [resource] = true;

			const rows = pg.querySync (

				"SELECT COUNT(*) FROM token"		+
				" WHERE id = $1::text"			+
				" AND resource_ids @> $2::jsonb"	+
				" AND issued_at >= DATE_TRUNC('day',NOW())",
				[
					consumer_id,			// 1
					JSON.stringify(resource_true),	// 2
				]
			);

			context.conditions.tokens_per_day = parseInt (
				rows[0].count, 10
			);
		}

		let CTX = context;

		if (r.body && policy_lowercase.search(" body.") >= 0)
		{
			// deep copy
			CTX = JSON.parse(JSON.stringify(context));

			for (const key in r.body)
				CTX.conditions["body." + key] = r.body[key];
		}

		for (const api of r.apis)
		{
			if (typeof api !== "string")
			{
				const error_response = {
					"message"	: "'api' must be a string",
					"invalid-input"	: {
						"id"	: xss_safe(resource),
						"api"	: xss_safe(api)
					}
				};

				return END_ERROR (res, 400, error_response);
			}

			CTX.conditions.api = api;

			for (const method of r.methods)
			{
				if (typeof method !== "string")
				{
					const error_response = {
						"message"	: "'method' must be a string",
						"invalid-input"	: {
							"id"		: xss_safe(resource),
							"method"	: xss_safe(method)
						}
					};

					return END_ERROR (res, 400, error_response);
				}

				CTX.conditions.method = method;

				try
				{
					// token expiry time as specified by
					// the provider in the policy

					const result = evaluator.evaluate (
						policy_in_json,
						CTX
					);

					const token_time_in_policy	= result.expiry || 0;

					if (token_time_in_policy < 1)
					{
						const error_response = {
							"message"	: "Unauthorized",
							"invalid-input"	: {
								"id"		: xss_safe(resource),
								"api"		: xss_safe(api),
								"method"	: xss_safe(method)
							}
						};

						return END_ERROR (res, 403, error_response);
					}

					token_time = Math.min (
						token_time,
						token_time_in_policy
					);
				}
				catch (x)
				{
					const error_response = {
						"message"	: "Unauthorized",
						"invalid-input"	: {
							"id"		: xss_safe(resource),
							"api"		: xss_safe(api),
							"method"	: xss_safe(method)
						}
					};

					return END_ERROR (res, 403, error_response);
				}
			}
		}

		if (requested_token_time)
			token_time = Math.min(requested_token_time,token_time);

		if (token_time < 1)
		{
			const error_response = {
				"message" : "token validity is less than 1 second"
			};

			return END_ERROR (res, 400, error_response);
		}

		processed_request_array.push ({
			"id"			: resource,
			"methods"		: r.methods,
			"apis"			: r.apis,
			"body"			: r.body,
		});

		resource_id_dict[resource] = true;

		++num_rules_passed;
	}

	if (num_rules_passed < 1 || num_rules_passed < request_array.length)
		return END_ERROR (res, 403, "Unauthorized!");

	let token;

	const random_hex = crypto
				.randomBytes(TOKEN_LEN)
				.toString("hex");

	/* Token format = issued-by / issued-to / random-hex-string */

	token = SERVER_NAME + "/" + consumer_id + "/" + random_hex;

	const response = {

		"token"			: token,
		"token-type"		: "IUDX",
		"expires-in"		: token_time,
		"is_token_valid"	: true,
	};

	const num_resource_servers = Object
					.keys(resource_server_token)
					.length;

	if (num_resource_servers > 1)
	{
		for (const key in resource_server_token)
		{
			/* server-token format = issued-to / random-hex-string */

			resource_server_token[key] = key + "/" +
							crypto
							.randomBytes(TOKEN_LEN)
							.toString("hex");

			sha256_of_resource_server_token[key] = sha256 (
				resource_server_token[key]
			);
		}
	}

	response["server-token"]	= resource_server_token;
	const sha256_of_token		= sha256(token);

	const query = "INSERT INTO token VALUES("		+
			"$1::text,"				+
			"$2::text,"				+
			"NOW() + $3::interval,"			+ // expiry
			"$4::jsonb,"				+
			"$5::text,"				+
			"$6::text,"				+
			"NOW(),"				+ // issued_at
			"$7::jsonb,"				+
			"false,"				+ // introspected
			"false,"				+ // revoked
			"$8::int,"				+
			"$9::jsonb,"				+
			"$10::jsonb,"				+
			"$11::jsonb,"				+
			"$12::text"				+ // api_called_from
	")";

	const params = [
		consumer_id,					//  1
		sha256_of_token,				//  2
		token_time + " seconds",			//  3
		JSON.stringify(processed_request_array),	//  4
		cert.serialNumber,				//  5
		cert.fingerprint,				//  6
		JSON.stringify(resource_id_dict),		//  7
		cert_class,					//  8
		JSON.stringify(sha256_of_resource_server_token),//  9
		JSON.stringify(providers),			// 10
		JSON.stringify(geoip),				// 11
		req.headers.origin,				// 12
	];

	pool.query (query, params, (error,results) =>
	{
		if (error || results.rowCount === 0)
		{
			return END_ERROR (
				res, 500,
				"Internal error!", error
			);
		}

		const expiry_date = new Date(Date.now() + (token_time * 1000));

		const details =
		{
			"requester"        : consumer_id,
			"requesterRole"    : cert_class,
			"token_expiry"     : expiry_date,
			"resource_ids"     : processed_request_array
		};

		log("info", "ISSUED_TOKEN", true, details);

		return END_SUCCESS (res,response);
	});
});

app.post("/auth/v[1-2]/token/introspect", (req, res) => {

	const cert			= res.locals.cert;
	const body			= res.locals.body;

	const hostname_in_certificate	= cert.subject.CN.toLowerCase();

	if (! body.token)
		return END_ERROR (res, 400, "No 'token' found in the body");

	if (! is_valid_token(body.token))
		return END_ERROR (res, 400, "Invalid 'token'");

	const token		= body.token.toLowerCase();
	let server_token	= body["server-token"] || true;

	if (server_token === true || server_token === "" || server_token === "true")
	{
		server_token = true;
	}
	else
	{
		server_token = server_token.toLowerCase();

		if (! is_valid_servertoken(server_token, hostname_in_certificate))
			return END_ERROR (res, 400, "Invalid 'server-token'");
	}

	const consumer_request = body.request;

	if (consumer_request)
	{
		if (! (consumer_request instanceof Array))
		{
			return END_ERROR (
				res, 400,
				"'request' must be an valid JSON array"
			);
		}

		Object.freeze(consumer_request);
	}

	const split		= token.split("/");
	const issued_to		= split[1];

	const sha256_of_token	= sha256(token);

	pool.query (

		"SELECT expiry,request,cert_class,"		+
		" server_token,providers"			+
		" FROM token"					+
		" WHERE id = $1::text"				+
		" AND token = $2::text"				+
		" AND revoked = false"				+
		" AND expiry > NOW()"				+
		" LIMIT 1",
		[
			issued_to,				// 1
			sha256_of_token				// 2
		],

		(error, results) =>
		{
			if (error)
			{
				return END_ERROR (
					res, 500, "Internal error!", error
				);
			}

			if (results.rows.length === 0)
				return END_ERROR (res, 403, "Invalid 'token'");

			const expected_server_token = results
							.rows[0]
							.server_token[hostname_in_certificate];

			// if token doesn't belong to this server
			if (! expected_server_token)
				return END_ERROR (res, 403, "Invalid 'token'");

			const num_resource_servers = Object.keys (
				results.rows[0].server_token
			).length;

			if (num_resource_servers > 1)
			{
				if (server_token === true) // should be a real token
				{
					return END_ERROR (
						res, 403,
						"Invalid 'server-token'"
					);
				}

				const sha256_of_server_token = sha256(server_token);

				if (sha256_of_server_token !== expected_server_token)
				{
					return END_ERROR (
						res, 403,
						"Invalid 'server-token'"
					);
				}
			}
			else
			{
				// token belongs to only 1 server

				if (server_token === true && expected_server_token === true)
				{
					// ok
				}
				else if (typeof expected_server_token === "string")
				{
					const sha256_of_server_token = sha256(server_token);

					if (sha256_of_server_token !== expected_server_token)
					{
						return END_ERROR (
							res, 403,
							"Invalid 'server-token'"
						);
					}
				}
				else
				{
					return END_ERROR (
						res, 500,
						"Invalid 'expected_server_token' in DB"
					);
				}
			}

			const request	= results.rows[0].request;
			const providers	= results.rows[0].providers;

			const request_for_resource_server = [];

			for (const r of request)
			{
				const split		= r.id.split("/");

				const email_domain	= split[0].toLowerCase();
				const sha1_of_email	= split[1].toLowerCase();

				const provider_id_hash	= email_domain + "/" + sha1_of_email;

				const resource_server	= split[2].toLowerCase();

				// if provider exists
				if (providers[provider_id_hash])
				{
					if (resource_server === hostname_in_certificate)
						request_for_resource_server.push (r);
				}
			}

			Object.freeze(request_for_resource_server);

			if (request_for_resource_server.length === 0)
				return END_ERROR (res, 403, "Invalid 'token'");

			if (consumer_request)
			{
				const l1 = Object.keys(
					consumer_request
				).length;

				const l2 = Object.keys(
					request_for_resource_server
				).length;

				// more number of requests than what is allowed

				if (l1 > l2)
				{
					return END_ERROR (
						res, 403, "Unauthorized !"
					);
				}

				for (const r1 of consumer_request)
				{
					if (! (r1 instanceof Object))
					{
						const error_response = {
							"message"	: "'request' must be a valid JSON object",
							"invalid-input"	: xss_safe(r1)
						};

						return END_ERROR (res, 400,
							error_response
						);
					}

					// default values

					if (! r1.methods)
						r1.methods = ["*"];

					if (! r1.apis)
						r1.apis = ["/*"];

					if (! r1.body)
						r1.body = null;

					Object.freeze(r1);

					let resource_found = false;

					for (const r2 of request_for_resource_server)
					{
						Object.freeze(r2);

						if (r1.id === r2.id)
						{
							if (! lodash.isEqual(r1,r2))
							{
								const error_response = {
									"message"	: "Unauthorized",
									"invalid-input"	: xss_safe(r1.id)
								};

								return END_ERROR (res, 403, error_response);
							}

							resource_found = true;
							break;
						}
					}

					if (! resource_found)
					{
						const error_response = {
							"message"	: "Unauthorized",
							"invalid-input"	: xss_safe(r1.id),
						};

						return END_ERROR (res, 403, error_response);
					}
				}
			}

			const response = {
				"consumer"			: issued_to,
				"expiry"			: results.rows[0].expiry,
				"request"			: request_for_resource_server,
				"consumer-certificate-class"	: results.rows[0].cert_class,
			};

			pool.query (

				"UPDATE token SET introspected = true"	+
				" WHERE token = $1::text"		+
				" AND introspected = false"		+
				" AND revoked = false"			+
				" AND expiry > NOW()",
				[
					sha256_of_token,		// 1
				],

				(update_error) =>
				{
					if (update_error)
					{
						return END_ERROR (
							res, 500,
							"Internal error!",
							update_error
						);
					}

					const details = {
						"resource_server"  : hostname_in_certificate,
						"token_hash"       : sha256_of_token,
						"issued_to"	   : issued_to
					};

					log("info", "INTROSPECTED_TOKEN", true, details);

					return END_SUCCESS (res,response);
				}
			);
		}
	);
});

app.post("/auth/v[1-2]/token/revoke", (req, res) => {

	const id		= res.locals.email;
	const body		= res.locals.body;

	const tokens		= body.tokens;
	const token_hashes	= body["token-hashes"];

	if (tokens && token_hashes)
	{
		return END_ERROR (
			res, 400,
			"Provide either 'tokens' or 'token-hashes'; but not both"
		);
	}

	if ( (! tokens) && (! token_hashes))
	{
		return END_ERROR (
			res, 400,
			"No 'tokens' or 'token-hashes' found"
		);
	}

	let num_tokens_revoked = 0;

	if (tokens)
	{
		// user is a consumer

		if (! (tokens instanceof Array))
			return END_ERROR (res, 400, "'tokens' must be a valid JSON array");

		for (const token of tokens)
		{
			if (! is_valid_token(token, id))
			{
				const error_response = {
					"message"		: "Invalid 'token'",
					"invalid-input"		: xss_safe(token),
					"num-tokens-revoked"	: num_tokens_revoked
				};

				return END_ERROR (res, 400, error_response);
			}

			const sha256_of_token = sha256(token);

			const rows = pg.querySync (

				"SELECT 1 FROM token"		+
				" WHERE id = $1::text "		+
				" AND token = $2::text "	+
				" AND expiry > NOW()"		+
				" LIMIT 1",
				[
					id,			// 1
					sha256_of_token		// 2
				]
			);

			if (rows.length === 0)
			{
				const error_response = {
					"message"		: "Invalid 'token'",
					"invalid-input"		: xss_safe(token),
					"num-tokens-revoked"	: num_tokens_revoked
				};

				return END_ERROR (res, 400, error_response);
			}

			const update_rows = pg.querySync (

				"UPDATE token SET revoked = true"	+
				" WHERE id = $1::text"			+
				" AND token = $2::text"			+
				" AND revoked = false"			+
				" AND expiry > NOW()",
				[
					id,				// 1
					sha256_of_token			// 2
				]
			);

			// querySync returns empty object for UPDATE
			num_tokens_revoked += 1;
		}
	}
	else
	{
		// user is a provider

		if (! (token_hashes instanceof Array))
			return END_ERROR (res, 400, "'token-hashes' must be a valid JSON array");

		const email_domain	= id.split("@")[1];
		const sha1_of_email	= sha1(id);

		const provider_id_hash	= email_domain + "/" + sha1_of_email;

		for (const token_hash of token_hashes)
		{
			if (! is_valid_tokenhash(token_hash))
			{
				const error_response = {
					"message"		: "Invalid 'token-hash'",
					"invalid-input"		: xss_safe(token_hash),
					"num-tokens-revoked"	: num_tokens_revoked
				};

				return END_ERROR (res, 400, error_response);
			}

			const rows = pg.querySync (

				"SELECT 1 FROM token"			+
				" WHERE token = $1::text"		+
				" AND providers-> $2::text = 'true'"	+
				" AND expiry > NOW()"			+
				" LIMIT 1",
				[
					token_hash,			// 1
					provider_id_hash		// 2
				]
			);

			if (rows.length === 0)
			{
				const error_response = {
					"message"		: "Invalid 'token-hash'",
					"invalid-input"		: xss_safe(token_hash),
					"num-tokens-revoked"	: num_tokens_revoked
				};

				return END_ERROR (res, 400, error_response);
			}

			const provider_false = {};
				provider_false[provider_id_hash] = false;

			const update_rows = pg.querySync (

				"UPDATE token SET"			+
				" providers = providers || $1::jsonb"	+
				" WHERE token = $2::text"		+
				" AND providers-> $3::text = 'true'"	+
				" AND expiry > NOW()",
				[
					JSON.stringify(provider_false),	// 1
					token_hash,			// 2
					provider_id_hash		// 3
				]
			);

			// querySync returns empty object for UPDATE
			num_tokens_revoked += 1;
		}
	}

	const response = {
		"num-tokens-revoked" : num_tokens_revoked
	};

	const details =
		{
			"requester"     : id,
			"requesterRole" : (tokens ? "consumer" : "provider"),
			"revoked"	: response["num-tokens-revoked"]
		};

	log("info", "REVOKED_TOKENS", false, details);

	return END_SUCCESS (res, response);
});

app.post("/auth/v[1-2]/token/revoke-all", (req, res) => {

	const id		= res.locals.email;
	const body		= res.locals.body;

	if (! body.serial)
		return END_ERROR (res, 400, "No 'serial' found in the body");

	if (! is_string_safe(body.serial))
		return END_ERROR (res, 400, "Invalid 'serial'");

	const serial = body.serial.toLowerCase();

	if (! body.fingerprint)
	{
		return END_ERROR (
			res, 400,
			"No 'fingerprint' found in the body"
		);
	}

	if (! is_string_safe(body.fingerprint,":")) // fingerprint contains ':'
		return END_ERROR (res, 400, "Invalid 'fingerprint'");

	const fingerprint	= body.fingerprint.toLowerCase();

	const email_domain	= id.split("@")[1];
	const sha1_of_email	= sha1(id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	pool.query (

		"UPDATE token"				+
		" SET revoked = true"			+
		" WHERE id = $1::text"			+
		" AND cert_serial = $2::text"		+
		" AND cert_fingerprint = $3::text"	+
		" AND expiry > NOW()"			+
		" AND revoked = false",
		[
			id,				// 1
			serial,				// 2
			fingerprint			// 3
		],

		(error,results) =>
		{
			if (error)
			{
				return END_ERROR (
					res, 500, "Internal error!", error
				);
			}

			const response = {
				"num-tokens-revoked" : results.rowCount
			};

			const provider_false = {};
			provider_false[provider_id_hash] = false;

			pool.query (

				"UPDATE token SET"			+
				" providers = providers || $1::jsonb"	+
				" WHERE cert_serial = $2::text"		+
				" AND cert_fingerprint = $3::text"	+
				" AND expiry > NOW()"			+
				" AND revoked = false"			+
				" AND providers-> $4::text = 'true'",
				[
					JSON.stringify(provider_false),	// 1
					serial,				// 2
					fingerprint,			// 3
					provider_id_hash		// 4
				],

				(update_error, update_results) =>
				{
					if (update_error)
					{
						return END_ERROR (
							res, 500,
							"Internal error!",
							update_error
						);
					}

					response["num-tokens-revoked"] += update_results.rowCount;

					const details = {
						"requester"     : id,
						"requesterRole" : update_results.rowCount == 0 ?
							"consumer" : "provider",
						"serial" 	: serial,
						"fingerprint"	: fingerprint,
						"revoked"	: response["num-tokens-revoked"]
					};

					log("info", "REVOKED_ALL_TOKENS", true, details);

					return END_SUCCESS (res,response);
				}
			);
		}
	);
});

app.post("/auth/v[1-2]/acl/set", (req, res) => {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.policy)
		return END_ERROR (res, 400, "No 'policy' found in request");

	if (typeof body.policy !== "string")
		return END_ERROR (res, 400, "'policy' must be a string");

	const policy		= body.policy.trim();
	const policy_lowercase	= policy.toLowerCase();

	if (
		(policy_lowercase.search(" like ")  >= 0) ||
		(policy_lowercase.search("::regex") >= 0)
	)
	{
		return END_ERROR (res, 400, "RegEx in 'policy' is not supported");
	}

	const rules = policy.split(";");

	set_acl(provider_id, rules, (err) =>
	{
		if (err)
			return END_ERROR (res, err.http_code, err.message);
		else
			return END_SUCCESS (res);
	});

});

app.post("/auth/v[1-2]/acl/append", (req, res) => {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.policy)
		return END_ERROR (res, 400, "No 'policy' found in request");

	if (typeof body.policy !== "string")
		return END_ERROR (res, 400, "'policy' must be a string");

	const policy		= body.policy.trim();
	const policy_lowercase	= policy.toLowerCase();

	if (
		(policy_lowercase.search(" like ")  >= 0) ||
		(policy_lowercase.search("::regex") >= 0)
	)
	{
		return END_ERROR (res, 400, "RegEx in 'policy' is not supported");
	}

	const rules = policy.split(";");

	let policy_in_json;

	try
	{
		policy_in_json = rules.map (
			(r) => {
				return (parser.parse(r.trim()));
			}
		);
	}
	catch (x)
	{
		const err = String(x);
		return END_ERROR (res, 400, "Syntax error in policy. " + err);
	}

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	pool.query (

		"SELECT policy FROM policy WHERE id = $1::text LIMIT 1",
		[
			provider_id_hash	// 1
		],

	(error, results) =>
	{
		if (error)
			return END_ERROR (res,500,"Internal error!",error);

		let query;
		let params;

		if (results.rows.length === 1)
		{
			const old_policy	= Buffer.from (
							results.rows[0].policy,
							"base64"
						).toString("ascii");

			const new_policy	= old_policy + ";" + policy;
			const new_rules		= new_policy.split(";");

			try
			{
				policy_in_json = new_rules.map (
					(r) => {
						return (parser.parse(r.trim()));
					}
				);
			}
			catch (x)
			{
				const err = String(x);

				return END_ERROR (
					res, 400,
					"Syntax error in policy. " + err
				);
			}

			const base64policy = Buffer
						.from(new_policy)
						.toString("base64");

			query	= "UPDATE policy"			+
					" SET policy = $1::text,"	+
					" policy_in_json = $2::jsonb,"	+
					" previous_policy = policy,"	+
					" last_updated = NOW(),"	+
					" api_called_from = $3::text"	+
					" WHERE id = $4::text";

			params	= [
					base64policy,			// 1
					JSON.stringify(policy_in_json),	// 2
					req.headers.origin,		// 3
					provider_id_hash		// 4
			];
		}
		else
		{
			const base64policy = Buffer
						.from(policy)
						.toString("base64");

			query	= "INSERT INTO policy VALUES("	+
					"$1::text,"		+
					"$2::text,"		+
					"$3::jsonb,"		+
					"NULL,"			+
					"NOW(),"		+
					"$4::text"		+
			")";

			params	= [
				provider_id_hash,			// 1
				base64policy,				// 2
				JSON.stringify(policy_in_json),		// 3
				req.headers.origin			// 4
			];
		}

		pool.query (query, params, (error_1, results_1) =>
		{
			if (error_1 || results_1.rowCount === 0)
			{
				return END_ERROR (
					res, 500,
						"Internal error!",
						error_1
				);
			}

			const details = {
				"provider"  : provider_id,
				"policy"    : policy
			};

			log("info", "APPENDED_POLICY", true, details);

			return END_SUCCESS (res);
		});
	});
});

app.post("/auth/v[1-2]/acl", (req, res) => {

	const provider_id	= res.locals.email;

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	pool.query (

		"SELECT policy, previous_policy, last_updated, api_called_from"	+
		" FROM policy"							+
		" WHERE id = $1::text "						+
		" LIMIT 1",
		[
			provider_id_hash			// 1
		],

	(error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!", error);

		if (results.rows.length === 0)
			return END_ERROR (res, 400, "No policies set yet!");

		const policy	= Buffer
					.from(results.rows[0].policy,"base64")
					.toString("ascii")
					.split(";");

		let previous_policy = [];

		if (results.rows[0].previous_policy)
		{
			previous_policy = Buffer
						.from(results.rows[0].previous_policy,"base64")
						.toString("ascii")
						.split(";");
		}

		const response = {
			"policy"		: policy,
			"previous-policy"	: previous_policy,
			"last-updated"		: results.rows[0].last_updated,
			"api-called-from"	: results.rows[0].api_called_from
		};

		return END_SUCCESS (res,response);
	});
});

app.post("/auth/v[1-2]/acl/revert", (req, res) => {

	const provider_id	= res.locals.email;

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	pool.query (

		"SELECT previous_policy FROM policy"	+
		" WHERE id = $1::text"			+
		" AND previous_policy IS NOT NULL"	+
		" LIMIT 1",
		[
			provider_id_hash		// 1
		],

	(error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!", error);

		if (results.rows.length === 0)
			return END_ERROR (res, 400, "No previous policies found!");

		const previous_policy = Buffer
					.from(results.rows[0].previous_policy,"base64")
					.toString("ascii")
					.split(";");

		let policy_in_json;

		try
		{
			policy_in_json = previous_policy.map (
				(r) => {
					return (parser.parse(r.trim()));
				}
			);
		}
		catch (x)
		{
			const err = String(x);

			return END_ERROR (
				res, 400,
				"Syntax error in previous-policy. " + err
			);
		}

		const query	= "UPDATE policy"			+
					" SET policy = previous_policy,"+
					" policy_in_json = $1::jsonb,"	+
					" previous_policy = NULL,"	+
					" last_updated = NOW(),"	+
					" api_called_from = $2::text"	+
					" WHERE id = $3::text";

		const params	= [
				JSON.stringify(policy_in_json),		// 1
				req.headers.origin,			// 2
				provider_id_hash			// 3
		];

		pool.query (query, params, (error_1, results_1) =>
		{
			if (error_1 || results_1.rowCount === 0)
			{
				return END_ERROR (
					res, 500,
						"Internal error!",
						error_1
				);
			}

			const details = {
				"provider"  : provider_id,
				"policy"    : previous_policy
			};

			log("info", "REVERTED_POLICY", true, details);

			return END_SUCCESS (res);
		});
	});
});

app.post("/auth/v[1-2]/audit/tokens", (req, res) => {

	const id		= res.locals.email;
	const body		= res.locals.body;

	if (! body.hours)
		return END_ERROR (res, 400, "No 'hours' found in the body");

	const hours = parseInt (body.hours,10);

	// 5 yrs max
	if (isNaN(hours) || hours < 1 || hours > 43800) {
		return END_ERROR (res, 400, "'hours' must be a positive number");
	}

	const as_consumer = [];
	const as_provider = [];

	pool.query (

		"SELECT issued_at,expiry,request,cert_serial,"	+
		" cert_fingerprint,introspected,revoked,"	+
		" expiry < NOW() as expired,geoip,"		+
		" api_called_from"				+
		" FROM token"					+
		" WHERE id = $1::text"				+
		" AND issued_at >= (NOW() - $2::interval)"	+
		" ORDER BY issued_at DESC",
		[
			id,					// 1
			hours + " hours"			// 2
		],

	(error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!", error);

		for (const row of results.rows)
		{
			as_consumer.push ({
				"token-issued-at"		: row.issued_at,
				"introspected"			: row.introspected,
				"revoked"			: row.revoked,
				"expiry"			: row.expiry,
				"expired"			: row.expired,
				"certificate-serial-number"	: row.cert_serial,
				"certificate-fingerprint"	: row.cert_fingerprint,
				"request"			: row.request,
				"geoip"				: row.geoip,
				"api-called-from"		: row.api_called_from
			});
		}

		const email_domain	= id.split("@")[1];
		const sha1_of_email	= sha1(id);

		const provider_id_hash	= email_domain + "/" + sha1_of_email;

		pool.query (

			"SELECT id,token,issued_at,expiry,request,"	+
			" cert_serial,cert_fingerprint,"		+
			" revoked,introspected,"			+
			" providers-> $1::text"				+
			" AS is_valid_token_for_provider,"		+
			" expiry < NOW() as expired,geoip,"		+
			" api_called_from"				+
			" FROM token"					+
			" WHERE providers-> $1::text"			+
			" IS NOT NULL"					+
			" AND issued_at >= (NOW() - $2::interval)"	+
			" ORDER BY issued_at DESC",
			[
				provider_id_hash,			// 1
				hours + " hours"			// 2
			],

		(error, results) =>
		{
			if (error)
			{
				return END_ERROR (
					res, 500, "Internal error!", error
				);
			}

			for (const row of results.rows)
			{
				const revoked = (
					row.revoked || (! row.is_valid_token_for_provider)
				);

				/* return only resource IDs belonging to provider
				   who requested audit */

				let filtered_request = [];

				for (const r of row.request)
				{
					const split		= r.id.split("/");

					const email_domain	= split[0].toLowerCase();
					const sha1_of_email	= split[1].toLowerCase();

					const provider		= email_domain + "/" + sha1_of_email;

					if (provider === provider_id_hash)
						filtered_request.push(r);
				}

				as_provider.push ({
					"consumer"			: row.id,
					"token-hash"			: row.token,
					"token-issued-at"		: row.issued_at,
					"introspected"			: row.introspected,
					"revoked"			: revoked,
					"expiry"			: row.expiry,
					"expired"			: row.expired,
					"certificate-serial-number"	: row.cert_serial,
					"certificate-fingerprint"	: row.cert_fingerprint,
					"request"			: filtered_request,
					"geoip"				: row.geoip,
					"api-called-from"		: row.api_called_from
				});
			}

			const response = {
				"as-consumer"	: as_consumer,
				"as-provider"	: as_provider,
			};

			return END_SUCCESS (res,response);
		});
	});
});

app.post("/auth/v[1-2]/group/add", (req, res) => {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.consumer)
		return END_ERROR (res, 400, "No 'consumer' found in the body");

	if (! is_valid_email(body.consumer))
		return END_ERROR (res, 400, "'consumer' must be an e-mail");

	const consumer_id = body.consumer.toLowerCase();

	if (! body.group)
		return END_ERROR (res, 400, "No 'group' found in the body");

	if (! is_string_safe (body.group))
		return END_ERROR (res, 400, "Invalid 'group'");

	const group = body.group.toLowerCase();

	if (! body["valid-till"])
		return END_ERROR (res, 400, "No 'valid-till' found in the body");

	const valid_till = parseInt(body["valid-till"],10);

	// 1 year max
	if (isNaN(valid_till) || valid_till < 1 || valid_till > 8760)
	{
		return END_ERROR (
			res, 400, "'valid-till' must be a positive number"
		);
	}

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	pool.query (

		"INSERT INTO groups"			+
		" VALUES ($1::text, $2::text, $3::text, NOW() + $4::interval)",
		[
			provider_id_hash,		// 1
			consumer_id,			// 2
			group,				// 3
			valid_till + " hours"		// 4
		],

	(error, results) =>
	{
		if (error || results.rowCount === 0)
			return END_ERROR (res, 500, "Internal error!", error);

		const details = {
			"provider"	: provider_id,
			"consumer"	: consumer_id,
			"group"		: group,
			"valid_for"	: valid_till + " hours"
		};

		log("info", "CONSUMER_ADDED_GROUP", true, details);

		return END_SUCCESS (res);
	});
});

app.post("/auth/v[1-2]/group/list", (req, res) => {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (body.group)
	{
		if (! is_string_safe (body.group))
			return END_ERROR (res, 400, "Invalid 'group'");
	}

	const group		= body.group ? body.group.toLowerCase() : null;

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	const response = [];

	if (group)
	{
		pool.query (

			"SELECT consumer, valid_till FROM groups"	+
			" WHERE id = $1::text"				+
			" AND group_name = $2::text"			+
			" AND valid_till > NOW()",
			[
				provider_id_hash,			// 1
				group					// 2
			],

		(error, results) =>
		{
			if (error)
			{
				return END_ERROR (
					res, 500, "Internal error!", error
				);
			}

			for (const row of results.rows)
			{
				response.push ({
					"consumer"	: row.consumer,
					"valid-till"	: row.valid_till
				});
			}

			return END_SUCCESS (res,response);
		});
	}
	else
	{
		pool.query (

			"SELECT consumer,group_name,valid_till"	+
			" FROM groups"				+
			" WHERE id = $1::text"			+
			" AND valid_till > NOW()",
			[
				provider_id_hash		// 1
			],

		(error, results) =>
		{
			if (error)
			{
				return END_ERROR (
					res, 500, "Internal error!", error
				);
			}

			for (const row of results.rows)
			{
				response.push ({
					"consumer"	: row.consumer,
					"group"		: row.group_name,
					"valid-till"	: row.valid_till
				});
			}

			return END_SUCCESS (res,response);
		});
	}
});

app.post("/auth/v[1-2]/group/delete", (req, res) => {

	const body		= res.locals.body;
	const provider_id	= res.locals.email;

	if (! body.consumer)
		return END_ERROR (res, 400, "No 'consumer' found in the body");

	if (body.consumer !== "*")
	{
		if (! is_valid_email(body.consumer))
		{
			return END_ERROR (
				res, 400, "'consumer' must be an e-mail"
			);
		}
	}

	const consumer_id = body.consumer.toLowerCase();

	if (! body.group)
		return END_ERROR (res, 400, "No 'group' found in the body");

	if (! is_string_safe (body.group))
		return END_ERROR (res, 400, "Invalid 'group'");

	const group		= body.group.toLowerCase();

	const email_domain	= provider_id.split("@")[1];
	const sha1_of_email	= sha1(provider_id);

	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	let query	= "UPDATE groups SET"					+
				" valid_till = (NOW() - interval '1 seconds')"	+
				" WHERE id = $1::text"				+
				" AND group_name = $2::text"			+
				" AND valid_till > NOW()";

	const params	= [
				provider_id_hash,			// 1
				group					// 2
	];

	if (consumer_id !== "*")
	{
		query	+= " AND consumer = $3::text";
		params.push(consumer_id);				// 3
	}

	pool.query (query, params, (error, results) =>
	{
		if (error)
			return END_ERROR (res, 500, "Internal error!", error);

		if (consumer_id !== "*" && results.rowCount === 0)
		{
			return END_ERROR (
				res, 400, "Consumer not found in the group"
			);
		}

		const response = {
			"num-consumers-deleted"	: results.rowCount
		};

		const details = {
			"provider"	: provider_id,
			"consumer"	: consumer_id,
			"group"		: group,
			"deleted"	: results.rowCount
		};

		log("info", "CONSUMER_DELETED_GROUP", true, details);

		return END_SUCCESS (res,response);
	});
});

app.post("/auth/v[1-2]/certificate-info", async (req, res) => {

	const cert	= res.locals.cert;
	let roles = [];

	try {
		const result = await pool.query (
			"SELECT role FROM consent.role JOIN" 	+
			" consent.users ON users.id = user_id"	+
			" WHERE users.email = $1::text",
			[ res.locals.email ]);

		roles = [...new Set(result.rows.map(row => row.role))];
	}
	catch(error) { return END_ERROR (res, 500, "Internal error!", error); }

	const response	= {
		"id"			: res.locals.email,
		"certificate-class"	: res.locals.cert_class,
		"serial"		: cert.serialNumber.toLowerCase(),
		"fingerprint"		: cert.fingerprint.toLowerCase(),
		"roles"			: roles
	};

	return END_SUCCESS (res,response);
});

app.post("/auth/v[1-2]/provider/access", async (req, res) => {

	const provider_email = res.locals.email;
	let provider_uid, accesser_uid, access_item_id;
	let rule, resource_name;
	let rules_array = [];

	try { provider_uid = await check_privilege(provider_email, "provider"); }
	catch(error) { return END_ERROR (res, 401, "Not allowed!"); }

	const email_domain	= provider_email.split("@")[1];
	const sha1_of_email	= sha1(provider_email);
	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	let accesser_email 	= res.locals.body.user_email;
	const accesser_role	= res.locals.body.user_role;
	const resource		= res.locals.body.item_id;
	let capability		= res.locals.body.capabilities;
	let res_type		= res.locals.body.item_type;
	let req_capability;

	let consumer_acc_id	= null;

	if (! accesser_email || ! is_valid_email(accesser_email))
		return END_ERROR (res, 400, "Invalid data (email)");

	accesser_email = accesser_email.toLowerCase();

	if (! accesser_role || ! ACCESS_ROLES.includes(accesser_role))
		return END_ERROR (res, 400, "Invalid data (role)");

	try { accesser_uid = await check_privilege(accesser_email, accesser_role); }
	catch(error) { return END_ERROR (res, 403, "Invalid accesser"); }

	if (accesser_role === "consumer")
	{
		if (! Array.isArray(capability) || 
			capability.length > Object.keys(CAPABILITIES).length ||
			capability.length === 0)
			return END_ERROR (res, 400, "Invalid data (capabilities)");

		capability = [...new Set(capability)];

		if (! capability.every( (val) => Object.keys(CAPABILITIES).includes(val)))
			return END_ERROR (res, 400, "Invalid data (capabilities)");

		req_capability = capability;
	}

	if (accesser_role === "consumer" || accesser_role === "data ingester")
	{
		if (! resource)
			return END_ERROR (res, 400, "Invalid data (item-id)");

		if (! res_type || ! RESOURCE_ITEM_TYPES.includes(res_type))
			return END_ERROR (res, 400, "Invalid data (item-type)");

		// resource group must have 3 slashes
		if ((resource.match(/\//g) || []).length !== 3)
			return END_ERROR (res, 400, "Invalid data (item-id)");

		if (! is_string_safe(resource, "_") || resource.indexOf("..") >= 0)
			return END_ERROR (res, 400, "Invalid data (item-id)");

		if (! resource.startsWith(provider_id_hash))
			return END_ERROR (res, 403, "Provider does not match resource owner");

		// create resource id that aperture expects
		resource_name = resource.replace(provider_id_hash + "/", "");

		// get access item id if it exists
		try {
			const result = await pool.query (
				"SELECT id from consent." + res_type +
				" WHERE cat_id = $1::text ",
				[
					resource
				]);

			if (result.rows.length !== 0)
				access_item_id = result.rows[0].id;

		}
		catch(error)
		{
			return END_ERROR (res, 500, "Internal error!", error);
		}
	}

	/* access_item_id for catalogue is -1 by default */
	if (accesser_role === "onboarder")
	{
		access_item_id 	= -1;
		res_type 	= "catalogue";
	}

	/* if rule exists for particular provider+accesser+role+
	   resource/catalogue */
	if (access_item_id)
	{
		try {
			const result = await pool.query (
				"SELECT a.id, a.policy_text "				+
				" FROM consent.role, consent.access as a"		+
				" WHERE consent.role.id = a.role_id"			+
				" AND a.provider_id = $1::integer"			+
				" AND role.user_id = $2::integer"			+
				" AND a.access_item_id = $3::integer"			+
				" AND role.role = $4::consent.role_enum",
			[
				provider_uid,			//$1
				accesser_uid,			//$2
				access_item_id,			//$3
				accesser_role			//$4
			]);

			if (result.rows.length !== 0 && accesser_role !== "consumer")
				return END_ERROR (res, 403, "Rule exists");

			/* if consumer exists with this resource-id, only update
			 * policy for said consumer and do not add a new row in
			 * the access table */

			if (result.rows.length !== 0 && accesser_role === "consumer")
			{
				consumer_acc_id	= result.rows[0].id;

				const caps = await pool.query (
					"SELECT capability from consent.capability"	+
					" WHERE access_id = $1::integer",
					[ consumer_acc_id ]);

				let existing_caps = [...new Set(caps.rows.map(row => row.capability))];
				let i; // get index of existing cap

				if (! capability.every( (val, index) => {
					i = index;
					return ! existing_caps.includes(val);
				}))
					return END_ERROR (res, 403, `Rule exists for ${capability[i]}`);

				/* merge old and new capabilities,
				 * no duplicates should be there */
				capability = capability.concat(existing_caps);
			}
		}
		catch(error)
		{
			return END_ERROR (res, 500, "Internal error!", error);
		}
	}

	switch (accesser_role)
	{
		case "onboarder":
			rule = `${accesser_email} can access ${CAT_API_RULE} for 1 week`;
			break;

		case "data ingester":
			rule = `${accesser_email} can access ${resource_name}/* for 1 week if api = "${INGEST_API_RULE}"`;
			break;

		case "consumer":
			rule = `${accesser_email} can access ${resource_name}/* for 1 week`;
			break;

		default:
			return END_ERROR (res, 500, "Internal error!");
	}

	/* add capabilities/APIs to policy */
	if (accesser_role === "consumer")
	{
		let join = "if", apis = [], index;

		capability.map(val => apis = apis.concat(CAPABILITIES[val]));
		apis = [...new Set(apis)];

		/* if latest API is there, then add resource group
		 * to the template */
		if ((index = apis.indexOf(LATEST)) !== -1)
			apis[index] = apis[index](resource);

		for (const i of apis)
		{
			rule = rule + ` ${join} api = "${i}"`;
			join = "or";
		}
	}

	try {
		if (! access_item_id)
		{
			const access_item = await pool.query (
				"INSERT INTO consent." + res_type 			+
				" (provider_id, cat_id, created_at, updated_at) "	+
				" VALUES ($1::integer, $2::text, NOW(), NOW())"		+
				"RETURNING id",
				[
					provider_uid,	//$1
					resource	//$2
				]);

			access_item_id = access_item.rows[0].id;
		}

		const role_id = await pool.query (
			"SELECT id from consent.role WHERE"	+
			" user_id = $1::integer "		+
			" AND role = $2::consent.role_enum",
			[
				accesser_uid,		//$1
				accesser_role		//$2
			]);

		let access;

		/* if consumer_acc_id is not null, there is an existing
		 * consumer with policy for same resource-id */
		if (consumer_acc_id === null)
		{
			access = await pool.query (
				"INSERT into consent.access (provider_id, "		+
				" role_id, policy_text, access_item_id, "		+
				" access_item_type, created_at, updated_at)"		+
				" VALUES ($1::integer, $2::integer, "			+
				" $3::text, $4::integer, $5::consent.access_item,"	+
				" NOW(), NOW()) RETURNING id",
				[
					provider_uid,		//$1
					role_id.rows[0].id,	//$2
					rule,			//$3
					access_item_id,		//$4
					res_type,		//$5
				]);
		}
		else
		{
			access = await pool.query (
				"UPDATE consent.access SET policy_text = $1::text,"	+
				" updated_at = NOW() WHERE access.id = $2::integer"	+
				" RETURNING id",
				[ rule, consumer_acc_id ]);
		}

		/* add newly requested capabilities to table if consumer */
		if (accesser_role === "consumer")
		{
			let access_id = access.rows[0].id;

			for (const cap of req_capability)
			{
				const result = await pool.query (
					"INSERT INTO consent.capability "		+
					" (access_id, capability) VALUES"		+
					" ($1::integer, $2::consent.capability_enum)",
					[ access_id, cap ]);
			}
		}
	}
	catch(error)
	{
		return END_ERROR (res, 500, "Internal error!", error);
	}

	try {
		const rules = await pool.query (
			"SELECT policy_text FROM consent.access,"	+
			" consent.role WHERE provider_id = $1::integer"	+
			" AND role.id = access.role_id ORDER BY role",
			[
				provider_uid
			]);

		rules_array = rules.rows.map(
				(row) => { return row.policy_text; });
	}
	catch(error)
	{
		return END_ERROR (res, 500, "Internal error!", error);
	}

	set_acl(provider_email, rules_array, (err) =>
	{
		if (err)
			return END_ERROR (res, err.http_code, err.message);
		else
			return END_SUCCESS (res);
	});

});

app.get("/auth/v[1-2]/provider/access",  async (req, res) => {

	const email = res.locals.email;
	let provider_uid, rules;
	var item_details = [];
	var cap_details	 = {};

	try { provider_uid = await check_privilege(email, "provider"); }
	catch(error) { return END_ERROR (res, 401, "Not allowed"); }

	try {
		let result = await pool.query (
			"SELECT a.id, a.created_at, a.updated_at, "		+
			" a.policy_text, a.access_item_type, a.access_item_id,"	+
			" email, role FROM consent.access as a, "		+
			" consent.users, consent.role "				+
			" WHERE a.role_id = role.id "				+
			" AND role.user_id = users.id "				+
			" AND a.provider_id = $1::integer",
			[ provider_uid ]);

		rules = result.rows;
	}
	catch(error)
	{
		return END_ERROR (res, 500, "Internal error!", error);
	}

	const accessid_arr = rules.map((obj) => obj.id);
	const access_items = [...new Set(rules.map((obj) => obj.access_item_type ))];

	for (const item of access_items)
	{
		if (item === "catalogue") continue;

		try {
			const result = await pool.query (
				"SELECT * FROM consent." + item + " as type, "	+
				" consent.access"	+
				" WHERE access_item_type = '" + item +"'"	+
				" AND access_item_id = type.id"	+
				" AND access.provider_id = $1::integer",
				[ provider_uid ]);

			item_details = [...item_details, ...result.rows];

		}
		catch(error)
		{
			return END_ERROR (res, 500, "Internal error!", error);
		}

	}

	/* get capability details for each access ID */
	try {
		const result = await pool.query (
			"SELECT access_id, capability "		+
			" FROM consent.capability "		+
			" WHERE access_id = ANY($1::integer[])",
			[ accessid_arr ]);

		result.rows.map ( row => {
			if (! cap_details[row.access_id])
				cap_details[row.access_id] = [];

			cap_details[row.access_id].push(row.capability);
		});
	}
	catch(error)
	{
		return END_ERROR (res, 500, "Internal error!", error);
	}

	const result = rules.map (rule => {

		const filter_item = item_details.filter (item =>
			item.access_item_type === rule.access_item_type &&
				item.access_item_id === rule.access_item_id)[0] || null;

		let response =  {
			id		: rule.id,
			email		: rule.email,
			role		: rule.role,
			item_type 	: rule.access_item_type,
			item 		: null,
			policy 		: rule.policy_text,
			created		: rule.created_at,
			capabilities	: cap_details[rule.id] || null
		};

		if (filter_item !== null)
		{
			response.item = {
				cat_id : filter_item.cat_id
			};
		}

		return response;
	});

	return END_SUCCESS (res, result);
});

app.delete("/auth/v[1-2]/provider/access", async (req, res) => {

	const provider_email = res.locals.email;

	let provider_uid;
	let rules_array = [];
	let to_delete = [];

	try { provider_uid = await check_privilege(provider_email, "provider"); }
	catch(error) { return END_ERROR (res, 401, "Not allowed!"); }

	const email_domain	= provider_email.split("@")[1];
	const sha1_of_email	= sha1(provider_email);
	const provider_id_hash	= email_domain + "/" + sha1_of_email;

	if (! Array.isArray(res.locals.body))
		return END_ERROR (res, 400, "Invalid data (body)");

	for (const obj of res.locals.body)
	{
		let id = obj.id;
		let capability = obj.capabilities || null;
		let delete_rule = false;
		let role_id, access_item_id, access_item_type;

		id = parseInt(id, 10);

		if (isNaN(id) || id < 1 || id > PG_MAX_INT)
		{
			let err = {
				message   : "Invalid data (id)",
				access_id : id
			};

			return END_ERROR (res, 400, err);
		}

		try {
			const check = await pool.query (
				"SELECT access.*, capability FROM consent.access" 	+
				" LEFT JOIN consent.capability ON access_id = " 	+
				" access.id WHERE access.id = $1::integer"		+
				" AND provider_id = $2::integer",
				[ id, provider_uid ]);

			if (check.rows.length === 0)
			{
				let err = {
					message   : "Invalid id",
					access_id : id
				};

				return END_ERROR (res, 403, err);
			}

			role_id 	 = check.rows[0].role_id;
			access_item_id 	 = check.rows[0].access_item_id;
			access_item_type = check.rows[0].access_item_type;

			let existing_caps = [...new Set(check.rows.map(row => row.capability))];

			/* remove nulls */
			existing_caps = existing_caps.filter(val => val !== null);

			/* if there are caps, must be a consumer rule
			 * if capability field not there, treat as normal
			 * rule and delete fully */

			if (existing_caps.length > 0 && capability)
			{
				if (! Array.isArray(capability) ||
					capability.length > Object.keys(CAPABILITIES).length ||
					capability.length === 0)
				{
					let err = {
						message   : "Invalid data (capability)",
						access_id : id
					};

					return END_ERROR (res, 400, err);
				}

				capability = [...new Set(capability)];

				if (! capability.every( (val) => Object.keys(CAPABILITIES).includes(val)))
				{
					let err = {
						message   : "Invalid data (capability)",
						access_id : id
					};

					return END_ERROR (res, 400, err);
				}

				/* should be something common between requested and existing */
				let matching = intersect(existing_caps, capability);

				if (matching.length !== capability.length)
				{
					let err = {
						message   : "Invalid id",
						access_id : id
					};

					return END_ERROR (res, 403, err);
				}

				/* if deleting all existing capabilities - delete rule itself */
				if (matching.length === existing_caps.length)
					delete_rule = true;
			}
			else
				delete_rule = true;
		}
		catch(error)
		{
			return END_ERROR (res, 500, "Internal error!", error);
		}

		for (const i of to_delete)
		{
			if (i.id === id)
			{
				if (! i.capability)
				{
					let err = {
						message   : "Duplicate data",
						access_id : id
					};

					return END_ERROR (res, 400, err);
				}
				else /* check if ids same, but diff in caps to be deleted */
				{
					let duplicate = intersect(capability, i.capability);

					if (duplicate.length !== 0)
					{
						let err = {
							message   : "Duplicate data",
							access_id : id
						};

						return END_ERROR (res, 400, err);
					}
				}
			}
		}

		to_delete.push({
			id : id,
			capability : capability,
			delete_rule: delete_rule,
			role_id: role_id,
			access_item_id:access_item_id,
			access_item_type:access_item_type
		});
	}

	if (to_delete.length === 0)
		return END_ERROR (res, 500, "Internal error!");

	for (const obj of to_delete)
	{
		const {id, capability, delete_rule, role_id} = obj;
		const {access_item_id, access_item_type} = obj;

		if (delete_rule === true)
		{
			try {
				const result = await pool.query(
					" DELETE FROM consent.access" +
					" WHERE id = $1::integer",
					[ id ]);

				if (result.rowCount === 0)
					throw new Error("Error in deletion");
			}
			catch(error)
			{
				return END_ERROR (res, 500, "Internal error!", error);
			}
		}
		else
		{
			try {
				const result = await pool.query(
					" DELETE FROM consent.capability" 	+
					" WHERE access_id = $1::integer"	+
					" AND capability = ANY ($2::consent.capability_enum[])",
					[ id, capability ]);

				if (result.rowCount === 0)
					throw new Error("Error in deletion");

				const check = await pool.query(
					"SELECT capability FROM consent.capability"	+
					" WHERE access_id = $1::integer",
					[ id ]);

				let existing_caps = [...new Set(check.rows.map(row => row.capability))];

				if (existing_caps.length === 0)
				{/* delete rule itself, since no caps are there */
					const result = await pool.query(
						" DELETE FROM consent.access" +
						" WHERE id = $1::integer",
						[ id ]);

					if (result.rowCount === 0)
						throw new Error("Error in deletion");
				}
				else
				{/* rewrite policy text */
					const email = await pool.query (
						"SELECT email FROM consent.users"		+
						" JOIN consent.role ON user_id = users.id"	+
						" WHERE role.id = $1::integer",
						[ role_id ]);

					const resource = await pool.query (
						"SELECT * FROM consent." + access_item_type +
						" WHERE id = $1::integer",
						[ access_item_id ]);

					let resource_id = resource.rows[0].cat_id;
					let resource_name = resource_id.replace(provider_id_hash + "/", "");
					let accesser_email = email.rows[0].email;

					let policy_text = create_consumer_policy_text(
								accesser_email,
								resource_id,
								resource_name,
								existing_caps);

					const access = await pool.query (
						"UPDATE consent.access SET policy_text = $1::text,"	+
						" updated_at = NOW() WHERE access.id = $2::integer"	+
						" RETURNING id",
						[ policy_text, id ]);
				}
			}
			catch(error)
			{
				return END_ERROR (res, 500, "Internal error!", error);
			}
		}
	}

	try {
		const rules = await pool.query (
			"SELECT policy_text FROM consent.access,"	+
			" consent.role WHERE provider_id = $1::integer"	+
			" AND role.id = access.role_id ORDER BY role",
			[ provider_uid ]);

		rules_array = rules.rows.map(
				(row) => { return row.policy_text; });
	}
	catch(error)
	{
		return END_ERROR (res, 500, "Internal error!", error);
	}

	set_acl(provider_email, rules_array, (err) =>
	{
		if (err)
			return END_ERROR (res, err.http_code, err.message);
		else
			return END_SUCCESS (res);
	});
});

/* --- Auth Admin APIs --- */

app.get("/auth/v[1-2]/admin/provider/registrations", (req, res) => {
	const email = res.locals.email;
	if (!admin_list.includes(email)) {
		return END_ERROR (res, 403, "Not allowed");
	}
	const filter = req.query.filter || "pending";
	let users, organizations;
	try {
		users = pg.querySync("SELECT * FROM consent.users, consent.role" 		+
				     " WHERE consent.users.id = consent.role.user_id "		+
				     " AND status = $1::consent.status_enum", [filter]);
		let organization_ids = [...new Set(users.map(row => row.organization_id))];
		let params = organization_ids.map((_, i) => '$' + (i + 1)).join(',');
		organizations = pg.querySync("SELECT * FROM consent.organizations WHERE id IN (" + params + ");", organization_ids);
	} catch(e) {
		return END_ERROR (res, 400, "Invalid filter value");
	}
	const result = users.map(user => {
		const organization = organizations.filter(org => user.organization_id === org.id)[0] || null;
		const res = {
			id: user.user_id,
			title: user.title,
			first_name: user.first_name,
			last_name: user.last_name,
			role: user.role,
			email: user.email,
			phone: user.phone,
			status: user.status,
		};
		if (organization === null) {
			res.organization = null;
		} else {
			res.organization = {
				name: organization.name,
				website: organization.website,
				city: organization.city,
				state: organization.state,
				country: organization.country
			};
		}
		return res;
	});
	return END_SUCCESS (res, result);
});

app.put("/auth/v[1-2]/admin/provider/registrations/status", (req, res) => {
	const email = res.locals.email;
	if (!admin_list.includes(email)) { return END_ERROR (res, 403, "Not allowed"); }
	const user_id = req.query.user_id || null;
	const status = req.query.status || null;
	if (user_id === null || status === null || !(["approved", "rejected"].includes(status))) {
		return END_ERROR (res, 400, "Missing or invalid information");
	}
	let user, csr, org, role;
	try {
		user = pg.querySync("SELECT users.*, role.role, role.status FROM consent.users, consent.role "	+
				    " WHERE consent.users.id = consent.role.user_id AND role.role = 'provider'"	+
				    " AND consent.users.id = $1::integer",[user_id])[0] || null;
		csr = pg.querySync("SELECT * FROM consent.certificates WHERE user_id = $1::integer", [user_id])[0] || null;
		org = pg.querySync("SELECT * FROM consent.organizations WHERE id = $1::integer", [user.organization_id])[0] || null;
		if (user === null || csr === null) { return END_ERROR(res, 404, "User information not found"); }
		if (user.status !== "pending") { return END_ERROR (res, 400, "User registration flow is complete"); }
	} catch (e) {
		return END_ERROR (res, 400, "Missing or invalid information");
	}

	if (status === "rejected") {
		// Update role table with status = rejected and return updated user
		role = pg.querySync("UPDATE consent.role SET status = $1::consent.status_enum, updated_at = NOW() "	+
			" WHERE user_id = $2::integer RETURNING *", [status, user.id])[0];

		const details	=
			{
				"id"  		: user.id,
				"organization" 	: org.name,
			};

		log("info", "PROVIDER_REJECTED", false, details);

		return END_SUCCESS(res, {
			id: user.id,
			title: user.title,
			first_name: user.first_name,
			last_name: user.last_name,
			role: role.role,
			email: user.email,
			phone: user.phone,
			status: role.status,
		});
	}

	let signed_cert;
	try {
		signed_cert = sign_csr(csr.csr, user);
		if (signed_cert === null) { throw "Unable to generate certificate"; }
	} catch (e) {
		return END_ERROR(res, 500, "Certificate Error", e.message);
	}

	// Update role table with status = approved
	// Update certificates table with cert = signed_cert
	role = pg.querySync("UPDATE consent.role SET status = $1::consent.status_enum, "    +
			    " updated_at = NOW() WHERE user_id = $2::integer RETURNING * ",
			     [status, user_id])[0];
	pg.querySync("UPDATE consent.certificates SET cert = $1::text, updated_at = NOW() " +
		     " WHERE user_id = $2::integer", [signed_cert, user_id]);
	user = pg.querySync("SELECT * FROM consent.users WHERE id = $1::integer",[user_id])[0];

	// Send email to user with cert attached and return updated user
	const message = {
		from: '"IUDX Admin" <noreply@iudx.org.in>',
		to: user.email,
		subject: "New Provider Registration",
		text: "Congratulations! Your IUDX Provider Registration is complete.\n\n" +
			"Please use the attached cert.pem file for all future API calls and to login at the Provider Dashboard.\n\n" +
			"Thank You!",
		attachments: [{ filename: "cert.pem", content: signed_cert }],
	};
	transporter.sendMail(message, function (error, info) {
		if (error)
			log("err", "MAILER_EVENT", true, {}, error.toString());
		else
			log("info", "MAIL_SENT", false, info);
	});

	const details	=
		{
			"id"  		: user.id,
			"organization" 	: org.name,
		};

	log("info", "PROVIDER_APPROVED", false, details);

	return END_SUCCESS (res, {
		id: user.id,
		title: user.title,
		first_name: user.first_name,
		last_name: user.last_name,
		role: role.role,
		email: user.email,
		phone: user.phone,
		status: role.status,
	});
});

app.post("/auth/v[1-2]/admin/organizations", async (req, res) => {
	const email = res.locals.email;
	if (!admin_list.includes(email)) {
		return END_ERROR (res, 403, "Not allowed");
	}
	const org = res.locals.body.organization;
	let real_domain;
	if (!org || !org.name || !org.website || !org.city || !org.state || !org.country)
		return END_ERROR (res, 400, "Invalid data (organization)");
	if ( org.state.length !== 2 || org.country.length !== 2)
		return END_ERROR (res, 400, "Invalid data (organization)");
	if ((real_domain = domain.get(org.website)) === null)
		return END_ERROR (res, 400, "Invalid data (organization)");

	const existing_orgs = await pool.query ("SELECT id FROM consent.organizations WHERE website = $1::text", [real_domain]);
	if (existing_orgs.rows.length !== 0)
		return END_ERROR (res, 403, `Invalid data (organization already exists, id: ${existing_orgs.rows[0].id})`);

	const new_org = await pool.query (
		"INSERT INTO consent.organizations (name, website, city, state, country, created_at, updated_at) " +
		"VALUES ($1::text,  $2::text, $3::text, $4::text, $5::text, NOW(), NOW()) " +
		"RETURNING id, name, website, city, state, country, created_at",
		[
			org.name,				//$1
			real_domain,				//$2
			org.city,				//$3
			org.state.toUpperCase(),		//$4
			org.country.toUpperCase()		//$5
		]
	);

	const details	=
		{
			"name"  	: org.name,
		};

	log("info", "ORG_CREATED", false, details);

	return END_SUCCESS(res, { organizations: new_org.rows });
});

/* --- Consent APIs --- */

app.post("/consent/v[1-2]/provider/registration", async (req, res) => {

	let email	= res.locals.body.email;
	const phone 	= res.locals.body.phone;
	let org_id 	= res.locals.body.organization;
	const name 	= res.locals.body.name;
	const raw_csr	= res.locals.body.csr;
	let  user_id;

	const phone_regex = new RegExp(/^[9876]\d{9}$/);

	if (! name || ! name.title || ! name.firstName || ! name.lastName)
		return END_ERROR (res, 400, "Invalid data (name)");

	if (! raw_csr || raw_csr.length > CSR_SIZE)
		return END_ERROR (res, 400, "Invalid data (csr)");

	if (! is_valid_email(email))
		return END_ERROR (res, 400, "Invalid data (email)");

	email = email.toLowerCase();

	if (! phone_regex.test(phone))
		return END_ERROR (res, 400, "Invalid data (phone)");

	if (! org_id)
		return END_ERROR (res, 400, "Invalid data (organization)");

	org_id = parseInt(org_id, 10);

	if (isNaN(org_id) || org_id < 1 || org_id > PG_MAX_INT)
		return END_ERROR (res, 400, "Invalid data (organization)");

	try
	{
		let csr = forge.pki.certificationRequestFromPem(raw_csr);
		csr.verify();
	}
	catch(error)
	{
		return END_ERROR (res, 400, "Invalid data (csr)");
	}

	try
	{
		const exists = await pool.query (
			" SELECT * FROM consent.users " 	+
			" WHERE email = $1::text",
			[ email ]);

		if (exists.rows.length !== 0)
			return END_ERROR (res, 403, "Email exists");

		const org_reg = await pool.query (
			" SELECT * FROM consent.organizations " +
			" WHERE id = $1::integer",
			[ org_id ]);

		if (org_reg.rows.length === 0)
			return END_ERROR (res, 403, "Invalid organization");
	}
	catch(error)
	{
		return END_ERROR (res, 500, "Internal error!", error);
	}

	try {
		const user = await pool.query (
			" INSERT INTO consent.users "			+
			" (title, first_name, last_name, "		+
			" email, phone, organization_id,  "		+
			" created_at ,updated_at) VALUES ( "		+
			" $1::text, $2::text, $3::text, "		+
			" $4::text, $5::text, $6::int, NOW(), NOW() )"	+
			" RETURNING id",
			[
				name.title,			//$1
				name.firstName,			//$2
				name.lastName,			//$3
				email,				//$4
				phone,				//$5
				org_id,				//$6
			]);

		user_id = user.rows[0].id;

		const role = await pool.query (
			" INSERT INTO consent.role "			+
			" (user_id, role, status, created_at, "		+
			" updated_at) VALUES ( "			+
			" $1::int, $2::consent.role_enum, "		+
			" $3::consent.status_enum, NOW(), NOW() )",
			[
				user_id,			//$1
				'provider',			//$2
				'pending',			//$3
			]);

		const cert = await pool.query (
			" INSERT INTO consent.certificates "	+
			" (user_id, csr, cert, created_at, "	+
			" updated_at) VALUES ( "		+
			" $1::int, $2::text, $3::text, "	+
			" NOW(), NOW() )",
			[
				user_id,			//$1
				raw_csr,			//$2
				null,				//$3
			]);
	}
	catch(error)
	{
		return END_ERROR (res, 500, "Internal error!", error);
	}

	const mail = {
		from: '"IUDX Admin" <noreply@iudx.org.in>',
		to	: email,
		subject	: "Provider Registration Successful !!!",
		text	: " Hello " + name.firstName + ". Your"		+
			  " provider registration request has been" 	+
			  " accepted, and is pending approval. "
	};

	transporter.sendMail(mail, function (error, info) {
		if (error)
			log("err", "MAILER_EVENT", true, {}, error.toString());
		else
			log("info", "MAIL_SENT", false, info);
	});

	const details	=
		{
			"email"  	: email,
			"org_id"	: org_id
		};

	log("info", "PROVIDER_REGISTERED", false, details);

	return END_SUCCESS (res);
});

app.post("/consent/v[1-2]/registration", async (req, res) => {

	let email	= res.locals.body.email;
	let phone 	= res.locals.body.phone;
	const name 	= res.locals.body.name;
	let raw_csr	= res.locals.body.csr;
	let org_id 	= res.locals.body.organization;
	let roles	= res.locals.body.roles;

	let user_id, signed_cert = null;
	let check_orgid = false;
	let existing_user = false;
	let message;

	const phone_regex = new RegExp(/^[9876]\d{9}$/);

	if (! name || ! name.title || ! name.firstName || ! name.lastName)
		return END_ERROR (res, 400, "Invalid data (name)");

	if (! is_valid_email(email))
		return END_ERROR (res, 400, "Invalid data (email)");

	email = email.toLowerCase();

	if (phone && (! phone_regex.test(phone)))
		return END_ERROR (res, 400, "Invalid data (phone)");

	if (! phone)
		phone = "0000000000";	    // phone has not null constraint

	if (! Array.isArray(roles) || roles.length > ACCESS_ROLES.length || roles.length === 0)
		return END_ERROR (res, 400, "Invalid data (roles)");

	// get unique elements
	roles = [...new Set(roles)];

	if (! roles.every( (val) => ACCESS_ROLES.includes(val)))
		return END_ERROR (res, 400, "Invalid data (roles)");

	if (roles.includes("onboarder") || roles.includes("data ingester"))
	{
		let domain;

		if (! org_id)
			return END_ERROR (res, 400, "Invalid data (organization)");

		org_id = parseInt(org_id, 10);

		if (isNaN(org_id) || org_id < 1 || org_id > PG_MAX_INT)
			return END_ERROR (res, 400, "Invalid data (organization)");

		// check if org registered
		try {
			const results = await pool.query (
				" SELECT * FROM consent.organizations " +
				" WHERE id = $1::integer",
				[ org_id ]);

			if (results.rows.length === 0)
				return END_ERROR (res, 403, "Invalid organization");

			domain = results.rows[0].website;
		}
		catch(error)
		{
			return END_ERROR (res, 500, "Internal error!", error);
		}

		let email_domain = email.split('@')[1];

		// check if org domain matches email domain
		if (email_domain !== domain)
			return END_ERROR (res, 403, "Invalid data (domains do not match)");
	}
	else
		org_id = null; // in the case of consumer

	try { // check if the user exists

		const check_uid = await pool.query (
			" SELECT * FROM consent.users" 		+
			" WHERE consent.users.email = $1::text ",
			[ email ]);

		if (check_uid.rows.length !== 0)
		{
			existing_user = true;
			user_id = check_uid.rows[0].id;

			/* if registered as consumer first, org_id will be undefined */
			check_orgid = check_uid.rows[0].organization_id;

			/* check if user has registered as provider before
			 * If yes, do not allow creation of new roles for that user */
			const check = await pool.query (
				"SELECT * FROM consent.role"		+
				" WHERE role.user_id = $1::integer"	+
				" AND role = 'provider'",
				[ user_id ]);

			if (check.rows.length !== 0)
				return END_ERROR (res, 403, "Email exists");

			/* check if user is trying to register for role
			 * that they are already registered for */
			for (const val of roles)
			{
				let uid = null;

				try { uid = await check_privilege(email, val); }
				catch(error) { /* do nothing if role not there */ }

				if (uid !== null)
					return END_ERROR (res, 403, "Already registered as " + val);
			}

			message = "Since you have registered before, please continue " +
				  "to use the certificate that was sent before.";
		}
	}
	catch(error)
	{
		return END_ERROR (res, 500, "Internal error!", error);
	}

	if (! existing_user)	// generate certificate
	{
		if (! raw_csr || raw_csr.length > CSR_SIZE)
			return END_ERROR (res, 400, "Invalid data (csr)");

		try
		{
			let csr = forge.pki.certificationRequestFromPem(raw_csr);
			csr.verify();
		}
		catch(error)
		{
			return END_ERROR (res, 400, "Invalid data (csr)");
		}

		let user_details = { email : email };

		try {
			signed_cert = sign_csr(raw_csr, user_details);
			if (signed_cert === null) { throw "Unable to generate certificate"; }
		} catch (e) {
			return END_ERROR(res, 500, "Certificate Error", e.message);
		}

		try {
			const user = await pool.query (
				" INSERT INTO consent.users "			+
				" (title, first_name, last_name, "		+
				" email, phone, organization_id,  "		+
				" created_at ,updated_at) VALUES ( "		+
				" $1::text, $2::text, $3::text, "		+
				" $4::text, $5::text, $6::int, NOW(), NOW() )"	+
				" RETURNING id",
				[
					name.title,			//$1
					name.firstName,			//$2
					name.lastName,			//$3
					email,				//$4
					phone,				//$5
					org_id,				//$6
				]);

			user_id = user.rows[0].id;

			const cert = await pool.query (
				" INSERT INTO consent.certificates "	+
				" (user_id, csr, cert, created_at, "	+
				" updated_at) VALUES ( "		+
				" $1::int, $2::text, $3::text, "	+
				" NOW(), NOW() )",
				[
					user_id,			//$1
					raw_csr,			//$2
					signed_cert,			//$3
				]);
		}
		catch(error)
		{
			return END_ERROR (res, 500, "Internal error!", error);
		}

		message = "A certificate has been generated and sent to your email";
	}

	/* update org_id if the user was originally a consumer
	 * (org_id would be null) */
	if (check_orgid === undefined)
	{
		try
		{
			const update = await pool.query (
				"UPDATE consent.users SET"		+
				" organization_id = $1::integer"	+
				" WHERE email = $2::text",
				[
					org_id,
					email
				]);
		}
		catch(error)
		{
			return END_ERROR (res, 500, "Internal error!", error);
		}
	}

	// insert roles
	for (const val of roles)
	{
		try {
			const role = await pool.query (
				" INSERT INTO consent.role "			+
				" (user_id, role, status, created_at, "		+
				" updated_at) VALUES ( "			+
				" $1::int, $2::consent.role_enum, "		+
				" $3::consent.status_enum, NOW(), NOW() )",
				[
					user_id,			//$1
					val,				//$2
					'approved',			//$3
				]);
		}
		catch(error)
		{
			return END_ERROR (res, 500, "Internal error!", error);
		}
	}

	if (signed_cert !== null)
	{
		const mail = {
			from: '"IUDX Admin" <noreply@iudx.org.in>',
			to: email,
			subject: "New " + roles.toString() + " Registration",
			text: "Congratulations! Your IUDX " + roles.toString() +
			" Registration is complete.\n\n" +
			"Please use the attached cert.pem file for all future API calls.\n\n" +
			"Thank You!",
			attachments: [{ filename: "cert.pem", content: signed_cert }],
		};

		transporter.sendMail(mail, function (error, info) {
			if (error)
				log("err", "MAILER_EVENT", true, {}, error.toString());
			else
				log("info", "MAIL_SENT", false, info);
		});
	}

	const response = {success : true, message : message};

	const details	=
		{
			"id"  	: email,
			"roles"	: roles,
			"org_id": org_id
		};

	log("info", "USER_REGISTERED", false, details);

	return END_SUCCESS (res, response);
});

app.get("/consent/v[1-2]/organizations", async (req, res) => {
	let { rows } = await pool.query("SELECT id, name FROM consent.organizations");
	return END_SUCCESS(res, { organizations: rows });
});

/* --- Invalid requests --- */

app.all("/*", (req, res) => {

	const doc = " Please visit <https://authdocs.iudx.org.in> for documentation";

	if (req.method === "POST")
	{
		return END_ERROR (res, 404, "No such API." + doc );
	}
	else if (req.method === "GET")
	{
		return END_ERROR (res, 404, "No such API." + doc );
	}
	else
	{
		return END_ERROR (res, 405, "Method must be POST, PUT or GET" + doc);
	}
});

app.on("error", () => {
	/* nothing */
});

/* --- The main application --- */

if (! is_openbsd)
{
	// ======================== START preload code for chroot =============

	const _tmp = ["x can y z"].map (
		(r) => {
			return (parser.parse(r.trim()));
		}
	);

	evaluator.evaluate(_tmp, {});

	dns.lookup("google.com", {all:true},
		(error) => {
			if (error)
				log("err", "EVENT", false, {},
					"DNS to google.com failed ");
		}
	);

	// ======================== END preload code for chroot ===============
}

function drop_worker_privileges()
{
	for (const k in password)
	{
		password[k] = null;
		delete password[k];	// forget all passwords
	}

	if (is_openbsd)
	{
		if (EUID === 0)
		{
			process.setgid("_aaa");
			process.setuid("_aaa");
		}

		unveil("/usr/lib",			"r" );
		unveil("/usr/libexec/ld.so",		"r" );
		unveil(__dirname + "/node_modules",	"r" );
		unveil(__dirname + "/node-aperture",	"r" );

		unveil();
	}
	else
	{
		if (EUID === 0)
		{
			process.setgid("_aaa");
			chroot("/home/iudx-auth-server","_aaa");
			process.chdir ("/");
		}
	}

	if (is_openbsd)
		pledge.init ("error stdio tty prot_exec inet rpath dns recvfd");

	assert (has_started_serving_apis === false);
}

if (cluster.isMaster)
{
	if (is_openbsd)
	{
		unveil("/usr/local/bin/node",	"x");
		unveil("/usr/lib",		"r");
		unveil("/usr/libexec/ld.so",	"r");

		unveil();

		pledge.init (
			"error stdio tty prot_exec inet rpath dns recvfd " +
			"sendfd exec proc"
		);
	}

	log("info", "EVENT", false, {}, "Master started with pid " + process.pid);

	for (let i = 0; i < NUM_CPUS; i++) {
		cluster.fork();
	}

	cluster.on ("exit", (worker) => {

		log("err", "WORKER_EVENT", true, {},"Worker " + worker.process.pid + " died.");

		cluster.fork();
	});

	if (is_openbsd) // drop "rpath"
	{
		pledge.init (
			"error stdio tty prot_exec inet dns recvfd " +
			"sendfd exec proc"
		);
	}

}
else
{
	http.createServer(app).listen(3000, "0.0.0.0");

	drop_worker_privileges();

	log("info", "WORKER_EVENT", false, {},"Worker started with pid " + process.pid);

}

// EOF
