/* vim: set ts=1 sw=1 tw=0 noet : */

"use strict";

const fs = require("fs");
const os = require("os");
const cors = require("cors");
const x509 = require("x509");
const Pool = require("pg").Pool;
const http = require("http");
const assert = require("assert").strict;
const forge = require("node-forge");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const cluster = require("cluster");
const express = require("express");
const { v4: uuidv4 } = require("uuid");
const timeout = require("connect-timeout");
const domain = require("getdomain");
const nodemailer = require("nodemailer");
const bodyParser = require("body-parser");
const http_request = require("request");
const pgNativeClient = require("pg-native");
const { DateTime, Settings } = require("luxon");

Settings.defaultZoneName = "utc";

const pg = new pgNativeClient();

const TOKEN_LEN = 16;
const TOKEN_LEN_HEX = 2 * TOKEN_LEN;
const CSR_SIZE = 2048;

const EUID = process.geteuid();

const NUM_CPUS = os.cpus().length;
const SERVER_NAME = "auth.iudx.org.in";
const CONSENT_URL = "cons.iudx.org.in";

const MAX_TOKEN_TIME = 31536000; // in seconds (1 year)
const TOKEN_TIME_SEC = 604800;
const BCRYPT_SALT_ROUNDS = 11;

const MIN_TOKEN_HASH_LEN = 64;
const MAX_TOKEN_HASH_LEN = 64;

const MAX_SAFE_STRING_LEN = 512;
const PG_MAX_INT = 2147483647;
const PHONE_PLACEHOLDER = "0000000000";

/* for access API */
const ACCESS_ROLES = ["consumer", "data ingester", "onboarder", "delegate"];
const RESOURCE_ITEM_TYPES = ["resourcegroup"];
const CAT_URL = "catalogue.iudx.io";
const CAT_RESOURCE = `${CAT_URL}/catalogue/crud`;
const CAPS = JSON.parse(fs.readFileSync("capabilities.json", "utf-8"));

const MIN_CERT_CLASS_REQUIRED = Object.freeze({
  /* resource server API */
  "/auth/v1/token/introspect": 1,
  "/auth/v1/certificate-info": 1,

  /* data consumer's APIs */
  "/auth/v1/token": -Infinity,
  "/auth/v1/consumer/resources": -Infinity,

  /* data provider's APIs */
  "/auth/v1/provider/access": -Infinity,
  "/auth/v1/get-session-id": -Infinity,

  "/auth/v1/delegate/providers": -Infinity,

  /* admin APIs */
  "/auth/v1/admin/provider/registrations": -Infinity,
  "/auth/v1/admin/provider/registrations/status": -Infinity,
  "/auth/v1/admin/organizations": -Infinity,
  "/auth/v1/admin/users": -Infinity,

  /* consent APIs */
  "/consent/v1/provider/registration": -Infinity,
  "/consent/v1/organizations": -Infinity,
  "/consent/v1/registration": -Infinity,
});

/* --- environment variables--- */

//process.env.TZ = "Asia/Kolkata";

/* --- telegram --- */

const TELEGRAM = "https://api.telegram.org";

const telegram_apikey = fs.readFileSync("telegram.apikey", "ascii").trim();
const telegram_chat_id = fs.readFileSync("telegram.chatid", "ascii").trim();
const root_cert = forge.pki.certificateFromPem(
  fs.readFileSync("passwords/cert.pem")
);
const root_key = forge.pki.privateKeyFromPem(
  fs.readFileSync("passwords/key.pem")
);

const telegram_url =
  TELEGRAM +
  "/bot" +
  telegram_apikey +
  "/sendMessage?chat_id=" +
  telegram_chat_id +
  "&text=";
/* --- nodemailer --- */

let transporter;

const mailer_config = JSON.parse(
  fs.readFileSync("mailer_config.json", "utf-8")
);
const mailer_options = {
  host: mailer_config.host,
  port: mailer_config.port,
  auth: {
    user: mailer_config.username,
    pass: mailer_config.password,
  },
  tls: { rejectUnauthorized: false },
};

transporter = nodemailer.createTransport(mailer_options);

transporter.verify(function (error, success) {
  if (error) log("err", "MAILER_EVENT", true, {}, error.toString());
  else log("info", "MAILER_EVENT", false, {}, success.toString());
});

//read 2fa config file for url and apikey
const sessionidConfig = JSON.parse(
  fs.readFileSync("2factor_config.json", "utf-8")
);
const twoFA_config = sessionidConfig.config;

const SECURED_ENDPOINTS = sessionidConfig.secured_endpoints;

const SESSIONID_EXP_TIME = twoFA_config.expiryTime;

/* --- postgres --- */
const DB_SERVER = "127.0.0.1";
const password = {
  DB: fs.readFileSync("passwords/auth.db.password", "ascii").trim(),
};

/* --- log file --- */

const log_file = fs.createWriteStream("/var/log/debug.log", { flags: "a" });

// async postgres connection
const pool = new Pool({
  host: DB_SERVER,
  port: 5432,
  user: "auth",
  database: "postgres",
  password: password.DB,
});

pool.connect();

// sync postgres connection
pg.connectSync(
  "postgresql://auth:" + password.DB + "@" + DB_SERVER + ":5432/postgres",
  (err) => {
    if (err) {
      throw err;
    }
  }
);

/* --- express --- */

const app = express();

app.disable("x-powered-by");

app.set("trust proxy", true);
app.use(timeout("5s"));
app.use(
  cors({
    credentials: true,
    methods: ["POST", "GET", "PUT", "DELETE"],
    origin: (origin, callback) => {
      callback(null, !!origin);
    },
  })
);

app.use(bodyParser.raw({ type: "*/*" }));

app.use(parse_cert_header);
app.use(basic_security_check);
app.use(log_conn);
app.use(sessionIdCheck);

/* --- functions --- */
function is_valid_token(token, user = null) {
  if (!is_string_safe(token, "_")) return false;

  const split = token.split("/");
  const hex_regex = new RegExp(/^[a-f0-9]+$/);
  const uuid_regex = new RegExp(
    /^[0-9a-f]{8}\b-[0-9a-f]{4}\b-[0-9a-f]{4}\b-[0-9a-f]{4}\b-[0-9a-f]{12}$/
  );
  if (split.length !== 4) return false;

  const issued_by = split[0];
  const issued_to = split[1];
  const random_hex = split[2];
  const uuid = split[3];

  if (issued_by !== SERVER_NAME) return false;

  if (random_hex.length !== TOKEN_LEN_HEX || !hex_regex.test(random_hex))
    return false;

  if (user && user !== issued_to) return false; // token was not issued to this user

  if (!uuid_regex.test(uuid)) return false;

  if (!is_valid_email(issued_to)) return false;

  return true;
}

function is_valid_tokenhash(token_hash) {
  if (!is_string_safe(token_hash)) return false;

  if (token_hash.length < MIN_TOKEN_HASH_LEN) return false;

  if (token_hash.length > MAX_TOKEN_HASH_LEN) return false;

  const hex_regex = new RegExp(/^[a-f0-9]+$/);

  if (!hex_regex.test(token_hash)) return false;

  return true;
}

function is_valid_servertoken(server_token, hostname) {
  if (!is_string_safe(server_token)) return false;

  const split = server_token.split("/");

  if (split.length !== 2) return false;

  const issued_to = split[0];
  const random_hex = split[1];

  if (issued_to !== hostname) return false;

  if (random_hex.length !== TOKEN_LEN_HEX) return false;

  return true;
}

function sha1(string) {
  return crypto.createHash("sha1").update(string).digest("hex");
}

function send_telegram(message) {
  http_request(
    telegram_url + "[ AUTH ] : " + message,
    (error, response, body) => {
      if (error) {
        log(
          "warn",
          "EVENT",
          true,
          {},
          "Telegram failed ! response = " +
            String(response) +
            " body = " +
            String(body)
        );
      }
    }
  );
}

function log(level, type, notify, details, message = null) {
  //const message = new Date() + " | " + msg;
  const log_msg = {
    level: level,
    type: type,
    notify: notify,
    details: details,
  };

  if (message !== null) log_msg.message = message;

  if (level === "err") send_telegram(message);

  let output = JSON.stringify(log_msg);

  log_file.write(output + "\n");
}

function END_SUCCESS(res, response = null) {
  // if no response is given, just send success

  if (!response) response = { success: true };

  res.setHeader("Content-Security-Policy", "default-src 'none'");
  res.setHeader("Content-Type", "application/json");

  res.status(200).end(JSON.stringify(response) + "\n");
}

function END_ERROR(res, http_status, error, exception = null) {
  if (exception)
    log("err", "END_ERROR", true, {}, String(exception).replace(/\n/g, " "));

  res.setHeader("Content-Security-Policy", "default-src 'none'");
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Connection", "close");

  const response = {};
  console.log(exception);

  if (typeof error === "string") response.error = { message: error };
  else {
    // error is already a JSON

    if (error["invalid-input"]) {
      response["//"] =
        "Unsafe characters (if any) in" +
        " 'invalid-input' field have been" +
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

function is_valid_email(email) {
  if (!email || typeof email !== "string") return false;

  if (email.length < 5 || email.length > 64) return false;

  // reject email ids starting with invalid chars
  const invalid_start_chars = ".-_@";

  if (invalid_start_chars.indexOf(email[0]) !== -1) return false;

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

  if (split.length !== 2) return false;

  const user = split[0]; // the login

  if (user.length === 0 || user.length > 30) return false;

  let num_dots = 0;

  for (const chr of email) {
    if (
      (chr >= "a" && chr <= "z") ||
      (chr >= "A" && chr <= "Z") ||
      (chr >= "0" && chr <= "9")
    ) {
      // ok;
    } else {
      switch (chr) {
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

function is_certificate_ok(req, cert, validate_email) {
  if (!cert || !cert.subject) return "No subject found in the certificate";

  if (!cert.subject.CN) return "No CN found in the certificate";

  if (validate_email) {
    if (!is_valid_email(cert.subject.emailAddress))
      return "Invalid 'emailAddress' field in the certificate";

    if (!cert.issuer || !cert.issuer.emailAddress)
      return "Certificate issuer has no 'emailAddress' field";

    const issuer_email = cert.issuer.emailAddress.toLowerCase();

    if (!is_valid_email(issuer_email))
      return "Certificate issuer's emailAddress is invalid";

    if (issuer_email.startsWith("iudx.sub.ca@")) {
      const issued_to_domain = cert.subject.emailAddress
        .toLowerCase()
        .split("@")[1];

      const issuer_domain = issuer_email.toLowerCase().split("@")[1];

      if (issuer_domain !== issued_to_domain) {
        // TODO
        // As this could be a fraud commited by a sub-CA
        // maybe revoke the sub-CA certificate

        log(
          "err",
          "ERROR",
          false,
          {},
          "Invalid certificate: issuer = " +
            issuer_domain +
            " and issued to = " +
            cert.subject.emailAddress
        );

        return "Invalid certificate issuer";
      }
    }
  }

  return "OK";
}

function is_secure(req, res, cert, validate_email = true) {
  res.header("Referrer-Policy", "no-referrer-when-downgrade");
  res.header("X-Frame-Options", "deny");
  res.header("X-XSS-Protection", "1; mode=block");
  res.header("X-Content-Type-Options", "nosniff");

  /*
	if (req.headers.host && req.headers.host !== SERVER_NAME)
		return "Invalid 'host' field in the header";
	*/

  if (req.headers.origin) {
    const origin = req.headers.origin.toLowerCase();

    // e.g Origin = https://www.iudx.org.in:8443/

    if (!origin.startsWith("https://")) {
      // allow the server itself to host "http"
      if (origin !== "http://" + SERVER_NAME) return "Insecure 'origin' field";
    }

    if ((origin.match(/\//g) || []).length < 2) return "Invalid 'origin' field";

    const origin_domain = String(
      origin
        .split("/")[2] // remove protocol
        .split(":")[0] // remove port number
    );

    if (
      !origin_domain.endsWith(".iudx.org.in") &&
      !origin_domain.endsWith(".iudx.io")
    ) {
      return (
        "Invalid 'origin' header; this website is not" +
        " permitted to call this API"
      );
    }

    res.header("Access-Control-Allow-Origin", req.headers.origin);
    res.header("Access-Control-Allow-Methods", "POST, PUT, GET, DELETE");
  }

  const error = is_certificate_ok(req, cert, validate_email);

  if (error !== "OK") return "Invalid certificate : " + error;

  return "OK";
}

function has_certificate_been_revoked(socket, cert, CRL) {
  const cert_fingerprint = cert.fingerprint.replace(/:/g, "").toLowerCase();

  const cert_serial = cert.serialNumber.toLowerCase().replace(/^0+/, "");

  const cert_issuer = cert.issuer.emailAddress.toLowerCase();

  for (const c of CRL) {
    c.issuer = c.issuer.toLowerCase();
    c.serial = c.serial.toLowerCase().replace(/^0+/, "");
    c.fingerprint = c.fingerprint.toLowerCase().replace(/:/g, "");

    if (
      c.issuer === cert_issuer &&
      c.serial === cert_serial &&
      c.fingerprint === cert_fingerprint
    ) {
      return true;
    }
  }

  // If it was issued by a sub-CA then check the sub-CA's cert too
  // Assuming depth is <= 3. ca@iudx.org.in -> sub-CA -> user

  if (cert_issuer.startsWith("iudx.sub.ca@")) {
    const ISSUERS = [];

    if (cert.issuerCertificate) {
      // both CA and sub-CA are the issuers
      ISSUERS.push(cert.issuerCertificate);

      if (cert.issuerCertificate.issuerCertificate) {
        ISSUERS.push(cert.issuerCertificate.issuerCertificate);
      }
    } else {
      /*
	if the issuerCertificate is empty,
	then the session must have been reused
	by the browser.

	if (! socket.isSessionReused())
	  return true;
			*/
    }

    for (const issuer of ISSUERS) {
      if (issuer.fingerprint && issuer.serialNumber) {
        issuer.fingerprint = issuer.fingerprint.replace(/:/g, "").toLowerCase();

        issuer.serialNumber = issuer.serialNumber.toLowerCase();

        for (const c of CRL) {
          if (c.issuer === "ca@iudx.org.in") {
            const serial = c.serial.toLowerCase().replace(/^0+/, "");

            const fingerprint = c.fingerprint.replace(/:/g, "").toLowerCase();

            if (serial === issuer.serial && fingerprint === issuer.fingerprint)
              return true;
          }
        }
      } else {
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

function xss_safe(input) {
  if (typeof input === "string")
    return input.replace(/[^-a-zA-Z0-9:/.@_]/g, "*");
  else {
    // we can only change string variables

    return input;
  }
}

/* check if name is valid. Name can have ', spaces
 * and hyphens. function parameter title set to true
 * if testing a title */

function is_name_safe(str, title = false) {
  if (!str || typeof str !== "string") return false;

  if (str.length === 0 || str.length > MAX_SAFE_STRING_LEN) return false;

  const name_regex = new RegExp(/^[a-zA-Z]+(?:(?: |[' -])[a-zA-Z]+)*$/);
  const title_regex = new RegExp(/^[a-zA-Z]+\.?$/);

  if (!name_regex.test(str) && title === false) return false;

  if (!title_regex.test(str) && title === true) return false;

  return true;
}

function is_string_safe(str, exceptions = "") {
  if (!str || typeof str !== "string") return false;

  if (str.length === 0 || str.length > MAX_SAFE_STRING_LEN) return false;

  exceptions = exceptions + "-/.@";

  for (const ch of str) {
    if (
      (ch >= "a" && ch <= "z") ||
      (ch >= "A" && ch <= "Z") ||
      (ch >= "0" && ch <= "9")
    ) {
      // ok
    } else {
      if (exceptions.indexOf(ch) === -1) return false;
    }
  }

  return true;
}

function is_iudx_certificate(cert) {
  if (!cert.issuer.emailAddress) return false;

  const email = cert.issuer.emailAddress.toLowerCase();

  // certificate issuer should be IUDX CA or a IUDX sub-CA

  // for dev - ca@iudx.io
  return (
    email === "ca@iudx.org.in" ||
    email.startsWith("iudx.sub.ca@") ||
    email === "ca@iudx.io"
  );
}

function body_to_json(body) {
  if (!body) return {};

  let string_body;

  try {
    string_body = Buffer.from(body, "utf-8").toString("ascii").trim();

    if (string_body.length === 0) return {};
  } catch (x) {
    return {};
  }

  try {
    const json_body = JSON.parse(string_body);

    if (json_body) return json_body;
    else return {};
  } catch (x) {
    return null;
  }
}

//generate session id for 2factor auth

function generateSessionId(sessionIdLen) {
  let code = "";
  code += Number.parseInt(crypto.randomBytes(3).toString("hex"), 16);

  if (code.length >= sessionIdLen) return code.slice(0, sessionIdLen);

  return code.padStart(sessionIdLen, "0");
}

//Trigger 2fact sms service

function SMS_Service(sessionId, phNo, done) {
  let errorDetails;
  let url =
    twoFA_config.url + twoFA_config.apiKey + "/SMS/" + phNo + "/" + sessionId;
  var options = {
    method: "GET",
    url: url,
  };
  return new Promise((resolve, reject) => {
    http_request(options, function (error, response) {
      if (error) {
        reject(error);
      } else {
        if (response.statusCode !== 200) {
          reject(new Error(response.body));
        } else resolve(true);
      }
    });
  });
}

/* ---
  Check role/privilege of any registered user.
  If user has particular role, return user ID.
  Else return null.
		--- */

async function check_privilege(email, role) {
  try {
    const result = await pool.query(
      " SELECT * FROM consent.users, consent.role" +
        " WHERE consent.users.id = consent.role.user_id " +
        " AND consent.users.email = $1::text " +
        " AND role = $2::consent.role_enum" +
        " AND status = $3::consent.status_enum",
      [
        email, //$1
        role, //$2
        "approved", //$3
      ]
    );

    if (result.rows.length === 0) throw new Error("Invalid");

    return result.rows[0].user_id;
  } catch (error) {
    throw error;
  }
}

/* ---
  Check if rule exists/delegate is valid delegate
  for that provider. If true, return role ID.
  else throw error.
		--- */

async function check_valid_delegate(delegate_uid, provider_uid) {
  try {
    const result = await pool.query(
      " SELECT access.* FROM consent.access" +
        " JOIN consent.role ON " +
        " consent.access.role_id = consent.role.id " +
        " WHERE provider_id = $1::integer AND " +
        " role.user_id = $2::integer AND " +
        " access_item_type = $3::consent.access_item AND" +
        " access.expiry > NOW()" +
        " AND access.status = 'active'",
      [
        provider_uid, //$1
        delegate_uid, //$2
        "provider-caps", //$3
      ]
    );

    if (result.rows.length === 0) throw new Error("Invalid");

    return result.rows[0].role_id;
  } catch (error) {
    throw error;
  }
}

function intersect(array1, array2) {
  return array1.filter((val) => array2.includes(val));
}

/* validates array of resource IDs, takes optional
 * Set for resource server. Returns object with 'success'
 * boolean and either resource server or error object
 * in 'result' key.*/
function validate_resource_array(arr, resource_server_set = new Set()) {
  let response = { success: true };
  let resource_set = new Set();

  for (const resource of arr) {
    if (!is_string_safe(resource, "_") || resource.indexOf("..") >= 0) {
      response.result = {
        message: "resource ID contains unsafe characters",
        "invalid-input": xss_safe(resource),
      };
      response.success = false;
      return response;
    }

    if ((resource.match(/\//g) || []).length < 3) {
      response.result = {
        message: "resource must have at least 3 '/' characters.",
        "invalid-input": xss_safe(resource),
      };

      response.success = false;
      return response;
    }

    if (resource_set.has(resource)) {
      response.result = {
        message: "Duplicate resource",
        "invalid-input": xss_safe(resource),
      };

      response.success = false;
      return response;
    }

    const resource_server = resource.split("/")[2].toLowerCase();

    resource_server_set.add(resource_server);
    if (resource_server_set.size > 1) {
      response.result = {
        message: "All resources must belong to same resource server",
        "invalid-input": xss_safe(resource),
      };

      response.success = false;
      return response;
    }

    resource_set.add(resource);
  }

  response.success = true;
  response.result = [...resource_server_set][0];
  return response;
}

/* process_token_request takes an array of resources, array of
 * role IDs and returns
 * an object with keys resource_server, processed_request_array.
 * Else an error is thrown
 */

async function process_requested_resources(resource_array, role_ids) {
  const processed_request_array = [];
  let is_onboarder_request = false;

  for (let resource of resource_array) {
    let provider_id, item_id;

    const split = resource.split("/");

    const email_domain = split[0].toLowerCase();
    const sha1_of_email = split[1].toLowerCase();

    const provider_id_hash = email_domain + "/" + sha1_of_email;

    const resource_server = split[2].toLowerCase();
    const resource_name = split.slice(3).join("/");

    const resource_group_id =
      provider_id_hash + "/" + resource_server + "/" + split[3];

    if (resource_server === CAT_URL && resource_name === "catalogue/crud")
      is_onboarder_request = true;

    if (!is_onboarder_request) {
      try {
        const result = await pool.query(
          "SELECT id, provider_id FROM consent.resourcegroup " +
            " WHERE cat_id = $1::text",
          [resource_group_id]
        );

        if (result.rowCount === 0) {
          const error = new Error(
            "Invalid 'id'; no access" +
              " control policies have been" +
              " set for this 'id'" +
              " by the data provider"
          );
          error["invalid-input"] = xss_safe(resource);
          error.status_code = 403;
          throw error;
        }

        provider_id = result.rows[0].provider_id;
        item_id = result.rows[0].id;
      } catch (error) {
        throw error;
      }
    } else {
      item_id = -1;

      try {
        const result = await pool.query(
          "SELECT users.id, email" +
            " FROM consent.users, consent.organizations" +
            " WHERE organization_id = organizations.id" +
            " AND website = $1::text",
          [email_domain]
        );

        if (result.rowCount === 0) {
          const error = new Error(
            "Invalid 'id'; no access" +
              " control policies have been" +
              " set for this 'id'" +
              " by the data provider"
          );
          error["invalid-input"] = xss_safe(resource);
          error.status_code = 403;
          throw error;
        }

        for (const g of result.rows)
          if (sha1_of_email === sha1(g.email)) provider_id = g.id;

        if (provider_id === undefined) {
          const error = new Error(
            "Invalid 'id'; no access" +
              " control policies have been" +
              " set for this 'id'" +
              " by the data provider"
          );
          error["invalid-input"] = xss_safe(resource);
          error.status_code = 403;
          throw error;
        }
      } catch (error) {
        throw error;
      }
    }

    try {
      const result = await pool.query(
        "SELECT id FROM consent.access" +
          " WHERE provider_id = $1::integer" +
          " AND access_item_id = $2::integer" +
          " AND access_item_type = $3::consent.access_item" +
          " AND role_id = ANY ($4::integer[])" +
          " AND status = 'active' AND expiry > NOW()",
        [
          provider_id,
          item_id,
          item_id === -1 ? "catalogue" : "resourcegroup",
          role_ids,
        ]
      );

      if (result.rowCount === 0) {
        const error = new Error("Unauthorized");
        error["invalid-input"] = xss_safe(resource);
        error.status_code = 403;
        throw error;
      }

      for (let obj of result.rows) {
        processed_request_array.push({
          cat_id: resource,
          access_id: obj.id,
        });
      }
    } catch (error) {
      throw error;
    }
  }

  return {
    processed_request_array: processed_request_array,
  };
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

function change_cert_keys(obj) {
  const newkeys = {
    countryName: "C",
    stateOrProvinceName: "ST",
    localityName: "L",
    organizationName: "O",
    organizationalUnitName: "OU",
    commonName: "CN",
    givenName: "GN",
    surName: "SN",
  };

  let new_obj = {};

  for (let key in obj) new_obj[newkeys[key] || key] = obj[key];

  return new_obj;
}

function parse_cert_header(req, res, next) {
  let cert;

  if (req.headers.host === CONSENT_URL) return next();

  try {
    let raw_cert = decodeURIComponent(req.headers["x-forwarded-ssl"]);
    cert = x509.parseCert(raw_cert);
  } catch (error) {
    return END_ERROR(res, 403, "Error in parsing certificate");
  }

  cert.subject = change_cert_keys(cert.subject);
  cert.issuer = change_cert_keys(cert.issuer);

  cert.fingerprint = cert.fingerPrint;
  cert.serialNumber = cert.serial;
  cert.subject["id-qt-unotice"] = cert.subject["Policy Qualifier User Notice"];

  delete cert.fingerPrint;
  delete cert.serial;
  delete cert.subject["Policy Qualifier User Notice"];

  req.certificate = cert;
  return next();
}

/* --- basic security checks to be done at every API call --- */

function basic_security_check(req, res, next) {
  if (!has_started_serving_apis) {
    has_started_serving_apis = true;
  }

  // replace all version with "/v1/"

  const endpoint = req.url.split("?")[0];
  const api = endpoint.replace(/\/v[1-2]\//, "/v1/");
  const min_class_required = MIN_CERT_CLASS_REQUIRED[api];

  if (!min_class_required) {
    return END_ERROR(
      res,
      404,
      "No such page/API. Please visit : " +
        "<https://authdocs.iudx.org.in> for documentation."
    );
  }

  if (!(res.locals.body = body_to_json(req.body))) {
    return END_ERROR(res, 400, "Body is not a valid JSON");
  }

  // skip checks for consent APIs
  if (req.headers.host === CONSENT_URL) return next();

  const cert = req.certificate;

  cert.serialNumber = cert.serialNumber.toLowerCase();
  cert.fingerprint = cert.fingerprint.toLowerCase();

  if ((res.locals.is_iudx_certificate = is_iudx_certificate(cert))) {
    // id-qt-unotice is in the format "key1:value1;key2:value2;..."

    const id_qt_notice = cert.subject["id-qt-unotice"] || "";
    const split = id_qt_notice.split(";");
    const user_notice = {};

    for (const s of split) {
      const ss = s.split(":"); // ss = split of split

      let key = ss[0];
      let value = ss[1];

      if (key && value) {
        key = key.toLowerCase();
        value = value.toLowerCase();

        user_notice[key] = value;
      }
    }

    const cert_class = user_notice["class"];
    let integer_cert_class = 0;

    if (cert_class) integer_cert_class = parseInt(cert_class, 10) || 0;

    if (integer_cert_class < 1)
      return END_ERROR(res, 403, "Invalid certificate class");

    if (integer_cert_class < min_class_required) {
      return END_ERROR(
        res,
        403,
        "A class-" +
          min_class_required +
          " or above certificate " +
          "is required to call this API"
      );
    }

    if (min_class_required === 1 && integer_cert_class !== 1) {
      /*
	class-1 APIs are special,
	user needs a class-1 certificate
	except in case of "/certificate-info"
      */

      if (!api.endsWith("/certificate-info")) {
        return END_ERROR(
          res,
          403,
          "A class-1 certificate is required " + "to call this API"
        );
      }
    }

    const error = is_secure(req, res, cert, true); // validate emails

    if (error !== "OK") return END_ERROR(res, 403, error);

    pool.query("SELECT crl FROM crl LIMIT 1", [], (error, results) => {
      if (error || results.rows.length === 0) {
        return END_ERROR(res, 500, "Internal error!", error);
      }

      const CRL = results.rows[0].crl;

      if (has_certificate_been_revoked(req.socket, cert, CRL)) {
        return END_ERROR(res, 403, "Certificate has been revoked");
      }

      res.locals.cert = cert;
      res.locals.cert_class = integer_cert_class;
      res.locals.email = cert.subject.emailAddress.toLowerCase();

      Object.freeze(res.locals);
      Object.freeze(res.locals.body);
      Object.freeze(res.locals.cert);

      return next();
    });
  } else {
    /*
      Certificates issued by other CAs
      may not have an "emailAddress" field.
      By default consider them as a class-1 certificate
     */

    const error = is_secure(req, res, cert, false);

    if (error !== "OK") return END_ERROR(res, 403, error);

    res.locals.cert_class = 1;
    res.locals.email = "";
    res.locals.cert = cert;

    /*
      But if the certificate has a valid "emailAddress"
      field then we consider it as a class-2 certificate
		*/

    if (is_valid_email(cert.subject.emailAddress)) {
      res.locals.cert_class = 2;
      res.locals.email = cert.subject.emailAddress.toLowerCase();
    }

    /*
	class-1 APIs are special,
	user needs a class-1 certificate

	except in case of "/certificate-info"

	if user is trying to call a class-1 API,
	then downgrade his certificate class
    */

    if (min_class_required === 1) {
      if (!api.endsWith("/certificate-info")) {
        res.locals.cert_class = 1;
      }
    }

    if (res.locals.cert_class < min_class_required) {
      return END_ERROR(
        res,
        403,
        "A class-" +
          min_class_required +
          " or above certificate is" +
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

function log_conn(req, res, next) {
  const endpoint = req.url.split("?")[0];
  const api = endpoint.replace(/\/v[1-2]\//, "/v1/");
  const api_details = api.split("/").slice(3).join("_");
  let id, cert_issuer;

  // if marketplace APIs called, api_details will be empty
  if (api_details == "") return next();

  /* if provider/consumer, id is email
   * if rs, id is hostname
   * if consent API, id is null? */

  if (res.locals.cert) {
    id = res.locals.email || res.locals.cert.subject.CN.toLowerCase();
    cert_issuer = res.locals.cert.issuer.CN;
  } else {
    id = null;
    cert_issuer = "none";
  }

  const type = api_details.toUpperCase() + "_REQUEST";
  const details = {
    ip: req.ip,
    authentication: "certificate " + cert_issuer,
    id: id,
  };

  log("info", type, false, details);

  return next();
}

//check before accessing secure end-points
function sessionIdCheck(req, res, next) {
  let apis;
  let email;
  const session_regex = new RegExp(/^[0-9]{6}$/); //sessionid can only be numeric and exactly 6 digits

  //TO-DO remove tfa header check when deploying to production.
  let twofaFlow = req.headers.tfa;
  if (twofaFlow === undefined) {
    //bypass middleware if this header is undefined
    return next();
  }

  const reqURL = req.url.split("?")[0];
  const reqEndpoint = reqURL.replace(/\/v[1-2]\//, "/v1/");
  const userEmail = res.locals.email;
  const method = req.method;

  //check if secure endpoint else proceed
  if (SECURED_ENDPOINTS[reqEndpoint] !== undefined) {
    //check if sessionId is present else 403
    const sessionId = req.headers["session-id"];
    if (sessionId === undefined) {
      return END_ERROR(res, 403, "SessionID not present");
    }

    if (!session_regex.test(sessionId))
      return END_ERROR(res, 403, "Invalid SessionId");

    //check if sessionId is valid for the same user-endpoint-method combination
    try {
      let result = pg.querySync(
        " SELECT session.endpoints" +
          " FROM consent.session,consent.users" +
          " WHERE session.session_id = $1::text " +
          " AND session.expiry_time >= NOW() " +
          " AND users.id = session.user_id" +
          " AND users.email = $2::text ",
        [sessionId, userEmail]
      );

      if (result.length === 0) return END_ERROR(res, 403, "Invalid SessionID");

      apis = result[0].endpoints;
    } catch (error) {
      return END_ERROR(res, 500, "Internal Server error");
    }

    //check if endPoint and method are available in 'endpoints' variable else invalid
    if (!apis.hasOwnProperty(reqEndpoint))
      return END_ERROR(res, 403, "Invalid SessionID");

    if (!apis[reqEndpoint].includes(method))
      return END_ERROR(res, 403, "Invalid SessionID");
  }

  return next();
}

function to_array(o) {
  if (o instanceof Object) {
    if (o instanceof Array) return o;
    else return [o];
  } else {
    return [o];
  }
}

function sign_csr(raw_csr, user) {
  const cert_class = user.role === "provider" ? "class:3" : "class:2";
  forge.pki.oids["id-qt-unotice"] = "1.3.6.1.5.5.7.2.2";
  const csr = forge.pki.certificationRequestFromPem(raw_csr);
  if (!csr.verify()) {
    return null;
  }
  let cert = forge.pki.createCertificate();
  cert.publicKey = csr.publicKey;
  cert.setIssuer(root_cert.subject.attributes);
  cert.serialNumber = crypto.randomBytes(20).toString("hex");
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

app.post("/auth/v[1-2]/token", async (req, res) => {
  const body = res.locals.body;
  const consumer_id = res.locals.email;

  const request_array = body.request;
  const existing_token = body.existing_token;

  let processed_request_array = [];
  let resource_server;

  let role_ids = [];
  let consumer_user_id;

  if (existing_token && request_array)
    return END_ERROR(
      res,
      400,
      "Either 'existing_token' or 'request', not both"
    );

  if (!existing_token && !request_array)
    return END_ERROR(res, 400, "Empty body");

  try {
    const result = await pool.query(
      "SELECT role.id, role.user_id FROM consent.role," +
        " consent.users WHERE user_id = users.id" +
        " AND email = $1::text AND status = 'approved'" +
        " AND role = ANY ($2::consent.role_enum[])",
      [
        consumer_id, // 1
        ["consumer", "onboarder", "data ingester"], // 2
      ]
    );

    if (result.rowCount === 0) return END_ERROR(res, 401, "Not allowed!");

    role_ids = result.rows.map((row) => row.id);
    consumer_user_id = result.rows[0].user_id;
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  let resource_set = new Set();

  if (request_array) {
    if (!Array.isArray(request_array) || request_array.length < 1) {
      return END_ERROR(
        res,
        400,
        "'request' must be a valid JSON array " + "with at least 1 element"
      );
    }
    let resp = validate_resource_array(request_array);
    if (!resp.success) return END_ERROR(res, 400, resp.result);

    resource_server = resp.result;

    try {
      /* process the requested resources to get access_id and cat_id */
      const result = await process_requested_resources(request_array, role_ids);

      ({ processed_request_array } = result);
    } catch (error) {
      /* If status_code key exists, will be normal error
       * Cannot send error object, it contains other stuff */
      if (error.status_code) {
        let err_resp = {
          message: error.message,
          "invalid-input": error["invalid-input"],
        };

        return END_ERROR(res, error.status_code, err_resp);
      } else return END_ERROR(res, 500, "Internal error!", error);
    }
  }

  if (existing_token) {
    const uuid_regex = new RegExp(
      /^[0-9a-f]{8}\b-[0-9a-f]{4}\b-[0-9a-f]{4}\b-[0-9a-f]{4}\b-[0-9a-f]{12}$/
    );

    if (!uuid_regex.test(existing_token))
      return END_ERROR(res, 400, "Invalid 'existing_token' uuid");

    try {
      const result = await pool.query(
        "SELECT id, resource_server, token, expiry < NOW() AS expired" +
          " FROM consent.token" +
          " WHERE uuid = $1::uuid" +
          " AND user_id = $2::integer" +
          " AND status = 'active'",
        [
          existing_token, // 1
          consumer_user_id, //2
        ]
      );

      if (result.rows.length === 0)
        return END_ERROR(res, 403, "Invalid 'existing_token'");

      if (result.rows[0].expired === false)
        return END_ERROR(res, 403, "'existing_token' not expired");

      let existing_token_id = result.rows[0].id;

      const access_items = await pool.query(
        "SELECT access_id, cat_id FROM consent.token_access" +
          " JOIN consent.access ON access_id = access.id" +
          " WHERE token_id = $1::integer AND token_access.status = 'active'" +
          " AND access.status = 'active' AND access.expiry > NOW()",
        [existing_token_id]
      );

      if (access_items.rows.length === 0)
        return END_ERROR(res, 403, "Token has no access to resources");

      resource_server = result.rows[0].resource_server;

      for (let obj of access_items.rows)
        processed_request_array.push({
          cat_id: obj.cat_id,
          access_id: obj.access_id,
        });
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }
  }

  let token;

  const random_hex = crypto.randomBytes(TOKEN_LEN).toString("hex");
  const uuid = uuidv4();

  /* Token format = issued-by / issued-to / random-hex-string / uuid */

  token = SERVER_NAME + "/" + consumer_id + "/" + random_hex + "/" + uuid;
  let token_id, expiry;

  try {
    let hash = await bcrypt.hash(token, BCRYPT_SALT_ROUNDS);

    const result = await pool.query(
      "INSERT INTO consent.token (token, uuid, user_id, " +
        "resource_server, expiry, status, created_at, updated_at)" +
        " VALUES ($1::text, $2::uuid, $3::integer, $4::text, " +
        " NOW() + $5::interval, $6::consent.token_status_enum, NOW(), NOW())" +
        " RETURNING id, expiry",
      [
        hash, //$1
        uuid, //$2
        consumer_user_id, //$3
        resource_server, //$4
        TOKEN_TIME_SEC + " seconds", //$5
        "active", //$6
      ]
    );
    token_id = result.rows[0].id;
    expiry = result.rows[0].expiry;
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  const response = {
    token: token,
    expiry: expiry,
  };

  for (let obj of processed_request_array) {
    try {
      const result = await pool.query(
        "INSERT INTO consent.token_access (token_id, access_id, " +
          "cat_id, status, created_at, updated_at)" +
          " VALUES ($1::integer, $2::integer, $3::text," +
          " $4::consent.token_access_status_enum, NOW(), NOW())",
        [
          token_id, //$1
          obj.access_id, //$2
          obj.cat_id, //$3
          "active", //$4
        ]
      );
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }
  }

  const details = {
    requester: consumer_id,
    token_expiry: expiry,
    resource_ids: request_array,
  };

  log("info", "ISSUED_TOKEN", true, details);

  return END_SUCCESS(res, response);
});

app.post("/auth/v[1-2]/token/introspect", async (req, res) => {
  const cert = res.locals.cert;
  const body = res.locals.body;
  const hostname_in_certificate = cert.subject.CN.toLowerCase();

  const response = {};
  const roles = [];
  let token_id;

  if (!body.token) return END_ERROR(res, 400, "No 'token' found in the body");

  if (!is_valid_token(body.token))
    return END_ERROR(res, 400, "Invalid 'token'");

  const token = body.token.toLowerCase();

  const split = token.split("/");
  const uuid = split[3];

  try {
    const result = await pool.query(
      "SELECT id, token ,user_id, resource_server, expiry" +
        " FROM consent.token" +
        " WHERE uuid = $1::uuid" +
        " AND resource_server = $2::text" +
        " AND expiry > NOW()" +
        " AND status = 'active'",
      [
        uuid, // 1
        hostname_in_certificate, //2
      ]
    );

    if (result.rows.length === 0) return END_ERROR(res, 403, "Invalid 'token'");

    let token_hash = result.rows[0].token;

    let is_token = await bcrypt.compare(token, token_hash);

    if (!is_token) return END_ERROR(res, 403, "Invalid 'token'");

    token_id = result.rows[0].id;
    let { user_id } = result.rows[0];

    response.consumer = split[1];
    response.expiry = result.rows[0].expiry;

    const result2 = await pool.query(
      "SELECT id, role FROM consent.role" +
        " WHERE user_id = $1::integer" +
        " AND status = 'approved'" +
        " AND role = ANY ($2::consent.role_enum[])",
      [
        user_id, // 1
        ["consumer", "onboarder", "data ingester"], // 2
      ]
    );

    /* this should not happen */
    if (result2.rowCount === 0) return END_ERROR(res, 403, "Invalid 'token'");

    result2.rows.map((row) => {
      roles[row.role] = row.id;
    });
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  let access = {},
    access_query,
    token_access_items;

  try {
    const result = await pool.query(
      "SELECT access_id, cat_id FROM consent.token_access" +
        " WHERE token_id = $1::integer AND status = 'active'",
      [token_id]
    );

    if (result.rows.length === 0)
      return END_ERROR(res, 403, "Token has no access to resources");

    token_access_items = result.rows;
    response.request = [];

    /* create access object with key as access ID */
    for (let obj of token_access_items) {
      if (!access[obj.access_id]) access[obj.access_id] = {};

      access[obj.access_id].id = obj.cat_id;
      access[obj.access_id].resource_group = obj.cat_id
        .split("/")
        .slice(0, 4)
        .join("/");
      access[obj.access_id].apis = new Set();
    }

    /* capability will be null for onboarder/data ingester */
    access_query = await pool.query(
      "SELECT access.id, role_id," +
        " capability FROM consent.access LEFT JOIN consent.capability" +
        " ON access_id =access.id WHERE access.id = ANY ($1::integer[])" +
        " AND access.status = 'active' AND access.expiry > NOW()" +
        " AND (capability.status = 'active' OR capability.status IS NULL)",
      [Object.keys(access)]
    );

    if (access_query.rows.length === 0)
      return END_ERROR(res, 403, "Token has no access to resources");
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  /* add function to access object to add APIs to
   * apis set for nested objects */
  let add_apis = function (id, arr) {
    arr.forEach((val) => {
      access[id].apis.add(
        val.replace("{{RESOURCE_GROUP_ID}}", access[id].resource_group)
      );
    });
  };

  for (let obj of access_query.rows) {
    /* get APIs depending on role/capability */
    if (obj.role_id === roles.onboarder) continue;
    else {
      const resource_server = access[obj.id].resource_group.split("/")[2];
      let caps_object = CAPS[resource_server];

      if (obj.role_id === roles["data ingester"])
        add_apis(obj.id, caps_object["data ingester"].default);
      else if (obj.role_id === roles.consumer)
        add_apis(obj.id, caps_object.consumer[obj.capability]);
    }
  }

	/* if 2 cat IDs are same, then concatenate the APIs together
	 * this happens when a user has consumer & ingester access to
	 * the same resource */
  let process_request = new Map();
  for (let i of Object.keys(access)) {
    if (!process_request.has(access[i].id))
      process_request.set(access[i].id, []);

    process_request.set(
      access[i].id,
      process_request.get(access[i].id).concat([...access[i].apis])
    );
  }

  for (let [id, apis] of process_request.entries()) {
    if (id.split("/").length === 4)
      //is resource group
      id = id + "/*";

    response.request.push({ id: id, apis: apis });
  }

  const details = {
    resource_server: hostname_in_certificate,
    issued_to: token.split("/")[1],
  };

  log("info", "INTROSPECTED_TOKEN", true, details);

  return END_SUCCESS(res, response);
});

app.get("/auth/v[1-2]/token", async (req, res) => {
  const body = res.locals.body;
  const consumer_id = res.locals.email;
  const response = [];

  let token_list = [],
    roles = {},
    consumer_user_id;

  try {
    const result = await pool.query(
      "SELECT role.id, role, role.user_id FROM consent.role," +
        " consent.users WHERE user_id = users.id" +
        " AND email = $1::text AND status = 'approved'" +
        " AND role = ANY ($2::consent.role_enum[])",
      [
        consumer_id, // 1
        ["consumer", "onboarder", "data ingester"], // 2
      ]
    );

    if (result.rowCount === 0) return END_ERROR(res, 401, "Not allowed!");
    consumer_user_id = result.rows[0].user_id;

    result.rows.map((row) => {
      roles[row.role] = row.id;
    });
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  try {
    const result = await pool.query(
      "SELECT id, uuid, expiry, expiry < NOW() AS expired, " +
        " status FROM consent.token WHERE user_id = $1::integer" +
        " AND status = 'active'",
      [consumer_user_id]
    );

    token_list = result.rows;
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  for (let token of token_list) {
    let details = {
      uuid: token.uuid,
      status:
        token.status === "active" && token.expired ? "expired" : token.status,
      expiry: token.expiry,
      request: [],
    };

    let access = {},
      access_query,
      token_access_items;

    try {
      const result = await pool.query(
        "SELECT t.status, t.cat_id," +
          " access.expiry < NOW() AS expired" +
          " FROM consent.token_access AS t JOIN consent.access ON" +
          " t.access_id = access.id WHERE token_id = $1::integer",
        [token.id]
      );

      token_access_items = result.rows;
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }

    for (let obj of token_access_items) {
      if (obj.status === "active" && obj.expired === true)
        obj.status = "expired";

      delete obj.expired;
      details.request.push(obj);
    }

    response.push(details);
  }

  return END_SUCCESS(res, response);
});

app.delete("/auth/v[1-2]/token", async (req, res) => {
  let token_uuids = res.locals.body.tokens;
  const consumer_id = res.locals.email;
  const uuid_regex = new RegExp(
    /^[0-9a-f]{8}\b-[0-9a-f]{4}\b-[0-9a-f]{4}\b-[0-9a-f]{4}\b-[0-9a-f]{12}$/
  );

  let consumer_user_id, token_ids;

  try {
    const result = await pool.query(
      "SELECT role.user_id FROM consent.role," +
        " consent.users WHERE user_id = users.id" +
        " AND email = $1::text AND status = 'approved'" +
        " AND role = ANY ($2::consent.role_enum[])",
      [
        consumer_id, // 1
        ["consumer", "onboarder", "data ingester"], // 2
      ]
    );

    if (result.rowCount === 0) return END_ERROR(res, 401, "Not allowed!");
    consumer_user_id = result.rows[0].user_id;
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }
  if (!token_uuids || !Array.isArray(token_uuids) || token_uuids.length < 1)
    return END_ERROR(
      res,
      400,
      "'tokens' must be a valid JSON array " + "with at least 1 element"
    );

  token_uuids = [...new Set(token_uuids)];

  for (let uuid of token_uuids) {
    if (!uuid_regex.test(uuid)) {
      const error_response = {
        message: "Invalid data (uuid)",
        "invalid-input": [xss_safe(uuid)],
      };
      return END_ERROR(res, 400, error_response);
    }
  }

  try {
    const result = await pool.query(
      "SELECT id, uuid FROM consent.token" +
        " WHERE user_id = $1::integer AND" +
        " uuid = ANY($2::uuid[])" +
        " AND status != 'deleted'" +
        " AND expiry > NOW()",
      [consumer_user_id, token_uuids]
    );

    if (result.rows.length === 0) {
      const error_response = {
        message: "Invalid uuids",
        "invalid-input": token_uuids,
      };

      return END_ERROR(res, 400, error_response);
    }

    if (result.rows.length !== token_uuids.length) {
      /* valid_uuids should always be subset of token_uuids */
      let valid_uuids = result.rows.map((obj) => obj.uuid);

      let invalid_uuids = token_uuids.filter(
        (uuid) => !valid_uuids.includes(uuid)
      );

      const error_response = {
        message: "Invalid uuids",
        "invalid-input": invalid_uuids,
      };
      return END_ERROR(res, 400, error_response);
    }

    token_ids = result.rows.map((obj) => obj.id);
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  try {
    const result = await pool.query(
      "UPDATE consent.token SET status = 'deleted'," +
        " updated_at = NOW() WHERE id = ANY($1::integer[])",
      [token_ids]
    );

    if (result.rowCount === 0) throw new Error("Error in deletion");

    const result2 = await pool.query(
      "UPDATE consent.token_access SET status = 'deleted'," +
        " updated_at = NOW() WHERE token_id = ANY($1::integer[])",
      [token_ids]
    );

    if (result2.rowCount === 0) throw new Error("Error in deletion");
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  const details = {
    requester: consumer_id,
  };

  log("info", "DELETED_TOKENS", true, details);

  return END_SUCCESS(res);
});

app.get("/auth/v[1-2]/consumer/resources", async (req, res) => {
  const consumer_email = res.locals.email;

  let item_details = {};
  let access_item_ids = {};
  let access_query;
  let consumer_id;

  try {
    const result = await pool.query(
      "SELECT role.id, role FROM consent.role," +
        " consent.users WHERE user_id = users.id" +
        " AND email = $1::text AND status = 'approved'" +
        " AND role = 'consumer'",
      [
        consumer_email, // 1
      ]
    );

    if (result.rowCount === 0) return END_ERROR(res, 401, "Not allowed!");

    consumer_id = result.rows[0].id;

    access_query = await pool.query(
      "SELECT access.id, access_item_id, access_item_type," +
        " capability FROM consent.access LEFT JOIN consent.capability" +
        " ON access_id = access.id WHERE role_id = $1::integer" +
        " AND access.status = 'active' AND expiry > NOW()" +
        " AND capability.status = 'active'",
      [consumer_id]
    );

    if (access_query.rows.length === 0) return END_ERROR(res, 200, []);

    for (let obj of access_query.rows) {
      if (!access_item_ids[obj.access_item_type])
        access_item_ids[obj.access_item_type] = [];

      access_item_ids[obj.access_item_type].push(obj.access_item_id);
    }
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  /* get resource ID of each resourcegroup item */
  for (const item of Object.keys(access_item_ids)) {
    item_details[item] = {};

    try {
      const result = await pool.query(
        "SELECT id, cat_id FROM consent." +
          item +
          " WHERE id = ANY($1::integer[])",
        [access_item_ids[item]]
      );

      for (let val of result.rows) {
        item_details[item][val.id] = val.cat_id;
      }
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }
  }

  const response = {};

  for (let obj of access_query.rows) {
    if (!response[obj.id]) {
      response[obj.id] = {
        cat_id: item_details[obj.access_item_type][obj.access_item_id],
        capabilities: [],
        type: obj.access_item_type,
      };
    }
    response[obj.id].capabilities.push(obj.capability);
  }

  return END_SUCCESS(res, Object.values(response));
});

app.put("/auth/v[1-2]/token", async (req, res) => {
  const consumer_id = res.locals.email;
  let roles = {},
    consumer_user_id;

  const request = res.locals.body.request;
  const uuid_regex = new RegExp(
    /^[0-9a-f]{8}\b-[0-9a-f]{4}\b-[0-9a-f]{4}\b-[0-9a-f]{4}\b-[0-9a-f]{12}$/
  );

  try {
    const result = await pool.query(
      "SELECT role.id, user_id, role FROM consent.role," +
        " consent.users WHERE user_id = users.id" +
        " AND email = $1::text AND status = 'approved'" +
        " AND role = ANY ($2::consent.role_enum[])",
      [
        consumer_id, // 1
        ["consumer", "onboarder", "data ingester"], // 2
      ]
    );

    if (result.rowCount === 0) return END_ERROR(res, 401, "Not allowed!");

    result.rows.map((row) => {
      roles[row.role] = row.id;
    });
    consumer_user_id = result.rows[0].user_id;
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  if (!request || !Array.isArray(request) || request.length < 1)
    return END_ERROR(res, 400, "Invalid data (request)");

  let req_object = {};
  let uuid_set = new Set();

  for (const obj of request) {
    if (typeof obj !== "object" || obj === null)
      return END_ERROR(res, 400, "Invalid data (request)");

    let uuid = obj.token;
    if (!uuid || !uuid_regex.test(uuid)) {
      const error_response = {
        message: "Invalid uuid",
        "invalid-input": xss_safe(uuid),
      };

      return END_ERROR(res, 400, error_response);
    }
    if (uuid_set.has(uuid)) {
      const error_response = {
        message: "Duplicate uuid",
        "invalid-input": xss_safe(uuid),
      };

      return END_ERROR(res, 400, error_response);
    }
    uuid_set.add(uuid);

    let resource_arr = obj.resources;

    if (
      !resource_arr ||
      !Array.isArray(resource_arr) ||
      resource_arr.length < 1
    )
      return END_ERROR(res, 400, "Invalid data (resources)");

    req_object[uuid] = {};

    let resp = validate_resource_array(resource_arr);
    if (!resp.success) return END_ERROR(res, 400, resp.result);

    req_object[uuid].requested_resource_server = resp.result;
  }

  /* get all token IDs from UUIDs */
  try {
    const result = await pool.query(
      "SELECT id, resource_server, uuid FROM consent.token WHERE" +
        " user_id = $1::integer AND" +
        " uuid = ANY($2::uuid[])" +
        " AND status = 'active' AND expiry > NOW()",
      [consumer_user_id, Object.keys(req_object)]
    );

    let valid_uuids = result.rows.map((obj) => obj.uuid);

    if (valid_uuids.length !== Object.keys(req_object).length) {
      let invalid_uuids = Object.keys(req_object).filter(
        (uuid) => !valid_uuids.includes(uuid)
      );

      const error_response = {
        message: "Invalid uuids",
        "invalid-input": invalid_uuids,
      };

      return END_ERROR(res, 400, error_response);
    }

    for (const obj of result.rows) {
      req_object[obj.uuid].id = obj.id;
      req_object[obj.uuid].resource_server = obj.resource_server;
    }
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  /* begin processing request */

  const updated_tokens = [];

  for (const i of request) {
    let uuid = i.token;
    let resources = i.resources;

    let deleted = new Map(),
      active = new Map(),
      to_activate = [],
      to_delete = [];
    let to_add;
    let processed_request_array;

    /* check if requested resource server matches
     * the token's resource server */
    if (
      req_object[uuid].requested_resource_server !==
      req_object[uuid].resource_server
    )
      return END_ERROR(
        res,
        400,
        "New resources must belong" + "to same resource server"
      );

    try {
      const result = await pool.query(
        "SELECT access_id, cat_id, token_access.id, " +
          " token_access.status FROM consent.token_access" +
          " JOIN consent.access ON access_id = access.id" +
          " WHERE access.status != 'deleted' AND access.expiry > NOW()" +
          " AND token_id = $1::integer",
        [req_object[uuid].id]
      );

      for (let obj of result.rows) {
        /* map accessID#cat_id to token_access ID */
        let key = `${obj.access_id}#${obj.cat_id}`;

        if (obj.status === "active") active.set(key, obj.id);
        else if (obj.status === "deleted") deleted.set(key, obj.id);
      }

      /* call process_requested_resources with resource server
       * of token */
      ({ processed_request_array } = await process_requested_resources(
        resources,
        Object.values(roles)
      ));
    } catch (error) {
      /* If status_code key exists, will be normal error
       * Cannot send error object, it contains other stuff */
      if (error.status_code) {
        let err_resp = {
          message: error.message,
          "invalid-input": error["invalid-input"],
        };

        return END_ERROR(res, error.status_code, err_resp);
      } else return END_ERROR(res, 500, "Internal error!", error);
    }

    /* to_add has resources that are neither active nor deleted */
    to_add = processed_request_array.filter(
      (obj) =>
        !(
          active.has(`${obj.access_id}#${obj.cat_id}`) ||
          deleted.has(`${obj.access_id}#${obj.cat_id}`)
        )
    );

    /* to_activate has currently deleted
     * token_access IDs corresponding to access IDs
     * present in the request array */
    for (let obj of processed_request_array) {
      let key = `${obj.access_id}#${obj.cat_id}`;
      if (deleted.has(key)) to_activate.push(deleted.get(key));
    }

    /* we delete all ids present in active that are present in
     * the request */
    for (let obj of processed_request_array) {
      let key = `${obj.access_id}#${obj.cat_id}`;
      if (active.has(key)) active.delete(key);
    }

    /* to_delete must have all currently active
     * token_access IDs corresponding to
     * access IDs NOT present in the request array */
    to_delete = [...active.values()];

    /* get cat IDs of resources going to be deleted */
    let deleted_resources = [...active.keys()].map((val) => val.split("#")[1]);

    req_object[uuid].to_add = to_add;
    req_object[uuid].to_activate = to_activate;
    req_object[uuid].to_delete = to_delete;
    req_object[uuid].deleted_resources = deleted_resources;
  }

  const response = [];

  for (const i of request) {
    let uuid = i.token;
    let resources = i.resources;

    try {
      if (req_object[uuid].to_activate.length !== 0) {
        let result = await pool.query(
          "UPDATE consent.token_access SET status = 'active', " +
            " updated_at = NOW() WHERE id = ANY($1::integer[])",
          [req_object[uuid].to_activate]
        );
      }

      if (req_object[uuid].to_delete.length !== 0) {
        let result = await pool.query(
          "UPDATE consent.token_access SET status = 'deleted', " +
            " updated_at = NOW() WHERE id = ANY($1::integer[])",
          [req_object[uuid].to_delete]
        );
      }

      for (let obj of req_object[uuid].to_add) {
        let result = await pool.query(
          "INSERT INTO consent.token_access (token_id, access_id, " +
            "cat_id, status, created_at, updated_at)" +
            " VALUES ($1::integer, $2::integer, $3::text," +
            " $4::consent.token_access_status_enum, NOW(), NOW())",
          [
            req_object[uuid].id, //$1
            obj.access_id, //$2
            obj.cat_id, //$3
            "active", //$4
          ]
        );
      }

      let result = await pool.query(
        "UPDATE consent.token SET updated_at = NOW()" +
          " WHERE id = $1::integer",
        [req_object[uuid].id]
      );

      response.push({
        token: uuid,
        active_resources: resources,
        deleted_resources: req_object[uuid].deleted_resources,
      });
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }
  }

  const details = {
    requester: consumer_id,
  };

  log("info", "UPDATED_TOKENS", true, details);

  return END_SUCCESS(res, response);
});

app.post("/auth/v[1-2]/certificate-info", async (req, res) => {
  const cert = res.locals.cert;
  let roles = [];
  let name = {};

  try {
    const result = await pool.query(
      "SELECT title, first_name, last_name, role FROM consent.role JOIN" +
        " consent.users ON users.id = user_id" +
        " WHERE users.email = $1::text",
      [res.locals.email]
    );

    if (result.rows.length !== 0) {
      roles = [...new Set(result.rows.map((row) => row.role))];
      name = {
        title: result.rows[0].title,
        first_name: result.rows[0].first_name,
        last_name: result.rows[0].last_name,
      };
    }
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  const response = {
    id: res.locals.email,
    user_name: name,
    "certificate-class": res.locals.cert_class,
    serial: cert.serialNumber.toLowerCase(),
    fingerprint: cert.fingerprint.toLowerCase(),
    roles: roles,
  };

  return END_SUCCESS(res, response);
});

app.post("/auth/v[1-2]/provider/access", async (req, res) => {
  const email = res.locals.email;
  const dateTimeNow = DateTime.now();
  let provider_uid, provider_email;
  let provider_rid, delegate_rid;
  let is_delegate = false;
  let rules_array = [];
  let to_add = [];
  let expiryTime;
  let isDefaultExpiry = false;
  let newExpiryTime;

  try {
    provider_uid = await check_privilege(email, "provider");
  } catch (error) {
    is_delegate = true;
  }

  if (is_delegate) {
    provider_email = req.headers["provider-email"];
    if (!provider_email || !is_valid_email(provider_email))
      return END_ERROR(res, 400, "Invalid data (provider_email)");

    try {
      provider_uid = await check_privilege(provider_email, "provider");
      let delegate_uid = await check_privilege(email, "delegate");
      delegate_rid = await check_valid_delegate(delegate_uid, provider_uid);
    } catch (error) {
      return END_ERROR(res, 401, "Not allowed");
    }
  } else {
    provider_email = email;

    try {
      const result = await pool.query(
        "SELECT id FROM consent.role WHERE " +
          " user_id = $1::integer AND" +
          " role = 'provider'",
        [provider_uid]
      );

      provider_rid = result.rows[0].id;
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }
  }

  const email_domain = provider_email.split("@")[1];
  const sha1_of_email = sha1(provider_email);
  const provider_id_hash = email_domain + "/" + sha1_of_email;

  const request = res.locals.body;

  if (!Array.isArray(request) || !request.length)
    return END_ERROR(res, 400, "Invalid data (body)");

  for (const [index, obj] of request.entries()) {
    if (typeof obj !== "object" || obj === null)
      return END_ERROR(res, 400, "Invalid data (body)");
    let accesser_uid, access_item_id;
    let req_capability;

    const accesser_role = obj.user_role;
    const resource = obj.item_id;

    let accesser_email = obj.user_email;
    let capability = obj.capabilities;
    let res_type = obj.item_type;
    let consumer_acc_id = null;
    let resource_server, caps_object;

    let err = {
      message: "",
      id: index,
    };

    if (!accesser_email || !is_valid_email(accesser_email)) {
      err.message = "Invalid data (email)";
      return END_ERROR(res, 400, err);
    }

    accesser_email = accesser_email.toLowerCase();

    if (!accesser_role || !ACCESS_ROLES.includes(accesser_role)) {
      err.message = "Invalid data (role)";
      return END_ERROR(res, 400, err);
    }

    try {
      accesser_uid = await check_privilege(accesser_email, accesser_role);
    } catch (error) {
      err.message = "Invalid accesser";
      return END_ERROR(res, 403, err);
    }

    if (obj.expiry_time !== undefined) {
      isDefaultExpiry = false;
      newExpiryTime = obj.expiry_time;
    } else {
      isDefaultExpiry = true;
    }

    if (!isDefaultExpiry) {
      let reqDateTime = DateTime.fromISO(newExpiryTime, { zone: "utc" });

      if (!reqDateTime.isValid) {
        err.message = "Invalid data (expiry)";
        return END_ERROR(res, 400, err);
      }

      if (reqDateTime < dateTimeNow) {
        err.message = "Invalid data (expiry)";
        return END_ERROR(res, 400, err);
      }
    } else newExpiryTime = DateTime.now().plus({ years: 1 });

    if (accesser_role === "consumer" || accesser_role === "data ingester") {
      if (!resource) {
        err.message = "Invalid data (item-id)";
        return END_ERROR(res, 400, err);
      }

      if (!res_type || !RESOURCE_ITEM_TYPES.includes(res_type)) {
        err.message = "Invalid data (item-type)";
        return END_ERROR(res, 400, err);
      }

      if (!is_string_safe(resource, "_") || resource.indexOf("..") >= 0) {
        err.message = "Invalid data (item-id)";
        return END_ERROR(res, 400, err);
      }

      // resource group must have 3 slashes
      if ((resource.match(/\//g) || []).length !== 3) {
        err.message = "Invalid data (item-id)";
        return END_ERROR(res, 400, err);
      }

      if (!resource.startsWith(provider_id_hash)) {
        err.message = "Provider does not match resource owner";
        return END_ERROR(res, 403, err);
      }

      /* get recognised capabilities from config file */
      resource_server = resource.split("/")[2];
      caps_object = CAPS[resource_server];
      if (caps_object === undefined) {
        err.message = "Invalid data (item-id)";
        return END_ERROR(res, 400, err);
      }
    }

    if (accesser_role === "consumer") {
      if (
        !Array.isArray(capability) ||
        capability.length > Object.keys(caps_object.consumer).length ||
        capability.length === 0
      ) {
        err.message = "Invalid data (capabilities)";
        return END_ERROR(res, 400, err);
      }

      req_capability = [...new Set(capability)];

      if (
        !req_capability.every((val) =>
          Object.keys(caps_object.consumer).includes(val)
        )
      ) {
        err.message = "Invalid data (capabilities)";
        return END_ERROR(res, 400, err);
      }
    }

    if (accesser_role === "consumer" || accesser_role === "data ingester") {
      // get access item id if it exists
      try {
        const result = await pool.query(
          "SELECT id from consent." + res_type + " WHERE cat_id = $1::text ",
          [resource]
        );

        if (result.rows.length !== 0) access_item_id = result.rows[0].id;
      } catch (error) {
        return END_ERROR(res, 500, "Internal error!", error);
      }
    }

    /* access_item_id for catalogue/delegate is -1 by default */
    if (accesser_role === "onboarder") {
      access_item_id = -1;
      res_type = "catalogue";
    } else if (accesser_role === "delegate") {
      if (is_delegate) {
        err.message = "Delegate cannot set delegate rule";
        return END_ERROR(res, 403, err);
      }

      access_item_id = -1;
      res_type = "provider-caps";
    }

    /* if rule exists for particular provider+accesser+role+
		   resource/catalogue */

    if (access_item_id) {
      try {
        const result = await pool.query(
          "SELECT a.id, a.expiry " +
            " FROM consent.role, consent.access as a" +
            " WHERE consent.role.id = a.role_id" +
            " AND a.provider_id = $1::integer" +
            " AND a.status = 'active'" +
            " AND role.user_id = $2::integer" +
            " AND a.access_item_id = $3::integer" +
            " AND role.role = $4::consent.role_enum",
          [
            provider_uid, //$1
            accesser_uid, //$2
            access_item_id, //$3
            accesser_role, //$4
          ]
        );

        if (
          result.rows.length !== 0 &&
          accesser_role !== "consumer" &&
          result.rows[0].expiry > dateTimeNow
        ) {
          err.message = "Rule exists";
          return END_ERROR(res, 403, err);
        }

        /* if consumer exists with this resource-id, only update
         * policy for said consumer and do not add a new row in
         * the access table */

        if (result.rows.length !== 0 && accesser_role === "consumer") {
          consumer_acc_id = result.rows[0].id;

          const caps = await pool.query(
            "SELECT capability from consent.capability" +
              " WHERE access_id = $1::integer" +
              " AND status = 'active'",
            [consumer_acc_id]
          );

          let existing_caps = [
            ...new Set(caps.rows.map((row) => row.capability)),
          ];

          let duplicate = intersect(req_capability, existing_caps);

          if (duplicate.length !== 0) {
            err.message = `Rule exists for ${duplicate.toString()}`;
            return END_ERROR(res, 403, err);
          }
        }
      } catch (error) {
        return END_ERROR(res, 500, "Internal error!", error);
      }
    }

    /* check for duplicates in the object array */
    for (const i of to_add) {
      if (i.accesser_role === "onboarder" && accesser_role === "onboarder") {
        if (i.accesser_email === accesser_email) {
          err.message = "Invalid data (duplicate)";
          return END_ERROR(res, 400, err);
        }
      } else if (
        i.accesser_role === "data ingester" &&
        accesser_role === "data ingester"
      ) {
        if (
          i.accesser_email === accesser_email &&
          i.resource === resource &&
          i.res_type === res_type
        ) {
          err.message = "Invalid data (duplicate)";
          return END_ERROR(res, 400, err);
        }
      } else if (
        i.accesser_role === "consumer" &&
        accesser_role === "consumer"
      ) {
        if (
          i.accesser_email === accesser_email &&
          i.resource === resource &&
          i.res_type === res_type
        ) {
          let duplicate = intersect(req_capability, i.req_capability);

          if (duplicate.length !== 0) {
            err.message = "Invalid data (duplicate)";
            return END_ERROR(res, 400, err);
          }
        }
      }
    }

    to_add.push({
      resource: resource,
      res_type: res_type,
      access_item_id: access_item_id,
      consumer_acc_id: consumer_acc_id,
      req_capability: req_capability,
      accesser_uid: accesser_uid,
      accesser_email: accesser_email,
      accesser_role: accesser_role,
      newExpiryTime: newExpiryTime,
    });
  }

  if (to_add.length === 0) return END_ERROR(res, 500, "Internal error!");

  for (const obj of to_add) {
    const { resource, res_type, consumer_acc_id } = obj;
    const { req_capability } = obj;
    const { accesser_uid, accesser_email, accesser_role } = obj;
    const { newExpiryTime } = obj;
    let { access_item_id } = obj;
    let rule, resource_name, policy_json;

    try {
      if (!access_item_id) {
        /* check if inserted by a prev. policy in same request */
        const result = await pool.query(
          "SELECT id from consent." + res_type + " WHERE cat_id = $1::text ",
          [resource]
        );

        if (result.rows.length !== 0) {
          access_item_id = result.rows[0].id;
        } else {
          const access_item = await pool.query(
            "INSERT INTO consent." +
              res_type +
              " (provider_id, cat_id, created_at, updated_at) " +
              " VALUES ($1::integer, $2::text, NOW(), NOW())" +
              "RETURNING id",
            [
              provider_uid, //$1
              resource, //$2
            ]
          );

          access_item_id = access_item.rows[0].id;
        }
      }

      const role_id = await pool.query(
        "SELECT id from consent.role WHERE" +
          " user_id = $1::integer " +
          " AND role = $2::consent.role_enum",
        [
          accesser_uid, //$1
          accesser_role, //$2
        ]
      );

      let access;

      /* if consumer_acc_id is not null, there is an existing
       * consumer with policy for same resource-id */
      if (consumer_acc_id === null) {
        access = await pool.query(
          "INSERT into consent.access (provider_id, " +
            " role_id, policy_text, policy_json, access_item_id, " +
            " access_item_type, status, expiry, created_at, updated_at)" +
            " VALUES ($1::integer, $2::integer, $3::text," +
            " $4::jsonb, $5::integer, $6::consent.access_item," +
            " $7::consent.access_status_enum, $8::timestamp, NOW(), NOW()) RETURNING id",
          [
            provider_uid, //$1
            role_id.rows[0].id, //$2
            " ", //$3
            {}, //$4
            access_item_id, //$5
            res_type, //$6
            "active", //$7
            newExpiryTime.toString(),
          ]
        );
      }

      /* add newly requested capabilities to table if consumer */
      if (accesser_role === "consumer") {
        let access_id = consumer_acc_id || access.rows[0].id;

        for (const cap of req_capability) {
          const result = await pool.query(
            "INSERT INTO consent.capability " +
              " (access_id, capability, status, created_at, updated_at)" +
              " VALUES ($1::integer, $2::consent.capability_enum," +
              " $3::consent.access_status_enum, NOW(), NOW())",
            [access_id, cap, "active"]
          );
        }
      }
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }

    const details = {
      provider: provider_email,
      accesser: accesser_email,
      role: accesser_role,
      resource_id: resource || null,
      capabilities: req_capability || null,
      delegated: is_delegate,
      performed_by: email,
    };

    log("info", "CREATED_POLICY", true, details);
  }

  return END_SUCCESS(res);
});

app.get("/auth/v[1-2]/provider/access", async (req, res) => {
  const email = res.locals.email;

  let provider_uid, rules;
  let is_delegate = false;
  let item_details = {};
  let cap_details = {};
  let access_item_ids = {};
  let accessid_arr = [];

  try {
    provider_uid = await check_privilege(email, "provider");
  } catch (error) {
    is_delegate = true;
  }

  if (is_delegate) {
    let provider_email = req.headers["provider-email"];
    if (!provider_email || !is_valid_email(provider_email))
      return END_ERROR(res, 400, "Invalid data (provider_email)");

    try {
      provider_uid = await check_privilege(provider_email, "provider");
      let delegate_uid = await check_privilege(email, "delegate");
      let delegate_rid = await check_valid_delegate(delegate_uid, provider_uid);
    } catch (error) {
      return END_ERROR(res, 401, "Not allowed");
    }
  }

  try {
    let result = await pool.query(
      "SELECT a.id, a.access_item_type, a.access_item_id, a.expiry," +
        " email, role, title, first_name, last_name" +
        " FROM consent.access as a, consent.users, consent.role " +
        " WHERE a.role_id = role.id AND role.user_id = users.id " +
        " AND a.provider_id = $1::integer AND a.status = 'active' ",
      [provider_uid]
    );

    rules = result.rows;
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  for (let obj of rules) {
    if (!access_item_ids[obj.access_item_type])
      access_item_ids[obj.access_item_type] = [];

    access_item_ids[obj.access_item_type].push(obj.access_item_id);
    accessid_arr.push(obj.id);
  }

  /* get resource ID of each resourcegroup item */
  for (const item of Object.keys(access_item_ids)) {
    if (item === "catalogue" || item === "provider-caps") continue;

    item_details[item] = {};

    try {
      const result = await pool.query(
        "SELECT id, cat_id FROM consent." +
          item +
          " WHERE id = ANY($1::integer[])",
        [access_item_ids[item]]
      );

      for (let val of result.rows) {
        item_details[item][val.id] = val.cat_id;
      }
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }
  }

  /* get capability details for each access ID */
  try {
    const result = await pool.query(
      "SELECT access_id, capability " +
        " FROM consent.capability " +
        " WHERE access_id = ANY($1::integer[])" +
        " AND status = 'active'",
      [accessid_arr]
    );

    for (let row of result.rows) {
      if (!cap_details[row.access_id]) cap_details[row.access_id] = [];

      cap_details[row.access_id].push(row.capability);
    }
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  let result = [];

  for (let rule of rules) {
    let response = {
      id: rule.id,
      email: rule.email,
      role: rule.role,
      user_name: {
        title: rule.title,
        first_name: rule.first_name,
        last_name: rule.last_name,
      },
      expiry: rule.expiry,
      status: rule.expiry < DateTime.now() ? "expired" : "active",
      item_type: rule.access_item_type,
      item: null,
      capabilities: cap_details[rule.id] || null,
    };

    if (rule.access_item_id !== -1)
      response.item = {
        cat_id: item_details[rule.access_item_type][rule.access_item_id],
      };

    result.push(response);
  }

  return END_SUCCESS(res, result);
});

app.put("/auth/v[1-2]/provider/access", async (req, res) => {
  const email = res.locals.email;
  let provider_uid;
  let provider_email;
  let delegate_rid;
  let is_delegate = false;
  let isDefaultExpiry = false;
  const dateTimeNow = DateTime.now();

  try {
    provider_uid = await check_privilege(email, "provider");
  } catch (error) {
    is_delegate = true;
  }

  if (is_delegate) {
    provider_email = req.headers["provider-email"];
    if (!provider_email || !is_valid_email(provider_email))
      return END_ERROR(res, 400, "Invalid data (provider_email)");

    try {
      provider_uid = await check_privilege(provider_email, "provider");
      let delegate_uid = await check_privilege(email, "delegate");
      delegate_rid = await check_valid_delegate(delegate_uid, provider_uid);
    } catch (error) {
      return END_ERROR(res, 401, "Not allowed");
    }
  } else {
    provider_email = email;
  }
  const request = res.locals.body;

  if (!Array.isArray(request) || !request.length)
    return END_ERROR(res, 400, "Invalid data (body)");

  for (const obj of request) {
    if (typeof obj !== "object" || obj === null)
      return END_ERROR(res, 400, "Invalid data (body)");

    let err = {
      message: "",
      access_id: undefined,
    };

    let id = obj.id;

    if (id === undefined) {
      err.message = "Invalid data (id)";
      err.access_id = id;
      return END_ERROR(res, 400, err);
    }

    id = parseInt(id, 10);

    if (isNaN(id) || id < 1 || id > PG_MAX_INT) {
      err.message = "Invalid data (id)";
      err.access_id = id;
      return END_ERROR(res, 400, err);
    }

    let newExpiryTime;
    if (obj.expiry_time !== undefined) {
      isDefaultExpiry = false;
      newExpiryTime = obj.expiry_time;
    } else {
      isDefaultExpiry = true;
    }

    //luxon validations only needed when expiry time is included in the request
    if (!isDefaultExpiry) {
      let reqDateTime = DateTime.fromISO(newExpiryTime, { zone: "utc" });

      if (!reqDateTime.isValid) {
        err.message = "Invalid data (expiry)";
        err.access_id = id;
        return END_ERROR(res, 400, err);
      }

      if (reqDateTime < dateTimeNow) {
        err.message = "Invalid data (expiry)";
        err.access_id = id;
        return END_ERROR(res, 400, err);
      }
    } else newExpiryTime = DateTime.now().plus({ years: 1 });

    try {
      /* left join on rows without caps will return NULLs
       * so check if capability status is active or NULL */
      const check = await pool.query(
        "SELECT access_item_type, expiry FROM consent.access" +
          " WHERE access.id = $1::integer" +
          " AND provider_id = $2::integer" +
          " AND access.status = 'active'",
        [id, provider_uid]
      );

      if (check.rows.length === 0) {
        err.message = "Invalid id";
        err.access_id = id;
        return END_ERROR(res, 403, err);
      }

      if (is_delegate && check.rows[0].access_item_type === "provider-caps") {
        err.message = "Delegate cannot update delegate rules";
        return END_ERROR(res, 403, err);
      }

      let oldExpiryTime = check.rows[0].expiry;
      //check if  expirytime from database < now and new expiry time > now

      if (oldExpiryTime > dateTimeNow) {
        err.message = "Cannot renew policy (not expired)";
        err.access_id = id;
        return END_ERROR(res, 400, err);
      }
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }
  }
  //update expiryTime and updated at in databse for the access id
  for (const obj of request) {
    let newExpiryTime;
    if (obj.expiry_time !== undefined) {
      newExpiryTime = obj.expiry_time;
    } else {
      newExpiryTime = DateTime.now().plus({ years: 1 });
    }

    try {
      const result = await pool.query(
        " UPDATE consent.access SET expiry = $1::timestamp," +
          " updated_at = NOW() WHERE id = $2::integer",
        [newExpiryTime.toString(), obj.id]
      );
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }

    const details = {
      provider: provider_email,
      delegated: is_delegate,
      performed_by: email,
    };

    log("info", "UPDATED_POLICY", true, details);
  }

  return END_SUCCESS(res);
});

app.delete("/auth/v[1-2]/provider/access", async (req, res) => {
  const email = res.locals.email;

  let provider_uid, delegate_rid, provider_email;
  let is_delegate = false;
  let rules_array = [];
  let to_delete = [];

  try {
    provider_uid = await check_privilege(email, "provider");
  } catch (error) {
    is_delegate = true;
  }

  if (is_delegate) {
    provider_email = req.headers["provider-email"];
    if (!provider_email || !is_valid_email(provider_email))
      return END_ERROR(res, 400, "Invalid data (provider_email)");

    try {
      provider_uid = await check_privilege(provider_email, "provider");
      let delegate_uid = await check_privilege(email, "delegate");
      delegate_rid = await check_valid_delegate(delegate_uid, provider_uid);
    } catch (error) {
      return END_ERROR(res, 401, "Not allowed");
    }
  } else {
    provider_email = email;
  }

  const email_domain = provider_email.split("@")[1];
  const sha1_of_email = sha1(provider_email);
  const provider_id_hash = email_domain + "/" + sha1_of_email;

  const request = res.locals.body;

  if (!Array.isArray(request) || !request.length)
    return END_ERROR(res, 400, "Invalid data (body)");

  for (const obj of request) {
    if (typeof obj !== "object" || obj === null)
      return END_ERROR(res, 400, "Invalid data (body)");

    let id = obj.id;
    let capability = obj.capabilities || null;
    let delete_rule = false;
    let accesser_email, accesser_role, resource;
    let access_item_id, access_item_type, role_id;
    let caps_object;

    let err = {
      message: "",
      access_id: undefined,
    };

    id = parseInt(id, 10);

    if (isNaN(id) || id < 1 || id > PG_MAX_INT) {
      err.message = "Invalid data (id)";
      err.access_id = id;
      return END_ERROR(res, 400, err);
    }

    err.access_id = id;

    try {
      /* left join on rows without caps will return NULLs
       * so check if capability status is active or NULL */
      const check = await pool.query(
        "SELECT access.*, capability FROM consent.access" +
          " LEFT JOIN consent.capability ON access_id = " +
          " access.id WHERE access.id = $1::integer" +
          " AND provider_id = $2::integer" +
          " AND access.status = 'active'" +
          " AND (capability.status = 'active'" +
          " OR capability.status IS NULL)",
        [id, provider_uid]
      );

      if (check.rows.length === 0) {
        err.message = "Invalid id";
        return END_ERROR(res, 403, err);
      }

      if (is_delegate && check.rows[0].access_item_type === "provider-caps") {
        err.message = "Delegate cannot delete delegate rules";
        return END_ERROR(res, 403, err);
      }

      role_id = check.rows[0].role_id;
      access_item_id = check.rows[0].access_item_id;
      access_item_type = check.rows[0].access_item_type;

      let existing_caps = [...new Set(check.rows.map((row) => row.capability))];

      /* remove nulls */
      existing_caps = existing_caps.filter((val) => val !== null);

      if (!["provider-caps", "catalogue"].includes(access_item_type)) {
        const result = await pool.query(
          "SELECT * FROM consent." +
            access_item_type +
            " WHERE id = $1::integer",
          [access_item_id]
        );

        resource = result.rows[0].cat_id;
      }

      /* if there are caps, must be a consumer rule
       * if capability field not there, treat as normal
       * rule and delete fully */

      if (existing_caps.length > 0 && capability) {
        let resource_server = resource.split("/")[2];
        caps_object = CAPS[resource_server];

        if (
          !Array.isArray(capability) ||
          capability.length > Object.keys(caps_object.consumer).length ||
          capability.length === 0
        ) {
          err.message = "Invalid data (capabilities)";
          return END_ERROR(res, 400, err);
        }

        capability = [...new Set(capability)];

        if (
          !capability.every((val) =>
            Object.keys(caps_object.consumer).includes(val)
          )
        ) {
          err.message = "Invalid data (capabilities)";
          return END_ERROR(res, 400, err);
        }

        /* should be something common between requested and existing */
        let matching = intersect(existing_caps, capability);

        if (matching.length !== capability.length) {
          err.message = "Invalid id";
          return END_ERROR(res, 403, err);
        }

        /* if deleting all existing capabilities - delete rule itself */
        if (matching.length === existing_caps.length) delete_rule = true;
      } else delete_rule = true;

      const user_details = await pool.query(
        "SELECT email, role FROM consent.users" +
          " JOIN consent.role ON users.id = " +
          " role.user_id WHERE role.id = $1::integer",
        [role_id]
      );

      accesser_email = user_details.rows[0].email;
      accesser_role = user_details.rows[0].role;
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }

    for (const i of to_delete) {
      if (i.id === id) {
        if (!i.capability) {
          err.message = "Duplicate data";
          return END_ERROR(res, 400, err);
        } /* check if ids same, but diff in caps to be deleted */ else {
          let duplicate = intersect(capability, i.capability);

          if (duplicate.length !== 0) {
            err.message = "Duplicate data";
            return END_ERROR(res, 400, err);
          }
        }
      }
    }

    to_delete.push({
      id: id,
      capability: capability,
      delete_rule: delete_rule,
      accesser_email: accesser_email,
      accesser_role: accesser_role,
      resource: resource || null,
    });
  }

  if (to_delete.length === 0) return END_ERROR(res, 500, "Internal error!");

  for (const obj of to_delete) {
    const { id, capability, delete_rule } = obj;
    const { accesser_email, accesser_role } = obj;
    const { resource } = obj;

    if (delete_rule === true) {
      try {
        const result = await pool.query(
          " UPDATE consent.access SET status = 'deleted'," +
            " updated_at = NOW() WHERE id = $1::integer",
          [id]
        );

        /* in case capabilities are there, then set those also as deleted */
        const result_caps = await pool.query(
          " UPDATE consent.capability SET status = 'deleted'," +
            " updated_at = NOW() WHERE access_id = $1::integer",
          [id]
        );

        const result_token_access = await pool.query(
          " UPDATE consent.token_access SET status = 'revoked'," +
            " updated_at = NOW() WHERE access_id = $1::integer",
          [id]
        );

        if (result.rowCount === 0) throw new Error("Error in deletion");
      } catch (error) {
        return END_ERROR(res, 500, "Internal error!", error);
      }
    } else {
      try {
        const result = await pool.query(
          " UPDATE consent.capability SET status = 'deleted'," +
            " updated_at = NOW() WHERE access_id = $1::integer" +
            " AND capability = ANY ($2::consent.capability_enum[])",
          [id, capability]
        );

        if (result.rowCount === 0) throw new Error("Error in deletion");

        const check = await pool.query(
          "SELECT capability FROM consent.capability" +
            " WHERE access_id = $1::integer" +
            " AND status = 'active'",
          [id]
        );

        let existing_caps = [
          ...new Set(check.rows.map((row) => row.capability)),
        ];

        if (existing_caps.length === 0) {
          /* delete rule itself, since no caps are there */
          const result = await pool.query(
            " UPDATE consent.access SET status = 'deleted'," +
              " updated_at = NOW() WHERE id = $1::integer",
            [id]
          );

          const result_token_access = await pool.query(
            " UPDATE consent.token_access SET status = 'revoked'," +
              " updated_at = NOW() WHERE access_id = $1::integer",
            [id]
          );

          if (result.rowCount === 0) throw new Error("Error in deletion");
        }
      } catch (error) {
        return END_ERROR(res, 500, "Internal error!", error);
      }
    }

    const details = {
      provider: provider_email,
      accesser: accesser_email,
      role: accesser_role,
      resource_id: resource || null,
      capabilities: null,
      delegated: is_delegate,
      performed_by: email,
    };

    /* if consumer rule, log explicit capabilities deleted or
     * empty array for all capabilities */
    if (accesser_role === "consumer") details.capabilities = capability || [];

    log("info", "DELETED_POLICY", true, details);
  }

  return END_SUCCESS(res);
});

app.get("/auth/v[1-2]/delegate/providers", async (req, res) => {
  const email = res.locals.email;
  let delegate_uid,
    organizations = [];
  let provider_details = [];

  try {
    delegate_uid = await check_privilege(email, "delegate");
  } catch (error) {
    return END_ERROR(res, 401, "Not allowed");
  }

  try {
    const rid = await pool.query(
      "SELECT id FROM consent.role" +
        " WHERE role.user_id = $1::integer" +
        " AND role = 'delegate'",
      [delegate_uid]
    );

    provider_details = await pool.query(
      "SELECT email, title, first_name, last_name," +
        " organization_id" +
        " FROM consent.access JOIN consent.users" +
        " ON access.provider_id = users.id" +
        " WHERE role_id = $1::integer" +
        " AND access.status= 'active'" +
        " AND access.expiry > NOW()",
      [rid.rows[0].id]
    );

    if (provider_details.rows.length === 0)
      return END_ERROR(res, 404, "Not approved by any providers");

    const org_ids = provider_details.rows.map((row) => {
      return row.organization_id;
    });

    organizations = await pool.query(
      "SELECT * FROM consent.organizations" + " WHERE id = ANY($1::integer[])",
      [org_ids]
    );
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  const result = provider_details.rows.map((row) => {
    const organization =
      organizations.rows.filter((org) => row.organization_id === org.id)[0] ||
      null;
    const res = {
      title: row.title,
      first_name: row.first_name,
      last_name: row.last_name,
      email: row.email,
    };

    if (organization === null) {
      res.organization = null;
    } else {
      res.organization = {
        name: organization.name,
        website: organization.website,
        city: organization.city,
        state: organization.state,
        country: organization.country,
      };
    }

    return res;
  });

  return END_SUCCESS(res, result);
});

/* --- Auth Admin APIs --- */

app.get("/auth/v[1-2]/admin/provider/registrations", async (req, res) => {
  const email = res.locals.email;

  try {
    let admin_uid = await check_privilege(email, "admin");
  } catch (e) {
    return END_ERROR(res, 403, "Not allowed");
  }

  const filter = req.query.filter || "pending";
  let users, organizations;
  try {
    users = pg.querySync(
      "SELECT * FROM consent.users, consent.role" +
        " WHERE consent.users.id = consent.role.user_id " +
        " AND status = $1::consent.status_enum",
      [filter]
    );
    let organization_ids = [
      ...new Set(users.map((row) => row.organization_id)),
    ];
    let params = organization_ids.map((_, i) => "$" + (i + 1)).join(",");
    organizations = pg.querySync(
      "SELECT * FROM consent.organizations WHERE id IN (" + params + ");",
      organization_ids
    );
  } catch (e) {
    return END_ERROR(res, 400, "Invalid filter value");
  }
  const result = users.map((user) => {
    const organization =
      organizations.filter((org) => user.organization_id === org.id)[0] || null;
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
        country: organization.country,
      };
    }
    return res;
  });
  return END_SUCCESS(res, result);
});

app.put(
  "/auth/v[1-2]/admin/provider/registrations/status",
  async (req, res) => {
    const email = res.locals.email;

    try {
      let admin_uid = await check_privilege(email, "admin");
    } catch (e) {
      return END_ERROR(res, 403, "Not allowed");
    }

    const user_id = req.query.user_id || null;
    const status = req.query.status || null;
    if (
      user_id === null ||
      status === null ||
      !["approved", "rejected"].includes(status)
    ) {
      return END_ERROR(res, 400, "Missing or invalid information");
    }
    let user, csr, org, role;
    try {
      user =
        pg.querySync(
          "SELECT users.*, role.role, role.status FROM consent.users, consent.role " +
            " WHERE consent.users.id = consent.role.user_id AND role.role = 'provider'" +
            " AND consent.users.id = $1::integer",
          [user_id]
        )[0] || null;
      csr =
        pg.querySync(
          "SELECT * FROM consent.certificates WHERE user_id = $1::integer",
          [user_id]
        )[0] || null;
      org =
        pg.querySync(
          "SELECT * FROM consent.organizations WHERE id = $1::integer",
          [user.organization_id]
        )[0] || null;
      if (user === null || csr === null) {
        return END_ERROR(res, 404, "User information not found");
      }
      if (user.status !== "pending") {
        return END_ERROR(res, 400, "User registration flow is complete");
      }
    } catch (e) {
      return END_ERROR(res, 400, "Missing or invalid information");
    }

    if (status === "rejected") {
      // Update role table with status = rejected and return updated user
      role = pg.querySync(
        "UPDATE consent.role SET status = $1::consent.status_enum, updated_at = NOW() " +
          " WHERE user_id = $2::integer RETURNING *",
        [status, user.id]
      )[0];

      const details = {
        id: user.email,
        organization: org.name,
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
      if (signed_cert === null) {
        throw "Unable to generate certificate";
      }
    } catch (e) {
      return END_ERROR(res, 500, "Certificate Error", e.message);
    }

    // Update role table with status = approved
    // Update certificates table with cert = signed_cert
    role = pg.querySync(
      "UPDATE consent.role SET status = $1::consent.status_enum, " +
        " updated_at = NOW() WHERE user_id = $2::integer RETURNING * ",
      [status, user_id]
    )[0];
    pg.querySync(
      "UPDATE consent.certificates SET cert = $1::text, updated_at = NOW() " +
        " WHERE user_id = $2::integer",
      [signed_cert, user_id]
    );
    user = pg.querySync("SELECT * FROM consent.users WHERE id = $1::integer", [
      user_id,
    ])[0];

    // Send email to user with cert attached and return updated user
    const message = {
      from: '"IUDX Admin" <noreply@iudx.org.in>',
      to: user.email,
      subject: "New Provider Registration",
      text:
        "Congratulations! Your IUDX Provider Registration is complete.\n\n" +
        "Please use the attached cert.pem file for all future API calls and to login at the Provider Dashboard.\n\n" +
        "Thank You!",
      attachments: [{ filename: "cert.pem", content: signed_cert }],
    };
    transporter.sendMail(message, function (error, info) {
      if (error) log("err", "MAILER_EVENT", true, {}, error.toString());
      else log("info", "MAIL_SENT", false, info);
    });

    const details = {
      id: user.email,
      organization: org.name,
    };

    log("info", "PROVIDER_APPROVED", false, details);

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
);

app.post("/auth/v[1-2]/admin/organizations", async (req, res) => {
  const email = res.locals.email;

  try {
    let admin_uid = await check_privilege(email, "admin");
  } catch (e) {
    return END_ERROR(res, 403, "Not allowed");
  }

  const org = res.locals.body.organization;
  let real_domain;
  if (
    !org ||
    !org.name ||
    !org.website ||
    !org.city ||
    !org.state ||
    !org.country
  )
    return END_ERROR(res, 400, "Invalid data (organization)");
  if (org.state.length !== 2 || org.country.length !== 2)
    return END_ERROR(res, 400, "Invalid data (organization)");
  if ((real_domain = domain.get(org.website)) === null)
    return END_ERROR(res, 400, "Invalid data (organization)");

  const existing_orgs = await pool.query(
    "SELECT id FROM consent.organizations WHERE website = $1::text",
    [real_domain]
  );
  if (existing_orgs.rows.length !== 0)
    return END_ERROR(
      res,
      403,
      `Invalid data (organization already exists, id: ${existing_orgs.rows[0].id})`
    );

  const new_org = await pool.query(
    "INSERT INTO consent.organizations (name, website, city, state, country, created_at, updated_at) " +
      "VALUES ($1::text,  $2::text, $3::text, $4::text, $5::text, NOW(), NOW()) " +
      "RETURNING id, name, website, city, state, country, created_at",
    [
      org.name, //$1
      real_domain, //$2
      org.city, //$3
      org.state.toUpperCase(), //$4
      org.country.toUpperCase(), //$5
    ]
  );

  const details = {
    name: org.name,
  };

  log("info", "ORG_CREATED", false, details);

  return END_SUCCESS(res, { organizations: new_org.rows });
});

app.delete("/auth/v[1-2]/admin/users", async (req, res) => {
  const email = res.locals.email;
  let uid = null,
    role_count = 0;
  let is_provider = true,
    is_otherrole = true;

  try {
    let admin_uid = await check_privilege(email, "admin");
  } catch (e) {
    return END_ERROR(res, 403, "Not allowed");
  }

  let email_todel = res.locals.body.email;

  if (!is_valid_email(email_todel))
    return END_ERROR(res, 400, "Invalid data (email)");

  email_todel = email_todel.toLowerCase();

  try {
    uid = await check_privilege(email_todel, "provider");
  } catch (error) {
    is_provider = false;
  }

  for (const val of ACCESS_ROLES) {
    try {
      uid = await check_privilege(email_todel, val);
    } catch (error) {
      role_count++;
    }
  }

  if (role_count === ACCESS_ROLES.length) is_otherrole = false;

  if (!is_provider && !is_otherrole)
    return END_ERROR(res, 400, "Invalid email");

  /* should never happen */
  if (is_provider && is_otherrole)
    return END_ERROR(res, 500, "Internal error!");

  try {
    let result = await pool.query(
      "DELETE FROM consent.users WHERE id = $1::integer",
      [uid]
    );

    if (result.rowCount === 0) throw new Error("Error in deletion");
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  const details = { email: email_todel, admin: email };
  log("info", "USER_DELETED", false, details);

  return END_SUCCESS(res);
});

/* --- Consent APIs --- */

app.post("/consent/v[1-2]/provider/registration", async (req, res) => {
  let email = res.locals.body.email;
  const phone = res.locals.body.phone;
  let org_id = res.locals.body.organization;
  const name = res.locals.body.name;
  const raw_csr = res.locals.body.csr;
  let user_id;

  const phone_regex = new RegExp(/^[9876]\d{9}$/);

  if (!name || !name.title || !name.firstName || !name.lastName)
    return END_ERROR(res, 400, "Invalid data (name)");

  if (
    !is_name_safe(name.title, true) ||
    !is_name_safe(name.firstName) ||
    !is_name_safe(name.lastName)
  )
    return END_ERROR(res, 400, "Invalid data (name)");

  if (!raw_csr || raw_csr.length > CSR_SIZE)
    return END_ERROR(res, 400, "Invalid data (csr)");

  if (!is_valid_email(email))
    return END_ERROR(res, 400, "Invalid data (email)");

  email = email.toLowerCase();

  if (!phone_regex.test(phone))
    return END_ERROR(res, 400, "Invalid data (phone)");

  if (!org_id) return END_ERROR(res, 400, "Invalid data (organization)");

  org_id = parseInt(org_id, 10);

  if (isNaN(org_id) || org_id < 1 || org_id > PG_MAX_INT)
    return END_ERROR(res, 400, "Invalid data (organization)");

  try {
    let csr = forge.pki.certificationRequestFromPem(raw_csr);
    csr.verify();
  } catch (error) {
    return END_ERROR(res, 400, "Invalid data (csr)");
  }

  try {
    const exists = await pool.query(
      " SELECT * FROM consent.users " + " WHERE email = $1::text",
      [email]
    );

    if (exists.rows.length !== 0) return END_ERROR(res, 403, "Email exists");

    const org_reg = await pool.query(
      " SELECT * FROM consent.organizations " + " WHERE id = $1::integer",
      [org_id]
    );

    if (org_reg.rows.length === 0)
      return END_ERROR(res, 403, "Invalid organization");

    let domain = org_reg.rows[0].website;
    let email_domain = email.split("@")[1];

    // check if org domain matches email domain
    if (email_domain !== domain)
      return END_ERROR(res, 403, "Invalid data (domains do not match)");
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  try {
    const user = await pool.query(
      " INSERT INTO consent.users " +
        " (title, first_name, last_name, " +
        " email, phone, organization_id,  " +
        " created_at ,updated_at) VALUES ( " +
        " $1::text, $2::text, $3::text, " +
        " $4::text, $5::text, $6::int, NOW(), NOW() )" +
        " RETURNING id",
      [
        name.title, //$1
        name.firstName, //$2
        name.lastName, //$3
        email, //$4
        phone, //$5
        org_id, //$6
      ]
    );

    user_id = user.rows[0].id;

    const role = await pool.query(
      " INSERT INTO consent.role " +
        " (user_id, role, status, created_at, " +
        " updated_at) VALUES ( " +
        " $1::int, $2::consent.role_enum, " +
        " $3::consent.status_enum, NOW(), NOW() )",
      [
        user_id, //$1
        "provider", //$2
        "pending", //$3
      ]
    );

    const cert = await pool.query(
      " INSERT INTO consent.certificates " +
        " (user_id, csr, cert, created_at, " +
        " updated_at) VALUES ( " +
        " $1::int, $2::text, $3::text, " +
        " NOW(), NOW() )",
      [
        user_id, //$1
        raw_csr, //$2
        null, //$3
      ]
    );
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  const mail = {
    from: '"IUDX Admin" <noreply@iudx.org.in>',
    to: email,
    subject: "Provider Registration Successful !!!",
    text:
      " Hello " +
      name.firstName +
      ". Your" +
      " provider registration request has been" +
      " accepted, and is pending approval. ",
  };

  transporter.sendMail(mail, function (error, info) {
    if (error) log("err", "MAILER_EVENT", true, {}, error.toString());
    else log("info", "MAIL_SENT", false, info);
  });

  const details = {
    email: email,
    org_id: org_id,
  };

  log("info", "PROVIDER_REGISTERED", false, details);

  return END_SUCCESS(res);
});

app.post("/consent/v[1-2]/registration", async (req, res) => {
  let email = res.locals.body.email;
  let phone = res.locals.body.phone;
  const name = res.locals.body.name;
  let raw_csr = res.locals.body.csr;
  let org_id = res.locals.body.organization;
  let roles = res.locals.body.roles;

  let user_id,
    signed_cert = null;
  let check_orgid = false;
  let check_phone;
  let existing_user = false;
  let message;

  const phone_regex = new RegExp(/^[9876]\d{9}$/);

  if (!name || !name.title || !name.firstName || !name.lastName)
    return END_ERROR(res, 400, "Invalid data (name)");

  if (
    !is_name_safe(name.title, true) ||
    !is_name_safe(name.firstName) ||
    !is_name_safe(name.lastName)
  )
    return END_ERROR(res, 400, "Invalid data (name)");

  if (!is_valid_email(email))
    return END_ERROR(res, 400, "Invalid data (email)");

  email = email.toLowerCase();

  if (phone && !phone_regex.test(phone))
    return END_ERROR(res, 400, "Invalid data (phone)");

  if (!phone) phone = PHONE_PLACEHOLDER; // phone has not null constraint

  if (
    !Array.isArray(roles) ||
    roles.length > ACCESS_ROLES.length ||
    roles.length === 0
  )
    return END_ERROR(res, 400, "Invalid data (roles)");

  // get unique elements
  roles = [...new Set(roles)];

  if (!roles.every((val) => ACCESS_ROLES.includes(val)))
    return END_ERROR(res, 400, "Invalid data (roles)");

  /* delegate needs valid phone no. for OTP */
  if (roles.includes("delegate") && phone === PHONE_PLACEHOLDER)
    return END_ERROR(res, 400, "Invalid data (phone)");

  if (
    roles.includes("onboarder") ||
    roles.includes("data ingester") ||
    roles.includes("delegate")
  ) {
    let domain;

    if (!org_id) return END_ERROR(res, 400, "Invalid data (organization)");

    org_id = parseInt(org_id, 10);

    if (isNaN(org_id) || org_id < 1 || org_id > PG_MAX_INT)
      return END_ERROR(res, 400, "Invalid data (organization)");

    // check if org registered
    try {
      const results = await pool.query(
        " SELECT * FROM consent.organizations " + " WHERE id = $1::integer",
        [org_id]
      );

      if (results.rows.length === 0)
        return END_ERROR(res, 403, "Invalid organization");

      domain = results.rows[0].website;
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }

    let email_domain = email.split("@")[1];

    // check if org domain matches email domain
    if (email_domain !== domain)
      return END_ERROR(res, 403, "Invalid data (domains do not match)");
  } else org_id = null; // in the case of consumer

  try {
    // check if the user exists

    const check_uid = await pool.query(
      " SELECT * FROM consent.users" + " WHERE consent.users.email = $1::text ",
      [email]
    );

    if (check_uid.rows.length !== 0) {
      existing_user = true;
      user_id = check_uid.rows[0].id;

      /* if registered as consumer first, org_id will be undefined */
      check_orgid = check_uid.rows[0].organization_id;

      /* if registered as some other role first, phone number
       * may be placeholder */
      check_phone = check_uid.rows[0].phone;

      /* check if user has registered as provider before
       * If yes, do not allow creation of new roles for that user */
      const check = await pool.query(
        "SELECT * FROM consent.role" +
          " WHERE role.user_id = $1::integer" +
          " AND role = 'provider'",
        [user_id]
      );

      if (check.rows.length !== 0) return END_ERROR(res, 403, "Email exists");

      /* check if user is trying to register for role
       * that they are already registered for */
      for (const val of roles) {
        let uid = null;

        try {
          uid = await check_privilege(email, val);
        } catch (error) {
          /* do nothing if role not there */
        }

        if (uid !== null)
          return END_ERROR(res, 403, "Already registered as " + val);
      }

      message =
        "Since you have registered before, please continue " +
        "to use the certificate that was sent before.";
    }
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  if (!existing_user) {
    // generate certificate
    if (!raw_csr || raw_csr.length > CSR_SIZE)
      return END_ERROR(res, 400, "Invalid data (csr)");

    try {
      let csr = forge.pki.certificationRequestFromPem(raw_csr);
      csr.verify();
    } catch (error) {
      return END_ERROR(res, 400, "Invalid data (csr)");
    }

    let user_details = { email: email };

    try {
      signed_cert = sign_csr(raw_csr, user_details);
      if (signed_cert === null) {
        throw "Unable to generate certificate";
      }
    } catch (e) {
      return END_ERROR(res, 500, "Certificate Error", e.message);
    }

    try {
      const user = await pool.query(
        " INSERT INTO consent.users " +
          " (title, first_name, last_name, " +
          " email, phone, organization_id,  " +
          " created_at ,updated_at) VALUES ( " +
          " $1::text, $2::text, $3::text, " +
          " $4::text, $5::text, $6::int, NOW(), NOW() )" +
          " RETURNING id",
        [
          name.title, //$1
          name.firstName, //$2
          name.lastName, //$3
          email, //$4
          phone, //$5
          org_id, //$6
        ]
      );

      user_id = user.rows[0].id;

      const cert = await pool.query(
        " INSERT INTO consent.certificates " +
          " (user_id, csr, cert, created_at, " +
          " updated_at) VALUES ( " +
          " $1::int, $2::text, $3::text, " +
          " NOW(), NOW() )",
        [
          user_id, //$1
          raw_csr, //$2
          signed_cert, //$3
        ]
      );
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }

    message = "A certificate has been generated and sent to your email";
  }

  /* update org_id if the user was originally a consumer
   * (org_id would be null) */
  if (check_orgid === undefined) {
    try {
      const update = await pool.query(
        "UPDATE consent.users SET" +
          " organization_id = $1::integer" +
          " WHERE email = $2::text",
        [org_id, email]
      );
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }
  }

  /* update phone if the user was originally a some other role
   * (phone might be placeholder) */
  if (check_phone === PHONE_PLACEHOLDER) {
    try {
      const update = await pool.query(
        "UPDATE consent.users SET" +
          " phone = $1::text" +
          " WHERE email = $2::text",
        [phone, email]
      );
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }
  }

  // insert roles
  for (const val of roles) {
    try {
      const role = await pool.query(
        " INSERT INTO consent.role " +
          " (user_id, role, status, created_at, " +
          " updated_at) VALUES ( " +
          " $1::int, $2::consent.role_enum, " +
          " $3::consent.status_enum, NOW(), NOW() )",
        [
          user_id, //$1
          val, //$2
          "approved", //$3
        ]
      );
    } catch (error) {
      return END_ERROR(res, 500, "Internal error!", error);
    }
  }

  if (signed_cert !== null) {
    const mail = {
      from: '"IUDX Admin" <noreply@iudx.org.in>',
      to: email,
      subject: "New " + roles.toString() + " Registration",
      text:
        "Congratulations! Your IUDX " +
        roles.toString() +
        " Registration is complete.\n\n" +
        "Please use the attached cert.pem file for all future API calls.\n\n" +
        "Thank You!",
      attachments: [{ filename: "cert.pem", content: signed_cert }],
    };

    transporter.sendMail(mail, function (error, info) {
      if (error) log("err", "MAILER_EVENT", true, {}, error.toString());
      else log("info", "MAIL_SENT", false, info);
    });
  }

  const response = { success: true, message: message };

  const details = {
    id: email,
    roles: roles,
    org_id: org_id,
  };

  log("info", "USER_REGISTERED", false, details);

  return END_SUCCESS(res, response);
});

app.get("/consent/v[1-2]/organizations", async (req, res) => {
  let { rows } = await pool.query("SELECT id, name FROM consent.organizations");
  return END_SUCCESS(res, { organizations: rows });
});

//two factor auth
app.post("/auth/v1/get-session-id", async (req, res) => {
  let method;
  let endpoint;
  let roles;
  let reqObj = res.locals.body;
  let is_delegate = false;
  let userRole;
  let titles;
  let expTime;
  let retryTime;
  let role_id;
  let user_id;
  let allowed_roles = [];

  //get details from user table
  const email = res.locals.email;
  try {
    let result = await pool.query(
      "SELECT users.id, users.title, users.first_name, users.last_name, users.phone , role.role " +
        "FROM  consent.users, consent.role " +
        "WHERE email = $1::text AND users.id = role.user_id AND role.status =  $2::consent.status_enum",
      [email, "approved"]
    );

    if (result.rows.length === 0) return END_ERROR(res, 403, "User not found");

    titles = result.rows[0];
    userRole = result.rows.map((row) => row.role); //run a map to ensure all roles are in an array
    user_id = titles.id;
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  //get all the methods and endpoints from the request
  let apis = {};

  if (reqObj.apis === undefined)
    return END_ERROR(res, 400, "Invalid data (apis)");

  if (!Array.isArray(reqObj.apis))
    return END_ERROR(res, 400, "Invalid data (apis)");

  if (reqObj.apis.length <= 0)
    return END_ERROR(res, 400, "Invalid data (apis)");

  for (let i in reqObj.apis) {
    if (
      reqObj.apis[i].method === undefined ||
      reqObj.apis[i].endpoint === undefined
    )
      return END_ERROR(res, 400, "Invalid data (apis)");

    if (
      !is_string_safe(reqObj.apis[i].method) ||
      !is_string_safe(reqObj.apis[i].endpoint)
    )
      return END_ERROR(res, 400, "Invalid data (apis)");

    method = reqObj.apis[i].method.toUpperCase();
    endpoint = reqObj.apis[i].endpoint.toLowerCase();

    if (!SECURED_ENDPOINTS[endpoint])
      return END_ERROR(res, 400, "No matching endpoint.");

    roles = SECURED_ENDPOINTS[endpoint][method];

    if (roles === undefined)
      return END_ERROR(res, 400, "No matching endpoint/method.");

    allowed_roles = intersect(roles, userRole);

    if (allowed_roles.length === 0)
      return END_ERROR(res, 400, "No matching endpoint/method.");

    //check if api.endpoint exists, if not create and add method as array elemets against this key value

    if (!apis.hasOwnProperty(endpoint)) apis[endpoint] = [];

    //avoid multiple entries for same method under same endpoint
    if (!apis[endpoint].includes(method)) apis[endpoint].push(method);
  }

  //generate session_id
  const session_id = generateSessionId(twoFA_config.sessionIdLen);

  /* The Sms_Service is only called when
	   the node environment is not set as development */
  try {
    if (process.env.NODE_ENV !== "development")
      await SMS_Service(session_id, titles.phone);
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  try {
    const time = await pool.query(
      " INSERT INTO consent.session " +
        "(session_id, user_id, endpoints, expiry_time, retry_time, created_at, updated_at)" +
        "VALUES ( " +
        " $1::text ,  $2::int, $3::json," +
        " NOW() + $4::interval, NOW() + $5::interval, NOW(), NOW() )" +
        "RETURNING expiry_time,retry_time",
      [
        session_id, //$2
        user_id, //$3
        apis, //$4
        SESSIONID_EXP_TIME + " seconds",
        SESSIONID_EXP_TIME + " seconds",
      ]
    );

    expTime = time.rows[0].expiry_time;
    retryTime = time.rows[0].retry_time;
  } catch (error) {
    return END_ERROR(res, 500, "Internal error!", error);
  }

  const response = {
    success: true,
    message: "Session id sent to mobile no",
    Validity: expTime,
  };

  const details = {
    requester: email,
    sessionId_expiry: expTime,
  };

  log("info", "ISSUED_SESSIONID", false, details);

  return END_SUCCESS(res, response);
});

/* --- Invalid requests --- */

app.all("/*", (req, res) => {
  const doc = " Please visit <https://authdocs.iudx.org.in> for documentation";

  if (req.method === "POST") {
    return END_ERROR(res, 404, "No such API." + doc);
  } else if (req.method === "GET") {
    return END_ERROR(res, 404, "No such API." + doc);
  } else {
    return END_ERROR(res, 405, "Method must be POST, PUT or GET" + doc);
  }
});

app.on("error", () => {
  /* nothing */
});

/* --- The main application --- */

function drop_worker_privileges() {
  for (const k in password) {
    password[k] = null;
    delete password[k]; // forget all passwords
  }

  if (EUID === 0) {
    process.setgid("_aaa");
  }

  assert(has_started_serving_apis === false);
}

if (cluster.isMaster) {
  log("info", "EVENT", false, {}, "Master started with pid " + process.pid);

  for (let i = 0; i < NUM_CPUS; i++) {
    cluster.fork();
  }

  cluster.on("exit", (worker) => {
    log(
      "err",
      "WORKER_EVENT",
      true,
      {},
      "Worker " + worker.process.pid + " died."
    );

    cluster.fork();
  });
} else {
  http.createServer(app).listen(3000, "0.0.0.0");

  drop_worker_privileges();

  log(
    "info",
    "WORKER_EVENT",
    false,
    {},
    "Worker started with pid " + process.pid
  );
}

// EOF
