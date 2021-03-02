/* This script converts the policy_text column in the access table
 * to json and inserts into the policy_json column.
 * Move the file to /home/iudx-auth-server and run `node add_json_policy_to_db.js`
 */

"use strict";

const fs = require("fs");
const aperture = require("./node-aperture");
const Pool = require("pg").Pool;

/* --- postgres --- */

const DB_SERVER = "127.0.0.1";

const password = {
  DB: fs.readFileSync("passwords/auth.db.password", "ascii").trim(),
};

const pool = new Pool({
  host: DB_SERVER,
  port: 5432,
  user: "auth",
  database: "postgres",
  password: password.DB,
});

pool.connect();

/* --- aperture --- */

const apertureOpts = {
  types: aperture.types,
  typeTable: {
    ip: "ip",
    time: "time",

    tokens_per_day: "number", // tokens issued today

    api: "string", // the API to be called
    method: "string", // the method for API

    "cert.class": "number", // the certificate class
    "cert.cn": "string",
    "cert.o": "string",
    "cert.ou": "string",
    "cert.c": "string",
    "cert.st": "string",
    "cert.gn": "string",
    "cert.sn": "string",
    "cert.title": "string",

    "cert.issuer.cn": "string",
    "cert.issuer.email": "string",
    "cert.issuer.o": "string",
    "cert.issuer.ou": "string",
    "cert.issuer.c": "string",
    "cert.issuer.st": "string",

    groups: "string", // CSV actually

    country: "string",
    region: "string",
    timezone: "string",
    city: "string",
    latitude: "number",
    longitude: "number",
  },
};
const parser = aperture.createParser(apertureOpts);

async function main() {
  let rules;
  try {
    const result = await pool.query(
      "SELECT id, policy_text FROM consent.access",
      []
    );
    rules = result.rows;
  } catch (error) {
    console.log("Error in query", error);
  }
  for (let rule of rules) {
    let json;
    if (rule.policy_text.length === 0) json = {};
    else json = parser.parse(rule.policy_text);

    try {
      const result = await pool.query(
        "UPDATE consent.access SET policy_json = $1::jsonb WHERE id = $2::integer",
        [json, rule.id]
      );
    } catch (error) {
      console.log("Error in query", error);
    }
  }

  console.log("Done");
  process.exit();
}

main();
