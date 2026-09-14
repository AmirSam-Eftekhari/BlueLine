// Intentionally vulnerable fixture. Local test data only.

const { exec } = require("child_process");

function runUserCommand(input) {
  exec("echo " + input); // JS-CHILDPROC-EXEC
}

function renderUser(name) {
  document.getElementById("out").innerHTML = name; // JS-INNERHTML
}

function evalExpr(expr) {
  return eval(expr); // JS-EVAL
}

const API_TOKEN = "sk_live_abcdEFGH12345678"; // JS-HARDCODED-SECRET

function buildQuery(table) {
  return "SELECT * FROM " + table + " WHERE active = 1"; // JS-SQL-CONCAT
}

function verifyToken(token) {
  return jwt.verify(token, null, { algorithms: ["none"] }); // JS-JWT-NONE
}

function insecureRequest() {
  return https.request({ rejectUnauthorized: false }); // JS-NOSNIFF-DISABLED
}

function genId() {
  return Math.random().toString(36); // JS-INSECURE-RANDOM
}

module.exports = { runUserCommand, evalExpr, buildQuery, verifyToken, insecureRequest, genId };
