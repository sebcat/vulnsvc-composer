<?php

require __DIR__ . "/../vendor/autoload.php";

define("VULNDATA_PATH", __DIR__ .
    "/../vendor/sensiolabs/security-advisories");

/* respond --
 *   Prints a standard-ish response and exit */
function respond($success, $val) {
  $respobj = [
    "success" => $success ? TRUE : FALSE,
  ];

  if ($success) {
    $respobj["data"] = $val;
  } else {
    $respobj["errmsg"] = $val;
  }

  /* XXX: setting the header here assumes nothing is sent already, e.g.,
   *      warning/error text &c */
  header('Content-Type: application/json');
  print(json_encode($respobj));
  exit(0);
}

/* Read input and parse it as JSON, assuming the input is a composer .lock
 * file. Input is read from stdin if PHP is run in CLI mode, which can be
 * useful for testing. */
$input = php_sapi_name() == "cli" ? "php://stdin" : "php://input";
$jsondata = json_decode(file_get_contents($input));
if (!$jsondata || !is_array($jsondata->packages)) {
  respond(FALSE, "no/invalid lockfile supplied");
}

/* Instantiate a vulnerability matcher and use it to match package names
 * and versions against known vulnerabilities. */
$matcher = new Placeholder\Vuln\Matcher(VULNDATA_PATH);
$vulns   = [];
$i       = 0;
foreach ($jsondata->packages as $package) {
  try {
    $res = $matcher->match($package->name, $package->version);
    $vulns = array_merge($vulns, $res);
  } catch (Exception $e) {
    respond(FALSE, "match failure at package index $i");
    /* TODO: log exception? */
  }
  $i++;
}

respond(TRUE, ["vulns" => $vulns]);
