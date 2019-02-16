<?php

namespace Placeholder\Vuln;

use Composer\Semver\Semver;
use Symfony\Component\Yaml\Yaml;

class Matcher {

  private $basepath;
  private $semver;

  public function __construct($basepath) {
    $this->basepath = $basepath;
    $this->$semver = new Semver();
  }

  private function anyBranchMatches($vuln, $version) {
    /* * (star) means any version, used for testing. It could be possible
     * to check constraints against constraints instead of versions but
     * it's not done here */
    if ($version === "*") {
      return TRUE;
    }

    foreach ($vuln["branches"] as $name => $branch) {
      $matches = TRUE;
      foreach($branch["versions"] as $constraint) {
        if (!$this->$semver->satisfies($version, $constraint)) {
          $matches = FALSE;
          break;
        }
      }

      if ($matches) {
        /* all version constraints in a branch matched against the given
         * version */
        return TRUE;
      }
    }

    return FALSE;
  }

  /* Match a name (vendor/product) and version against a set of known
   * vulnerabilities. Returns a (possibly empty) array of found
   * vulnerabilities. May throw Semver and Yaml exceptions.*/
  public function match($name, $version) {
    $res = [];

    /* Split the name into vendor/version and do basic input validation */
    $nameparts = explode("/", $name);
    if (sizeof($nameparts) != 2) {
      return $res;
    }
    $vendor  = strtolower($nameparts[0]);
    $product = strtolower($nameparts[1]);
    if ($vendor == "." || $vendor == ".." ||
        $product == "." || $product == "..") {
      return $res;
    }

    /* Open up the directory where the vulnerability information is stored
     * for this vendor/product entry. Iterate over the entries (if any)
     * and match the product version against the version constraints of the
     * vulnerable products branches. If any branch matches, it is added
     * to the result */
    $dirpath = "$this->basepath/$vendor/$product";
    if ($handle = @opendir($dirpath)) {
      while (($entry = readdir($handle)) !== false) {
        if (!(substr($entry, -5) === ".yaml")) {
          continue;
        }

        $vuln = Yaml::parseFile("$dirpath/$entry");
        if ($this->anyBranchMatches($vuln, $version)) {
          $res[] = $vuln;
        }
      }
    }

    return $res;
  }
}
