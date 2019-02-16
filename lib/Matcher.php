<?php

namespace Placeholder\Vuln;

use Composer\Semver\Semver;
use Symfony\Component\Yaml\Yaml;

class Matcher {

  private $basepath;

  public function __construct($basepath) {
    $this->basepath = $basepath;
  }

  /* Match a name (vendor/product) and version against a set of known
   * vulnerabilities. Returns a (possibly empty) array of found
   * vulnerabilities. May throw Semver and Yaml exceptions.*/
  public function match($name, $version) {
    $res = [];

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

    $dirpath = "$this->basepath/$vendor/$product";
    if ($handle = @opendir($dirpath)) {
      while (($entry = readdir($handle)) !== false) {
        if (!(substr($entry, -5) === ".yaml")) {
          continue;
        }

        $value = Yaml::parseFile("$dirpath/$entry");
        $res[] = ["title" => $value["title"],
                  "link"  => $value["link"],
                  "cve"   => $value["cve"]];
      }
    }

    $semver = new Semver();
    return $res;//$semver->satisfies($version, $constraints);
  }
}



