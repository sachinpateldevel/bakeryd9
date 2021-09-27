<?php

namespace Drupal\bakery\PageCache;

use Drupal\Core\PageCache\RequestPolicyInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A policy allowing delivery of cached pages when there is no session open.
 *
 * Do not serve cached pages to authenticated users, or to anonymous users when
 * CHOCOLATECHIPCOOKIE exist in the request header.
 */
class BakeryRequestPolicy implements RequestPolicyInterface {

  /**
   * {@inheritdoc}
   */
  public function check(Request $request) {
    if ($this->pregArrayKeyExists('/^CHOCOLATECHIP/', $_COOKIE)) {
      return self::DENY;
    }

    $oatmeal_skip_cache_paths = [
      '/bakery/login'
    ];
    if ($this->pregArrayKeyExists('/^OATMEAL/', $_COOKIE) && in_array($request->getPathInfo(), $oatmeal_skip_cache_paths)) {
      return self::DENY;
    }
  }

  /**
   * Check pattern key exist in array.
   *
   * @param string $pattern
   *   Regex pattern to match key.
   * @param array $array
   *   Array from which key needs to be checked.
   *
   * @return int
   *   if found return positive number else -1
   */
  private function pregArrayKeyExists($pattern, $array) {
    $keys = array_keys($array);
    return (int) preg_grep($pattern, $keys);
  }

}
