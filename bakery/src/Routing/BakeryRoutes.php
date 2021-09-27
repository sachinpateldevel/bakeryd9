<?php

namespace Drupal\bakery\Routing;

use Symfony\Component\Routing\Route;

/**
 * Defines dynamic routes.
 */
class BakeryRoutes {

  /**
   * {@inheritdoc}
   */
  public function routes() {
    $routes = [];
    if (\Drupal::config('bakery.settings')->get('bakery_is_master')) {
      $routes['bakery.register'] = new Route(
        // Path to attach this route to:
        '/bakery',
        [
          '_controller' => '\Drupal\bakery\Controller\BakeryController::bakeryRegister',
          '_title' => 'Register',
        ],
        [
          '_custom_access'  => '\Drupal\bakery\Controller\BakeryController::userIsAnonymous',
        ]
      );
      $routes['bakery.login'] = new Route(
        // Path to attach this route to:
        '/bakery/login',
        [
          '_controller' => '\Drupal\bakery\Controller\BakeryController::bakeryLogin',
          '_title' => 'Login',
        ],
        [
          '_access' => 'TRUE',
        ]
      );
      $routes['bakery.validate'] = new Route(
        // Path to attach this route to:
        '/bakery/validate',
        [
          '_controller' => '\Drupal\bakery\Controller\BakeryController::bakeryEatThinmintCookie',
          '_title' => 'Validate',
        ],
        [
          '_custom_access'  => '\Drupal\bakery\Controller\BakeryController::bakeryTasteThinmintCookie',
        ]
      );
      $routes['bakery.create'] = new Route(
        // Path to attach this route to:
        '/bakery/create',
        [
          '_controller' => '\Drupal\bakery\Controller\BakeryController::bakeryEatGingerbreadCookie',
          '_title' => 'Bakery create',
        ],
        [
          '_custom_access'  => '\Drupal\bakery\Controller\BakeryController::bakeryTasteGingerbreadCookie',
        ]
      );
    }
    else {
      $routes['bakery.register'] = new Route(
        // Path to attach this route to:
        '/bakery',
        [
          '_controller' => '\Drupal\bakery\Controller\BakeryController::bakeryRegisterReturn',
          '_title' => 'Register',
        ],
        [
          '_access' => 'TRUE',
        ]
      );
      $routes['bakery.login'] = new Route(
        // Path to attach this route to:
        '/bakery/login',
        [
          '_controller' => '\Drupal\bakery\Controller\BakeryController::bakeryLoginReturn',
          '_title' => 'Login',
        ],
        [
          '_access' => 'TRUE'
        ]
      );
      $routes['bakery.update'] = new Route(
        // Path to attach this route to:
        '/bakery/update',
        [
          '_controller' => '\Drupal\bakery\Controller\BakeryController::bakeryEatStroopwafelCookie',
          '_title' => 'Update',
        ],
        [
          '_custom_access'  => '\Drupal\bakery\Controller\BakeryController::bakeryTasteStroopwafelCookie',
        ]
      );

      $routes['bakery.repair'] = new Route(
        // Path to attach this route to:
        '/bakery/repair',
        [
          '_form' => '\Drupal\bakery\Forms\BakeryUncrumbleForm',
          '_title' => 'Repair account',
        ],
        [
          '_custom_access'  => '\Drupal\bakery\Controller\BakeryController::bakeryUncrumbleAccess',
        ]
      );

      $routes['bakery.pull'] = new Route(
        // Path to attach this route to:
        '/admin/config/people/bakery',
        [
          '_form' => '\Drupal\bakery\Forms\BakeryPullForm',
          '_title' => 'Pull Bakery user',
        ],
        [
          '_permission' => 'administer users',
        ]
      );
    }
    return $routes;
  }

}
