<?php

namespace Drupal\bakery\EventSubscriber;

/**
 * @file
 * For Boot event subscribe.
 */

use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Drupal\bakery\BakeryService;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * For handling chocolatechip cookie on boot.
 */
class BootSubscriber implements EventSubscriberInterface {

  protected $bakeryService;

  /**
   * Initilizing bakeryService.
   *
   * @param object \Drupal\bakery\BakeryService $bakeryService
   *   Bakery service used.
   */
  public function __construct(BakeryService $bakeryService) {
    $this->bakeryService  = $bakeryService;
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    // Should be called on cached pages also.
    return [
      KernelEvents::REQUEST => ['onRequest', 27],
      KernelEvents::FINISH_REQUEST => ['onFinishRequest', 27]
    ];
  }

  /**
   * On boot event we need to test the cookie.
   */
  public function onRequest(GetResponseEvent $event) {
    // error_log("Here we testing cookie", 0);.
    $result = $this->bakeryService->tasteChocolatechipCookie();
    if ($result instanceof RedirectResponse) {
      $event->setResponse($result);
    }
  }

  /**
   * At the end of request...
   */
  public function onFinishRequest(\Symfony\Component\HttpKernel\Event\FinishRequestEvent $event) {

    //Clean up oatmeal cookies if we've authenticated
    //TODO: Why aren't they being cleaned up properly?
    if (\Drupal::currentUser()->isAuthenticated()) {
      $this->bakeryService->eatCookie('OATMEAL');
    }
  }

}
