<?php

namespace Drupal\bakery\Controller;

/**
 * @file
 * Router call back functions for bakery SSO functions.
 */
use Drupal\bakery\BakeryService;
use Drupal\Component\Utility\UrlHelper;
use Drupal\Component\Utility\Xss;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Cache\CacheableMetadata;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Form\FormState;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Url;
use Drupal\user\Entity\User;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Route callback functionlities.
 */
class BakeryController extends ControllerBase {

  protected $bakeryService;

  /**
   * For initilizing bakery service.
   *
   * @param object \Drupal\bakery\BakeryService $bakeryService
   *   For bakery service.
   */
  public function __construct(BakeryService $bakeryService) {
    $this->bakery_service = $bakeryService;
  }

  /**
   * When this controller is created, it will get the bakery.bakery_service.
   *
   * @param object \Symfony\Component\DependencyInjection\ContainerInterface $container
   *   For getting Bakery service.
   *
   * @return static
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('bakery.bakery_service')
    );
  }

  /**
   * Special Bakery register callback registers the user and returns to slave.
   */
  public function bakeryRegister() {

    $cookie = $this->bakeryTasteOatmealCookie();
    if ($cookie) {
      // Valid cookie.
      // Destroy the current oatmeal cookie,
      // we'll set a new one when we return to the slave.
      $this->bakery_service->eatCookie('OATMEAL');
      // TODO: need to fix
      // if (variable_get('user_register', 1)) {.
      if (TRUE) {
        // Users are allowed to register.
        $data = [];
        // Save errors.
        $errors = [];
        $name = trim($cookie['data']['name']);
        $mail = trim($cookie['data']['mail']);

        // Check if user exists with same email.
        $account = user_load_by_mail($mail);
        if ($account) {
          $errors['mail'] = 1;
        }
        else {
          // Check username.
          $account = user_load_by_name($name);
          if ($account) {
            $errors['name'] = 1;
          }
        }
        $oatmeal['name'] = $name;
      }
      else {
        \Drupal::logger('bakery')->error('Master Bakery site user registration is disabled but users are trying to register from a subsite.');
        $errors['register'] = 1;
      }
      if (empty($errors)) {
        // Create user.
        if (!$cookie['data']['pass']) {
          $pass = user_password();
        }
        else {
          $pass = $cookie['data']['pass'];
        }
        $language = \Drupal::languageManager()->getCurrentLanguage()->getId();
        $account = User::create();
        // Mandatory settings.
        $account->setPassword($pass);
        $account->enforceIsNew();
        $account->setEmail($mail);
        // This username must be unique and accept only a-Z,0-9, - _ @ .
        $account->setUsername($name);
        // Optional settings.
        $account->set("init", $mail);
        $account->set("langcode", $language);
        $account->set("preferred_langcode", $language);
        $account->set("preferred_admin_langcode", $language);
        // $user->set("setting_name", 'setting_value');.
        $account->activate();
        // Save user.
        $account->save();
        // Set some info to return to the slave.
        $oatmeal['uid'] = $account->id();
        $oatmeal['mail'] = $mail;
        \Drupal::logger('bakery')->notice('New external user: %name using module bakery from slave !slave.', ['%name' => $account->getUsername(), '!slave' => $cookie['slave']]);
        // Redirect to slave.
        if (!$this->config('user.settings')->get('verify_mail')) {
          // Create identification cookie and log user in.
          $init = $this->bakery_service->initField($account->id());
          $this->bakery_service->bakeChocolatechipCookie($account->getUsername(), $account->getEmail(), $init);
          $this->bakery_service->userExternalLogin($account);
        }
        else {
          // The user needs to validate their email, redirect back to slave to
          // inform them.
          $errors['validate'] = 1;
        }

      }
      else {
        // There were errors.
        \Drupal::service('session_manager')->destroy();
      }

      // Redirect back to custom Bakery callback on slave.      
      // Carry destination through return.
      if (isset($cookie['data']['destination'])) {
        $oatmeal['destination'] = $cookie['data']['destination'];
      }

      $this->bakery_service->bakeOatmealCookie($name, $oatmeal);
      $slave_url = Url::fromUri($cookie['slave']);
      if ($slave_url && $slave_url->isExternal()) {
        return self::trustedRedirect($slave_url->toString() . 'bakery');
      }
    }
    // Invalid request.
    throw new AccessDeniedHttpException();
  }

  /**
   * Special Bakery login callback authenticates the user and returns to slave.
   */
  public function bakeryLogin() {

    $cookie = $this->bakeryTasteOatmealCookie();

    if ($cookie) {
      $errors = [];
      // Remove the data pass cookie.
      $this->bakery_service->eatCookie('OATMEAL');

      // First see if the user_login form validation has any errors for them.
      $name = trim($cookie['data']['name']);
      $pass = trim($cookie['data']['pass']);
      // Execute the login form which checks
      // username, password, status and flood.
      $form_state = new FormState();
      $form_state->setValues([
        'name' => $name,
        'pass' => $pass,
      ]);
      \Drupal::formBuilder()->submitForm('Drupal\user\Form\UserLoginForm', $form_state);
      foreach ($form_state->getErrors() as $error) {
        $errors[] = $error->render();
      }

      $uid = $form_state->get('uid');
      if (empty($uid)) {
        $errors['incorrect-credentials'] = 1;
      }
      $oatmeal = ['errors' => $errors, 'name' => $name];


      if (empty($errors) && !empty($uid)) {
        // Check if account credentials are correct.
        $account = User::load($uid);
        $init = $this->bakery_service->initField($uid);
        if ($account) {
          // Passed all checks, create identification cookie and log in.          
          $this->bakery_service->bakeChocolatechipCookie($account->getUsername(), $account->getEmail(), $init);
          user_login_finalize($account);
          $oatmeal['mail'] = $account->getEmail();
          $oatmeal['init'] = $init;
        }
      }

      if (!empty($errors)) {
        // Report failed login.
        \Drupal::logger('user')->notice('Login attempt failed for %user.', ['%user' => $name]);
        // Clear the messages on the master's session,
        // since they were set during
        // drupal_form_submit() and will be displayed out of context.
        drupal_get_messages();
      }
      // Bake a new cookie for validation on the slave.        
      // Carry destination through login.
      if (isset($cookie['data']['destination'])) {
        $oatmeal['destination'] = $cookie['data']['destination'];
      }

      $this->bakery_service->bakeOatmealCookie($name, $oatmeal);
      $slave_url = Url::fromUri($cookie['slave']);
      if ($slave_url && $slave_url->isExternal()) {
        return self::trustedRedirect($slave_url->toString() . 'bakery/login');
      }
    }

    throw new AccessDeniedHttpException();
  }

  /**
   * Update the user's login time to reflect them validating their email.
   */
  public function bakeryEatThinmintCookie() {
    // Session was set in validate.
    $name = $_SESSION['bakery']['name'];
    unset($_SESSION['bakery']['name']);
    $slave = $_SESSION['bakery']['slave'];
    unset($_SESSION['bakery']['slave']);
    $uid = $_SESSION['bakery']['uid'];
    unset($_SESSION['bakery']['uid']);

    $account = user_load_by_name($name);
    if ($account) {
      // @todo
      \Drupal::database()->query("UPDATE {users_field_data} SET login = :login WHERE uid = :uid", [':login' => $_SERVER['REQUEST_TIME'], ':uid' => $account->id()]);

      // Save UID provided by slave site.
      $this->bakerySaveSlaveUid($account, $slave, $uid);
    }
  }

  /**
   * Respond with account information.
   */
  public function bakeryEatGingerbreadCookie() {
    // Session was set in validate.
    $name = $_SESSION['bakery']['name'];
    unset($_SESSION['bakery']['name']);
    $or_email = $_SESSION['bakery']['or_email'];
    unset($_SESSION['bakery']['or_email']);
    $slave = $_SESSION['bakery']['slave'];
    unset($_SESSION['bakery']['slave']);
    $slave_uid = $_SESSION['bakery']['uid'];
    unset($_SESSION['bakery']['uid']);

    $key = $this->config('bakery.settings')->get('bakery_key');

    $account = user_load_by_name($name);
    if (!$account && $or_email) {
      $account = user_load_by_mail($name);
    }
    if ($account) {
      $this->bakerySaveSlaveUid($account, $slave, $slave_uid);

      $payload = [];
      $payload['name'] = $account->getUsername();
      $payload['mail'] = $account->getEmail();
      // For use in slave init field.
      $payload['uid'] = $account->id();
      // Add any synced fields.
      foreach ($this->config('bakery.settings')->get('bakery_supported_fields') as $type => $enabled) {
        if ($enabled && $account->$type) {
          $payload[$type] = $account->{$type}->getValue();
        }
      }
      $payload['timestamp'] = $_SERVER['REQUEST_TIME'];
      // Respond with encrypted and signed account information.
      $message = $this->bakery_service->bakeData($payload);
    }
    else {
      $message = t('No account found');
      header('HTTP/1.1 409 Conflict');
    }
    $this->moduleHandler()->invokeAll('exit');
    print $message;
    exit();
  }

  /**
   * Custom return for slave registration process.
   *
   * Redirects to the homepage on success or to
   * the register page if there was a problem.
   */
  public function bakeryRegisterReturn() {
    $cookie = $this->bakeryTasteOatmealCookie();

    if ($cookie) {
      // Valid cookie, now destroy it.
      $this->bakery_service->eatCookie('OATMEAL');

      // Destination in cookie was set before user left this site, extract it to
      // be sure destination workflow is followed.
      if (empty($cookie['data']['destination'])) {
        $destination = '/';
      }
      else {
        $destination = $cookie['data']['destination'];
      }

      $errors = isset($cookie['data']['errors']) ? $cookie['data']['errors'] : [];
      if (empty($errors)) {
        \Drupal::messenger()->addMessage(t('Registration successful. You are now logged in.'));
        // Redirect to destination.
        $destination = Url::fromUserInput($destination)->toString();
        return new RedirectResponse($destination);
      }
      else {
        if (!empty($errors['register'])) {
          \Drupal::messenger()->addMessage(t('Registration is not enabled on @master. Please contact a site administrator.', ['@master' => $this->config('bakery.settings')->get('bakery_master')]), 'error');
          \Drupal::logger('bakery')->error('Master Bakery site user registration is disabled', []);
        }
        if (!empty($errors['validate'])) {
          // If the user must validate their email then we need to create an
          // account for them on the slave site.
          // Save a stub account so we have a slave UID to send.
          $language = \Drupal::languageManager()->getCurrentLanguage()->getId();
          $account = User::create();
          // Mandatory settings.
          $account->setPassword(user_password());
          $account->enforceIsNew();
          $account->setEmail($cookie['data']['mail']);
          // This username must be unique and accept only a-Z,0-9, - _ @ .
          $account->setUsername($cookie['name']);
          // Optional settings.
          $account->set("init", $this->bakery_service->initField($cookie['data']['uid']));
          $account->set("langcode", $language);
          $account->set("preferred_langcode", $language);
          $account->set("preferred_admin_langcode", $language);
          // $user->set("setting_name", 'setting_value');.
          $account->activate();
          // Save user.
          $account->save();

          // Notify the user that they need to validate their email.
          _user_mail_notify('register_no_approval_required', $account);
          unset($_SESSION['bakery']['register']);
          \Drupal::messenger()->addMessage(t('A welcome message with further instructions has been sent to your e-mail address.'));
        }
        if (!empty($errors['name'])) {
          \Drupal::messenger()->addMessage(t('Name is already taken.'), 'error');
        }
        if (!empty($errors['mail'])) {
          \Drupal::messenger()->addMessage(t('E-mail address is already registered.'), 'error');
        }
        if (!empty($errors['mail_denied'])) {
          \Drupal::messenger()->addMessage(t('The e-mail address has been denied access..'), 'error');
        }
        if (!empty($errors['name_denied'])) {
          \Drupal::messenger()->addMessage(t('The name has been denied access..'), 'error');
        }
        // There are errors so keep user on registration page.        
        return $this->redirect('user.register')->addCacheableDependency((new CacheableMetadata())->setCacheMaxAge(0));
      }
    }
    throw new AccessDeniedHttpException();
  }

  /**
   * Custom return for errors during slave login process.
   */
  public function bakeryLoginReturn() {
    $cookie = $this->bakeryTasteOatmealCookie();
    if ($cookie) {
      // Valid cookie, now destroy it.
      $this->bakery_service->eatCookie('OATMEAL');

      if (!empty($cookie['data']['errors'])) {
        $errors = $cookie['data']['errors'];
        if (!empty($errors['incorrect-credentials'])) {
          \Drupal::messenger()->addMessage(t('Sorry, unrecognized username or password.'), 'error');
        }
        elseif (!empty($errors['name'])) {
          // In case an attacker got the hash we filter the argument
          // here to avoid exposing a XSS vector.
          \Drupal::messenger()->addMessage(Xss::filter($errors['name']), 'error');
        }
      }
      if (empty($cookie['data']['destination'])) {
        return $this->redirect('user.page');
      }
      else if (!UrlHelper::isExternal($cookie['data']['destination'])) {
        $dest = Url::fromUserInput($cookie['data']['destination'])->toString();
        return new RedirectResponse($dest);
      }
    }
    throw new AccessDeniedHttpException();
  }

  /**
   * Menu callback, invoked on the slave.
   */
  public function bakeryEatStroopwafelCookie() {
    // The session got set during validation.
    $stroopwafel = $_SESSION['bakery'];
    unset($_SESSION['bakery']);

    $init = $this->bakery_service->initField($stroopwafel['uid']);

    // Check if the user exists.
    $account = \Drupal::entityManager()->getStorage('user')->loadByProperties(['init' => $init]);
    if (empty($account)) {
      // User not present.
      $message = t('Account not found on %slave.', ['%slave' => $this->config('system.site')->get('name')]);

    }
    else {
      $account = reset($account);
      drupal_add_http_header('X-Drupal-bakery-UID', $account->id());

      // If profile field is enabled we manually save profile fields along.
      $fields = [];
      foreach ($this->config('bakery.settings')->get('bakery_supported_fields') as $type => $value) {
        if ($value && $account->hasField($type)) {
          // If the field is set in the cookie
          // it's being updated, otherwise we'll
          // populate $fields with the existing
          // values so nothing is lost.
          $account->{$type}->setValue($stroopwafel[$type]);
        }
      }
      

      $status = $account->save();
      if ($status !== SAVED_UPDATED) {
        \Drupal::logger('bakery')
          ->error('User update from name %name_old to %name_new, mail %mail_old to %mail_new failed.', [
            '%name_old' => $account->getUsername(),
            '%name_new' => $stroopwafel['name'],
            '%mail_old' => $account->getEmail(),
            '%mail_new' => $stroopwafel['mail'],
          ]);
        $message = t('There was a problem updating your account on %slave. Please contact the administrator.', [
          '%slave' => $this->config('system.site')->get('name'),
        ]);

        header('HTTP/1.1 409 Conflict');
      }
      else {
        \Drupal::logger('bakery')
          ->notice('user updated name %name_old to %name_new, mail %mail_old to %mail_new.', [
            '%name_old' => $account->getUsername(),
            '%name_new' => $stroopwafel['name'],
            '%mail_old' => $account->getEmail(),
            '%mail_new' => $stroopwafel['mail'],
          ]);
        $message = t('Successfully updated account on %slave.', [
          '%slave' => $this->config('system.site')->get('name'),
        ]);
      }
    }
    $this->moduleHandler()->invokeAll('exit');
    print $message;
    exit();
  }

  /**
   * Save UID provided by a slave site. Should only be used on the master site.
   *
   * @param object $account
   *   A local user object.
   * @param string $slave
   *   The URL of the slave site.
   * @param int $slave_uid
   *   The corresponding UID on the slave site.
   */
  private function bakerySaveSlaveUid($account, $slave, $slave_uid) {
    $slave_user_exists = \Drupal::database()->queryRange("SELECT 1 FROM {bakery_user} WHERE uid = :uid AND slave = :slave", 0, 1, [
      ':uid' => $account->id(),
      ':slave' => $slave,
    ])->fetchField();
    $slaves = $this->config('bakery.settings')->get('bakery_slaves') ?: [];
    if ($this->config('bakery.settings')->get('bakery_is_master') &&
        !empty($slave_uid) &&
        in_array($slave, $slaves) &&
      !$slave_user_exists) {
      $row = [
        'uid' => $account->id(),
        'slave' => $slave,
        'slave_uid' => $slave_uid,
      ];
      \Drupal::database()->insert('bakery_user')->fields($row)->execute();
    }
  }

  /**
   * Validate update request.
   */
  public function bakeryTasteStroopwafelCookie() {
    $type = 'stroopwafel';
    if (empty($_POST[$type])) {
      return AccessResult::forbidden();
    }
    if (($payload = $this->bakery_service->validateData($_POST[$type], $type)) === FALSE) {
      return AccessResult::forbidden();
    }

    $_SESSION['bakery'] = unserialize($payload['data']);
    $_SESSION['bakery']['uid'] = $payload['uid'];
    $_SESSION['bakery']['category'] = $payload['category'];
    return AccessResult::allowed();
  }

  /**
   * Only let people with actual problems mess with uncrumble.
   */
  public function bakeryUncrumbleAccess() {
    $user = \Drupal::currentUser();
    $access = AccessResult::forbidden();
    if ($user->id() == 0) {
      if (isset($_SESSION['BAKERY_CRUMBLED']) && $_SESSION['BAKERY_CRUMBLED']) {
        $access = AccessResult::allowed();
      }
    }
    return $access;
  }

  /**
   * Validate the account information request.
   */
  public function bakeryTasteGingerbreadCookie() {
    $type = 'gingerbread';
    if (empty($_POST[$type])) {
      return AccessResult::forbidden();
    }
    if (($cookie = $this->bakery_service->validateData($_POST[$type], $type)) === FALSE) {
      return AccessResult::forbidden();
    }
    $_SESSION['bakery']['name'] = $cookie['name'];
    $_SESSION['bakery']['or_email'] = $cookie['or_email'];
    $_SESSION['bakery']['slave'] = $cookie['slave'];
    $_SESSION['bakery']['uid'] = $cookie['uid'];
    return AccessResult::allowed();
  }

  /**
   * Verify the validation request.
   */
  public function bakeryTasteThinmintCookie() {
    $type = 'thinmint';
    if (empty($_POST[$type])) {
      return AccessResult::forbidden();
    }
    if (($cookie = $this->bakery_service->validateData($_POST[$type], $type)) === FALSE) {
      return AccessResult::forbidden();
    }
    $_SESSION['bakery']['name'] = $cookie['name'];
    $_SESSION['bakery']['slave'] = $cookie['slave'];
    $_SESSION['bakery']['uid'] = $cookie['uid'];
    return AccessResult::allowed();
  }

  /**
   * User is anonymous or not .
   */
  public function userIsAnonymous() {
    if (\Drupal::currentUser()->isAnonymous()) {
      return AccessResult::allowed();
    }
    else {
      return AccessResult::forbidden();
    }
  }

  /**
   * For testing the Cookie.
   */
  private function bakeryTasteOatmealCookie() {
    $key = $this->config('bakery.settings')->get('bakery_key');
    $type = $this->bakery_service->cookieName('OATMEAL');

    if (!isset($_COOKIE[$type]) || !$key || !$this->config('bakery.settings')->get('bakery_domain')) {
      return FALSE;
    }
    if (($data = $this->bakery_service->validateData($_COOKIE[$type], $type)) !== FALSE) {
      return $data;
    }
    return FALSE;
  }

  /**
   * Redirect to the given URL
   *
   * @param type $url
   * @return RedirectResponse
   */
  public function trustedRedirect($url) {
    $redirect_url = Url::fromUri($url);
    if ($redirect_url->isExternal()) {
      $response = (new TrustedRedirectResponse($redirect_url->toString()))->addCacheableDependency((new CacheableMetadata())->setCacheMaxAge(0));
      //Errors set by the UserLoginForm contain URLS sometimes, and these
      //Mess with the cache metadata so we can't return a redirect response
      //Directly. This aweful workaround allows the redirect to work at least
      //See https://www.drupal.org/node/2638686
      $response->send();
    }
    else {
      $redirect_url = Url::fromUserInput($url);
      return new RedirectResponse($redirect_url->toString());
    }
  }

}
