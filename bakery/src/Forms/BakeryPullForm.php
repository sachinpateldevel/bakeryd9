<?php

namespace Drupal\bakery\Forms;
use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Contribute form.
 */
class BakeryPullForm extends FormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'bakery_forms_pull_form';
  }

  /**
   * Form for admins to pull accounts.
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $form['or_email'] = [
      '#type' => 'radios',
      '#options' => [
        0 => t('Username'),
        1 => t('Username or email'),
      ],
      '#default_value' => 0,
    ];

    $form['name'] = [
      '#type' => 'textfield',
      '#required' => TRUE,
    ];

    $form['submit'] = [
      '#type' => 'submit',
      '#value' => t('Request account'),
    ];

    return $form;
  }

  /**
   * Make sure we are not trying to request an existing user.
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $existing_account = user_load_by_name($form_state->getValue('name'));
    if (!$existing_account && $form_state->getValue('or_email')) {
      $existing_account = user_load_by_mail($form_state->getValue('name'));
    }
    // Raise an error in case the account already exists locally.
    if ($existing_account) {
      $form_state->setError('name', t('Account !link exists.', ['!link' => theme('username', ['account' => $existing_account])]));
    }
  }

  /**
   * If the request succeeds, go to the user page. Otherwise, show an error.
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $result = bakery_request_account($form_state->getValue('name'), $form_state->getValue('or_email'));
    if ($result === FALSE) {
      \Drupal::messenger()->addMessage(t("Pulling account %name failed: maybe there is a typo or they don't exist on the master site.", [
        '%name' => $form_state->getValue('name'),
      ]), 'error');
    }
    else {
      $form_state->setRedirect('user',
        ['id' => $result]
      );
    }
  }

}
