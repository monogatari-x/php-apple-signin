# php-apple-signin


PHP library to manage Sign In with Apple identifier tokens, and validate them server side passed through by the iOS client.
The liarary come from griffinledingham/php-apple-signin, original library require php version >= 7.0,
According to my project needs, I need a libray match 5.6,so change => test => build this.

if you want to use origin library, Please use composer to install:

```bash
composer require griffinledingham/php-apple-signin
```

Installation
------------

Use composer to manage your dependencies and download php-apple-signin:

```bash
composer require monogatari/php-apple-signin
```

Example
-------
```php
<?php
use AppleSignIn\ASDecoder;

$clientUser = "example_client_user";
$identityToken = "example_encoded_jwt";

$appleSignInPayload = ASDecoder::getAppleSignInPayload($identityToken);

/**
 * Obtain the Sign In with Apple email and user creds.
 */
$email = $appleSignInPayload->getEmail();
$user = $appleSignInPayload->getUser();

/**
 * Determine whether the client-provided user is valid.
 */
$isValid = $appleSignInPayload->verifyUser($clientUser);

?>
```
