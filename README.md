# Merchant Integration Documentation(Backend Python Auth SDK)

---

> ## A. OTPLessAuth Dependency
>
> install Below dependency in your project's

```shell
composer require otpless/otpless-auth-sdk
```

you can also get latest version of dependency
at https://packagist.org/packages/otpless/otpless-auth-sdk

---

> ## B. OTPLessAuth class

The `OtplessAuth` class provides methods to integrate OTPLess authentication into your PHP backend application. This
documentation explains the usage of the class and its methods.

### Methods:

---

> ### 1. decodeIdToken

---

This method help to resolve `idToken(JWT token)` which is issued by `OTPLess` which return user detail
from that token also this method verify that token is valid, token should not expired and
issued by only `otpless.com`

##### Method Signature:

```php
decodeIdToken(id_token, client_id, client_secret, audience=None)
```

#### Method Params:

| Params       | Data type | Mandatory | Constraints | Remarks                                                                      |
| ------------ | --------- | --------- | ----------- | ---------------------------------------------------------------------------- |
| idToken      | String    | true      |             | idToken which is JWT token which you get from `OTPLess` by exchange code API |
| clientId     | String    | true      |             | Your OTPLess `Client Id`                                                     |
| clientSecret | String    | true      |             | Your OTPLess `Client Secret`                                                 |

#### Return

Return:
Object Name: UserDetail

```json
{'success': True, 'auth_time': 1697649943, 'phone_number': '+9193******', 'email': 'dev***@gmail.com', 'name': 'Devloper From OTP-less', 'country_code': '+91', 'national_phone_number': '9313******'}
```

> ### 2. verify code

---

This method help to resolve `code` which is return from `OTPLess` which will return user detail
from that code also this method verify that code is valid, code should not expired and
issued by only `otpless.com`

##### Method Signature:

```php
verifyCode(code, client_id, client_secret)
```

#### Method Params:

| Params       | Data type | Mandatory | Constraints | Remarks                           |
| ------------ | --------- | --------- | ----------- | --------------------------------- |
| code         | String    | true      |             | code which you get from `OTPLess` |
| clientId     | String    | true      |             | Your OTPLess `Client Id`          |
| clientSecret | String    | true      |             | Your OTPLess `Client Secret`      |

#### Return

Return:
Object Name: UserDetail

```json
{'success': True, 'auth_time': 1697649943, 'phone_number': '+9193******', 'email': 'dev***@gmail.com', 'name': 'Devloper From OTP-less', 'country_code': '+91', 'national_phone_number': '9313******'}
```



> ### 3. Verify Auth Token

---

This method help to resolve `token` which is issued by `OTPLess` which return user detail
from that token also this method verify that token is valid, token should not expired and
issued by only `otpless.com`

##### Method Signature:

```php
verifyToken(token, client_id, client_secret)
```

#### Method Params:

| Params       | Data type | Mandatory | Constraints | Remarks                            |
| ------------ | --------- | --------- | ----------- | ---------------------------------- |
| token        | String    | true      |             | token which you get from `OTPLess` |
| clientId     | String    | true      |             | Your OTPLess `Client Id`           |
| clientSecret | String    | true      |             | Your OTPLess `Client Secret`       |

#### Return

Return:
Object Name: UserDetail

```json
{'success': True, 'auth_time': 1697649943, 'phone_number': '+9193******', 'email': 'dev***@gmail.com', 'name': 'Devloper From OTP-less', 'country_code': '+91', 'national_phone_number': '9313******'}
```

---

### Example of usage

```php

require '../vendor/autoload.php';

use Otpless\OtplessAuth\OTPLessAuth; 

// Your ID token to decode
$token = 'your token here';

$clientId = 'your client id here';
$clientSecret = 'your client secret here';
// Initialize the library class
$auth = new OtplessAuth(); 


$auth->verifyToken($token,$clientId,$clientSecret);
```
