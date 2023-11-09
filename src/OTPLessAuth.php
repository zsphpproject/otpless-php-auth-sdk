<?php

namespace Otpless;

require '../vendor/autoload.php';

use Exception;
use Otpless\OIDCMasterConfig;
use Otpless\PublicKeyResponse;
use Otpless\UserDetail;
use Otpless\MagicLinkTokens;

use \Firebase\JWT\Key;

use GuzzleHttp\Client;
use Firebase\JWT\JWT;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;

class OTPLessAuth
{
    public function decodeIdToken($idToken)
    {
        $client = new Client();
        $authConfig = $this->getConfig($client);

        $keyResponse = $this->getPublicKey($authConfig->jwks_uri, $client);

        $response = $this->decodeJWT($keyResponse['n'], $keyResponse['e'], $idToken);

        return json_encode($response);
    }

    public function verifyCode($code, $clientId, $clientSecret)
    {
        try {
            $client = new Client();
            $authConfig = $this->getConfig($client);

            $tokenEndPoint = $authConfig->token_endpoint;

            $client = new Client();

            $response = $client->post($tokenEndPoint, [
                'form_params' => [
                    'code' => $code,
                    'client_id' => $clientId,
                    'client_secret' => $clientSecret,
                ]
            ]);

            $responseBody = $response->getBody()->getContents();
            $data = json_decode($responseBody, true);

            $keyResponse = $this->getPublicKey($authConfig->jwks_uri, $client);

            $response = $this->decodeJWT($keyResponse['n'], $keyResponse['e'], $data['id_token']);

            return json_encode($response);
        } catch (\Exception  $e) {
            $userDetail = new UserDetail();
            $userDetail->success = false;
            $userDetail->errorMsg = "Something went wrong please try again";

            $userDetailArray = (array) $userDetail;

            return json_encode(array_filter($userDetailArray, function ($value) {
                return $value !== null;
            }));
        }
    }


    public function verifyToken($token, $clientId, $clientSecret)
    {

        try {
            $client = new Client();
            $tokenEndpoint = 'https://oidc.otpless.app/auth/userInfo';

            $response = $client->post($tokenEndpoint, [
                'form_params' => [
                    'token' => $token,
                    'client_id' => $clientId,
                    'client_secret' => $clientSecret,
                ]
            ]);

            $responseBody = $response->getBody()->getContents();
            $data = json_decode($responseBody, true);


            $userDetail = new UserDetail();
            $userDetail->success = true;
            $userDetail->auth_time = $data['auth_time'] ?? null;;
            $userDetail->name = $data['name'] ?? null;;
            $userDetail->phone_number = $data['phone_number'] ?? null;;
            $userDetail->email = $data['email'] ?? null;;
            $userDetail->country_code = $data['country_code'] ?? null;;
            $userDetail->national_phone_number = $data['national_phone_number'] ?? null;;

            return json_encode($userDetail);
        } catch (\Exception  $e) {
            $userDetail = new UserDetail();
            $userDetail->success = false;
            $userDetail->errorMsg = "Something went wrong please try again";

            $userDetailArray = (array) $userDetail;

            return json_encode(array_filter($userDetailArray, function ($value) {
                return $value !== null;
            }));
        }
    }


    public function generateMagicLink($mobile, $email, $clientId, $clientSecret, $redirectURI)
    {
        try {
            $client = new Client();
            $baseURL = "https://oidc.otpless.app/auth/v1/authorize";
            $queryParams = array(
                "client_id" => $clientId,
                "client_secret" => $clientSecret
            );

            if (!empty($email)) {
                $queryParams["email"] = $email;
            }

            if (!empty($mobile)) {
                $queryParams["mobile_number"] = $mobile;
            }

            if (!empty($redirectURI)) {
                $queryParams["redirect_uri"] = $redirectURI;
            }

            $queryString = http_build_query($queryParams);
            $finalURL = $baseURL . '?' . $queryString;
            $response = $client->get($finalURL);

            $response = $client->get($finalURL);
            $responseBody = $response->getBody()->getContents();
            $responseData = json_decode($responseBody, true);


            $magicLinkTokens = new MagicLinkTokens($responseData);
            return json_encode($magicLinkTokens);
        } catch (\Exception $e) {
            $userDetail = new UserDetail();
            $userDetail->success = false;
            $userDetail->errorMsg = "Something went wrong please try again";

            $userDetailArray = (array) $userDetail;

            return json_encode(array_filter($userDetailArray, function ($value) {
                return $value !== null;
            }));
        }
    }
    private function getConfig($client)
    {
        $response = $client->get('https://otpless.com/.well-known/openid-configuration');
        $json = $response->getBody()->getContents();

        $oidcConfig = new OIDCMasterConfig(json_decode($json, true));

        return $oidcConfig;
    }

    private function getPublicKey($url, $client)
    {
        $response = $client->get($url);
        $json = $response->getBody()->getContents();

        $responseData = json_decode($json, true);

        $publicKeyResponse = new PublicKeyResponse($responseData);

        return $publicKeyResponse->keys[0];
    }

    public function decodeJWT($n, $e, $jwtToken)
    {
        try {
            $decoded = JWT::decode($jwtToken, new Key($this->createRSAPublicKey($n, $e), 'RS256'));
            $decodedDataArray = (array) $decoded;

            $userDetail = json_decode(json_encode($decodedDataArray), false);

            if (isset($decodedDataArray['authentication_details'])) {
                $decodedDataArray['authentication_details'] = json_decode($decodedDataArray['authentication_details']);
            }

            $res = json_decode(json_encode($decodedDataArray), false);


            $userDetail = new UserDetail();
            $userDetail->success = true;
            $userDetail->auth_time = $res->auth_time ?? null;
            $userDetail->name = $res->name ?? null;;
            $userDetail->phone_number = $res->phone_number ?? null;;
            $userDetail->email = $res->email ?? null;;
            $userDetail->country_code = $res->country_code ?? null;;

            $userDetail->national_phone_number = $res->national_phone_number;

            return $userDetail;
        } catch (\Exception  $e) {
            $userDetail = new UserDetail();
            $userDetail->success = false;
            $userDetail->errorMsg = "Something went wrong please try again";

            $userDetailArray = (array) $userDetail;

            return array_filter($userDetailArray, function ($value) {
                return $value !== null;
            });
        }
    }

    function createRSAPublicKey($n, $e)
    {
        $n = base64_decode(strtr($n, '-_', '+/'));
        $e = base64_decode(strtr($e, '-_', '+/'));

        $publicKey = PublicKeyLoader::load([
            'e' => new BigInteger(bin2hex($e), 16),
            'n' => new BigInteger(bin2hex($n), 16)
        ]);

        return openssl_pkey_get_public($publicKey);
    }
}

$auth = new OTPLessAuth();
$data = $auth->generateMagicLink("919428407972","","kp79hlri","4djabbfg2bl5oxqx",null);
print_r($data);
