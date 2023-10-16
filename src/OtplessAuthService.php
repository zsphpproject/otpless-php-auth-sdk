<?php

require '../vendor/autoload.php';

use Otpless\OtplessAuth\OIDCMasterConfig;
use Otpless\OtplessAuth\PublicKeyResponse;
use Otpless\OtplessAuth\UserDetail;

use \Firebase\JWT\Key;

use GuzzleHttp\Client;
use Firebase\JWT\JWT;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;

class OtplessAuthService
{
    public function decodeIdToken($idToken)
    {
        $client = new Client();
        $authConfig = $this->getConfig($client);

        $keyResponse = $this->getPublicKey($authConfig->jwks_uri, $client);

        $response = $this->decodeJWT($keyResponse['n'], $keyResponse['e'], $idToken);

        return $response;
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

            return $response;
        } catch (Exception $e) {
            $userDetail = new UserDetail();
            $userDetail->success = false;
            $userDetail->errorMsg = "Something went wrong please try again";

            $userDetailArray = (array) $userDetail;

            return array_filter($userDetailArray, function ($value) {
                return $value !== null;
            });
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

            $userDetail = json_decode(json_encode($decodedDataArray), false);

            $userDetail->success = true;

            return $userDetail;
        } catch (Exception $e) {
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