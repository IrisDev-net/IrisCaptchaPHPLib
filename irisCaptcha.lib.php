<?PHP

/*
example 
//* another page.php
require "irisCaptcha.lib.php";
$irisCaptchaPublicKey = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh+qPUxi6QYz7T22NdHcI
k3JxGQ4yzgaM+b+ReHHjnxy/o9FQ0bAU8B/jwAWGMAhtFoj6ERmbYEgWwUMy4yJ5
f0EFfrzcbSKkI+lr5LejyjocxxA5PI5tNLPTVrQMC/5kkHpylN5mTmcDFz3zT6EQ
EFJzJ+zRBdoQNIc3CW2WSA5vK2042iZRhOsbTWbxaP0TK+lqbcQSoWRAFBTOA4ZF
6PSTlO84p9M6/JkoyRPDYplVqXq+HMLs9uFHal3rN+KjQ2E7g0poFkvfXgGC0nUh
lMoLQBdSB1yT7oJc9Mua+/4Z1e1ma47d/kNxV+U5GjOfLHfqMo7xcfwocQ7ky+be
MQIDAQAB
-----END PUBLIC KEY-----";
$irisCaptcha = new IrisCaptcha("your secret",$irisCaptchaPublicKey);

...

 $res = $irisCaptcha->Check_Answer($_POST["irisCaptcha"],$_SERVER['REMOTE_ADDR'],true);

    if ($res->is_valid) {
        //* Captcha verified - continue ...
        echo "HOOOORAAAA";
    }else{
        echo $res->error;
    }

*/


define("LibVersion","1");
define("IrisCaptcha_VERIFY_SERVER", "captcha.irisdev.net");
define("IrisCaptcha_JS_SERVER", "https://captcha.irisdev.net/js");

class SignatureInvalidException extends \UnexpectedValueException {
    public function __toString()
    {
        return "Invalid Signature";
    }
}
class BeforeValidException extends \UnexpectedValueException {
    public function __toString()
    {
        return "Issued Date Error";
    }
}

class OpenSocketException extends \UnexpectedValueException {
    public function __toString()
    {
        return "Could not open socket";
    }
}
class InValidRemoteIpException extends \UnexpectedValueException {
    public function __toString()
    {
        return "The Ip of user and token does not match";
    }
}

class ExpiredException extends \UnexpectedValueException {}




class IrisCaptcha
{
    Private $PublicKey = null ;
    Private $UniqId = null ;
    Private $Secret = null ;
    Public $Key = null;

    Public function __construct($secret,$publickKey = "") {
        $this->Secret = $secret;
        $ss = explode("0x",$secret);
        $this->UniqId = "0x".end($ss);
        $this->PublicKey = $publickKey;
    }

    Public function Get_HTML() {
                return "<iris-captcha name='irisCaptcha' id='irisCaptcha' ></iris-captcha>";
        }
    Public function Get_Js() {
            return "<script src='".IrisCaptcha_JS_SERVER."/$this->UniqId' ></script>";
    }
    Private function _irisCaptcha_http_post($host, $path, $data, $port = 443) {

        // prepaire the raw body
        $rawBody = $this->_irisCaptcha_qsencode($data);
        // prepaire the raw packets
        $http_request  = "POST $path HTTP/1.1\r\n";
        $http_request .= "Host: $host\r\n";
        $http_request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
        $http_request .= "Content-Length: " . strlen($rawBody) . "\r\n";
        $http_request .= "User-Agent: IrisCaptchaLib/PHP/v".LibVersion."\r\n";
        $http_request .= 'Connection: close' . "\r\n";
        $http_request .= "\r\n";
        $http_request .= $rawBody;

        $response = '';

        // opening Socket port
        $fs = @fsockopen("ssl://". $host, 443, $errno, $errstr, 10);
        if( $fs == false ) {
            throw new OpenSocketException;
            return;
        }

        // write packets
        fwrite($fs, $http_request);

        // read packets
        while ( !feof($fs) )
                $response .= fgets($fs, 1024); // One TCP-IP packet
        // close the socket
        fclose($fs);

        // processing the response
        $response = explode("\r\n\r\n", $response, 2);

        return $response;
    }

    Private function _irisCaptcha_qsencode ($data) {
            $req = "";
            foreach ( $data as $key => $value )
                    $req .= $key . '=' . urlencode( stripslashes($value) ) . "&";

            // Cut the last '&'
            $req=substr($req,0,strlen($req)-1);
            return $req;
    }

    Private function Check_Answer_Remote ( $response, $remoteip, $extra_params = array()){
                //$privkey, $remoteip, $challenge,
            if ($this->Secret  == null || $this->Secret == '') {
                die ("To use IrisCaptcha you must register your domain. <a href='https://my.irisdev.net/new/captcha'>https://my.irisdev.net</a>");
            }

            if ($remoteip == null || $remoteip == '') {
                die ("For security reasons, you must pass the remote ip to IrisCaptcha");
            }

            //discard spam submissions
            if ( $response == null || strlen($response) == 0) {
                    $irisCaptcha_response = new IrisCaptchaResponse();
                    $irisCaptcha_response->is_valid = false;
                    $irisCaptcha_response->error = 'Incorrect User Response';
                    return $irisCaptcha_response;
            }

            $response = $this->_irisCaptcha_http_post (IrisCaptcha_VERIFY_SERVER, "/check",
                                                array (
                                                        'secret' => $this->Secret,
                                                        'remoteip' => $remoteip,
                                                        'response' => $response
                                                        ) + $extra_params
                                                );

        $response = explode("{",$response[1],2);
        $response = explode("}",strrev($response[1]),2);

        $response = "{" . strrev($response[1])."}";

        $answers = json_decode($response);
        $irisCaptcha_response = new IrisCaptchaResponse();

        if ($answers->Success) {
                $irisCaptcha_response->is_valid = true;
        }
        else {
                $irisCaptcha_response->is_valid = false;
                $irisCaptcha_response->error = $answers->Message;
        }
        return $irisCaptcha_response;

        }


    Private function Check_Answer_Signature( $response, $remoteip) {
       $irisCaptcha_response = new IrisCaptchaResponse();
        try {
            $decoded = JWT::decode($response, $this->PublicKey, array('RS256'));
        } catch (\Throwable $th) {
            //throw $th;
            $class = get_class($th);
            
            
            switch ($class) {

                case ExpiredException::class :    
                    $irisCaptcha_response->error = "Token Expired";
                    # code...
                break;
                
                default:
                    throw $th;
                break;
            }
            $irisCaptcha_response->is_valid = FALSE;
            return $irisCaptcha_response;
        }
        

        if($decoded->ip != $remoteip ) {
            $irisCaptcha_response = new IrisCaptchaResponse();
            $irisCaptcha_response->is_valid = FALSE;
            $irisCaptcha_response->error = "The Ip of user and token does not match";
            return $irisCaptcha_response;
            
        }
        $irisCaptcha_response->is_valid = $decoded->success;
        if(isset($decoded->Message)) {
            $irisCaptcha_response->error = $decoded->Message;
        }
        return $irisCaptcha_response;
    }

    /**
     * Check the user Response and return the value 
     *
     * @param string                    $response               The User Response
     * @param string                    $remoteip               The User IP - for security reasons it's necessary 
     * @param bool                      $SignaturePreferration  Specify that is validation with public key is preferred or not - if invalid Signature accored , it will try to check with server
     * @param array                     $extra_params           Extra parameters to send for irisdev server.
     *                                                  
     * 
     * 
     * @return object IrisCaptchaResponse  The Standard Response to check Status - get $IrisCaptchaResponse->is_valid (bool) | get $IrisCaptchaResponse->error (string)
     *
     * @throws UnexpectedValueException     Provided JWT was invalid
     * @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
     * @throws BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
     * @throws BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
     * @throws ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
     *
     * @uses Check_Answer_Remote
     * @uses Check_Answer_Signature
     */
    Public function Check_Answer ( $response, $remoteip, $SignaturePreferration=false, $extra_params = array()){
        $res = NULL;
        if(!$SignaturePreferration){
            try {
                $res = $this->Check_Answer_Remote($response, $remoteip, $extra_params);
            } catch (\Throwable $th) {
                $res =  $this->Check_Answer_Signature($response, $remoteip);
            } finally {
                if ($res == NULL) {
                    $res =   new IrisCaptchaResponse();
                    $res->is_valid = false;
                    $res->error = "UnExpected Error";
                }
                return $res;
            }
        }else{
            try {
                $res =  $this->Check_Answer_Signature($response, $remoteip);
            } catch (\Throwable $th) {
                $res = $this->Check_Answer_Remote($response, $remoteip, $extra_params);
            } finally {
                if ($res == NULL) {
                    $res =   new IrisCaptchaResponse();
                    $res->is_valid = false;
                    $res->error = "UnExpected Error";
                }
                return $res;
            }
        }
    }
    
    }

/**
 * A IrisCaptchaResponse is returned from IrisCaptcha->Check_Answer()
 */
class IrisCaptchaResponse {
        var $is_valid;
        var $error;
}

class JWK
{
    /**
     * Parse a set of JWK keys
     *
     * @param array $jwks The JSON Web Key Set as an associative array
     *
     * @return array An associative array that represents the set of keys
     *
     * @throws InvalidArgumentException     Provided JWK Set is empty
     * @throws UnexpectedValueException     Provided JWK Set was invalid
     * @throws DomainException              OpenSSL failure
     *
     * @uses parseKey
     */
    public static function parseKeySet(array $jwks)
    {
        $keys = array();

        if (!isset($jwks['keys'])) {
            throw new UnexpectedValueException('"keys" member must exist in the JWK Set');
        }
        if (empty($jwks['keys'])) {
            throw new InvalidArgumentException('JWK Set did not contain any keys');
        }

        foreach ($jwks['keys'] as $k => $v) {
            $kid = isset($v['kid']) ? $v['kid'] : $k;
            if ($key = self::parseKey($v)) {
                $keys[$kid] = $key;
            }
        }

        if (0 === \count($keys)) {
            throw new UnexpectedValueException('No supported algorithms found in JWK Set');
        }

        return $keys;
    }

    /**
     * Parse a JWK key
     *
     * @param array $jwk An individual JWK
     *
     * @return resource|array An associative array that represents the key
     *
     * @throws InvalidArgumentException     Provided JWK is empty
     * @throws UnexpectedValueException     Provided JWK was invalid
     * @throws DomainException              OpenSSL failure
     *
     * @uses createPemFromModulusAndExponent
     */
    private static function parseKey(array $jwk)
    {
        if (empty($jwk)) {
            throw new InvalidArgumentException('JWK must not be empty');
        }
        if (!isset($jwk['kty'])) {
            throw new UnexpectedValueException('JWK must contain a "kty" parameter');
        }

        switch ($jwk['kty']) {
            case 'RSA':
                if (\array_key_exists('d', $jwk)) {
                    throw new UnexpectedValueException('RSA private keys are not supported');
                }
                if (!isset($jwk['n']) || !isset($jwk['e'])) {
                    throw new UnexpectedValueException('RSA keys must contain values for both "n" and "e"');
                }

                $pem = self::createPemFromModulusAndExponent($jwk['n'], $jwk['e']);
                $publicKey = \openssl_pkey_get_public($pem);
                if (false === $publicKey) {
                    throw new DomainException(
                        'OpenSSL error: ' . \openssl_error_string()
                    );
                }
                return $publicKey;
            default:
                // Currently only RSA is supported
                break;
        }
    }

    /**
     * Create a public key represented in PEM format from RSA modulus and exponent information
     *
     * @param string $n The RSA modulus encoded in Base64
     * @param string $e The RSA exponent encoded in Base64
     *
     * @return string The RSA public key represented in PEM format
     *
     * @uses encodeLength
     */
    private static function createPemFromModulusAndExponent($n, $e)
    {
        $modulus = JWT::urlsafeB64Decode($n);
        $publicExponent = JWT::urlsafeB64Decode($e);

        $components = array(
            'modulus' => \pack('Ca*a*', 2, self::encodeLength(\strlen($modulus)), $modulus),
            'publicExponent' => \pack('Ca*a*', 2, self::encodeLength(\strlen($publicExponent)), $publicExponent)
        );

        $rsaPublicKey = \pack(
            'Ca*a*a*',
            48,
            self::encodeLength(\strlen($components['modulus']) + \strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );

        // sequence(oid(1.2.840.113549.1.1.1), null)) = rsaEncryption.
        $rsaOID = \pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
        $rsaPublicKey = \chr(0) . $rsaPublicKey;
        $rsaPublicKey = \chr(3) . self::encodeLength(\strlen($rsaPublicKey)) . $rsaPublicKey;

        $rsaPublicKey = \pack(
            'Ca*a*',
            48,
            self::encodeLength(\strlen($rsaOID . $rsaPublicKey)),
            $rsaOID . $rsaPublicKey
        );

        $rsaPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            \chunk_split(\base64_encode($rsaPublicKey), 64) .
            '-----END PUBLIC KEY-----';

        return $rsaPublicKey;
    }

    /**
     * DER-encode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.  See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3} for more information.
     *
     * @param int $length
     * @return string
     */
    private static function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return \chr($length);
        }

        $temp = \ltrim(\pack('N', $length), \chr(0));

        return \pack('Ca*', 0x80 | \strlen($temp), $temp);
    }
}

class JWT
{
    const ASN1_INTEGER = 0x02;
    const ASN1_SEQUENCE = 0x10;
    const ASN1_BIT_STRING = 0x03;

    /**
     * When checking nbf, iat or expiration times,
     * we want to provide some extra leeway time to
     * account for clock skew.
     */
    public static $leeway = 0;

    /**
     * Allow the current timestamp to be specified.
     * Useful for fixing a value within unit testing.
     *
     * Will default to PHP time() value if null.
     */
    public static $timestamp = null;

    public static $supported_algs = array(
        'ES256' => array('openssl', 'SHA256'),
        'RS256' => array('openssl', 'SHA256'),
        'RS384' => array('openssl', 'SHA384'),
        'RS512' => array('openssl', 'SHA512'),
    );

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string                    $jwt            The JWT
     * @param string|array|resource     $key            The key, or map of keys.
     *                                                  If the algorithm used is asymmetric, this is the public key
     * @param array                     $allowed_algs   List of supported verification algorithms
     *                                                  Supported algorithms are 'ES256', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', and 'RS512'
     *
     * @return object The JWT's payload as a PHP object
     *
     * @throws UnexpectedValueException     Provided JWT was invalid
     * @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
     * @throws BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
     * @throws BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
     * @throws ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
     *
     * @uses jsonDecode
     * @uses urlsafeB64Decode
     */
    public static function decode($jwt, $key, array $allowed_algs = array())
    {
        $timestamp = \is_null(static::$timestamp) ? \time() : static::$timestamp;

        if (empty($key)) {
            throw new InvalidArgumentException('Key may not be empty');
        }
        $tks = \explode('.', $jwt);
        if (\count($tks) != 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }
        list($headb64, $bodyb64, $cryptob64) = $tks;
        if (null === ($header = static::jsonDecode(static::urlsafeB64Decode($headb64)))) {
            throw new UnexpectedValueException('Invalid header encoding');
        }
        if (null === $payload = static::jsonDecode(static::urlsafeB64Decode($bodyb64))) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }
        if (false === ($sig = static::urlsafeB64Decode($cryptob64))) {
            throw new UnexpectedValueException('Invalid signature encoding');
        }
        if (empty($header->alg)) {
            throw new UnexpectedValueException('Empty algorithm');
        }
        if (empty(static::$supported_algs[$header->alg])) {
            throw new UnexpectedValueException('Algorithm not supported');
        }
        if (!\in_array($header->alg, $allowed_algs)) {
            throw new UnexpectedValueException('Algorithm not allowed');
        }
        if ($header->alg === 'ES256') {
            // OpenSSL expects an ASN.1 DER sequence for ES256 signatures
            $sig = self::signatureToDER($sig);
        }

        if (\is_array($key) || $key instanceof \ArrayAccess) {
            if (isset($header->kid)) {
                if (!isset($key[$header->kid])) {
                    throw new UnexpectedValueException('"kid" invalid, unable to lookup correct key');
                }
                $key = $key[$header->kid];
            } else {
                throw new UnexpectedValueException('"kid" empty, unable to lookup correct key');
            }
        }

        // Check the signature
        if (!static::verify("$headb64.$bodyb64", $sig, $key, $header->alg)) {
            throw new SignatureInvalidException('Signature verification failed');
        }

        // Check the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($payload->nbf) && $payload->nbf > ($timestamp + static::$leeway)) {
            throw new BeforeValidException(
                'Cannot handle token prior to ' . \date(DateTime::ISO8601, $payload->nbf)
            );
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (isset($payload->iat) && $payload->iat > ($timestamp + static::$leeway)) {
            throw new BeforeValidException(
                'Cannot handle token prior to ' . \date(DateTime::ISO8601, $payload->iat)
            );
        }

        // Check if this token has expired.
        if (isset($payload->exp) && ($timestamp - static::$leeway) >= $payload->exp) {
            throw new ExpiredException('Expired token');
        }

        return $payload;
    }




    /**
     * Verify a signature with the message, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string            $msg        The original message (header and body)
     * @param string            $signature  The original signature
     * @param string|resource   $key        For HS*, a string key works. for RS*, must be a resource of an openssl public key
     * @param string            $alg        The algorithm
     *
     * @return bool
     *
     * @throws DomainException Invalid Algorithm or OpenSSL failure
     */
    private static function verify($msg, $signature, $key, $alg)
    {
        if (empty(static::$supported_algs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }

        list($function, $algorithm) = static::$supported_algs[$alg];
        switch ($function) {
            case 'openssl':
                $success = \openssl_verify($msg, $signature, $key, $algorithm);
                if ($success === 1) {
                    return true;
                } elseif ($success === 0) {
                    return false;
                }
                // returns 1 on success, 0 on failure, -1 on error.
                throw new DomainException(
                    'OpenSSL error: ' . \openssl_error_string()
                );
            case 'hash_hmac':
            default:
                $hash = \hash_hmac($algorithm, $msg, $key, true);
                if (\function_exists('hash_equals')) {
                    return \hash_equals($signature, $hash);
                }
                $len = \min(static::safeStrlen($signature), static::safeStrlen($hash));

                $status = 0;
                for ($i = 0; $i < $len; $i++) {
                    $status |= (\ord($signature[$i]) ^ \ord($hash[$i]));
                }
                $status |= (static::safeStrlen($signature) ^ static::safeStrlen($hash));

                return ($status === 0);
        }
    }

    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input JSON string
     *
     * @return object Object representation of JSON string
     *
     * @throws DomainException Provided string was invalid JSON
     */
    public static function jsonDecode($input)
    {
        if (\version_compare(PHP_VERSION, '5.4.0', '>=') && !(\defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            /** In PHP >=5.4.0, json_decode() accepts an options parameter, that allows you
             * to specify that large ints (like Steam Transaction IDs) should be treated as
             * strings, rather than the PHP default behaviour of converting them to floats.
             */
            $obj = \json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        } else {
            /** Not all servers will support that, however, so for older versions we must
             * manually detect large ints in the JSON string and quote them (thus converting
             *them to strings) before decoding, hence the preg_replace() call.
             */
            $max_int_length = \strlen((string) PHP_INT_MAX) - 1;
            $json_without_bigints = \preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
            $obj = \json_decode($json_without_bigints);
        }

        if ($errno = \json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }

    

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = \strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= \str_repeat('=', $padlen);
        }
        return \base64_decode(\strtr($input, '-_', '+/'));
    }


    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     *
     * @return void
     */
    private static function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters' //PHP >= 5.3.3
        );
        throw new DomainException(
            isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno
        );
    }

    /**
     * Get the number of bytes in cryptographic strings.
     *
     * @param string $str
     *
     * @return int
     */
    private static function safeStrlen($str)
    {
        if (\function_exists('mb_strlen')) {
            return \mb_strlen($str, '8bit');
        }
        return \strlen($str);
    }

    /**
     * Convert an ECDSA signature to an ASN.1 DER sequence
     *
     * @param   string $sig The ECDSA signature to convert
     * @return  string The encoded DER object
     */
    private static function signatureToDER($sig)
    {
        // Separate the signature into r-value and s-value
        list($r, $s) = \str_split($sig, (int) (\strlen($sig) / 2));

        // Trim leading zeros
        $r = \ltrim($r, "\x00");
        $s = \ltrim($s, "\x00");

        // Convert r-value and s-value from unsigned big-endian integers to
        // signed two's complement
        if (\ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (\ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }

        return self::encodeDER(
            self::ASN1_SEQUENCE,
            self::encodeDER(self::ASN1_INTEGER, $r) .
            self::encodeDER(self::ASN1_INTEGER, $s)
        );
    }

    /**
     * Encodes a value into a DER object.
     *
     * @param   int     $type DER tag
     * @param   string  $value the value to encode
     * @return  string  the encoded object
     */
    private static function encodeDER($type, $value)
    {
        $tag_header = 0;
        if ($type === self::ASN1_SEQUENCE) {
            $tag_header |= 0x20;
        }

        // Type
        $der = \chr($tag_header | $type);

        // Length
        $der .= \chr(\strlen($value));

        return $der . $value;
    }
}

function Test(){

    $irisCaptchaPublicKey = "-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh+qPUxi6QYz7T22NdHcI
    k3JxGQ4yzgaM+b+ReHHjnxy/o9FQ0bAU8B/jwAWGMAhtFoj6ERmbYEgWwUMy4yJ5
    f0EFfrzcbSKkI+lr5LejyjocxxA5PI5tNLPTVrQMC/5kkHpylN5mTmcDFz3zT6EQ
    EFJzJ+zRBdoQNIc3CW2WSA5vK2042iZRhOsbTWbxaP0TK+lqbcQSoWRAFBTOA4ZF
    6PSTlO84p9M6/JkoyRPDYplVqXq+HMLs9uFHal3rN+KjQ2E7g0poFkvfXgGC0nUh
    lMoLQBdSB1yT7oJc9Mua+/4Z1e1ma47d/kNxV+U5GjOfLHfqMo7xcfwocQ7ky+be
    MQIDAQAB
    -----END PUBLIC KEY-----";
    $secret ="533a64afb4c496cc34dfd00d1ecbd45cfa2784b2c3eba4aa02e7a4dcbe081aa40x2711";
    $irisCaptcha = new IrisCaptcha($secret,$irisCaptchaPublicKey);

    $userResponse = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWNjZXNzIjp0cnVlLCJob3N0bmFtZSI6ImlyaXNkZXYubmV0IiwiaXAiOiIxODUuMjM1LjQwLjE3MSIsImV4cCI6MTYxMjk1MDQ4NCwiaWF0IjoxNjEyOTUwNDI0fQ.S0l_YksAMSGjipvPb0sw4QkF8R2l3j84IKFJwvQor0ok6_UbnpeGmvLPTdeD7EUO7tYKRKKZMI3M6yvMpt_bOFUXCoGWQwQG4shmaIMVWqPAjayDU_ccbC6ialEiEETBtShscDoXo63JfcG0aBUTb0cPlMYFcillW1XeiyGuvXvMHRrBa_oz8NS7we8xysPA9gr2dnrHKsWb1oU30Om8w4Xy_tRJVxIRWRH9DiE8d8iYT-9cL-NAyS2jA20I7tQ2V36tKrtJbr72IOc-Nu4vNY3QvvytPkdDlqY9lTN7sX5_THYDAPtsAjaF-Taq0EHrS1qxjFmM2l5z5MPjFo1sYQ";

    $res = $irisCaptcha->Check_Answer($userResponse,"185.235.40.171",false);
    if ($res->is_valid) {
        echo "HOOOORRRAAA";
    }else{

        var_dump($res);
    }

};

Test();