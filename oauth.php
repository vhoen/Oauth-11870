<pre>
<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

$conf = include 'conf.php';

$appToken = $conf['appToken'];
$appSecret = $conf['appSecret'];

//first step
//let's get an unauthorized request token

if (count($_REQUEST) == 0) {
    $url = 'https://11870.com/services/manage-api/request-token';
    $params = array(
        'oauth_consumer_key' => $appToken,
        'oauth_signature_method' => 'HMAC-SHA1',
        'oauth_timestamp' => time(),
        'oauth_nonce' => uniqid(),
        'oauth_version' => '1.0',
        'oauth_callback' => sprintf('%s://%s%s', $_SERVER['REQUEST_SCHEME'], $_SERVER['SERVER_NAME'], $_SERVER['REQUEST_URI']),
    );

    //creating signing key with appSecret and nothing else since there is no token at this point
    $signingKey = rawurlencode($appSecret) . '&';

    $output = getOutput($url, $params, $signingKey);

    parse_str($output, $values);

    if (isset($values['oauth_token']) && isset($values['oauth_token_secret'])) {
        $authToken = $values['oauth_token'];
        $authTokenSecret = $values['oauth_token_secret'];

        //token secret is stored to be used later
        $_SESSION['oauth_token_secret'] = $values['oauth_token_secret'];

        $url = 'https://11870.com/services/manage-api/authorize';

        $authorizeUrl = $url . '?oauth_token=' . $values['oauth_token'];

        header('Location: ' . $authorizeUrl);
    } else {
        var_dump($values);
    }
} else if (isset($_REQUEST['oauth_token']) && isset($_REQUEST['oauth_verifier'])) {
    $oauthToken = $_REQUEST['oauth_token'];
    $oauthVerifier = $_REQUEST['oauth_verifier'];

    $url = 'https://11870.com/services/manage-api/access-token';

    $params = array(
        'oauth_consumer_key' => rawurlencode($appToken),
        'oauth_token' => $oauthToken,
        'oauth_signature_method' => rawurlencode('HMAC-SHA1'),
        'oauth_timestamp' => rawurlencode(time()),
        'oauth_nonce' => rawurlencode(uniqid()),
        'oauth_version' => rawurlencode('1.0'),
        'oauth_verifier' => $oauthVerifier,
    );

    $signingKey = $appSecret . '&' . $_SESSION['oauth_token_secret'];

    $output = getOutput($url, $params, $signingKey);

    parse_str($output, $values);

    if (isset($values['oauth_token']) && isset($values['oauth_token_secret'])) {
        $oauthToken = $values['oauth_token'];
        $oauthTokenSecret = $values['oauth_token_secret'];

        echo sprintf('Auth success : token : %s', $oauthToken);
    } else {
        echo 'Auth failed';
    }
}

function buildSignatureBaseString($method, $url, $params)
{
    $urlElements = parse_url($url);

    $signatureParams = array(
        rawurlencode(strtoupper($method)),
        rawurlencode(sprintf('%s://%s%s', $urlElements['scheme'], $urlElements['host'], $urlElements['path'])),
        rawurlencode(getOauthQueryString($params)),
    );

    return implode('&', $signatureParams);
}

function buildSignature($signingKey, $signatureBaseString)
{
    $hash = hash_hmac('sha1', $signatureBaseString, $signingKey, true);

    return base64_encode($hash);
}

function getOauthQueryString($params, $separator = '&')
{
    $pairs = array();
    foreach ($params as $kParams => $vParams) {
        $k = rawurlencode(utf8_encode($kParams));
        $v = rawurlencode(utf8_encode($vParams));

        $pairs[$k] = $k . '=' . $v;
    }

    return implode('&', $pairs);
}

function getOutput($url, $params, $signingKey)
{

    $urlElems = parse_url($url);

    ksort($params);

    //creating signature params
    $signatureBaseString = buildSignatureBaseString('GET', $url, $params);

    $signature = buildSignature($signingKey, $signatureBaseString);
    var_dump($url, $params, $signingKey, $signatureBaseString, $signature);

    //and adding it to params
    $params['oauth_signature'] = $signature;

    $fullUrl = $url . '?' . getOauthQueryString($params);

    $headers = 'Authorization: OAuth realm=""';

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $fullUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    curl_setopt($ch, CURLOPT_VERBOSE, true);
    curl_setopt($ch, CURLOPT_STDERR, fopen('php://output', 'w'));
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Content-Type: application/x-www-form-urlencoded',
        'OAuth realm=""',
    ));

    $output = curl_exec($ch);
    curl_close($ch);

    return $output;
}
