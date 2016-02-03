<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

$appToken = 'APP_TOKEN';
$appSecret = 'APP_SECRET';

//first step
//let's get an unauthorized request token
if (count($_REQUEST) == 0) {
    $url = 'https://11870.com/services/manage-api/request-token';
    
    $params = array(
        'oauth_consumer_key' => rawurlencode($appToken) ,
        'oauth_signature_method' => rawurlencode('HMAC-SHA1') ,
        'oauth_timestamp' => rawurlencode(time()) ,
        'oauth_nonce' => rawurlencode(uniqid()) ,
        'oauth_version' => rawurlencode('1.0') ,
        'oauth_callback' => 'http://localhost/oauth.php',
    );
    
    //creating signing key with appSecret and nothing else since there is no token at this point
    $signingKey = $appSecret . '&';
    
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
    }
} 
else if (isset($_REQUEST['oauth_token']) && isset($_REQUEST['oauth_verifier'])) {
    $oauthToken = $_REQUEST['oauth_token'];
    $oauthVerifier = $_REQUEST['oauth_verifier'];
    
    $url = 'https://11870.com/services/manage-api/access-token';
    
    $params = array(
        'oauth_consumer_key' => rawurlencode($appToken) ,
        'oauth_token' => $oauthToken,
        'oauth_signature_method' => rawurlencode('HMAC-SHA1') ,
        'oauth_timestamp' => rawurlencode(time()) ,
        'oauth_nonce' => rawurlencode(uniqid()) ,
        'oauth_version' => rawurlencode('1.0') ,
        'oauth_verifier' => $oauthVerifier,
    );
    
    $signingKey = $appSecret . '&' . $_SESSION['oauth_token_secret'];
    
    $output = getOutput($url, $params, $signingKey);
    
    parse_str($output, $values);
    
    if (isset($values['oauth_token']) && isset($values['oauth_token_secret'])) {
        $oauthToken = $values['oauth_token'];
        $oauthTokenSecret = $values['oauth_token_secret'];
        
        echo sprintf('Auth success : token : %s', $oauthToken);
    } 
    else {
        echo 'Auth failed';
    }
}

function getOauthQueryString($params, $separator = '&') {
    $queryStringPairs = array();
    foreach ($params as $kParams => $vParams) {
        $queryStringPairs[] = $kParams . '=' . rawurlencode($vParams);
    }
    
    return implode($separator, $queryStringPairs);
}

function getOutput($url, $params, $signingKey) {
    
    //sorting params by alphabetical order
    ksort($params);
    
    //gathering signature params
    $signatureParams = array(
        'GET',
        rawurlencode($url) ,
        rawurlencode(getOauthQueryString($params)) ,
    );
    
    //creating signature params
    $signature = implode('&', $signatureParams);
    
    //creating signature
    $signedSignature = base64_encode(hash_hmac('sha1', $signature, $signingKey, true));
    
    //and adding it to params
    $params['oauth_signature'] = $signedSignature;
    
    $fullUrl = $url . '?' . getOauthQueryString($params);
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $fullUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    // curl_setopt($ch, CURLOPT_VERBOSE, true);
    // curl_setopt($ch, CURLOPT_STDERR, fopen('php://output', 'w'));
    // curl_setopt($ch, CURLOPT_HTTPHEADER, array('Authorization: OAuth realm="' . $url . '"'));
    
    $output = curl_exec($ch);
    curl_close($ch);
    
    return $output;
}
