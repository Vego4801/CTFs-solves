<?php
require_once('config.php');


/**
 * Then we check the hmac (we don't want any abuse)
 */

$hmac   =     (isset($_GET['hmac']) && !is_array($_GET['hmac'])) ? $_GET['hmac']:'';
$url    =     (isset($_GET['url']) && !is_array($_GET['url'])) ? $_GET['url'] :'';

$computed_hmac = hash_hmac('md5', $url, $hmac_secret);

if($hmac !== $computed_hmac){
    die('Wrong hmac');
}

/**
 * Now some url checks.
 * Localhost is bad
 * We want only images to be loaded.
 */

 // Resolve the hostname
 $hostname = parse_url($url, PHP_URL_HOST);
 $ip = gethostbyname($hostname);

// lol no localhost pls
 if(strncmp($ip, '127', 3) === 0){
     die('no localhost!');
 }

 //fetch the headers
$response = @file_get_contents($url);

if($response === FALSE){
    die('Error');
}
// http://php.net/manual/en/reserved.variables.httpresponseheader.php
$headers = $http_response_header;

function startsWith($str, $t){
    $t_len = strlen($t);
    return strncmp($str,$t,$t_len) === 0;
}

//Accepted Content-Type

$whitelist = ['image/png', 'image/jpg', 'image/svg', 'image/gif'];

// we iterate over all headers. When we find the content-type header
// we have to check if it is in our whitelist.
foreach($headers as $header){
   if(!startsWith($header, 'Content-Type'))
        continue;
    $value = substr($header, strlen('Content-Type: '));
    if(in_array($value, $whitelist)){
        header('Content-Type: ' . $value);
        break;
    }else{
        die('File type not permitted');
    }
}

echo $response;
