<?php
/*
define('CLIENT_SECRET', 'my_shared_secret');

function verify_webhook($data, $hmac_header){
	$calculated_hmac = base64_encode(hash_hmac('sha256', $data, CLIENT_SECRET, true));
	return ($hmac_header == $calculated_hmac);
}
*/

function base64url_encode($data){
	$b64 = base64_encode($data);

	if ($b64 === false) {
		return false;
	}

  	// Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
  	$url = strtr($b64, '+/', '-_');

  	// Remove padding character from the end of line and return the Base64URL result
	return rtrim($url, '=');
}

function base64url_decode($data, $strict = false){
  	// Convert Base64URL to Base64 by replacing “-” with “+” and “_” with “/”
	$b64 = strtr($data, '-_', '+/');

	return base64_decode($b64, $strict);
}

$string = readline("String to be encoded: ");

$encodedStr = base64url_encode($string);
echo "\n" . $encodedStr . "\n";

$decodedStr =  base64url_decode($encodedStr);
echo $decodedStr . "\n";


// Signature
/*HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
*/
?>
