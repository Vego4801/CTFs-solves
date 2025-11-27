 <?php
if(isset($_GET['source'])){
    highlight_file(__FILE__);
    return;
}

header("Content-Security-Policy: default-src 'none'; style-src cdnjs.cloudflare.com");
function cidr_match($ip, $range){
    list ($subnet, $bits) = explode('/', $range);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask; // in case the supplied subnet was not correctly aligned
    return ($ip & $mask) == $subnet;
}

if(isset($_GET['url']) && !is_array($_GET['url'])){
    $url = $_GET['url'];
    if (filter_var($url, FILTER_VALIDATE_URL) === FALSE) {
        die('Not a valid URL');
    }
    $parsed = parse_url($url);
    $host = $parsed['host'];
    if (!in_array($parsed['scheme'], ['http','https'])){
        die('Not a valid URL');
    }

    $true_ip = gethostbyname($host);
    if(cidr_match($true_ip, '127.0.0.1/8') || cidr_match($true_ip, '0.0.0.0/32')){
        die('Not a valid URL');
    }
    /*
    Orange it's my new obsession
    Yeah, Orange it's not even a question(mark)
    Orange on the host of your gopher, cause
    Orange is the bug you discovah
    Orange as the ping on your server
    Orange cause you are so very
    Orange it's the color of parsers
    A-cause curl it just goes with the setopt
    */
    $ch = curl_init($url);
    curl_setopt ($ch, CURLOPT_FOLLOWLOCATION, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    echo curl_exec($ch);
    curl_close($ch);
    return;
}

?>
<html>
<head>
    <meta charset="utf-8">
    <title>SSRF Example</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" media="screen" href="https://cdnjs.cloudflare.com/ajax/libs/bulma/0.7.4/css/bulma.min.css">
</head>
<body>
<section class="hero">
  <div class="hero-body">
    <div class="container">
      <h1 class="title">
        Basic SSRF
      </h1>
      <h2 class="subtitle">
        Yeah, this may seems hard. As always the flag is in get_flag.php. The source code <a href="/?source">here</a>
      </h2>
    </div>
  </div>
</section>
    <section class="section">
        <div class="container">
    
        <form method="GET">
            <div class="field">
                <div class="control">
                    <input class="input" type="text" placeholder="Try url" name="url">
                </div>
            </div>
            <div class="field">
                <div class="control">
                    <input class="submit" type="submit" placeholder="Send" value="Send">
                </div>
            </div>      
        </form>
        </div>
    </section>
</body>
</html>

