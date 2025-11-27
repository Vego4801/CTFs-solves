 <?php
if(isset($_GET['source'])){
    highlight_file(__FILE__);
    return;
}

header("Content-Security-Policy: default-src 'none'; style-src cdnjs.cloudflare.com");
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
    if(in_array($host, ['localhost', '127.0.0.1']))
        die('Not a valid URL');
    echo file_get_contents($url);
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
        Try to get the contents of /get_flag.php bypassing the additional checks. You can view the source code <a href="/?source">here</a>
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

