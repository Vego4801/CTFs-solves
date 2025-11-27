<?php
session_start();
require __DIR__ . '/vendor/autoload.php'; 
require_once('classes/Db.php');
require_once('classes/User.php');
require_once('classes/Post.php');
require_once('classes/Utils.php');

$hmac_secret = getenv('SECRET');

error_reporting(E_ALL & ~E_NOTICE);

define('TEMPLATES_DIR', __DIR__ . '/templates/');

$loader = new Twig_Loader_Filesystem(TEMPLATES_DIR);

$options = array(
    'strict_variables' => false,
    'debug' => false,
    'cache'=> false
);

$twig = new Twig_Environment($loader, $options);

