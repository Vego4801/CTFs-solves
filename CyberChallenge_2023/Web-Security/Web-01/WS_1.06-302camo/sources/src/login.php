<?php
require_once('config.php');


$error = false;
if(isset($_POST['username']) && isset($_POST['password'])){
    $username = $_POST['username'];
    $password = $_POST['password'];
    if(User::login($username, $password)){
        header('Location: /index.php');
        return;
    }else{
        $error = "Invalid credentials.";
    }
}

echo $twig->render('login.html', ['error' => $error]);