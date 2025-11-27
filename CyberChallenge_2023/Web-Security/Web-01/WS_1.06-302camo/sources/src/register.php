<?php
require_once('config.php');


$error = false;
if(isset($_POST['username']) && isset($_POST['password'])){
    $username = $_POST['username'];
    $password = $_POST['password'];
    if(User::register($username, $password)){
        header('Location: /index.php');
        return;
    }else{
        $error = "User already exists.";
    }
}

echo $twig->render('register.html', ['error' => $error]);