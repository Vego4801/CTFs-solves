<?php

include 'config.php';



$user = User::is_logged();
if(!$user){
    echo $twig->render('index.html');
    return;
}

if($user){
    // retrieve user's posts
    echo $twig->render('list.html', ["posts" => Post::from_user(), "user" => $user, "csrf" => User::get_csrf_token()]);
}
if(isset($_POST['title']) && isset($_POST['body'])){
    Post::new_post($title,$body,$user->get_id());
}
