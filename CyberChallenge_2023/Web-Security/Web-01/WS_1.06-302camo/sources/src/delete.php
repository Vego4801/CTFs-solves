<?php
include 'config.php';


$user = User::is_logged();
if(!$user){
    header('Location: /');
    return;
}

$error = false;
if(isset($_GET['id']) && isset($_GET['csrf'])){
    if(User::check_csrf_token($_GET['csrf'])){
        if(Post::delete($_GET['id'])){
            header('Location: /');
            return;
        }
        else
            $error = 'Cannot delete this post.';
    }else{
        $error = 'Invalid csrf token.';
    }
}else $error = 'No id or csrf token provided';
#echo $error;
echo $twig->render('error.html', ["user" => $user, "csrf" => User::get_csrf_token(), "error" => $error]);