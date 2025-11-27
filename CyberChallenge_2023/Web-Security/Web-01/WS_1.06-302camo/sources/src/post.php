<?php
include 'config.php';

$user = User::is_logged();
if(!$user){
    header('Location: /');
    return;
}

$error = false;
if(isset($_POST['title']) && isset($_POST['body']) && isset($_POST['csrf'])){
    if(User::check_csrf_token($_POST['csrf'])){
        $title = $_POST['title'];
        $body = $_POST['body'];
        if($title == ''){
            $title = 'No Title (?!)';
        }
        if($body == ''){
            $body = 'No post body...........Don\'t be shy, write something!';
        }
        $post = Post::new_post($title, $body, $user->getId());
        header('Location: /view.php?id=' . $post->getId());
        return;
    }else{
        $error = 'The csrf token you provided is invalid.';
    }
}
echo $twig->render('post.html', ["user"=>$user, "csrf" => User::get_csrf_token()]);