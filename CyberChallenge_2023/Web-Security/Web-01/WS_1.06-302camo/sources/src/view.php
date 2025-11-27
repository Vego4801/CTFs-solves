<?php   
include 'config.php';

if(!isset($_GET['id'])){
    header('Location: /');
   return;
}

$post = Post::from_id($_GET['id']);
if(!$post){
    echo $twig->render('error.html', ['user' => User::is_logged(), 'error' => 'Post not found.']);
    return;
}
$user = User::is_logged();
echo $twig->render('view.html', ['user' => $user, 'post' => $post]);