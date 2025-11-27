<?php

class Post{
    private $title;
    private $body;

    public static function new_post($title, $body, $user_id){
        if(!Utils::validate(func_get_args())){
            return false;
        }
        $db = Db::get_db();

        // we don't want xss, at least we don't want easy xss :)
        $escaped_body = htmlspecialchars($body);
        $id = md5(openssl_random_pseudo_bytes(10));
        $stm = $db->prepare("INSERT INTO posts (id, title, body, user_id) VALUES (?,?,?,?)");
        
        $stm->execute([$id, $title, $escaped_body, $user_id]);
        
        return self::from_id($id);
        
    }

    public static function delete($id){
        if(!Utils::validate(func_get_args())){
            return false;
        }
        $db = Db::get_db();

        //We need to ensure that the owner of the post is the same that is requesting its deletion
        $stm = $db->prepare("SELECT user_id FROM posts WHERE id = ?");
        $stm->execute([$id]);
        // if the post doesn't exist
        $res = $stm->fetch(PDO::FETCH_ASSOC);
        if(!$res)
            return false;
        
        $owner_id = $res['user_id'];
        if($owner_id === User::get_current_user()->getId()){
            $stm = $db->prepare("DELETE FROM posts WHERE id = ?");
            $stm->execute([$id]);
            return true;
        }
        return false;
    }

    public static function format($text){
        if(!Utils::validate(func_get_args())){
            return false;
        }
        $str = preg_replace_callback('#\[img\](.+?)\[/img\]#i',function($m) {
            $url = $m[1];
            $parsed = parse_url($url);
            if(!filter_var($url, FILTER_VALIDATE_URL)){
                return '<i>' . $m[1] . '</i>';
            }
            if(!in_array($parsed['scheme'], ['http','https'])){
                return '<i>' . $m[1] . '</i>';
            }
            
            $url = '/camo.php?url=' . urlencode($m[1]);
            $url .= '&hmac=' . hash_hmac('md5', $m[1], getenv('SECRET'));
            return '<img src="'.$url.'"/>';
        },$text,10);

        $str = preg_replace('#\[i\](.+?)\[/i\]#i','<span style="font-style:italic">$1</span>',$str);
        $str = preg_replace('#\[b\](.+?)\[/b\]#i','<strong>$1</strong>',$str);

        $str = nl2br($str);
        return $str;
    }

    public static function from_id($id){
        if(!Utils::validate(func_get_args())){
            return false;
        }
        $db = Db::get_db();
        $stm = $db->prepare("SELECT * FROM posts where id = ?");
        $stm->execute([$id]);
        
        $res = $stm->fetch(PDO::FETCH_ASSOC);
        if(!$res){
            die('Sqlite is going crazy again. please contact a sysadmin asap');
        }
        return new Post($res['id'], $res['title'], $res['body'], $res['user_id']);
    }

    public static function from_user(){
        $db = Db::get_db();
        $stm = $db->prepare('SELECT * FROM posts WHERE user_id = ?');
        $stm->execute([$_SESSION['username']]);
        
        $post_list=[];
        while($data = $stm->fetch(PDO::FETCH_ASSOC)){
            $post_list[] = new Post($data['id'], $data['title'], $data['body'], $data['user_id']);
        }
        return $post_list;
    }

    private function __construct($id, $title, $body, $user_id){
        $this->id=$id;
        $this->title=$title;
        $this->body=$body;
        $this->user_id=$user_id;

    }

    public function getId(){
        return $this->id;
    }
    public function getTitle(){
        return $this->title;
    }
    public function getBody(){
        return self::format($this->body);
    }
}