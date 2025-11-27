<?php

class User{
    private $username;

    public static function register($username, $password){
        if(!Utils::validate(func_get_args())){
            return false;
        }
        $password = password_hash($password, PASSWORD_DEFAULT);
        $db = Db::get_db();
        $stm = $db->prepare('INSERT INTO users(username, password) VALUES (?,?)');
        if($stm->execute([$username, $password])){
            $_SESSION['username']=$username;
            $_SESSION['csrf_token'] = self::gen_csrf_token();
            return new User($username);
        }
        return false;
    }

    public static function login($username, $password){
        if(!Utils::validate(func_get_args())){
            return false;
        }
        $db = Db::get_db();
        $stm = $db->prepare('SELECT username,password FROM users WHERE username = ?');
        $stm->execute([$username]);
        $res = $stm->fetch(PDO::FETCH_ASSOC);
        if($res && count($res)){
            if(password_verify($password, $res['password'])){
                $_SESSION['username'] = $res['username'];
                $_SESSION['csrf_token'] = self::gen_csrf_token();
                return new User($res['username']);
            }
        }
        return false;
    }

    public static function get_current_user(){
        return self::is_logged();
    }

    public static function is_logged(){
        if(isset($_SESSION['username']))
            return new User($_SESSION['username']);
        else 
            return false;
    }
    /**
     * Some security functions
     */
    public static function get_csrf_token(){
        return $_SESSION['csrf_token'];
    }

    public static function gen_csrf_token(){
        return md5(openssl_random_pseudo_bytes(8));
    }
    
    public static function check_csrf_token($token){
        return $token === $_SESSION['csrf_token'];
    }

    private function __construct($username){
        $this->username = $username;
    }

    public function __toString(){
        return $this->username;
    }
    public function getId(){
        return $this->username;
    }
}