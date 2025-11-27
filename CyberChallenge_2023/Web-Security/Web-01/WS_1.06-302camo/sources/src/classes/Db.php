<?php


/**
 * Simple singleton for the db connection
 */
class Db{
    private static $db = false;

    public static function get_db(){
        if(!self::$db){
            try{
                $dsn = "sqlite:/srv/app.db";
                self::$db = new PDO($dsn);
            }catch(PDOException $e){
                echo $e->getMessage();
                die("<br>\nCannot connect to the database. Please contact our majestic sysadmin:)");
            }
        }
        return self::$db;
    }
}