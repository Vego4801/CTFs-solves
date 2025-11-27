<?php

class Utils{

    /**
     * Check if all the arguments are not arrays
     */
    public static function validate($args){
        foreach($args as $arg){
            if(is_array($arg))
            return false;
        }

        return true;
    }
}