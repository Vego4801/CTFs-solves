<?php

if($_SERVER['REMOTE_ADDR'] == '127.0.0.1'){
    echo getenv('FLAG');
}else
    echo 'lol nope';