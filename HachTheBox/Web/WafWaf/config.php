<?php

class Connection extends MySQLi {

    public function query($sql, $null = NULL) {
        $dbh = new MySQLi("localhost", 'root', '', 'wafwaf');
        $result = $dbh->query($sql);
        $result->fetch_all());
    }

}

?>
