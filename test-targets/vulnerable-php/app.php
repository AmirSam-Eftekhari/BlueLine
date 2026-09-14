<?php
$apiKey = "sk_live_abcdEFGH12345678";

function runCommand($input) {
    exec("echo " . $input);
}

function loadSession($blob) {
    return unserialize($blob);
}

function loadPage() {
    include($_GET['page']);
}

function setupVars() {
    extract($_POST);
}

function runQuery($conn, $table) {
    $result = mysqli_query($conn, "SELECT * FROM " . $_GET['table'] . " WHERE active=1");
    return $result;
}

function riskyEval($expr) {
    return eval($expr);
}
?>
