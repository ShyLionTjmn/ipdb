<?php
error_reporting(E_ALL);
ini_set('display_errors',1);
ini_set('display_startup_errors',1);
ini_set('memory_limit', '256M');

require("local_config.php");
require("db_utils.php");
require("myphplib.php");


$time=time();

$IPDB_CHARSET="utf8mb4";

$db=null;

$html_started=FALSE;

function start_html($title=NULL) {
  global $html_started;

  if($html_started) { return; };

  $html_started=TRUE;

  header("Cache-Control: no-cache, no-store, must-revalidate");
  header("Pragma: no-cache");
  header("Expires: 0");

  echo "<!DOCTYPE html>\n";
  echo "<HTML>\n";
  echo "<HEAD>\n";
  echo "<META charset=\"utf-8\">\n";

  echo "<TITLE>";
  if($title !== NULL) {
    echo htmlentities($title, ENT_HTML5, "UTF-8");
  } else {
    echo "Message";
  };
  echo "</TITLE>\n";
  
  echo "</HEAD>\n";
  echo "<BODY>\n";
};

function error_exit($redtext) {
  start_html("Error");
  close_db(FALSE);
  echo "<pre>";
  echo htmlentities(jstr($redtext), ENT_HTML5, "UTF-8");
  echo "</pre>";
  echo "</BODY>\n";
  echo "</HTML>\n";
  exit;
};


function require_param($param_name) {
  if(!isset($_REQUEST[$param_name])) {
    error_exit("Required param '$param_name' is missing");
  };
};


$db=mysqli_connect($IPDB_HOST, $IPDB_USER, $IPDB_PASS, $IPDB_DB);
if(!$db) {
  error_exit("Db connect error at ".__LINE__);
};

if (!mysqli_set_charset($db, $IPDB_CHARSET)) {
  error_exit("Set charset error at ".__LINE__);
};

$in_transaction=0;


session_name($PHP_SESSION_NAME);
session_start();

reset_session();

require_param("ipdb_uri");
require_param("success_uri");
require_param("ap_id");

$query="SELECT ap_auth_ep, ap_client_id, ap_scope FROM aps WHERE ap_off = 0 AND ap_id=".mq($_REQUEST['ap_id']);
$ap=return_one($query, TRUE);

$back_uri=$_REQUEST['ipdb_uri']."openid_back.php";
$back_uri .= "?ap_id=".urlencode($_REQUEST['ap_id']);

$nonce=bin2hex(random_bytes(64));

$location=$ap['ap_auth_ep'];
$location .= "?client_id=".urlencode($ap['ap_client_id']);
$location .= "&scope=".urlencode($ap['ap_scope']);
$location .= "&response_type=code";
$location .= "&nonce=$nonce";
$location .= "&redirect_uri=".urlencode($back_uri);

$_SESSION['openid_ap_id'] = $_REQUEST['ap_id'];
$_SESSION['openid_redirect_uri'] = $back_uri;
$_SESSION['openid_nonce'] = $nonce;
$_SESSION['openid_success_uri'] = $_REQUEST['success_uri'];

close_db();
header("Location: ".$location);
?>
