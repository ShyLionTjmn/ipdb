<?php
error_reporting(E_ALL);
ini_set('display_errors',1);
ini_set('display_startup_errors',1);
ini_set('memory_limit', '256M');

require("local_config.php");
require("openid_lib.php");
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
  global $curl;
  if(isset($curl) && $curl !== FALSE) { curl_close($curl); };
  start_html("Error");
  close_db(FALSE);
  echo "<pre>";
  echo htmlentities(jstr($redtext), ENT_HTML5, "UTF-8");
  echo "</pre>";
  echo "</BODY>\n";
  echo "</HTML>\n";
  exit;
};

function ok_exit($uri) {
  global $curl;
  if(isset($curl) && $curl !== FALSE) { curl_close($curl); };
  close_db();
  header("Location: ".$uri);
  exit;
};

function require_param($param_name) {
  if(!isset($_REQUEST[$param_name])) {
    error_exit("Required param '$param_name' is missing");
  };
};

require_param("back_uri");

$curl = curl_init();
if($curl === FALSE) {
  error_exit("cURL init error");
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

#error_exit($_SESSION);

if(!isset($_SESSION['openid_ap_id'])) {
  reset_session();
  ok_exit($_REQUEST['back_uri']);
};

$query="SELECT * FROM aps WHERE ap_off = 0 AND ap_id=".mq($_SESSION['openid_ap_id']);
$ap=return_one($query);
if($ap === NULL || $ap === FALSE) {
  reset_session();
  ok_exit($_REQUEST['back_uri']);
};

reset_session();

$uri=$ap['ap_logout_ep'];
if(strpos($uri, "?") === FALSE) {
  $uri .= "?";
} else {
  $uri .= "&";
};

$uri .= "post_logout_redirect_uri=".urlencode($_REQUEST['back_uri']);

ok_exit($uri);

?>
