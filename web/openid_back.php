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

function jstr($data) {
  return json_encode($data, JSON_PRETTY_PRINT);
};

function dumper($var) {
  ob_start();
  var_dump($var);
  $dump_str=ob_get_contents();
  ob_end_clean();
  return $dump_str;
};

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

function ok_exit($redtext) {
  global $curl;
  if(isset($curl) && $curl !== FALSE) { curl_close($curl); };
  close_db();
  header("Location: /ipdb/");
  exit;
};

function require_param($param_name) {
  if(!isset($_REQUEST[$param_name])) {
    error_exit("Required param '$param_name' is missing");
  };
};

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

require_param("code");
require_param("ap_id");

if(!isset($_SESSION['openid_ap_id']) || $_SESSION['openid_ap_id'] != $_REQUEST['ap_id']) {
  reset_session();
  error_exit("Auth sync error");
};

$query="SELECT * FROM aps WHERE ap_off = 0 AND ap_id=".mq($_REQUEST['ap_id']);
$ap=return_one($query, TRUE);


$post_fields=Array("client_id" => $ap['ap_client_id'],
                   "grant_type" => "authorization_code",
                   "code" => $_REQUEST['code'],
                   "redirect_uri" => $_SESSION['openid_redirect_uri']
);

$post_headers=NULL;
if($ap['ap_client_secret'] != "") {
  $post_headers="Authorization: Basic ".base64_encode(urlencode($ap['ap_client_id']).":".urlencode($ap['ap_client_secret']));
};

$tokens=http_post($ap['ap_token_ep'], $post_fields, $post_headers);

if(isset($tokens['error'])) {
  if($tokens['error'] == "invalid_grant") {
    header("Location: ".$_SESSION['openid_success_uri']);
    reset_session();
    exit;
  } else {
    reset_session();
    error_exit($tokens['error']);
  };
};

$debug_out=Array();
$debug_out['tokens']=$tokens;

$pres=process_tokens($tokens, $ap);

if(isset($pres['error'])) {
  reset_session();
  error_exit($pres['error']);
};

close_db();

$_SESSION['source'] = "login";

header("Location: ".$_SESSION['openid_success_uri']);

?>
