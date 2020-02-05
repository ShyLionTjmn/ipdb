<?php
error_reporting(E_ALL);
ini_set('display_errors',1);
ini_set('display_startup_errors',1);
ini_set('memory_limit', '256M');

require("local_config.php");
require("db_utils.php");
require("openid_lib.php");
require("myphplib.php");

$time=time();

$IPDB_CHARSET="utf8mb4";

header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

$db=null;

function error_exit($redtext) {
  close_db(FALSE);
  global $curl;
  if(isset($curl) && $curl !== FALSE) { curl_close($curl); };
  echo JSON_encode(array("error" => $redtext));
  exit;
};

function ok_exit($redtext) {
  close_db();
  global $curl;
  if(isset($curl) && $curl !== FALSE) { curl_close($curl); };
  echo JSON_encode(array("ok" => $redtext));
  exit;
};

function custom_exit($data) {
  close_db();
  global $curl;
  if(isset($curl) && $curl !== FALSE) { curl_close($curl); };
  echo JSON_encode($data);
  exit;
};

function require_param($param_name) {
  if(!isset($_REQUEST[$param_name])) {
    error_exit("Required param '$param_name' is missing");
  };
};

function require_p($param_name, $param_regex=null) {
  global $q;
  if(!isset($q[$param_name])) {
    error_exit("Required param '$param_name' is missing");
  };
  if(isset($param_regex) && !preg_match($param_regex, $q[$param_name])) {
    error_exit("Required param '$param_name' has bad value '".$q[$param_name]."'");
  };
};


$json=file_get_contents("php://input");
$q = json_decode($json, true);
if($q === NULL) {
  error_exit("Bad JSON input: $json");
};

if(!isset($q['action'])) {
  error_exit("No action in JSON");
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

foreach(Array('expire', 'refresh_expire', 'user', 'refresh_token', 'openid_ap_id') as $key) {  #, 'openid_redirect_uri'
  if(!isset($_SESSION[$key])) {
    reset_session();
  };
};

if(isset($_SESSION['expire']) && $_SESSION['expire'] <= $time+295) {
  if($_SESSION['refresh_expire'] <= $time) {
    reset_session();
  } else {
    #time to refresh tokens
    $query="SELECT * FROM aps WHERE ap_off = 0 AND ap_id=".mq($_SESSION['openid_ap_id']);
    $ap=return_one($query);
    if($ap === NULL) {
      reset_session();
    } else {

      $curl = curl_init();
      if($curl === FALSE) {
        error_exit("cURL init error");
      };


      $post_fields=Array("client_id" => $ap['ap_client_id'],
                   "grant_type" => "refresh_token",
                   "refresh_token" => $_SESSION['refresh_token'],
                   #"redirect_uri" => $_SESSION['openid_redirect_uri']
      );

      $post_headers=NULL;
      if($ap['ap_client_secret'] != "") {
        $post_headers="Authorization: Basic ".base64_encode(urlencode($ap['ap_client_id']).":".urlencode($ap['ap_client_secret']));
      };

      $tokens=http_post($ap['ap_token_ep'], $post_fields, $post_headers);
      if(isset($tokens['error'])) {
        reset_session();
        goto SKIP_SESSION;
      };

      $pres=process_tokens($tokens, $ap);

      if(isset($pres['error'])) {
        reset_session();
        error_exit($pres['error']);
      };

      $_SESSION['source'] = 'refresh';
    };
  };
};

if(isset($_SESSION['user'])) {
  #check if ap is still on
  $query="SELECT ap_id FROM aps WHERE ap_off=0 AND ap_id=".mq($_SESSION['user']['user_fk_ap_id']);
  if( return_single($query) === FALSE) {
    reset_session();
  } else {
    $user=return_one("SELECT * FROM users WHERE user_id=".mq($_SESSION['user']['user_id']));
    if($user === NULL) {
      reset_session();
    } else {
      $_SESSION['user'] = $user;
    };
  };
};

SKIP_SESSION:

if($q['action'] == 'check_auth') {
  if(!isset($_SESSION['user'])) {

    $query="SELECT ap_id, ap_name, ap_icon FROM aps WHERE ap_off = 0";

    $providers_list=return_query($query);
    ok_exit(Array("status" => "unauth", "providers" => $providers_list));
  } else {
    ok_exit(Array("status" => "auth", "user" => $_SESSION['user']));
  };
};

if(!isset($_SESSION['user'])) {
  $query="SELECT ap_id, ap_name, ap_icon FROM aps WHERE ap_off = 0";
  $providers_list=return_query($query);
  custom_exit(Array("no_auth" => $providers_list));
};

if($q['action'] == 'boo') {
  ok_exit("moo");
} else {
  error_exit("Unknown action");
};

?>
