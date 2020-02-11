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

function len2mask($m) {
  return 0xFFFFFFFF & ( 0xFFFFFFFF << (32-$m));
};

function get_closest_v4netinfo($n, $m) {
  # validate n and m prior call !!
  $ret=Array();

  $mask=len2mask($m);
  $net=$n & $mask;

  $mask_rev = 0xFFFFFFFF & (~ $mask );

  $ret['net'] = $net;
  $ret['net_text'] = long2ip($net);
  $ret['bitmask'] = $mask;
  $ret['bitmask_text'] = long2ip($mask);
  $ret['bitmask_rev'] = $mask_rev;
  $ret['bitmask_rev_text'] = long2ip($mask_rev);
  $ret['masklen'] = $m;
  $ret['net_bcast'] = $net | $mask_rev;
  $ret['net_bcast_text'] = long2ip($net | $mask_rev);

  return $ret;

  # LEFT
};

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

function require_p($param_name, $param_check=null) {
  global $q;
  if(!isset($q[$param_name])) {
    error_exit("Required param '$param_name' is missing");
  };
  if(isset($param_check)) {
    if(is_array($param_check)) {
      switch($param_check['type']) {
      case "v4addr":
        if(!preg_match('/^\d+$/', $q[$param_name])) { error_exit("Required param '$param_name' has bad value '".$q[$param_name]."'"); };
        if($q[$param_name] > 4294967295) { error_exit("Required param '$param_name' has bad value '".$q[$param_name]."'"); };
        break;
      case "v4masklen":
        if(!preg_match('/^\d+$/', $q[$param_name])) { error_exit("Required param '$param_name' has bad value '".$q[$param_name]."'"); };
        if($q[$param_name] > 32) { error_exit("Required param '$param_name' has bad value '".$q[$param_name]."'"); };
        break;
      case "v6addr":
        if(!preg_match('/^[0-9a-f]{32}$/', $q[$param_name])) { error_exit("Required param '$param_name' has bad value '".$q[$param_name]."'"); };
        break;
      case "v6masklen":
        if(!preg_match('/^\d+$/', $q[$param_name])) { error_exit("Required param '$param_name' has bad value '".$q[$param_name]."'"); };
        if($q[$param_name] > 128) { error_exit("Required param '$param_name' has bad value '".$q[$param_name]."'"); };
        break;
      default:
        error_exit("Prog error at ".__LINE__);
      };
    } else {
      if(!preg_match($param_check, $q[$param_name])) {
        error_exit("Required param '$param_name' has bad value '".$q[$param_name]."'");
      };
    };
  };
};

function has_right($right, $rightstr=NULL) {
  if($rightstr === NULL) { $rightstr = $_SESSION['user']['rights']; };
  if(strpos($rightstr, 'r_super') !== FALSE || strpos($rightstr, $right) !== FALSE) {
    return TRUE;
  } else {
    return FALSE;
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

unset($_SESSION['.reset_reason']);

foreach(Array('expire', 'refresh_expire', 'user', 'refresh_token', 'openid_ap_id') as $key) {  #, 'openid_redirect_uri'
  if(!isset($_SESSION[$key])) {
    reset_session("no keys");
  };
};

if(isset($_SESSION['expire']) && $_SESSION['expire'] <= $time) {
  if($_SESSION['refresh_expire'] <= $time) {
    reset_session("refresh_expire");
  } else {
    #time to refresh tokens
    $query="SELECT * FROM aps WHERE ap_off = 0 AND ap_id=".mq($_SESSION['openid_ap_id']);
    $ap=return_one($query);
    if($ap === NULL) {
      reset_session("no ap");
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
        reset_session("refresh error: ".$tokens['error']);
        goto SKIP_SESSION;
      };

      $pres=process_tokens($tokens, $ap);

      if(isset($pres['error'])) {
        reset_session("refresh process_tokens error: ".$pres['error']);
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
    reset_session("no user ap");
  } else {
    $user=return_one("SELECT * FROM users WHERE user_id=".mq($_SESSION['user']['user_id']));
    if($user === NULL) {
      reset_session("no user_id");
    } else {
      $_SESSION['user'] = $user;
      $groups=return_single("SELECT GROUP_CONCAT(ug_fk_group_id SEPARATOR ',') FROM ugs WHERE ug_fk_user_id=".mq($_SESSION['user']['user_id']));
      if($groups === NULL) {
        run_query("INSERT INTO ugs SET ug_fk_group_id=(SELECT group_id FROM groups WHERE group_default=1 LIMIT 1), ug_fk_user_id=".mq($_SESSION['user']['user_id']));
        $groups=return_single("SELECT GROUP_CONCAT(ug_fk_group_id SEPARATOR ',') FROM ugs WHERE ug_fk_user_id=".mq($_SESSION['user']['user_id']));
      };
      if($groups === NULL || $groups === "") { eror_exit("User is not in any group"); };
      $_SESSION['user']['groups'] = $groups;

      $rights=return_single("SELECT GROUP_CONCAT(DISTINCT group_rights SEPARATOR ',') FROM groups WHERE group_rights != '' AND group_id IN ($groups)");
      if($rights === NULL) { $rights = ""; };
      #used by has_right !
      $_SESSION['user']['rights'] = $rights;

      if(!has_right('r_super')) {
        #networks access
        $query="SELECT gn4rs_rmask, v4net_id, v4net_addr, v4net_mask FROM gn4rs INNER JOIN v4nets ON gn4rs_fk_v4net_id=v4net_id WHERE gn4rs_fk_group_id IN ($groups)";
        $_SESSION['user']['v4nets_access']=return_query($query, 'v4net_id');

        $query="SELECT v4r_id, v4r_start, v4r_stop, v4r_visible, v4r_access, v4net_id";
        $query .= " FROM (gn4rs INNER JOIN v4nets ON gn4rs_fk_v4net_id=v4net_id) INNER JOIN v4rs ON v4r_fk_v4net_id=v4net_id";
        $query .= " WHERE gn4rs_fk_group_id IN ($groups)";
        $_SESSION['user']['v4rs_net_access']=return_query($query, 'v4r_id');

        $query="SELECT v4r_id, v4r_start, v4r_stop, v4r_visible, v4r_access, gr4rs_rmask FROM gr4rs INNER JOIN v4rs ON v4r_id=gr4rs_fk_v4r_id";
        $query .= " WHERE gr4rs_fk_group_id IN ($groups)";
        $_SESSION['user']['v4rs_access']=return_query($query, 'v4r_id');
      };

    };
  };
};

SKIP_SESSION:

if($q['action'] == 'check_auth') {
  if(!isset($_SESSION['user'])) {

    $query="SELECT ap_id, ap_name, ap_icon FROM aps WHERE ap_off = 0";

    $providers_list=return_query($query);
    $ret=Array("status" => "unauth", "providers" => $providers_list);
    if(isset($_SESSION['.reset_reason'])) {
      $ret['.reset_reason'] = $_SESSION['.reset_reason'];
    };
    ok_exit($ret);
  } else {
    $query="SELECT v4net_addr, v4net_mask FROM v4favs WHERE v4fav_fk_user_id=".mq($_SESSION['user']['user_id'])." ORDER BY v4net_addr ASC, v4net_mask ASC";
    $v4favs=return_query($query);

    $query="SELECT DISTINCT v4net_addr, v4net_mask FROM g4favs WHERE v4fav_fk_group_id IN (".$_SESSION['user']['groups'].") ORDER BY v4net_addr ASC, v4net_mask ASC";
    $g4favs=return_query($query);

    $ret=Array("status" => "auth",
                "user" => $_SESSION['user'],
                "expire_in" => ($_SESSION['expire'] - $time),
                "refresh_expire_in" => ($_SESSION['refresh_expire'] - $time)
    );
    $ret['user']['v4favs']=$v4favs;
    $ret['user']['g4favs']=$g4favs;
    ok_exit($ret);
  };
};

if(!isset($_SESSION['user'])) {
  $query="SELECT ap_id, ap_name, ap_icon FROM aps WHERE ap_off = 0";
  $providers_list=return_query($query);
  $ret=Array("no_auth" => $providers_list);

  if(isset($_SESSION['.reset_reason'])) {
    $ret['.reset_reason'] = $_SESSION['.reset_reason'];
  };
  ok_exit($ret);

  custom_exit(Array("no_auth" => $providers_list));
};

if($q['action'] == 'v4get_net') {
  require_p('net', [ "type" => "v4addr" ]);
  require_p('mask', [ "type" => "v4masklen" ]);

  $net_info=get_closest_v4netinfo($q['net'], $q['mask']);

  ok_exit($net_info);
} else {
  error_exit("Unknown action");
};

?>
