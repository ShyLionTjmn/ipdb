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

const R_SUPER		= 'r_super';
const R_VIEWANY		= 'r_viewany';


const NR_VIEWNAME	= 1 << 0;
const NR_VIEWOTHER	= 1 << 1;
const NR_TAKE_IP	= 1 << 2;
const NR_EDIT_IP	= NR_TAKE_IP;
const NR_FREE_IP	= 1 << 3;
const NR_IGNORE		= 1 << 4;
const NR_MAN_ACCESS	= 1 << 5;
const NR_MAN_RANGES	= 1 << 6;
const NR_DROP_NET	= 1 << 7;
const NR_EDIT_NET	= 1 << 8;
const RR_TAKE_NET	= 1 << 9;
const RR_DENY_TAKE_IP	= 1 << 10; //also deny editing

function len2mask($m) {
  return 0xFFFFFFFF & ( 0xFFFFFFFF << (32-$m));
};

/*
function get_v4net_rights($netrow) {
  $ret = 0;

  if(isset($GLOBALS['v4nets_access']) && isset($GLOBALS['v4nets_access'][ $netrow['v4net_id'] ])) {
    return $GLOBALS['v4nets_access'][ $netrow['v4net_id'] ]['rmask'];
  };

#  foreach($GLOBALS['v4rs_access'] as $row) {
#    if($netrow['v4net_addr'] >= $row['v4r_start'] && $netrow['v4net_addr'] <= $row['v4r_stop'])
#    if($row['v4r_start'] <= $netrow['v4net_last'] &&
#  };

  return $ret;
};
*/

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
  $ret['net_last'] = $net | $mask_rev;
  $ret['net_last_text'] = long2ip($net | $mask_rev);

  return $ret;
};

function get_v4netinfo($n, $m) {
  $net_info=get_closest_v4netinfo($n, $m);
  if($n != $net_info['net']) {
    error_exit("Bad network supplied $n/$m vs:\n".JSON_encode($net_info));
  };
  return $net_info;
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
  if(strpos($rightstr, R_SUPER) !== FALSE || strpos($rightstr, $right) !== FALSE) {
    return TRUE;
  } else {
    return FALSE;
  };
};

function has_nright($rmask, $right) {
  if(has_right(R_SUPER)) {
    return TRUE;
  };
  if(has_right(R_VIEWANY) && ($right === NR_VIEWNAME || $right === NR_VIEWOTHER)) {
    return TRUE;
  };
  if($rmask & $right) {
    return TRUE;
  };
  return FALSE;
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
} else {
  #get access rights for future use in requests
  if(!has_right(R_SUPER)) {
    #networks access
    $query="SELECT BIT_OR(gn4r_rmask) as rmask, v4net_id FROM gn4rs INNER JOIN v4nets ON gn4r_fk_v4net_id=v4net_id WHERE gn4r_fk_group_id IN ($groups) GROUP BY v4net_id";
    $GLOBALS['v4nets_access']=return_query($query, 'v4net_id');

    $query="SELECT DISTINCT v4r_id, v4r_start, v4r_stop, v4r_visible, v4net_id";
    $query .= " FROM (gn4rs INNER JOIN v4nets ON gn4r_fk_v4net_id=v4net_id) INNER JOIN v4rs ON v4r_fk_v4net_id=v4net_id";
    $query .= " WHERE gn4r_fk_group_id IN ($groups)";
    $GLOBALS['v4rs_net_access']=return_query($query);

    $query="SELECT v4r_id, v4r_start, v4r_stop, v4r_visible, BIT_OR(gr4r_rmask) AS rmask FROM gr4rs INNER JOIN v4rs ON v4r_id=gr4r_fk_v4r_id";
    $query .= " WHERE gr4r_fk_group_id IN ($groups)";
    $query .= " GROUP BY v4r_id";
    $GLOBALS['v4rs_access']=return_query($query);
  };
};

if($q['action'] == 'v4get_net') {
  require_p('net', [ "type" => "v4addr" ]);
  require_p('mask', [ "type" => "v4masklen" ]);
  $ret=Array();

  $net_info=get_closest_v4netinfo($q['net'], $q['mask']);

  $query="SELECT v4nets.*";
  $query .=", (SELECT BIT_OR(gn4r_rmask) FROM gn4rs WHERE gn4r_fk_v4net_id=v4net_id AND gn4r_fk_group_id IN ($groups)) as rmask";
  $query .=" FROM v4nets WHERE v4net_addr <= ".mq($net_info['net']);
  $query .= " AND v4net_last >= ".mq($net_info['net']);
  $query .= " AND v4net_mask <= ".mq($q['mask']);

  $ret['_queries']=Array();

  $ret['_queries'][] = $query;

  $row=return_one($query);
  if($row !== NULL) {

    if(!has_nright($row['rmask'], NR_VIEWNAME)) { $row['v4net_name'] = 'hidden'; $row['v4net_descr'] = 'hidden'; };
    if(!has_nright($row['rmask'], NR_VIEWOTHER)) { $row['v4net_descr'] = 'hidden'; };

    $ret['net']=$row;

    $ret['type']="net";

    if(!has_nright($row['rmask'], NR_VIEWOTHER)) {
      $ret['net']['noaccess']=TRUE;
    } else {
      $net_info=get_v4netinfo($row['v4net_addr'], $row['v4net_mask']);

      $query="SELECT v4rs.*";
      $query .= ", (SELECT BIT_OR(gr4r_rmask) FROM gr4rs WHERE gr4r_fk_v4r_id=v4r_id AND gr4r_fk_group_id IN ($groups)) as rmask";
      $query .= " FROM v4rs WHERE";
      $query .= " v4r_stop >= ".mq($row['v4net_addr']);
      $query .= " AND v4r_start <= ".mq($row['v4net_last']);
      $query .= " AND v4r_fk_v4net_id IS NULL";

      $ret['_queries'][] = $query;
      $ext_ranges=return_query($query);

      $ret['ext_ranges']=Array();

      foreach($ext_ranges as $row) {
        if(!has_nright($row['rmask'], NR_VIEWNAME)) { $row['v4r_name'] = 'hidden'; $row['v4r_descr'] = 'hidden'; };
        if(!has_nright($row['rmask'], NR_VIEWOTHER)) { $row['v4r_descr'] = 'hidden'; };
        $ret['ext_ranges'][] = $row;
      };

      $query="SELECT v4rs.*";
      $query .= ", (SELECT BIT_OR(gr4r_rmask) FROM gr4rs WHERE gr4r_fk_v4r_id=v4r_id AND gr4r_fk_group_id IN ($groups)) as rmask";
      $query .= " FROM v4rs WHERE";
      $query .= " v4r_stop >= ".mq($row['v4net_addr']);
      $query .= " AND v4r_start <= ".mq($row['v4net_last']);
      $query .= " AND v4r_fk_v4net_id = ".mq($row['v4net_id']);

      $ret['_queries'][] = $query;
      $int_ranges=return_query($query);

      $ret['int_ranges']=Array();

      foreach($int_ranges as $row) {
        if(!has_nright($row['rmask'], NR_VIEWNAME)) { $row['v4r_name'] = 'hidden'; $row['v4r_descr'] = 'hidden'; };
        if(!has_nright($row['rmask'], NR_VIEWOTHER)) { $row['v4r_descr'] = 'hidden'; };
        $ret['int_ranges'][] = $row;
      };
    };

    ok_exit($ret);
  } else {

    $ret['type']="nav";
    $ret['net_info']=$net_info;

    $max_mask_len=8;
    if($net_info['masklen'] >= 8) { $max_mask_len=16; };
    if($net_info['masklen'] >= 16) { $max_mask_len=24; };
    if($net_info['masklen'] >= 24) { $max_mask_len=32; };

    $query="SELECT v4nets.*";
    $query .= ", (SELECT BIT_OR(gn4r_rmask) FROM gn4rs WHERE gn4r_fk_v4net_id=v4net_id AND gn4r_fk_group_id IN ($groups)) as rmask";
    $query .= " FROM v4nets WHERE";
    $query .= " v4net_addr >= ".mq($net_info['net']);
    $query .= " AND v4net_addr <= ".mq($net_info['net_last']);
    $query .= " AND v4net_mask <= ".mq($max_mask_len);
    $query .= " ORDER BY v4net_addr ASC";

    $ret['_queries'][] = $query;
    $rows=return_query($query);

    $nets=Array();
    foreach($rows as $row) {

      if(!has_nright($row['rmask'], NR_VIEWNAME)) { $row['v4net_name'] = 'hidden'; $row['v4net_descr'] = 'hidden'; };
      if(!has_nright($row['rmask'], NR_VIEWOTHER)) { $row['v4net_descr'] = 'hidden'; };


      $nets[ $row['v4net_addr'] ] = $row;
    };
    $ret['nets']=$nets;

    $query="SELECT COUNT(*) AS aggr_count, (v4net_addr & ".mq(len2mask($max_mask_len)).") AS aggr_net, ".mq($max_mask_len)." AS aggr_mask FROM v4nets WHERE";
    $query .= " v4net_addr >= ".mq($net_info['net']);
    $query .= " AND v4net_addr <= ".mq($net_info['net_last']);
    $query .= " AND v4net_mask > ".mq($max_mask_len);
    $query .= " GROUP BY aggr_net";
    $query .= " ORDER BY aggr_net ASC";

    $ret['_queries'][] = $query;
    $rows=return_query($query, 'aggr_net');

    $ret['aggr_nets']=$rows;

    $query="SELECT v4rs.*";
    $query .= ", (SELECT BIT_OR(gr4r_rmask) FROM gr4rs WHERE gr4r_fk_v4r_id=v4r_id AND gr4r_fk_group_id IN ($groups)) as rmask";
    $query .= " FROM v4rs WHERE";
    $query .= " v4r_stop >= ".mq($net_info['net']);
    $query .= " AND v4r_start <= ".mq($net_info['net_last']);
    $query .= " AND v4r_fk_v4net_id IS NULL";
     
    $ret['_queries'][] = $query;
    $ext_ranges=return_query($query);
    
    $ret['ext_ranges']=Array();

    foreach($ext_ranges as $row) {
      if(!has_nright($row['rmask'], NR_VIEWNAME)) { $row['v4r_name'] = 'hidden'; $row['v4r_descr'] = 'hidden'; };
      if(!has_nright($row['rmask'], NR_VIEWOTHER)) { $row['v4r_descr'] = 'hidden'; };
      $ret['ext_ranges'][] = $row;
    };


  };
  ok_exit($ret);
} else if($q['action'] == 'v4_get_range') {
  require_p('range_id', "/^\d+$/");
  $ret=Array();

  $query="SELECT v4rs.*";
  $query .= ", (SELECT BIT_OR(gr4r_rmask) FROM gr4rs WHERE gr4r_fk_v4r_id=v4r_id AND gr4r_fk_group_id IN ($groups)) as rmask";
  $query .= " FROM v4rs WHERE";
  $query .= " v4r_id=".mq($q['range_id']);

  $range_info=return_one($query, TRUE, "Range not found.");

  if(!has_nright($range_info['rmask'], NR_VIEWNAME)) { $range_info['v4r_name'] = 'hidden'; $range_info['v4r_descr'] = 'hidden'; };
  if(!has_nright($range_info['rmask'], NR_VIEWOTHER)) { $range_info['v4r_descr'] = 'hidden'; };

  $ret['range_info']=$range_info;

  $query="SELECT gr4r_rmask as rmask, group_id";
  if(has_nright($range_info['rmask'], NR_VIEWOTHER)) {
    $query .= ", group_name";
  } else {
    $query .= ", 'hidden' as group_name";
  };
  $query .= " FROM gr4rs INNER JOIN groups ON gr4r_fk_group_id=group_id";
  $query .= " WHERE gr4r_fk_v4r_id=".mq($q['range_id']);
  $query .= " ORDER BY group_name, group_id";

  $ret['range_group_rights']=return_query($query);

  ok_exit($ret);
} else {
  error_exit("Unknown action");
};

?>
