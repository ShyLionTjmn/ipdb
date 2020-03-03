<?php
error_reporting(E_ALL);
ini_set('display_errors',1);
ini_set('display_startup_errors',1);
ini_set('memory_limit', '256M');

require("local_config.php");
require("db_utils.php");
require("openid_lib.php");
require("myphplib.php");

$dt=new DateTime();
$time=$dt->getTimestamp();

$ajax_start=microtime(TRUE);

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
const NR_TAKE_VLAN        = NR_TAKE_IP;
const NR_EDIT_VLAN        = NR_TAKE_VLAN;
const NR_FREE_IP	= 1 << 3;
const NR_FREE_VLAN      = NR_FREE_IP;
const NR_IGNORE		= 1 << 4;
const NR_MAN_ACCESS	= 1 << 5;
const NR_MAN_RANGES	= 1 << 6;
const NR_DROP_NET	= 1 << 7;
const NR_EDIT_NET	= 1 << 8;
const RR_TAKE_NET	= 1 << 9;
const RR_DENY_TAKE_IP	= 1 << 10; //also deny editing

const user_hide=Array("user_name", "user_username", "user_phone", "user_email", "user_sub", "user_last_login");

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
  global $ajax_start;
  if(isset($curl) && $curl !== FALSE) { curl_close($curl); };
  $ajax_time = microtime(TRUE) - $ajax_start;
  echo JSON_encode(array("ok" => $redtext, "_time" => round($ajax_time, 6)));
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
  optional_p($param_name, $param_check);
};

function optional_p($param_name, $param_check=null) {
  global $q;
  if(!isset($q[$param_name])) {
    return;
  };

  if(isset($param_check)) {
    if(is_array($param_check)) {
      switch($param_check['type']) {
      case "v4long":
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
      case "num2num":
        if(!is_array($q[$param_name])) { error_exit("Required param '$param_name' has bad type"); };
        foreach($q[$param_name] as $key => $val) {
          if(!preg_match('/^\d+$/', $key)) { error_exit("Required param '$param_name' has bad key '$key'"); };
          if(!is_scalar($val)) { error_exit("Required param '$param_name' has bad key value type"); };
          if(!preg_match('/^\d+$/', $val)) { error_exit("Required param '$param_name' has bad key value '$val'"); };
        };
        break;
      case "num_any":
        if(!is_array($q[$param_name])) { error_exit("Required param '$param_name' has bad type"); };
        if( $q[$param_name] === Array() ) { return; };
        if( array_keys($q[$param_name]) !== range(0, count($q[$param_name]) - 1) ) {
          error_exit("Required param '$param_name' is not sequential array");
        };
        foreach($q[$param_name] as $val) {
          if(!is_scalar($val)) { error_exit("Required param '$param_name' has bad key value type"); };
          if(!preg_match('/^\d+$/', $val)) { error_exit("Required param '$param_name' has bad key value '$val'"); };
        };
        break;
      case "num_many":
        if(!is_array($q[$param_name])) { error_exit("Required param '$param_name' has bad type"); };
        if( $q[$param_name] === Array() ) { error_exit("Required param '$param_name' is empty array"); };
        if( array_keys($q[$param_name]) !== range(0, count($q[$param_name]) - 1) ) {
          error_exit("Required param '$param_name' is not sequential array");
        };
        foreach($q[$param_name] as $val) {
          if(!is_scalar($val)) { error_exit("Required param '$param_name' has bad key value type"); };
          if(!preg_match('/^\d+$/', $val)) { error_exit("Required param '$param_name' has bad key value '$val'"); };
        };
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

function require_right($right) {
  if(!has_right($right)) { error_exit("Недостаточно прав."); };
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

function audit_log($subject, $subject_id, $tables, $operation, $prev_row, $new_row) {
  global $q;
  global $time;
  $query="INSERT INTO audit_log SET";
  $query .= " fk_user_id=".mq($_SESSION['user']['user_id']);
  $query .= ",al_subject=".mq($subject);
  $query .= ",al_subject_id=".mq($subject_id);
  $query .= ",al_tables=".mq($tables);
  $query .= ",al_op=".mq($operation);
  $query .= ",al_query=".mq(jstr($q));
  $query .= ",al_prev_data=".mq(jstr($prev_row));
  $query .= ",al_new_data=".mq(jstr($new_row));
  $query .= ",ts=$time";
  run_query($query);
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
        run_query("INSERT INTO ugs SET ts=$time, ug_fk_group_id=(SELECT group_id FROM groups WHERE group_default=1 LIMIT 1), ug_fk_user_id=".mq($_SESSION['user']['user_id']));
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
    #$ret['user']['id_token']=$_SESSION['id_token'];
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
  if($_SESSION['user']['user_state'] != 1) {
    error_exit("Пользователь не активирован или отключен");
  };
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

$this_user_id = $_SESSION['user']['user_id'];
$set_fk_user_id = "fk_user_id=".mq($this_user_id);

if($q['action'] == 'v4get_net') {
  require_p('net', [ "type" => "v4long" ]);
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

  $netrow=return_one($query);

  if($netrow !== NULL) {

    $query="SELECT v4rs.*";
    $query .= ", (SELECT BIT_OR(gr4r_rmask) FROM gr4rs WHERE gr4r_fk_v4r_id=v4r_id AND gr4r_fk_group_id IN ($groups)) as rmask";
    $query .= " FROM v4rs WHERE TRUE";
    $query .= " AND v4r_start <= ".mq($netrow['v4net_last']);
    $query .= " AND v4r_stop >= ".mq($netrow['v4net_addr']);
    $query .= " AND v4r_fk_v4net_id IS NULL";

    $ret['_queries'][] = $query;
    $ext_ranges=return_query($query);

    $ret['ext_ranges']=Array();

    $net_range_rmask=0;

    foreach($ext_ranges as $row) {
      if(!has_nright($row['rmask'], NR_VIEWNAME)) { $row['v4r_name'] = 'hidden'; $row['v4r_descr'] = 'hidden'; };
      if(!has_nright($row['rmask'], NR_VIEWOTHER)) { $row['v4r_descr'] = 'hidden'; };
      $ret['ext_ranges'][] = $row;
      if($row['v4r_start'] <= $netrow['v4net_addr'] && $row['v4r_stop'] >= $netrow['v4net_addr']) {
        $net_range_rmask = $net_range_rmask | $row['rmask'];
      };
    };

    $netrow['rmask_effective'] = $netrow['rmask'] | ( $net_range_rmask & (NR_VIEWNAME | NR_VIEWOTHER) );

    if(!has_nright($netrow['rmask_effective'], NR_VIEWNAME)) { $netrow['v4net_name'] = 'hidden'; $netrow['v4net_descr'] = 'hidden'; };
    if(!has_nright($netrow['rmask_effective'], NR_VIEWOTHER)) { $netrow['v4net_descr'] = 'hidden'; };

    $ret['net']=$netrow;

    $ret['type']="net";

    if(!has_nright($netrow['rmask_effective'], NR_VIEWOTHER)) {
      $ret['net']['noaccess']=TRUE;
    } else {
      $net_info=get_v4netinfo($netrow['v4net_addr'], $netrow['v4net_mask']);

      $query="SELECT v4rs.*";
      $query .= ", (SELECT BIT_OR(gr4r_rmask) FROM gr4rs WHERE gr4r_fk_v4r_id=v4r_id AND gr4r_fk_group_id IN ($groups)) as rmask";
      $query .= " FROM v4rs WHERE TRUE";
      $query .= " AND v4r_start <= ".mq($netrow['v4net_last']);
      $query .= " AND v4r_stop >= ".mq($netrow['v4net_addr']);
      $query .= " AND v4r_fk_v4net_id = ".mq($netrow['v4net_id']);

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

    $query="SELECT v4rs.*";
    $query .= ", (SELECT BIT_OR(gr4r_rmask) FROM gr4rs WHERE gr4r_fk_v4r_id=v4r_id AND gr4r_fk_group_id IN ($groups)) as rmask";
    $query .= " FROM v4rs WHERE TRUE";
    $query .= " AND v4r_start <= ".mq($net_info['net_last']);
    $query .= " AND v4r_stop >= ".mq($net_info['net']);
    $query .= " AND v4r_fk_v4net_id IS NULL";
     
    $ret['_queries'][] = $query;
    $ext_ranges=return_query($query);
    
    $ret['ext_ranges']=Array();

    foreach($ext_ranges as $row) {
      if(!has_nright($row['rmask'], NR_VIEWNAME)) { $row['v4r_name'] = 'hidden'; $row['v4r_descr'] = 'hidden'; };
      if(!has_nright($row['rmask'], NR_VIEWOTHER)) { $row['v4r_descr'] = 'hidden'; };
      $ret['ext_ranges'][] = $row;
    };

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

      $net_range_rmask=0;
      foreach($ext_ranges as $range) {
        if($range['v4r_start'] <= $row['v4net_addr'] && $range['v4r_stop'] >= $row['v4net_last']) {
          $net_range_rmask = $net_range_rmask | $range['rmask'];
        };
      };

      $row['rmask_effective'] = $row['rmask'] | ( $net_range_rmask & (NR_VIEWNAME | NR_VIEWOTHER));

      if(!has_nright($row['rmask_effective'], NR_VIEWNAME)) { $row['v4net_name'] = 'hidden'; $row['v4net_descr'] = 'hidden'; };
      if(!has_nright($row['rmask_effective'], NR_VIEWOTHER)) { $row['v4net_descr'] = 'hidden'; };


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

  $query="SELECT gr4r_rmask as rmask, group_id, group_name";
  $query .= " FROM gr4rs INNER JOIN groups ON gr4r_fk_group_id=group_id";
  $query .= " WHERE gr4r_fk_v4r_id=".mq($q['range_id']);
  $query .= " ORDER BY group_name, group_id";

  $ret['range_group_rights']=return_query($query);

  ok_exit($ret);
} else if($q['action'] == 'v4_edit_global_range') {
  require_right(R_SUPER);
  require_p('range_id', "/^\d+$/");
  require_p('range_start', Array("type" => "v4long"));
  require_p('range_stop', Array("type" => "v4long"));
  if($q['range_start'] > $q['range_stop']) { error_exit("Invalid range"); };
  require_p('range_name');
  require_p('range_descr');
  require_p('range_style');
  require_p('range_icon');
  require_p('range_icon_style');
  require_p('range_visible', "/^[01]$/");
  require_p('groups_rights',  Array("type" => "num2num"));

  trans_start();

  $query="SELECT v4rs.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(gr4r_fk_group_id, ':', gr4r_rmask)) FROM gr4rs WHERE gr4r_fk_v4r_id=v4r_id ORDER BY gr4r_fk_group_id) as groups_rights";
  $query .= " FROM v4rs WHERE v4r_id=".mq($q['range_id']);
  $prev_row=return_one($query, TRUE, "Диапазон не существует");

  $query="UPDATE v4rs SET";
  $query .= " v4r_start=".mq($q['range_start']);
  $query .= ",v4r_stop=".mq($q['range_stop']);
  $query .= ",v4r_name=".mq($q['range_name']);
  $query .= ",v4r_descr=".mq($q['range_descr']);
  $query .= ",v4r_visible=".mq($q['range_visible']);
  $query .= ",v4r_style=".mq($q['range_style']);
  $query .= ",v4r_icon=".mq($q['range_icon']);
  $query .= ",v4r_icon_style=".mq($q['range_icon_style']);
  $query .= ",ts=$time";
  $query .= ",$set_fk_user_id";
  $query .= " WHERE v4r_id=".mq($q['range_id']);

  run_query($query);

  $query="DELETE FROM gr4rs WHERE gr4r_fk_v4r_id=".mq($q['range_id']);
  run_query($query);

  foreach($q['groups_rights'] as $gr_id => $rmask) {
    $query="INSERT INTO gr4rs SET";
    $query .= " gr4r_fk_v4r_id=".mq($q['range_id']);
    $query .= ",gr4r_fk_group_id=".mq($gr_id);
    $query .= ",gr4r_rmask=".mq($rmask);
    $query .= ",$set_fk_user_id";
    $query .= ",ts=$time";
    run_query($query);
  };

  $query="SELECT v4rs.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(gr4r_fk_group_id, ':', gr4r_rmask)) FROM gr4rs WHERE gr4r_fk_v4r_id=v4r_id ORDER BY gr4r_fk_group_id) as groups_rights";
  $query .= " FROM v4rs WHERE v4r_id=".mq($q['range_id']);
  $new_row=return_one($query, TRUE, "Диапазон не существует");

  audit_log("v4range", $q['range_id'], "v4rs,gr4rs", $q['action'], $prev_row, $new_row);

  ok_exit("done");

} else if($q['action'] == 'v4_add_global_range') {
  require_right(R_SUPER);
  require_p('range_start', Array("type" => "v4long"));
  require_p('range_stop', Array("type" => "v4long"));
  if($q['range_start'] > $q['range_stop']) { error_exit("Invalid range"); };
  require_p('range_name');
  require_p('range_descr');
  require_p('range_style');
  require_p('range_icon');
  require_p('range_icon_style');
  require_p('range_visible', "/^[01]$/");
  require_p('groups_rights',  Array("type" => "num2num"));

  $query="INSERT INTO v4rs SET";
  $query .= " v4r_start=".mq($q['range_start']);
  $query .= ",v4r_stop=".mq($q['range_stop']);
  $query .= ",v4r_name=".mq($q['range_name']);
  $query .= ",v4r_descr=".mq($q['range_descr']);
  $query .= ",v4r_visible=".mq($q['range_visible']);
  $query .= ",v4r_style=".mq($q['range_style']);
  $query .= ",v4r_icon=".mq($q['range_icon']);
  $query .= ",v4r_icon_style=".mq($q['range_icon_style']);
  $query .= ",$set_fk_user_id";
  $query .= ",ts=$time";

  trans_start();

  run_query($query);

  $id=mysqli_insert_id($db);
  if($id == 0) { error_exit("Bad insert ID returned"); };

  foreach($q['groups_rights'] as $gr_id => $rmask) {
    $query="INSERT INTO gr4rs SET";
    $query .= " gr4r_fk_v4r_id=".mq($id);
    $query .= ",gr4r_fk_group_id=".mq($gr_id);
    $query .= ",gr4r_rmask=".mq($rmask);
    $query .= ",$set_fk_user_id";
    $query .= ",ts=$time";
    run_query($query);
  };

  $query="SELECT v4rs.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(gr4r_fk_group_id, ':', gr4r_rmask)) FROM gr4rs WHERE gr4r_fk_v4r_id=v4r_id ORDER BY gr4r_fk_group_id) as groups_rights";
  $query .= " FROM v4rs WHERE v4r_id=".mq($id);
  $new_row=return_one($query, TRUE, "Диапазон не существует");

  audit_log("v4range", $id, "v4rs,gr4rs", $q['action'], [], $new_row);
  ok_exit("done");

} else if($q['action'] == 'v4_delete_global_range') {
  require_right(R_SUPER);
  require_p('range_id', "/^\d+$/");

  trans_start();

  $query="SELECT v4rs.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(gr4r_fk_group_id, ':', gr4r_rmask)) FROM gr4rs WHERE gr4r_fk_v4r_id=v4r_id ORDER BY gr4r_fk_group_id) as groups_rights";
  $query .= " FROM v4rs WHERE v4r_id=".mq($q['range_id']);
  $prev_row=return_one($query, TRUE, "Диапазон не существует");

  $query = "DELETE FROM v4rs";
  $query .= " WHERE v4r_id=".mq($q['range_id']);

  run_query($query);

  audit_log("v4range", $q['range_id'], "v4rs,gr4rs", $q['action'], $prev_row, []);

  ok_exit("done");
} else if($q['action'] == 'get_groups') {
  $ret=return_query("SELECT groups.*, (SELECT COUNT(*) FROM ugs WHERE ug_fk_group_id=group_id) as users_count FROM groups ORDER BY group_name");
  if(!has_right(R_VIEWANY)) {
    foreach($ret as $key => $value) {
      $ret[$key]['group_name'] = "hidden";
    };
  };
  ok_exit($ret);
} else if($q['action'] == 'get_group') {
  require_p('group_id');

  $ret=return_one("SELECT * FROM groups WHERE group_id=".mq($q['group_id']), TRUE, "Группа не существует");
  if(!has_right(R_VIEWANY)) {
    $ret['group_name'] = "hidden";
  };

  $query = "SELECT users.*, aps.ap_off, aps.ap_name FROM (users INNER JOIN ugs ON ug_fk_user_id=user_id";
  $query .= ") INNER JOIN aps ON ap_id=user_fk_ap_id";
  $query .= " WHERE ug_fk_group_id=".mq($q['group_id']);
  $query .= " ORDER BY user_name";

  $ret['group_users']=return_query($query);

  if(!has_right(R_VIEWANY)) {
    foreach($ret['group_users'] as $key => $value) {
      if($value['user_id'] != $this_user_id) {
        foreach(user_hide as $field) {
          $ret['group_users'][$key][$field] = "hidden";
        };
      };
    };
  };

  ok_exit($ret);
} else if($q['action'] == 'get_users') {
  require_right(R_VIEWANY);
  $ret=return_query("SELECT users.*, aps.ap_off, aps.ap_name FROM users INNER JOIN aps ON ap_id=user_fk_ap_id");
  ok_exit($ret);
} else if($q['action'] == 'get_user') {
  require_p('user_id');

  $ret=return_one("SELECT users.*, aps.ap_off, aps.ap_name FROM users INNER JOIN aps ON ap_id=user_fk_ap_id WHERE user_id=".mq($q['user_id']), TRUE, "Пользователь не существует");
  if(!has_right(R_VIEWANY) && $this_user_id != $q['user_id']) {
    foreach(user_hide as $field) {
      $ret[$field] = "hidden";
    };
  };

  $query = "SELECT groups.* FROM groups INNER JOIN ugs ON ug_fk_group_id=group_id";
  $query .= " WHERE ug_fk_user_id=".mq($q['user_id']);
  $query .= " ORDER BY group_name";

  $ret['user_groups']=return_query($query);

  if(!has_right(R_VIEWANY)) {
    foreach($ret['user_groups'] as $key => $value) {
      $ret['user_groups'][$key]['group_name'] = "hidden";
    };
  };

  ok_exit($ret);
} else if($q['action'] == 'save_user') {
  require_right(R_SUPER);
  require_p('user_id', "/^\d+$/");
  optional_p('user_state', "/^(?:-[21]|[01])$/");
  require_p('user_groups', Array("type" => "num_many"));

  if(isset($q['user_state']) && $q['user_id'] == $this_user_id) {
    error_exit("Нельзя изменить собственный статус");
  };

  trans_start();

  $query="SELECT users.*, aps.ap_off, aps.ap_name";
  $query .= ", (SELECT GROUP_CONCAT(ug_fk_group_id) FROM ugs WHERE ug_fk_user_id=user_id ORDER BY ug_fk_group_id) as user_groups";
  $query .= " FROM users INNER JOIN aps ON ap_id=user_fk_ap_id WHERE user_id=".mq($q['user_id']);
  $prev_row=return_one($query, TRUE, "Пользователь не существует");

  $query="UPDATE users SET";
  $query .= " ts=$time";
  $query .= ",$set_fk_user_id";

  if(isset($q['user_state'])) {
    $query .= ",user_state=".mq($q['user_state']);
  };

  $query .= " WHERE user_id=".mq($q['user_id']);

  run_query($query);

  $query="DELETE FROM ugs WHERE ug_fk_user_id=".mq($q['user_id']);
  run_query($query);

  $query="INSERT INTO ugs(ts, fk_user_id,ug_fk_user_id,ug_fk_group_id)";
  $query .= " SELECT $time, ".mq($this_user_id).", ".mq($q['user_id']).", group_id FROM groups WHERE";
  $query .= " group_id IN(".join(",", $q['user_groups']).")";
  run_query($query);

  $rstr=return_single("SELECT GROUP_CONCAT(group_rights) FROM groups INNER JOIN ugs ON ug_fk_group_id=group_id WHERE ug_fk_user_id=".mq($this_user_id), TRUE);
  if(!has_right(R_SUPER, $rstr)) {
    error_exit("Операция приведет к потере права суперпользователя\nтекущим администратором. Операция отменена");
  };

  $query="SELECT users.*, aps.ap_off, aps.ap_name";
  $query .= ", (SELECT GROUP_CONCAT(ug_fk_group_id) FROM ugs WHERE ug_fk_user_id=user_id ORDER BY ug_fk_group_id) as user_groups";
  $query .= " FROM users INNER JOIN aps ON ap_id=user_fk_ap_id WHERE user_id=".mq($q['user_id']);
  $new_row=return_one($query, TRUE, "Пользователь не существует");

  audit_log("user", $q['user_id'], "users,ugs", $q['action'], $prev_row, $new_row);

  $ret=return_one("SELECT users.*, aps.ap_off, aps.ap_name FROM users INNER JOIN aps ON ap_id=user_fk_ap_id WHERE user_id=".mq($q['user_id']));
  
  ok_exit($ret);
} else if($q['action'] == 'save_group') {
  require_right(R_SUPER);
  require_p('group_id', "/^\d+$/");
  require_p('group_name', "/\S+/");
  require_p('group_rights', "/^(?:[a-z0-9_]+(?:,[a-z0-9_]+)*)?$/");
  require_p('group_users', Array("type" => "num_any"));

  trans_start();

  $query="SELECT groups.*, (SELECT GROUP_CONCAT(ug_fk_user_id) FROM ugs WHERE ug_fk_group_id=group_id ORDER BY ug_fk_user_id) as group_users FROM groups WHERE group_id=".mq($q['group_id']);
  $prev_row=return_one($query, TRUE, "Группа не существует");

  if($prev_row['group_default'] != 0 || $prev_row['group_name'] == "default") {
    if($q['group_name'] != "default") {
      error_exit("Нельзя переименовывать группу по умолчанию");
    };
  } else {
    if($q['group_name'] == "default") {
      error_exit("Нельзя переименовывать группу в группу по умолчанию");
    };
  };

  $query="UPDATE groups SET";
  $query .= " ts=$time";
  $query .= ",$set_fk_user_id";
  $query .= ",group_name=".mq($q['group_name']);
  $query .= ",group_rights=".mq($q['group_rights']);
  $query .= " WHERE group_id=".mq($q['group_id']);

  run_query($query);

  run_query("DELETE FROM ugs WHERE ug_fk_group_id=".mq($q['group_id']));

  foreach($q['group_users'] as $user_id) {
    $query = "INSERT INTO ugs SET";
    $query .= " $set_fk_user_id";
    $query .= ",ug_fk_group_id=".mq($q['group_id']);
    $query .= ",ug_fk_user_id=".mq($user_id);
    $query .= ",ts=$time";
    run_query($query);
  };

  #check if self R_SUPER right is lost
  
  $rstr=return_single("SELECT GROUP_CONCAT(group_rights) FROM groups INNER JOIN ugs ON ug_fk_group_id=group_id WHERE ug_fk_user_id=".mq($this_user_id), TRUE);
  if(!has_right(R_SUPER, $rstr)) {
    error_exit("Операция приведет к потере права суперпользователя\nтекущим администратором. Операция отменена");
  };

  $query="SELECT groups.*, (SELECT GROUP_CONCAT(ug_fk_user_id) FROM ugs WHERE ug_fk_group_id=group_id ORDER BY ug_fk_user_id) as group_users FROM groups WHERE group_id=".mq($q['group_id']);
  $new_row=return_one($query, TRUE, "Группа не существует");

  audit_log("group", $q['group_id'], "groups,ugs", $q['action'], $prev_row, $new_row);

  $query="SELECT groups.*, (SELECT COUNT(*) FROM ugs WHERE ug_fk_group_id=group_id) as users_count FROM groups WHERE group_id=".mq($q['group_id']);

  ok_exit(return_one($query, TRUE, "Группа не существует"));
} else if($q['action'] == 'add_group') {
  require_right(R_SUPER);
  require_p('group_name', "/\S+/");
  require_p('group_rights', "/^(?:[a-z0-9_]+(?:,[a-z0-9_]+)*)?$/");
  require_p('group_users', Array("type" => "num_any"));

  if($q['group_name'] == "default") {
    error_exit("Нельзя добавлять группу по умолчанию");
  };

  trans_start();

  $query="INSERT INTO groups SET";
  $query .= " ts=$time";
  $query .= ",$set_fk_user_id";
  $query .= ",group_name=".mq($q['group_name']);
  $query .= ",group_rights=".mq($q['group_rights']);

  run_query($query);

  $id=mysqli_insert_id($db);
  if($id == 0) { error_exit("Bad insert ID returned"); };


  foreach($q['group_users'] as $user_id) {
    $query = "INSERT INTO ugs SET";
    $query .= " $set_fk_user_id";
    $query .= ",ug_fk_group_id=".mq($id);
    $query .= ",ug_fk_user_id=".mq($user_id);
    $query .= ",ts=$time";
    run_query($query);
  };

  $query="SELECT groups.*, (SELECT GROUP_CONCAT(ug_fk_user_id) FROM ugs WHERE ug_fk_group_id=group_id ORDER BY ug_fk_user_id) as group_users FROM groups WHERE group_id=".mq($id);
  $new_row=return_one($query, TRUE, "Группа не существует");

  audit_log("group", $id, "groups,ugs", $q['action'], [], $new_row);

  $query="SELECT groups.*, (SELECT COUNT(*) FROM ugs WHERE ug_fk_group_id=group_id) as users_count FROM groups WHERE group_id=".mq($id);

  ok_exit(return_one($query, TRUE, "Группа не существует"));
} else if($q['action'] == 'delete_group') {
  require_right(R_SUPER);
  require_p('group_id', "/^\d+$/");

  trans_start();

  # save for history
  $query="SELECT groups.*";
  $query .= ", (SELECT GROUP_CONCAT(ug_fk_user_id) FROM ugs WHERE ug_fk_group_id=group_id ORDER BY ug_fk_user_id) as group_users";
  $query .= " FROM groups WHERE group_id=".mq($q['group_id']);
  $prev_row=return_one($query, TRUE, "Группа не существует");

  if($prev_row['group_default'] != 0 || $prev_row['group_name'] == "default") {
    error_exit("Нельзя удалять группу по умолчанию");
  };

  $query="SELECT DISTINCT v4net_addr, v4net_mask FROM g4favs WHERE v4fav_fk_group_id=".mq($q['group_id']);
  $prev_row['group_v4favs']=return_query($query);

  $query="SELECT DISTINCT HEX(v6net_addr), v6net_mask FROM g6favs WHERE v6fav_fk_group_id=".mq($q['group_id']);
  $prev_row['group_v6favs']=return_query($query);

  $query="SELECT gn4r_fk_v4net_id, gn4r_rmask FROM gn4rs WHERE gn4r_fk_group_id=".mq($q['group_id']);
  $prev_row['group_v4net_rights']=return_query($query);

  $query="SELECT gn6r_fk_v6net_id, gn6r_rmask FROM gn6rs WHERE gn6r_fk_group_id=".mq($q['group_id']);
  $prev_row['group_v6net_rights']=return_query($query);

  $query="SELECT gr4r_fk_v4r_id, gr4r_rmask FROM gr4rs WHERE gr4r_fk_group_id=".mq($q['group_id']);
  $prev_row['group_v4range_rights']=return_query($query);

  $query="SELECT gr6r_fk_v6r_id, gr6r_rmask FROM gr6rs WHERE gr6r_fk_group_id=".mq($q['group_id']);
  $prev_row['group_v6range_rights']=return_query($query);

  ###
  $query="DELETE FROM groups";
  $query .= " WHERE group_id=".mq($q['group_id']);

  run_query($query);

  #check if self R_SUPER right is lost
  
  $rstr=return_single("SELECT GROUP_CONCAT(group_rights) FROM groups INNER JOIN ugs ON ug_fk_group_id=group_id WHERE ug_fk_user_id=".mq($this_user_id), TRUE);
  if(!has_right(R_SUPER, $rstr)) {
    error_exit("Операция приведет к потере права суперпользователя\nтекущим администратором. Операция отменена");
  };

  audit_log("group", $q['group_id'], "groups,ugs", $q['action'], $prev_row, []);

  ok_exit("done");
} else if($q['action'] == 'get_vdomains') {
  optional_p('focus_on_vlan_id', "/^\d+$/");

  $query="SELECT vds.*, (SELECT COUNT(*) FROM vlans WHERE vlan_fk_vd_id=vd_id) as vlans_count FROM vds";

  $ret=Array();
  $vds=return_query($query);

  if(!has_right(R_VIEWANY)) {
    foreach($vds as $key => $val) {
      $vds[$key]['vd_name']=substr($vds[$key]['vd_name'], 0, 1)."...";
      $vds[$key]['vd_descr']='hidden';
    };
  };

  $ret['vds']=$vds;

  if(isset($q['focus_on_vlan_id'])) {
    $ret['select_vd_id']=return_only("SELECT vlan_fk_vd_id WHERE vlan_id=".mq($q['focus_on_vlan_id']), TRUE, "VLAN не существует");
  };

  ok_exit($ret);
} else if($q['action'] == 'get_vdomain') {
  require_p('vd_id', "/^\d+$/");

  $query="SELECT vds.*, (SELECT COUNT(*) FROM vlans WHERE vlan_fk_vd_id=vd_id) as vlans_count FROM vds WHERE vd_id=".mq($q['vd_id']);
  $vdomain=return_one($query, TRUE);

  if(!has_right(R_VIEWANY)) {
    $vdomain['vd_name']=substr($vdomain['vd_name'], 0, 1)."...";
    $vdomain['vd_descr']='hidden';
  };

  ok_exit($vdomain);
} else if($q['action'] == 'edit_vdomain') {
  require_right(R_SUPER);
  require_p('vd_id', "/^\d+$/");
  require_p('vd_max_num', "/^\d+$/");
  require_p('vd_name', "/^\S(?:.*\S)?$/");
  require_p('vd_descr');

  trans_start();

  $prev_row=return_one("SELECT vds.*, (SELECT COUNT(*) FROM vlans WHERE vlan_fk_vd_id=vd_id) as vlans_count FROM vds WHERE vd_id=".mq($q['vd_id']), TRUE);

  $query="UPDATE vds SET";
  $query .= " $set_fk_user_id";
  $query .= ",ts=$time";
  $query .= ",vd_name=".mq($q['vd_name']);
  $query .= ",vd_max_num=".mq($q['vd_max_num']);
  $query .= ",vd_descr=".mq($q['vd_descr']);
  $query .= ",vd_check=vd_check+1";
  $query .= " WHERE vd_id=".mq($q['vd_id']);

  run_query($query);

  $new_row=return_one("SELECT vds.*, (SELECT COUNT(*) FROM vlans WHERE vlan_fk_vd_id=vd_id) as vlans_count FROM vds WHERE vd_id=".mq($q['vd_id']), TRUE);


  audit_log("vd", $q['vd_id'], "vds", $q['action'], $prev_row, $new_row);

  ok_exit($new_row);
} else if($q['action'] == 'add_vdomain') {
  require_right(R_SUPER);
  require_p('vd_max_num', "/^\d+$/");
  require_p('vd_name', "/^\S(?:.*\S)?$/");
  require_p('vd_descr');

  trans_start();

  $prev_row=[];

  $query="INSERT INTO vds SET";
  $query .= " $set_fk_user_id";
  $query .= ",ts=$time";
  $query .= ",vd_name=".mq($q['vd_name']);
  $query .= ",vd_max_num=".mq($q['vd_max_num']);
  $query .= ",vd_descr=".mq($q['vd_descr']);
  $query .= ",vd_check=vd_check+1";

  run_query($query);

  $q['vd_id']=mysqli_insert_id($db);
  if( $q['vd_id'] == 0 ) { error_exit("Bad insert id"); };

  $new_row=return_one("SELECT vds.*, (SELECT COUNT(*) FROM vlans WHERE vlan_fk_vd_id=vd_id) as vlans_count FROM vds WHERE vd_id=".mq($q['vd_id']), TRUE);


  audit_log("vd", $q['vd_id'], "vds", $q['action'], $prev_row, $new_row);

  ok_exit($new_row);
} else if($q['action'] == 'delete_vdomain') {
  require_right(R_SUPER);
  require_p('vd_id', "/^\d+$/");

  trans_start();

  $prev_row=return_one("SELECT vds.*, (SELECT COUNT(*) FROM vlans WHERE vlan_fk_vd_id=vd_id) as vlans_count FROM vds WHERE vd_id=".mq($q['vd_id']), TRUE);

  $query="DELETE FROM vds WHERE vd_id=".mq($q['vd_id']);
  run_query($query);

  $new_row=[];

  audit_log("vd", $q['vd_id'], "vds", $q['action'], $prev_row, $new_row);

  ok_exit("done");
} else if($q['action'] == 'get_vlans') {
  require_p('vd_id', "/^\d+$/");

  $vdomain=return_one("SELECT vds.* FROM vds WHERE vd_id=".mq($q['vd_id']), TRUE);
  if(!has_right(R_VIEWANY)) {
    $vdomain['vd_name']=substr($vdomain['vd_name'], 0, 1)."...";
    $vdomain['vd_descr']='hidden';
  };

  $query="SELECT vrs.*, (SELECT BIT_OR(gvrr_rmask) FROM gvrrs WHERE gvrr_fk_vr_id=vr_id AND gvrr_fk_group_id IN ($groups)) as rmask";
  $query .=" FROM vrs";
  $query .=" WHERE vr_fk_vd_id=".mq($q['vd_id']);

  $vrs=return_query($query, 'vr_id');

  foreach($vrs as $key => $val) {
    if(!has_nright($val['rmask'], NR_VIEWNAME)) { $vrs[$key]['vr_name'] = 'hidden';  $vrs[$key]['vr_descr'] = 'hidden'; };
    if(!has_nright($val['rmask'], NR_VIEWOTHER)) { $vrs[$key]['vr_descr'] = 'hidden'; };
  };

  $query="SELECT vlans.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v4net_id,':',v4net_addr,'/',v4net_mask)) FROM v4nets WHERE v4net_fk_vlan_id=vlan_id GROUP BY v4net_fk_vlan_id ORDER BY v4net_addr) as v4nets";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v6net_id,':',HEX(v6net_addr),'/',v6net_mask)) FROM v6nets WHERE v6net_fk_vlan_id=vlan_id GROUP BY v6net_fk_vlan_id ORDER BY v6net_addr) as v6nets";
  $query .= " FROM vlans WHERE vlan_fk_vd_id=".mq($q['vd_id']);
  $query .= " ORDER BY vlan_number";
  $vlans=return_query($query, 'vlan_number');


  foreach($vlans as $i => $v) {
    $vlan_num=$v['vlan_number'];

    if(!isset($min_vlan) || $vlan_num < $min_vlan) {
      $min_vlan=$vlan_num;
    };

    if(!isset($max_vlan) || $vlan_num > $max_vlan) {
      $max_vlan=$vlan_num;
    };

    $effective_rmask = 0;

    foreach($vrs as $vrange) {
      if($vrange['vr_start'] <= $vlan_num && $vrange['vr_stop'] >= $vlan_num && $vrange['rmask'] !== NULL) { $effective_rmask = $effective_rmask | $vrange['rmask']; };
    };

    if(!has_nright($effective_rmask, NR_VIEWNAME)) { $vlans[$i]['vlan_name'] = 'hidden';  $vlans[$i]['vlan_descr'] = 'hidden'; };
    if(!has_nright($effective_rmask, NR_VIEWOTHER)) { $vlans[$i]['vlan_descr'] = 'hidden'; };

  };

  $ret=Array();
  $ret['vd']=$vdomain;
  $ret['vrs']=$vrs;
  $ret['vlans']=$vlans;

  if(count($vlans) > 0) {
    $ret['vlans_start']=$min_vlan;
    $ret['vlans_stop']=$max_vlan;
  };

  ok_exit($ret);
} else if($q['action'] == 'take_vlan') {
  require_p('vd_id', "/^\d+$/");
  require_p('vlan_number', "/^\d+$/");

  $query="SELECT vrs.vr_start,vrs.vr_stop, (SELECT BIT_OR(gvrr_rmask) FROM gvrrs WHERE gvrr_fk_vr_id=vr_id AND gvrr_fk_group_id IN ($groups)) as rmask";
  $query .=" FROM vrs";
  $query .=" WHERE vr_fk_vd_id=".mq($q['vd_id']);
  $query .=" AND vr_start <= ".mq($q['vlan_number']);
  $query .=" AND vr_stop >= ".mq($q['vlan_number']);

  $vrs=return_query($query);

  $effective_rmask = 0;
  foreach($vrs as $vr) {
    $effective_rmask = $effective_rmask | $vr['rmask'];
  };

  if(!has_nright($effective_rmask, NR_TAKE_VLAN)) {
    error_exit("Недостаточно прав");
  };

  trans_start();

  $prev_row=[];

  $query="INSERT INTO vlans SET";
  $query .= " vlan_fk_vd_id=".mq($q['vd_id']);
  $query .= ",vlan_number=".mq($q['vlan_number']);
  $query .= ",vlan_name=CONCAT('VLAN',LPAD(vlan_number, 4, '0'))";
  $query .= ",ts=$time";
  $query .= ",$set_fk_user_id";

  run_query($query);

  $id=mysqli_insert_id($db);
  if($id == 0) { error_exit("Bad insert ID returned"); };

  run_query("UPDATE vds SET vd_check=vd_check+1 WHERE vd_id=".mq($q['vd_id']));
  
  $new_row=return_one("SELECT * FROM vlans WHERE vlan_id=".mq($id), TRUE);

  audit_log("vlan", $id, "vlans", $q['action'], $prev_row, $new_row);

  $query="SELECT vlans.*";
  $query .= ", NULL as v4nets";
  $query .= ", NULL as v6nets";
  $query .= " FROM vlans WHERE vlan_id=".mq($id);
  $ret=return_one($query, TRUE);

  if(!has_nright($effective_rmask, NR_VIEWNAME)) { $ret['vlan_name'] = 'hidden';  $ret['vlan_descr'] = 'hidden'; };
  if(!has_nright($effective_rmask, NR_VIEWOTHER)) { $ret['vlan_descr'] = 'hidden'; };

  ok_exit($ret);

} else if($q['action'] == 'free_vlan') {
  require_p('vlan_id', "/^\d+$/");

  trans_start();

  $query="SELECT vlans.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v4net_id,':',v4net_addr,'/',v4net_mask)) FROM v4nets WHERE v4net_fk_vlan_id=vlan_id GROUP BY v4net_fk_vlan_id ORDER BY v4net_addr) as v4nets";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v6net_id,':',HEX(v6net_addr),'/',v6net_mask)) FROM v6nets WHERE v6net_fk_vlan_id=vlan_id GROUP BY v6net_fk_vlan_id ORDER BY v6net_addr) as v6nets";
  $query .= " FROM vlans WHERE vlan_id=".mq($q['vlan_id']);
  $prev_row=return_one($query, TRUE);

  $query="SELECT vrs.vr_start,vrs.vr_stop, (SELECT BIT_OR(gvrr_rmask) FROM gvrrs WHERE gvrr_fk_vr_id=vr_id AND gvrr_fk_group_id IN ($groups)) as rmask";
  $query .=" FROM vrs";
  $query .=" WHERE vr_fk_vd_id=".mq($prev_row['vlan_fk_vd_id']);
  $query .=" AND vr_start <= ".mq($prev_row['vlan_number']);
  $query .=" AND vr_stop >= ".mq($prev_row['vlan_number']);

  $vrs=return_query($query);

  $effective_rmask = 0;
  foreach($vrs as $vr) {
    $effective_rmask = $effective_rmask | $vr['rmask'];
  };

  if(!has_nright($effective_rmask, NR_FREE_VLAN)) {
    error_exit("Недостаточно прав");
  };

  run_query("DELETE FROM vlans WHERE vlan_id=".mq($q['vlan_id']));

  run_query("UPDATE vds SET vd_check=vd_check+1 WHERE vd_id=".mq($q['vd_id']));
  $new_row=[];

  audit_log("vlan", $q['vlan_id'], "vlans", $q['action'], $prev_row, $new_row);

  ok_exit("done");
} else if($q['action'] == 'set_vlan_prop') {
  require_p('vlan_id', "/^\d+$/");
  require_p('prop_name', "/^(?:vlan_name|vlan_descr)$/");

  if($q['prop_name'] == "vlan_name") {
    require_p('value', "/^[0-9a-zA-Z_]{1,64}$/");
  } else {
    require_p('value');
  };

  trans_start();

  $query="SELECT vlans.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v4net_id,':',v4net_addr,'/',v4net_mask)) FROM v4nets WHERE v4net_fk_vlan_id=vlan_id GROUP BY v4net_fk_vlan_id ORDER BY v4net_addr) as v4nets";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v6net_id,':',HEX(v6net_addr),'/',v6net_mask)) FROM v6nets WHERE v6net_fk_vlan_id=vlan_id GROUP BY v6net_fk_vlan_id ORDER BY v6net_addr) as v6nets";
  $query .= " FROM vlans WHERE vlan_id=".mq($q['vlan_id']);
  $prev_row=return_one($query, TRUE);

  $query="SELECT vrs.vr_start,vrs.vr_stop, (SELECT BIT_OR(gvrr_rmask) FROM gvrrs WHERE gvrr_fk_vr_id=vr_id AND gvrr_fk_group_id IN ($groups)) as rmask";
  $query .=" FROM vrs";
  $query .=" WHERE vr_fk_vd_id=".mq($prev_row['vlan_fk_vd_id']);
  $query .=" AND vr_start <= ".mq($prev_row['vlan_number']);
  $query .=" AND vr_stop >= ".mq($prev_row['vlan_number']);

  $vrs=return_query($query);

  $effective_rmask = 0;
  foreach($vrs as $vr) {
    $effective_rmask = $effective_rmask | $vr['rmask'];
  };

  if(!has_nright($effective_rmask, NR_EDIT_VLAN)) {
    error_exit("Недостаточно прав");
  };

  $query="UPDATE vlans SET";
  $query .= " ".$q['prop_name']."=".mq($q['value']);
  $query .= ",ts=$time";
  $query .= ",$set_fk_user_id";
  $query .= " WHERE vlan_id=".mq($q['vlan_id']);

  run_query($query);

  run_query("UPDATE vds SET vd_check=vd_check+1 WHERE vd_id=".mq($prev_row['vlan_fk_vd_id']));

  $query="SELECT vlans.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v4net_id,':',v4net_addr,'/',v4net_mask)) FROM v4nets WHERE v4net_fk_vlan_id=vlan_id GROUP BY v4net_fk_vlan_id ORDER BY v4net_addr) as v4nets";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v6net_id,':',HEX(v6net_addr),'/',v6net_mask)) FROM v6nets WHERE v6net_fk_vlan_id=vlan_id GROUP BY v6net_fk_vlan_id ORDER BY v6net_addr) as v6nets";
  $query .= " FROM vlans WHERE vlan_id=".mq($q['vlan_id']);
  $new_row=return_one($query, TRUE);

  audit_log("vlan", $q['vlan_id'], "vlans", $q['action'], $prev_row, $new_row);

  ok_exit("done");
} else if($q['action'] == 'save_vlan') {
  require_p('vlan_id', "/^\d+$/");
  require_p('vlan_name', "/^[0-9a-zA-Z_]{1,64}$/");
  require_p('vlan_descr');

  trans_start();

  $query="SELECT vlans.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v4net_id,':',v4net_addr,'/',v4net_mask)) FROM v4nets WHERE v4net_fk_vlan_id=vlan_id GROUP BY v4net_fk_vlan_id ORDER BY v4net_addr) as v4nets";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v6net_id,':',HEX(v6net_addr),'/',v6net_mask)) FROM v6nets WHERE v6net_fk_vlan_id=vlan_id GROUP BY v6net_fk_vlan_id ORDER BY v6net_addr) as v6nets";
  $query .= " FROM vlans WHERE vlan_id=".mq($q['vlan_id']);
  $prev_row=return_one($query, TRUE);

  $query="SELECT vrs.vr_start,vrs.vr_stop, (SELECT BIT_OR(gvrr_rmask) FROM gvrrs WHERE gvrr_fk_vr_id=vr_id AND gvrr_fk_group_id IN ($groups)) as rmask";
  $query .=" FROM vrs";
  $query .=" WHERE vr_fk_vd_id=".mq($prev_row['vlan_fk_vd_id']);
  $query .=" AND vr_start <= ".mq($prev_row['vlan_number']);
  $query .=" AND vr_stop >= ".mq($prev_row['vlan_number']);

  $vrs=return_query($query);

  $effective_rmask = 0;
  foreach($vrs as $vr) {
    $effective_rmask = $effective_rmask | $vr['rmask'];
  };

  if(!has_nright($effective_rmask, NR_EDIT_VLAN)) {
    error_exit("Недостаточно прав");
  };

  $query="UPDATE vlans SET";
  $query .= " vlan_name=".mq($q['vlan_name']);
  $query .= ",vlan_descr=".mq($q['vlan_descr']);
  $query .= ",ts=$time";
  $query .= ",$set_fk_user_id";
  $query .= " WHERE vlan_id=".mq($q['vlan_id']);

  run_query($query);

  run_query("UPDATE vds SET vd_check=vd_check+1 WHERE vd_id=".mq($prev_row['vlan_fk_vd_id']));

  $query="SELECT vlans.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v4net_id,':',v4net_addr,'/',v4net_mask)) FROM v4nets WHERE v4net_fk_vlan_id=vlan_id GROUP BY v4net_fk_vlan_id ORDER BY v4net_addr) as v4nets";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(v6net_id,':',HEX(v6net_addr),'/',v6net_mask)) FROM v6nets WHERE v6net_fk_vlan_id=vlan_id GROUP BY v6net_fk_vlan_id ORDER BY v6net_addr) as v6nets";
  $query .= " FROM vlans WHERE vlan_id=".mq($q['vlan_id']);
  $new_row=return_one($query, TRUE);

  audit_log("vlan", $q['vlan_id'], "vlans", $q['action'], $prev_row, $new_row);

  $ret=$new_row;

  if(!has_nright($effective_rmask, NR_VIEWNAME)) { $ret['vlan_name'] = 'hidden';  $ret['vlan_descr'] = 'hidden'; };
  if(!has_nright($effective_rmask, NR_VIEWOTHER)) { $ret['vlan_descr'] = 'hidden'; };

  ok_exit($ret);

} else if($q['action'] == 'vlan_get_range') {
  require_p('range_id', "/^\d+$/");
  $ret=Array();

  $query="SELECT vrs.*";
  $query .= ", (SELECT BIT_OR(gvrr_rmask) FROM gvrrs WHERE gvrr_fk_vr_id=vr_id AND gvrr_fk_group_id IN ($groups)) as rmask";
  $query .= " FROM vrs WHERE";
  $query .= " vr_id=".mq($q['range_id']);

  $range_info=return_one($query, TRUE, "Range not found.");

  if(!has_nright($range_info['rmask'], NR_VIEWNAME)) { $range_info['vr_name'] = 'hidden'; $range_info['vr_descr'] = 'hidden'; };
  if(!has_nright($range_info['rmask'], NR_VIEWOTHER)) { $range_info['vr_descr'] = 'hidden'; };

  $ret['range_info']=$range_info;

  $query="SELECT gvrr_rmask as rmask, group_id, group_name";
  $query .= " FROM gvrrs INNER JOIN groups ON gvrr_fk_group_id=group_id";
  $query .= " WHERE gvrr_fk_vr_id=".mq($q['range_id']);
  $query .= " ORDER BY group_name, group_id";

  $ret['range_group_rights']=return_query($query);

  ok_exit($ret);
} else if($q['action'] == 'vlan_edit_range') {
  require_p('range_id', "/^\d+$/");
  require_p('range_start', "/^\d+$/");
  require_p('range_stop', "/^\d+$/");
  if($q['range_start'] > $q['range_stop']) { error_exit("Invalid range"); };
  require_p('range_name');
  require_p('range_descr');
  require_p('range_style');
  require_p('range_icon');
  require_p('range_icon_style');
  require_p('groups_rights',  Array("type" => "num2num"));

  trans_start();

  $query="SELECT vrs.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(gvrr_fk_group_id, ':', gvrr_rmask)) FROM gvrrs WHERE gvrr_fk_vr_id=vr_id ORDER BY gvrr_fk_group_id) as groups_rights";
  $query .= " FROM vrs WHERE vr_id=".mq($q['range_id']);
  $prev_row=return_one($query, TRUE, "Диапазон не существует");

  $query="UPDATE vrs SET";
  $query .= " vr_start=".mq($q['range_start']);
  $query .= ",vr_stop=".mq($q['range_stop']);
  $query .= ",vr_name=".mq($q['range_name']);
  $query .= ",vr_descr=".mq($q['range_descr']);
  $query .= ",vr_style=".mq($q['range_style']);
  $query .= ",vr_icon=".mq($q['range_icon']);
  $query .= ",vr_icon_style=".mq($q['range_icon_style']);
  $query .= ",ts=$time";
  $query .= ",$set_fk_user_id";
  $query .= " WHERE vr_id=".mq($q['range_id']);

  run_query($query);

  $query="DELETE FROM gvrrs WHERE gvrr_fk_vr_id=".mq($q['range_id']);
  run_query($query);

  foreach($q['groups_rights'] as $gr_id => $rmask) {
    $query="INSERT INTO gvrrs SET";
    $query .= " gvrr_fk_vr_id=".mq($q['range_id']);
    $query .= ",gvrr_fk_group_id=".mq($gr_id);
    $query .= ",gvrr_rmask=".mq($rmask);
    $query .= ",$set_fk_user_id";
    $query .= ",ts=$time";
    run_query($query);
  };

  run_query("UPDATE vds SET vd_check=vd_check+1 WHERE vd_id=".mq($prev_row['vr_fk_vd_id']));

  $query="SELECT vrs.*";
  $query .= ", (SELECT GROUP_CONCAT(CONCAT(gvrr_fk_group_id, ':', gvrr_rmask)) FROM gvrrs WHERE gvrr_fk_vr_id=vr_id ORDER BY gvrr_fk_group_id) as groups_rights";
  $query .= " FROM vrs WHERE vr_id=".mq($q['range_id']);
  $new_row=return_one($query, TRUE, "Диапазон не существует");

  audit_log("vrange", $q['range_id'], "vrs,gvrrs", $q['action'], $prev_row, $new_row);

  ok_exit("done");
} else {
  error_exit("Unknown action '".$q['action']."'");
};

?>
