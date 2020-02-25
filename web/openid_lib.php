<?php
function http_post($uri, $fields, $headers=NULL) {
  global $curl;
  curl_reset($curl);
  curl_setopt($curl, CURLOPT_URL, $uri);
  curl_setopt($curl, CURLOPT_POST, TRUE);
  curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
  curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($fields));

  if($headers !== NULL) {
    if(gettype($headers) == "array") {
      curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
    } else {
      curl_setopt($curl, CURLOPT_HTTPHEADER, Array($headers));
    };
  };

  $json=curl_exec($curl);
  if($json === FALSE) {
    error_exit("cURL error: ".curl_error($curl));
  };

  $resp_data = curl_getinfo($curl);
  if($resp_data === FALSE) {
    error_exit("cURL getinfo error: ".curl_error($curl));
  };

  if($resp_data["content_type"] != "application/json") {
    error_exit("Bad response content type: ".$resp_data["content_type"]."\n".$json);
  };

  $r=@json_decode($json, TRUE);
  if($r === NULL) {
    error_exit("Cannot decode JSON: ".$json);
  };

  #if($resp_data["http_code"] != 200) {
  #  error_exit("Bad response code: ".$resp_data["http_code"]."\n".$json);
  #};

  return $r;
};

function base64url_decode($base64url) {
  $base64 = strtr($base64url, '-_', '+/');
  $plainText = base64_decode($base64);
  return ($plainText);
};

$RSA_SIGN_ALGOS=Array(
  "RS256" => OPENSSL_ALGO_SHA256,
  "RS384" => OPENSSL_ALGO_SHA384,
  "RS512" => OPENSSL_ALGO_SHA512,
);

$HMAC_SIGN_ALGOS=Array(
  "HS256" => "sha256",
  "HS384" => "sha384",
  "HS512" => "sha512",
);

function decode_token($token_str, $pub_key=NULL, $hmac_key=NULL) {
  global $RSA_SIGN_ALGOS;
  global $HMAC_SIGN_ALGOS;
  $parts=explode(".", $token_str);

  $header_json=base64url_decode($parts[0]);
  if($header_json === FALSE) {
    return(Array("error" => "Error base64 decoding token header"));
  };

  $header=@json_decode($header_json, TRUE);
  if($header === FALSE) {
    return(Array("error" => "Error JSON decoding token header"));
  };



  $body_json=base64url_decode($parts[1]);
  if($body_json === FALSE) {
    return(Array("error" => "Error base64 decoding token body"));
  };

  $body=@json_decode($body_json, TRUE);
  if($body === FALSE) {
    return(Array("error" => "Error JSON decoding token body"));
  };

  $ret=$body;
  $ret["_header"]=$header;

  $signature=base64url_decode($parts[2]);
  if($signature === FALSE) {
    return(Array("error" => "Error base64 decoding token signature"));
  };

  if($pub_key !== NULL && isset($header["alg"]) && isset($RSA_SIGN_ALGOS[ $header["alg"] ])) {
    $ver_res=openssl_verify($parts[0].".".$parts[1], $signature, $pub_key, $RSA_SIGN_ALGOS[ $header["alg"] ]);
    $ret["verify_res"] = $ver_res;
  } else if($hmac_key !== NULL && isset($header["alg"]) && isset($HMAC_SIGN_ALGOS[ $header["alg"] ])) {
    $hash=hash_hmac($HMAC_SIGN_ALGOS[ $header["alg"] ], $parts[0].".".$parts[1], $hmac_key, TRUE);
    if($hash === FALSE) {
      return(Array("error" => "Error calculating hash"));
    };
    if($signature === $hash) {
      $ret["verify_res"] = 1;
    } else {
      $ret["verify_res"] = 0;
    };
  } else {
    $ret["verify_res"] = -2;
  };

  return $ret;
};

function process_tokens($tokens, $ap, $just_logged_in=FALSE) {
  global $DEFAULT_MAX_AUTO_ADD_ALLOWED;
  global $MAX_TOKEN_AGE;

  $time=time();

  if(!isset($_SESSION['openid_redirect_uri']) ||
     !isset($_SESSION['openid_nonce']) ||
     !isset($_SESSION['openid_success_uri']) ||
     FALSE
  ) {
    reset_session();
    return(Array("error" => "Bad session"));
  };


  $id_token_str = $tokens['id_token'];
  $refresh_token_str = $tokens['refresh_token'];
  $access_token_str = $tokens['access_token'];
  
  $pub_key_str=$ap['ap_rsa_pub_key'];
  if(strpos($pub_key_str, '-----BEGIN') === FALSE) {
    $pub_key_str="-----BEGIN PUBLIC KEY-----\n".$pub_key_str."\n-----END PUBLIC KEY-----\n";
  };
  $pub_key=openssl_pkey_get_public($pub_key_str);
  
  if($pub_key === FALSE) {
    reset_session();
    return(Array("error" => "Error decoding public key"));
  };
  
  $hmac_key=$ap['ap_client_secret'];
  
  $id_token=decode_token($id_token_str, $pub_key, $hmac_key);
  $refresh_token=decode_token($refresh_token_str, $pub_key, $hmac_key);
  $access_token=decode_token($access_token_str, $pub_key, $hmac_key);
  
  $ver_error=FALSE;
  
  $keys_check=Array();
  
  foreach(Array($id_token, $access_token, $refresh_token) as $token) {
    foreach(Array('verify_res', 'exp', 'iat', 'iss', 'sub', 'nonce') as $attr) {
      $cv=!isset($token[$attr]);
      $keys_check[ "notexists:".$token['typ'].".".$attr ] = $cv;
    };
  };
  
  $keys_check[ 'notexists:id.aud' ] = !isset($id_token['aud']);
  $keys_check[ 'notexists:refresh.aud' ] = !isset($refresh_token['aud']);
  
  $keys_check[ 'id.verify_res' ] = $id_token['verify_res'] !== 1;
  $keys_check[ 'access.verify_res' ] = $access_token['verify_res'] !== 1;
  
  $keys_check[ 'id.nonce' ] = $id_token['nonce'] !== $_SESSION['openid_nonce'];
  $keys_check[ 'access.nonce' ] = $access_token['nonce'] !== $_SESSION['openid_nonce'];
  $keys_check[ 'refresh.nonce' ] = $refresh_token['nonce'] !== $_SESSION['openid_nonce'];
  
  $keys_check[ 'id.aud'] = $id_token['aud'] !== $ap['ap_client_id'];
  
  $keys_check[ 'id.azp'] = (isset($id_token['azp']) && $id_token['azp'] !== $ap['ap_client_id']);
  $keys_check[ 'access.azp'] = (isset($access_token['azp']) && $access_token['azp'] !== $ap['ap_client_id']);
  $keys_check[ 'refresh.azp'] = (isset($refresh_token['azp']) && $refresh_token['azp'] !== $ap['ap_client_id']);
  
  $keys_check[ 'id.exp' ] = $id_token['exp'] <= $time;
  $keys_check[ 'id.iat' ] = $id_token['iat'] > $time || $id_token['iat'] < ($time - $MAX_TOKEN_AGE);
  $keys_check[ 'access.exp' ] = $access_token['exp'] <= $time;
  $keys_check[ 'access.iat' ] = $access_token['iat'] > $time || $access_token['iat'] < ($time - $MAX_TOKEN_AGE);
  $keys_check[ 'refresh.exp' ] = $refresh_token['exp'] <= $time;
  $keys_check[ 'refresh.iat' ] = $refresh_token['iat'] > $time || $refresh_token['iat'] < ($time - $MAX_TOKEN_AGE);
  
  $keys_check[ 'id.iss' ] = $id_token['iss'] !== $ap['ap_issuer'];
  $keys_check[ 'access.iss' ] = $access_token['iss'] !== $ap['ap_issuer'];
  $keys_check[ 'refresh.iss' ] = $refresh_token['iss'] !== $ap['ap_issuer'];
  
  $keys_check[ 'id.sub' ] = $id_token['sub'] == '';
  $keys_check[ 'access.sub' ] = $id_token['sub'] !== $access_token['sub'];
  $keys_check[ 'refresh.sub' ] = $id_token['sub'] !== $refresh_token['sub'];
  
  foreach($keys_check as $val) {
    if($val) {
      reset_session();
      return(Array("error" => "Error checking tokens", "keys_check" => $keys_check, "tokens" => Array($id_token, $refresh_token, $access_token)));
    };
  };
  
  $query="SELECT * FROM users WHERE TRUE";
  $query .= " AND user_fk_ap_id=".mq($ap['ap_id']);
  $query .= " AND user_sub=".mq($id_token['sub']);
  
  $user=return_one($query);
  if($user !== NULL) {
  
    if($just_logged_in) {
      run_query("UPDATE users SET ts=ts, user_last_login=NOW() WHERE user_id=".mq($user['user_id']));
    };

    if($user['user_state'] == 1) {
      $updates=Array();
      if(isset($id_token['name']) && $user['user_name'] != $id_token['name']) {
        $updates['user_name']=$id_token['name'];
      };
      if(isset($id_token['preferred_username']) && $user['user_username'] != $id_token['preferred_username']) {
        $updates['user_username']=$id_token['preferred_username'];
      };
      if(isset($id_token['email']) && $user['user_email'] != $id_token['email']) {
        $updates['user_email']=$id_token['email'];
      };
      if(isset($id_token['phone']) && $user['user_phone'] != $id_token['phone']) {
        $updates['user_phone']=$id_token['phone'];
      };
  
      if(count($updates) > 0) {
        $query="UPDATE users SET ";
        $sets=Array();
        foreach($updates as $key => $value) {
          array_push($sets, $key."=".mq($value));
        };
        $query .= join(", ", $sets);
  
        $query .= " WHERE user_id=".mq($user['user_id']);
        run_query($query);
        foreach($updates as $key => $value) {
          $user[$key] = $value;
        };
      };
    };
  } else {
    $allowed_auto_add=get_attr_value("system", 0, "autoreg_max_users");
    if($allowed_auto_add === NULL) {
      $allowed_auto_add=$DEFAULT_MAX_AUTO_ADD_ALLOWED;
    };

    trans_start();
    $query="SELECT COUNT(*) AS c FROM users WHERE user_state= -1";
    $auto_added=return_single($query, TRUE);
  
    if($auto_added < $allowed_auto_add) {
      $debug_out['user_auto_add'] = TRUE;
  
      $query="INSERT INTO users SET";
      $query .= " user_fk_ap_id=".mq($ap['ap_id']);
      $query .= ",user_sub=".mq($id_token['sub']);
      $query .= ",user_last_login=NOW()";
      if(isset($id_token['name'])) {
        $query .= ",user_name=".mq($id_token['name']);
      };
      if(isset($id_token['preferred_username'])) {
        $query .= ",user_username=".mq($id_token['preferred_username']);
      };
      if(isset($id_token['email'])) {
        $query .= ",user_email=".mq($id_token['email']);
      };
      if(isset($id_token['phone'])) {
        $query .= ",user_phone=".mq($id_token['phone']);
      };
  
      run_query($query);
      trans_end();
  
    } else {
      trans_end();
      reset_session();
      return(Array("error" => "Пользователь не существует и превышен лимит на авто-добавление новых пользователей. Обратитесь к администратору системы"));
    };
  };

  $query="SELECT * FROM users WHERE TRUE";
  $query .= " AND user_fk_ap_id=".mq($ap['ap_id']);
  $query .= " AND user_sub=".mq($id_token['sub']);
  
  $user=return_one($query);

  if($user === NULL) {
    reset_session();
    return(Array("error" => "Ошибка авто-добавления пользователя"));
  };

  $_SESSION['expire']=$id_token['exp'];
  $_SESSION['refresh_expire']=$refresh_token['exp'];
  $_SESSION['user']=$user;
  $_SESSION['refresh_token']=$refresh_token_str;
  $_SESSION['id_token']=$id_token;

  return(Array("ok" => "good"));
};
?>
