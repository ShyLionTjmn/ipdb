<?php

function reset_session() {
  foreach($_SESSION as $key => $val) {
    unset($_SESSION[$key]);
  };
};

function get_attr_value($object, $object_id, $key, $multiple=FALSE) {
  $query="SELECT att_id, att_default, att_multiple FROM atts WHERE TRUE";
  $query .= " AND att_object=".mq($object);
  $query .= " AND att_key=".mq($key);

  $att=return_one($query, FALSE);
  if($att === NULL) {
    return(NULL);
  };

  $query="SELECT atv_value FROM atvs WHERE TRUE";
  $query .= " AND atv_fk_att_id=".mq($att['att_id']);
  $query .= " AND atv_object_id=".mq($object_id);
  $query .= " ORDER BY atv_index ASC";

  $values=return_array($query);

  if(count($values) == 0) {
    if($multiple) {
      return(Array($att['att_default']));
    } else {
      return($att['att_default']);
    };
  } else {
    if($multiple) {
      return($values);
    } else {
      return($values[0]);
    };
  };
};

?>
