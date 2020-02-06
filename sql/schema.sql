-- OpenID Connect auth providers
CREATE TABLE aps (
  ap_id		INTEGER NOT NULL AUTO_INCREMENT,
  ap_off	INTEGER NOT NULL DEFAULT 0,
  ap_name	VARCHAR(256) NOT NULL DEFAULT '',
  ap_scope	VARCHAR(256) NOT NULL DEFAULT '',
  ap_icon	VARCHAR(1024) NOT NULL DEFAULT '',
  ap_auth_ep	VARCHAR(1024) NOT NULL DEFAULT '',
  ap_token_ep	VARCHAR(1024) NOT NULL DEFAULT '',
  ap_userinfo_ep	VARCHAR(1024) NOT NULL DEFAULT '',
  ap_logout_ep	VARCHAR(1024) NOT NULL DEFAULT '',
  ap_client_id	VARCHAR(256) NOT NULL DEFAULT '',
  ap_client_secret	VARCHAR(1024) NOT NULL DEFAULT '',
  ap_issuer	VARCHAR(1024) NOT NULL DEFAULT '',
  ap_rsa_pub_key	TEXT(16000) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL DEFAULT '',
  `ts` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  fk_user_id	INTEGER,
  PRIMARY KEY pk_ap_id(ap_id)
);

CREATE TABLE groups (
  group_id	INTEGER NOT NULL AUTO_INCREMENT,
  group_name	VARCHAR(190) NOT NULL DEFAULT '',
  group_rights	VARCHAR(1024) NOT NULL DEFAULT '',
  group_default	INTEGER NOT NULL DEFAULT 0,
  `ts` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  fk_user_id	INTEGER,
  PRIMARY KEY pk_group_id(group_id),
  UNIQUE KEY uk_group_name(group_name)
);

INSERT INTO groups SET group_name='default', group_default=1, group_rights='r_viewany';
INSERT INTO groups SET group_name='Admins', group_default=0, group_rights='r_super';

DELIMITER //

CREATE TRIGGER groups_insert_protect
  BEFORE INSERT ON groups
  FOR EACH ROW
BEGIN
  IF NEW.group_name = 'default' OR NEW.group_default = 1 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'cannot insert another default group';
  END IF;
END; //

CREATE TRIGGER groups_update_protect
  BEFORE UPDATE ON groups
  FOR EACH ROW
BEGIN
  IF (NEW.group_name = 'default' AND OLD.group_name != 'default') OR (NEW.group_default = 1 AND OLD.group_default != 1) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'cannot make another group as default';
  END IF;
  IF (OLD.group_name = 'default' AND NEW.group_name != 'default') OR (OLD.group_default = 1 AND NEW.group_default != 1) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'cannot make default group as non-default';
  END IF;
END; //

CREATE TRIGGER groups_delete_protect
  BEFORE DELETE ON groups
  FOR EACH ROW
BEGIN
  IF OLD.group_name = 'default' OR OLD.group_default = 1 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'cannot delete default group';
  END IF;
END; //

DELIMITER ;

  
CREATE TABLE users (
  user_id	INTEGER NOT NULL AUTO_INCREMENT,
  user_fk_ap_id	INTEGER,
  user_sub	VARCHAR(256) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL DEFAULT '',
  user_name	VARCHAR(256) NOT NULL DEFAULT '',
  user_email	VARCHAR(256) NOT NULL DEFAULT '',
  user_phone	VARCHAR(256) NOT NULL DEFAULT '',
  user_state	INTEGER NOT NULL DEFAULT -1 COMMENT '-2: deleted, -1: auto-added, 0: disabled, 1: enabled',
  user_last_login DATETIME NOT NULL,
  `ts` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  fk_user_id	INTEGER,
  PRIMARY KEY pk_user_id(user_id),
  FOREIGN KEY fk_user_ap_id(user_fk_ap_id) REFERENCES aps(ap_id) ON DELETE SET NULL ON UPDATE CASCADE,
  UNIQUE KEY uk_ap_id_sub(user_fk_ap_id, user_sub)
);

CREATE TABLE ugs (
  ug_fk_user_id	INTEGER NOT NULL,
  ug_fk_group_id	INTEGER NOT NULL,
  `ts` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  fk_user_id	INTEGER,
  UNIQUE KEY uk_id_pair(ug_fk_user_id,ug_fk_group_id),
  FOREIGN KEY fk_user_id(ug_fk_user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY fk_group_id(ug_fk_group_id) REFERENCES groups(group_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE atts (
  `att_id` int(11) NOT NULL AUTO_INCREMENT,
  `att_key` varchar(64) NOT NULL,
  `att_object` varchar(16) NOT NULL,
  `att_regex` varchar(256) NOT NULL DEFAULT '.*',
  `att_name` varchar(256) NOT NULL,
  `att_comment` varchar(1024) NOT NULL,
  `att_default` varchar(1024) NOT NULL,
  `att_multiple` int(11) NOT NULL DEFAULT '0',
  `att_input_size` varchar(16) NOT NULL DEFAULT '4em',
  `att_sort` int(11) NOT NULL DEFAULT 0,
  `ts` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `att_type` varchar(64) NOT NULL DEFAULT 'text',
  `att_flags` int(11) NOT NULL DEFAULT '0',
  fk_user_id	INTEGER,
  PRIMARY KEY (`att_id`),
  UNIQUE KEY `uk_att` (`att_key`,`att_object`),
  KEY `att_key` (`att_key`),
  KEY `att_object` (`att_object`)
);

CREATE TABLE `atvs` (
  `atv_id` int(11) NOT NULL AUTO_INCREMENT,
  `atv_fk_att_id` int(11) NOT NULL,
  `atv_object_id` int(11) NOT NULL,
  `atv_index` int(11) NOT NULL DEFAULT '0',
  `atv_value` varchar(1024) NOT NULL,
  `ts` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  fk_user_id	INTEGER,
  PRIMARY KEY (`atv_id`),
  UNIQUE KEY `uk_atv` (`atv_object_id`,`atv_index`,`atv_fk_att_id`),
  KEY `atv_object_id` (`atv_object_id`),
  KEY `atv_fk_att_id` (`atv_fk_att_id`),
  FOREIGN KEY fk_atv_att_id(atv_fk_att_id) REFERENCES `atts` (`att_id`) ON UPDATE CASCADE ON DELETE CASCADE
);
