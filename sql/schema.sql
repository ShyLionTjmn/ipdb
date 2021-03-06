-- OpenID Connect auth providers
CREATE TABLE aps (
  ap_id		BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
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
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY pk_ap_id(ap_id),
  tc		TINYINT COMMENT 'OpenID Connect Access providers'
);

CREATE TABLE groups (
  group_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  group_name	VARCHAR(190) NOT NULL DEFAULT '',
  group_rights	VARCHAR(1024) NOT NULL DEFAULT '',
  group_default	INTEGER NOT NULL DEFAULT 0,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY pk_group_id(group_id),
  UNIQUE KEY uk_group_name(group_name),
  tc		TINYINT COMMENT 'user groups. user without any group will be auto-added to "default" group. "default" group cannot be removed or set non-default.'
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
  user_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_fk_ap_id	BIGINT UNSIGNED,
  user_sub	VARCHAR(256) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL DEFAULT '',
  user_name	VARCHAR(256) NOT NULL DEFAULT '',
  user_username	VARCHAR(256) NOT NULL DEFAULT '',
  user_email	VARCHAR(256) NOT NULL DEFAULT '',
  user_phone	VARCHAR(256) NOT NULL DEFAULT '',
  user_state	INTEGER NOT NULL DEFAULT -1 COMMENT '-2: deleted, -1: auto-added, 0: disabled, 1: enabled',
  user_last_login BIGINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY pk_user_id(user_id),
  FOREIGN KEY fk_user_ap_id(user_fk_ap_id) REFERENCES aps(ap_id) ON DELETE SET NULL ON UPDATE CASCADE,
  UNIQUE KEY uk_ap_id_sub(user_fk_ap_id, user_sub),
  tc		TINYINT COMMENT 'Users, tied to its OpenID Connect Auth provider'
);

CREATE TABLE ugs (
  ug_fk_user_id	BIGINT UNSIGNED NOT NULL,
  ug_fk_group_id	BIGINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  UNIQUE KEY uk_id_pair(ug_fk_user_id,ug_fk_group_id),
  FOREIGN KEY fk_user_id(ug_fk_user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY fk_group_id(ug_fk_group_id) REFERENCES groups(group_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE gms (
  gm_fk_group_id	BIGINT UNSIGNED NOT NULL,
  gm_fk_user_id		BIGINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  UNIQUE KEY uk_ids(gm_fk_group_id, gm_fk_user_id),
  FOREIGN KEY (gm_fk_group_id) REFERENCES groups(group_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (gm_fk_user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'group managers - non-super users who can add/remove users from group'
);


CREATE TABLE atts (
  `att_id`	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `att_key`	varchar(64) NOT NULL,
  `att_object`	varchar(16) NOT NULL,
  `att_regex`	varchar(256) NOT NULL DEFAULT '.*',
  `att_name`	varchar(256) NOT NULL,
  `att_comment`	varchar(1024) NOT NULL,
  `att_default`	varchar(1024) DEFAULT NULL,
  `att_multiple`	int(11) NOT NULL DEFAULT '0',
  `att_style`	varchar(1024) NOT NULL DEFAULT '{}' COMMENT 'css style JSON, passed as INPUT/LABEL .css()',
  `att_sort`	int(11) NOT NULL DEFAULT 0,
  `att_type`	varchar(64) NOT NULL DEFAULT 'text',
  `att_flags`	int(11) NOT NULL DEFAULT '0' COMMENT '1 - protect',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (`att_id`),
  UNIQUE KEY `uk_att` (`att_key`,`att_object`),
  KEY `att_key` (`att_key`),
  KEY `att_object` (`att_object`),
  tc		TINYINT COMMENT 'Custom attributes. "key" is text key, "object" is object type, like "system", "v4net", etc.'
);

CREATE TABLE `atvs` (
  `atv_id`	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `atv_fk_att_id`	BIGINT UNSIGNED NOT NULL,
  `atv_object_id`	BIGINT UNSIGNED NOT NULL,
  `atv_index`	BIGINT UNSIGNED NOT NULL DEFAULT '0',
  `atv_value`	varchar(1024) NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (`atv_id`),
  UNIQUE KEY `uk_atv` (`atv_object_id`,`atv_index`,`atv_fk_att_id`),
  KEY `atv_object_id` (`atv_object_id`),
  KEY `atv_fk_att_id` (`atv_fk_att_id`),
  FOREIGN KEY fk_atv_att_id(atv_fk_att_id) REFERENCES `atts` (`att_id`) ON UPDATE CASCADE ON DELETE CASCADE,
  tc		TINYINT COMMENT 'Custom attributes values. object_id is _id field from corresponding oject`s table'
);

# VLAN/BDs domains
CREATE TABLE vds (
  vd_id		BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  vd_max_num	BIGINT UNSIGNED NOT NULL DEFAULT 4095,
  vd_name	VARCHAR(190) NOT NULL DEFAULT '',
  vd_descr	VARCHAR(1024) NOT NULL DEFAULT '',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (vd_id),
  UNIQUE KEY uk_vd_name(vd_name),
  tc		TINYINT COMMENT 'VLANs or Bridge domain domains'
);

CREATE TABLE vlans (
  vlan_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  vlan_number	BIGINT UNSIGNED NOT NULL,
  vlan_name	VARCHAR(64) NOT NULL,
  vlan_descr	VARCHAR(1024) NOT NULL DEFAULT '',
  vlan_fk_vd_id	BIGINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (vlan_id),
  UNIQUE KEY uk_number_vd_id(vlan_number,vlan_fk_vd_id),
  UNIQUE KEY uk_name_vd_id(vlan_name,vlan_fk_vd_id),
  FOREIGN KEY (vlan_fk_vd_id) REFERENCES vds(vd_id) ON UPDATE CASCADE ON DELETE RESTRICT,
  tc		TINYINT COMMENT 'VLANs or Bridge domain domains members'
);

#vlan ranges
CREATE TABLE vrs (
  vr_id		BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  vr_start	BIGINT UNSIGNED NOT NULL,
  vr_stop	BIGINT UNSIGNED NOT NULL,
  vr_fk_vd_id	BIGINT UNSIGNED NOT NULL,
  vr_name	VARCHAR(190) NOT NULL DEFAULT '',
  vr_descr	VARCHAR(1024) NOT NULL DEFAULT '',
  vr_style	VARCHAR(1024) NOT NULL DEFAULT '{}' COMMENT 'JSON style applied to range line as .css(style)',
  vr_icon	VARCHAR(1024) NOT NULL DEFAULT '' COMMENT 'jquery ui icon class or &#xxxx; HTML char code or URI to picture',
  vr_icon_style	VARCHAR(1024) NOT NULL DEFAULT '{}' COMMENT 'icon JSON style applied to icon as .css(style)',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (vr_id),
  UNIQUE KEY uk_vr(vr_fk_vd_id,vr_start,vr_stop,vr_name),
  FOREIGN KEY (vr_fk_vd_id) REFERENCES vds(vd_id) ON UPDATE CASCADE ON DELETE CASCADE,
  tc		TINYINT COMMENT 'VLANs or Bridge domain ranges'
);

#group vlan range rights
CREATE TABLE gvrrs (
  gvrr_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  gvrr_fk_vr_id	BIGINT UNSIGNED NOT NULL,
  gvrr_fk_group_id	BIGINT UNSIGNED NOT NULL,
  gvrr_rmask	INTEGER UNSIGNED NOT NULL COMMENT 'bitmask:  1-view name, 2-view other info, 4-take/edit VLAN, 8-free VLAN',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (gvrr_id),
  UNIQUE KEY uk_gvrr(gvrr_fk_vr_id,gvrr_fk_group_id),
  FOREIGN KEY (gvrr_fk_vr_id) REFERENCES vrs(vr_id) ON UPDATE CASCADE ON DELETE CASCADE,
  FOREIGN KEY (gvrr_fk_group_id) REFERENCES groups(group_id) ON UPDATE CASCADE ON DELETE CASCADE,
  tc		TINYINT COMMENT 'VLANs or Bridge range group access'
);

CREATE TABLE sites (
  site_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  site_name	VARCHAR(190) NOT NULL DEFAULT '',
  site_address	VARCHAR(512) NOT NULL DEFAULT '',
  site_descr	VARCHAR(1024) NOT NULL DEFAULT '',
  site_lat	DECIMAL(10,7) NOT NULL DEFAULT 0.0,
  site_lon	DECIMAL(10,7) NOT NULL DEFAULT 0.0,
  site_parent_id BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'used for unique keys checks, must be the same as site_fk_site_id, 0 if null',
  site_fk_site_id BIGINT UNSIGNED DEFAULT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (site_id),
  UNIQUE KEY uk_site_name(site_name,site_parent_id),
  FOREIGN KEY (site_fk_site_id) REFERENCES sites(site_id),
  tc		TINYINT COMMENT 'Sites, could be tree organized, like Country->City->District->Building, etc.'
);

-- ip columns
CREATE TABLE ics(
  ic_id		BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ic_default	INTEGER NOT NULL DEFAULT 0 COMMENT 'auto-add to created templates',
  ic_name	VARCHAR(128) NOT NULL DEFAULT '',
  ic_regexp	VARCHAR(256) NOT NULL DEFAULT '',
  ic_icon	VARCHAR(1024) NOT NULL DEFAULT '' COMMENT 'jquery ui icon class',
  ic_icon_style	VARCHAR(1024) NOT NULL DEFAULT '{}' COMMENT 'css icon style JSON, passed as $("SPAN").css( ic_icon_style )',
  ic_descr	VARCHAR(1024) NOT NULL DEFAULT '',
  ic_sort	INTEGER NOT NULL DEFAULT 0,
  ic_style	VARCHAR(1024) NOT NULL DEFAULT '{}' COMMENT 'css style JSON, passed as $("INPUT").css( ic_style )',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id    BIGINT UNSIGNED,
  PRIMARY KEY (ic_id),
  UNIQUE KEY uk_ic_name(ic_name),
  tc		TINYINT COMMENT 'IP columns, linked to nets via templates'
);

CREATE TABLE tps(
  tp_id		BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  tp_name	VARCHAR(190) NOT NULL DEFAULT '',
  tp_descr	VARCHAR(1024) NOT NULL DEFAULT '',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id    BIGINT UNSIGNED,
  PRIMARY KEY (tp_id),
  UNIQUE KEY uk_tp_name(tp_name),
  tc		TINYINT COMMENT 'net templates'
);

CREATE TABLE tcs(
  tc_fk_ic_id	BIGINT UNSIGNED NOT NULL,
  tc_fk_tp_id	BIGINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  UNIQUE KEY uk_ids(tc_fk_ic_id,tc_fk_tp_id),
  KEY k_tp_id(tc_fk_tp_id),
  FOREIGN KEY (tc_fk_ic_id) REFERENCES ics(ic_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (tc_fk_tp_id) REFERENCES tps(tp_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'template columns'
);

CREATE TABLE v4nets (
  v4net_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'used for att linking',
  v4net_addr	INTEGER UNSIGNED NOT NULL,
  v4net_last	INTEGER UNSIGNED NOT NULL COMMENT 'last address in this net, including broadcast, for search speedup',
  v4net_mask	TINYINT UNSIGNED NOT NULL,
  v4net_fk_vlan_id	BIGINT UNSIGNED DEFAULT NULL,
  v4net_name	VARCHAR(256) NOT NULL DEFAULT '',
  v4net_descr	VARCHAR(1024) NOT NULL DEFAULT '',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (v4net_id),
  UNIQUE KEY (v4net_addr),
  FOREIGN KEY (v4net_fk_vlan_id) REFERENCES vlans(vlan_id) ON DELETE SET NULL
);

CREATE TABLE v4ips(
  v4ip_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'used for att linking and column values',
  v4ip_addr	INTEGER UNSIGNED NOT NULL,
  v4ip_fk_v4net_id	BIGINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (v4ip_id),
  UNIQUE KEY (v4ip_addr),
  KEY k_net(v4ip_fk_v4net_id),
  FOREIGN KEY (v4ip_fk_v4net_id) REFERENCES v4nets(v4net_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE v4nsites (
  v4nsite_fk_v4net_id	BIGINT UNSIGNED NOT NULL,
  v4nsite_fk_site_id	BIGINT UNSIGNED DEFAULT NULL,
  UNIQUE KEY (v4nsite_fk_v4net_id, v4nsite_fk_site_id),
  FOREIGN KEY (v4nsite_fk_site_id) REFERENCES sites(site_id) ON UPDATE CASCADE ON DELETE CASCADE,
  FOREIGN KEY (v4nsite_fk_v4net_id) REFERENCES v4nets(v4net_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE v4ipsites (
  v4ipsite_fk_v4ip_id	BIGINT UNSIGNED NOT NULL,
  v4ipsite_fk_site_id	BIGINT UNSIGNED DEFAULT NULL,
  UNIQUE KEY (v4ipsite_fk_v4ip_id, v4ipsite_fk_site_id),
  FOREIGN KEY (v4ipsite_fk_site_id) REFERENCES sites(site_id) ON UPDATE CASCADE ON DELETE CASCADE,
  FOREIGN KEY (v4ipsite_fk_v4ip_id) REFERENCES v4ips(v4ip_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE v6nets (
  v6net_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'used for att linking',
  v6net_addr    VARBINARY(16) NOT NULL,
  v6net_last	VARBINARY(16) NOT NULL COMMENT 'last address in this net, including broadcast, for search speedup',
  v6net_mask    TINYINT UNSIGNED NOT NULL,
  v6net_fk_vlan_id      BIGINT UNSIGNED DEFAULT NULL,
  v6net_name    VARCHAR(256) NOT NULL DEFAULT '',
  v6net_descr   VARCHAR(1024) NOT NULL DEFAULT '',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id    BIGINT UNSIGNED,
  PRIMARY KEY (v6net_id),
  UNIQUE KEY (v6net_addr),
  FOREIGN KEY (v6net_fk_vlan_id) REFERENCES vlans(vlan_id) ON DELETE SET NULL
);

CREATE TABLE v6ips(
  v6ip_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'used for att linking and column values',
  v6ip_addr     VARBINARY(16) NOT NULL,
  v6ip_fk_v6net_id    BIGINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id    BIGINT UNSIGNED,
  PRIMARY KEY (v6ip_id),
  UNIQUE KEY (v6ip_addr),
  KEY k_net(v6ip_fk_v6net_id),
  FOREIGN KEY (v6ip_fk_v6net_id) REFERENCES v6nets(v6net_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE v6nsites (
  v6nsite_fk_v6net_id	BIGINT UNSIGNED NOT NULL,
  v6nsite_fk_site_id	BIGINT UNSIGNED DEFAULT NULL,
  UNIQUE KEY (v6nsite_fk_v6net_id, v6nsite_fk_site_id),
  FOREIGN KEY (v6nsite_fk_site_id) REFERENCES sites(site_id) ON UPDATE CASCADE ON DELETE CASCADE,
  FOREIGN KEY (v6nsite_fk_v6net_id) REFERENCES v6nets(v6net_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE v6ipsites (
  v6ipsite_fk_v6ip_id	BIGINT UNSIGNED NOT NULL,
  v6ipsite_fk_site_id	BIGINT UNSIGNED DEFAULT NULL,
  UNIQUE KEY (v6ipsite_fk_v6ip_id, v6ipsite_fk_site_id),
  FOREIGN KEY (v6ipsite_fk_site_id) REFERENCES sites(site_id) ON UPDATE CASCADE ON DELETE CASCADE,
  FOREIGN KEY (v6ipsite_fk_v6ip_id) REFERENCES v6ips(v6ip_id) ON UPDATE CASCADE ON DELETE CASCADE
);


CREATE TABLE i4vs(
  iv_fk_ic_id	BIGINT UNSIGNED NOT NULL,
  iv_fk_v4ip_id	BIGINT UNSIGNED NOT NULL,
  iv_value	VARCHAR(256) NOT NULL DEFAULT '',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  UNIQUE KEY uk_ids(iv_fk_ic_id,iv_fk_v4ip_id),
  KEY k_v4ip_id(iv_fk_v4ip_id),
  FOREIGN KEY (iv_fk_ic_id) REFERENCES ics(ic_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (iv_fk_v4ip_id) REFERENCES v4ips(v4ip_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'ipv4 column values'
);

CREATE TABLE i6vs(
  iv_fk_ic_id	BIGINT UNSIGNED NOT NULL,
  iv_fk_v6ip_id	BIGINT UNSIGNED NOT NULL,
  iv_value	VARCHAR(256) NOT NULL DEFAULT '',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  UNIQUE KEY uk_ids(iv_fk_ic_id,iv_fk_v6ip_id),
  KEY k_v6ip_id(iv_fk_v6ip_id),
  FOREIGN KEY (iv_fk_ic_id) REFERENCES ics(ic_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (iv_fk_v6ip_id) REFERENCES v6ips(v6ip_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'ipv6 column values'
);

CREATE TABLE n4cs(
  nc_fk_ic_id	BIGINT UNSIGNED NOT NULL,
  nc_fk_v4net_id	BIGINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  UNIQUE KEY (nc_fk_ic_id, nc_fk_v4net_id),
  KEY k_v4net_id (nc_fk_v4net_id),
  FOREIGN KEY (nc_fk_ic_id) REFERENCES ics(ic_id) ON DELETE RESTRICT ON UPDATE CASCADE,
  FOREIGN KEY (nc_fk_v4net_id) REFERENCES v4nets(v4net_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'v4 network columns, copied from template, but could be added/removed later'
);

CREATE TABLE n6cs(
  nc_fk_ic_id	BIGINT UNSIGNED NOT NULL,
  nc_fk_v6net_id	BIGINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  UNIQUE KEY (nc_fk_ic_id, nc_fk_v6net_id),
  KEY k_v6net_id (nc_fk_v6net_id),
  FOREIGN KEY (nc_fk_ic_id) REFERENCES ics(ic_id) ON DELETE RESTRICT ON UPDATE CASCADE,
  FOREIGN KEY (nc_fk_v6net_id) REFERENCES v6nets(v6net_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'v6 network columns, copied from template, but could be added/removed later'
);

CREATE TABLE v4favs(
  v4fav_fk_user_id	BIGINT UNSIGNED NOT NULL,
  v4net_addr	INTEGER UNSIGNED NOT NULL,
  v4net_mask	TINYINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  UNIQUE KEY uk_v4favs(v4fav_fk_user_id, v4net_addr, v4net_mask),
  KEY k_user_id(v4fav_fk_user_id),
  FOREIGN KEY (v4fav_fk_user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'v4 user favorites'
);

CREATE TABLE v6favs(
  v6fav_fk_user_id	BIGINT UNSIGNED NOT NULL,
  v6net_addr	VARBINARY(16) NOT NULL,
  v6net_mask	TINYINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  UNIQUE KEY uk_v6favs(v6fav_fk_user_id, v6net_addr, v6net_mask),
  KEY k_user_id(v6fav_fk_user_id),
  FOREIGN KEY (v6fav_fk_user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'v6 user favorites'
);

CREATE TABLE g4favs(
  v4fav_fk_group_id	BIGINT UNSIGNED NOT NULL,
  v4net_addr	INTEGER UNSIGNED NOT NULL,
  v4net_mask	TINYINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  UNIQUE KEY uk_v4favs(v4fav_fk_group_id, v4net_addr, v4net_mask),
  KEY k_group_id(v4fav_fk_group_id),
  FOREIGN KEY (v4fav_fk_group_id) REFERENCES groups(group_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'v4 group favorites'
);

CREATE TABLE g6favs(
  v6fav_fk_group_id	BIGINT UNSIGNED NOT NULL,
  v6net_addr	VARBINARY(16) NOT NULL,
  v6net_mask	TINYINT UNSIGNED NOT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  UNIQUE KEY uk_v6favs(v6fav_fk_group_id, v6net_addr, v6net_mask),
  KEY k_group_id(v6fav_fk_group_id),
  FOREIGN KEY (v6fav_fk_group_id) REFERENCES groups(group_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'v4 group favorites'
);


CREATE TABLE v4rs(
  v4r_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  v4r_start	INTEGER UNSIGNED NOT NULL,
  v4r_stop	INTEGER UNSIGNED NOT NULL,
  v4r_visible	TINYINT UNSIGNED NOT NULL DEFAULT 1,
  v4r_name	VARCHAR(128) NOT NULL DEFAULT '',
  v4r_descr	VARCHAR(1024) NOT NULL DEFAULT '',
  v4r_style	VARCHAR(1024) NOT NULL DEFAULT '{}' COMMENT 'css style JSON, passed as elm.css( ic_style )',
  v4r_icon	VARCHAR(1024) NOT NULL DEFAULT '' COMMENT 'jquery ui icon class',
  v4r_icon_style	VARCHAR(1024) NOT NULL DEFAULT '{}' COMMENT 'css icon style JSON, passed as $("SPAN").css( ic_icon_style )',
  v4r_fk_v4net_id	BIGINT UNSIGNED DEFAULT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (v4r_id),
  UNIQUE KEY uk_name(v4r_start,v4r_stop,v4r_name),
  FOREIGN KEY (v4r_fk_v4net_id) REFERENCES v4nets(v4net_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'v4 address ranges'
);

CREATE TABLE v6rs(
  v6r_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  v6r_start	VARBINARY(16) NOT NULL,
  v6r_stop	VARBINARY(16) NOT NULL,
  v6r_visible	TINYINT UNSIGNED NOT NULL DEFAULT 1,
  v6r_name	VARCHAR(128) NOT NULL DEFAULT '',
  v6r_descr	VARCHAR(1024) NOT NULL DEFAULT '',
  v6r_style	VARCHAR(1024) NOT NULL DEFAULT '{}' COMMENT 'css style JSON, passed as elm.css( ic_style )',
  v6r_icon	VARCHAR(1024) NOT NULL DEFAULT '' COMMENT 'jquery ui icon class',
  v6r_icon_style	VARCHAR(1024) NOT NULL DEFAULT '{}' COMMENT 'css icon style JSON, passed as $("SPAN").css( ic_icon_style )',
  v6r_fk_v6net_id	BIGINT UNSIGNED DEFAULT NULL,
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (v6r_id),
  UNIQUE KEY uk_name(v6r_start,v6r_stop,v6r_name),
  FOREIGN KEY (v6r_fk_v6net_id) REFERENCES v6nets(v6net_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'v6 address ranges'
);

CREATE TABLE gn4rs(
  gn4r_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  gn4r_fk_group_id	BIGINT UNSIGNED NOT NULL,
  gn4r_fk_v4net_id	BIGINT UNSIGNED NOT NULL,
  gn4r_rmask	INTEGER UNSIGNED NOT NULL COMMENT 'bitmask:  1-view name, 2-view other info and IPs, 4-take/edit IPs, 8-free IPs, 16-ignore range denies, 32-manage access, 64-add/del/edit ranges, 128-drop net, 256-edit net name/desr, 512-reserved for ranges, 1024-reserved for ranges',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id    BIGINT UNSIGNED,
  PRIMARY KEY (gn4r_id),
  UNIQUE KEY uk_ids(gn4r_fk_group_id,gn4r_fk_v4net_id),
  FOREIGN KEY (gn4r_fk_group_id) REFERENCES groups(group_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (gn4r_fk_v4net_id) REFERENCES v4nets(v4net_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'v4 net group rights. rmasks from multiple groups membership is ORed'
);

CREATE TABLE gn6rs(
  gn6r_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  gn6r_fk_group_id	BIGINT UNSIGNED NOT NULL,
  gn6r_fk_v6net_id	BIGINT UNSIGNED NOT NULL,
  gn6r_rmask	INTEGER UNSIGNED NOT NULL COMMENT 'bitmask:  1-view name, 2-view other info and IPs, 4-take/edit IPs, 8-free IPs, 16-ignore range denies, 32-manage access, 64-add/del/edit ranges, 128-drop net, 256-edit net name/desr, 512-reserved for ranges, 1024-reserved for ranges',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id    BIGINT UNSIGNED,
  PRIMARY KEY (gn6r_id),
  UNIQUE KEY uk_ids(gn6r_fk_group_id,gn6r_fk_v6net_id),
  FOREIGN KEY (gn6r_fk_group_id) REFERENCES groups(group_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (gn6r_fk_v6net_id) REFERENCES v6nets(v6net_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc		TINYINT COMMENT 'v6 net group rights. rmasks from multiple groups membership is ORed'
);

CREATE TABLE gr4rs(
  gr4r_id      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  gr4r_fk_group_id     BIGINT UNSIGNED NOT NULL,
  gr4r_fk_v4r_id     BIGINT UNSIGNED NOT NULL,
  gr4r_rmask   INTEGER UNSIGNED NOT NULL COMMENT 'bitmask:  1-view names, 2-view other info and IPs, 512-take nets, 1024-deny ip taking(range must be linked with network, overrided by 16)',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id    BIGINT UNSIGNED,
  PRIMARY KEY (gr4r_id),
  UNIQUE KEY uk_ids(gr4r_fk_group_id,gr4r_fk_v4r_id),
  FOREIGN KEY (gr4r_fk_group_id) REFERENCES groups(group_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (gr4r_fk_v4r_id) REFERENCES v4rs(v4r_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc            TINYINT COMMENT 'v4 range group rights'
);

CREATE TABLE gr6rs(
  gr6r_id      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  gr6r_fk_group_id     BIGINT UNSIGNED NOT NULL,
  gr6r_fk_v6r_id     BIGINT UNSIGNED NOT NULL,
  gr6r_rmask   INTEGER UNSIGNED NOT NULL COMMENT 'bitmask:  1-view names, 2-view other info and IPs, 512-take nets, 1024-deny ip taking(range must be linked with network, overrided by 16)',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id    BIGINT UNSIGNED,
  PRIMARY KEY (gr6r_id),
  UNIQUE KEY uk_ids(gr6r_fk_group_id,gr6r_fk_v6r_id),
  FOREIGN KEY (gr6r_fk_group_id) REFERENCES groups(group_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (gr6r_fk_v6r_id) REFERENCES v6rs(v6r_id) ON DELETE CASCADE ON UPDATE CASCADE,
  tc            TINYINT COMMENT 'v6 range group rights'
);

CREATE TABLE audit_log(
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id    BIGINT UNSIGNED,
  al_subject	VARCHAR(64) NOT NULL DEFAULT '',
  al_subject_id BIGINT UNSIGNED,
  al_tables	VARCHAR(256) NOT NULL DEFAULT '',
  al_op		VARCHAR(256) NOT NULL DEFAULT '',
  al_query	VARCHAR(4096) NOT NULL DEFAULT '',
  al_prev_data	VARCHAR(4096) NOT NULL DEFAULT '',
  al_new_data	VARCHAR(4096) NOT NULL DEFAULT ''
) ENGINE=MyISAM;

CREATE TABLE checks(
  check_count	BIGINT NOT NULL DEFAULT 0 COMMENT 'should be incremented each time data changed and periodiaclly checked by front-end to notify user if out of sync',
  check_ts	BIGINT UNSIGNED NOT NULL COMMENT 'time of last change',
  check_by	BIGINT UNSIGNED COMMENT 'user_id by which check changed',
  check_subject	VARCHAR(64) NOT NULL COMMENT 'user, group, vd, vr, v4net, etc',
  check_subject_id BIGINT UNSIGNED NOT NULL COMMENT 'id of subject, 0 for global',
  UNIQUE KEY uk_checks(check_subject,check_subject_id)
);

CREATE TABLE v4oobs (
  v4oob_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'used for att linking',
  v4oob_addr	INTEGER UNSIGNED NOT NULL,
  v4oob_mask	TINYINT UNSIGNED NOT NULL,
  v4oob_descr	VARCHAR(256) NOT NULL DEFAULT '',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (v4oob_id),
  UNIQUE KEY (v4oob_addr, v4oob_mask),
  tc            TINYINT COMMENT 'v4 out of band nets for router_groups, etc...'
);

CREATE TABLE v6oobs (
  v6oob_id	BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'used for att linking',
  v6oob_addr	INTEGER UNSIGNED NOT NULL,
  v6oob_mask	TINYINT UNSIGNED NOT NULL,
  v6oob_descr	VARCHAR(256) NOT NULL DEFAULT '',
  ts		BIGINT UNSIGNED NOT NULL,
  fk_user_id	BIGINT UNSIGNED,
  PRIMARY KEY (v6oob_id),
  UNIQUE KEY (v6oob_addr, v6oob_mask),
  tc            TINYINT COMMENT 'v6 out of band nets for router_groups, etc...'
);

