SET sql_safe_updates = 0;
DELETE FROM glrs;

SET @R_NAME=1;
SET @R_VIEW_NET_INFO=2;
SET @R_VIEW_NET_IPS=4;
SET @R_EDIT_IP_VLAN=8;
SET @R_IGNORE_R_DENY=16;
SET @R_MANAGE_NET=32;
SET @R_DENYIP=64;

INSERT INTO glrs SET
  glr_object="nets"
 ,glr_rmask=@R_NAME|@R_VIEW_NET_INFO
 ,glr_fk_g_id=(SELECT g_id FROM gs WHERE g_name='Все')
 ,ts=UNIX_TIMESTAMP()
;

INSERT INTO glrs SET
  glr_object="vlans"
 ,glr_rmask=@R_VIEW_NET_IPS
 ,glr_fk_g_id=(SELECT g_id FROM gs WHERE g_name='Все')
 ,ts=UNIX_TIMESTAMP()
;

INSERT INTO glrs SET
  glr_object="tags"
 ,glr_rmask=@R_VIEW_NET_IPS
 ,glr_fk_g_id=(SELECT g_id FROM gs WHERE g_name='Все')
 ,ts=UNIX_TIMESTAMP()
;
