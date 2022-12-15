DELETE FROM v4rs;

INSERT INTO v4rs SET
  v4r_start=INET_ATON('7.0.0.0')
 ,v4r_stop=INET_ATON('191.255.255.255')
 ,v4r_name='7-192'
 ,v4r_descr='descr for 7-192'
 ,v4r_style='{"color": "green"}'
 ,v4r_icon='ui-icon-info'
 ,v4r_icon_style='{}'
 ,ts=UNIX_TIMESTAMP()
;

INSERT INTO v4rs SET
  v4r_start=INET_ATON('27.1.0.0')
 ,v4r_stop=INET_ATON('27.10.255.255')
 ,v4r_name='27.10/16'
 ,v4r_descr='descr for 27.10/16'
 ,v4r_style='{"color": "blue"}'
 ,v4r_icon='ui-icon-info'
 ,v4r_icon_style='{}'
 ,ts=UNIX_TIMESTAMP()
;

INSERT INTO v4rs SET
  v4r_start=INET_ATON('27.11.0.0')
 ,v4r_stop=INET_ATON('27.11.255.255')
 ,v4r_name='27.11/16'
 ,v4r_descr='descr for 27.11/16'
 ,v4r_style='{"color": "orange"}'
 ,v4r_icon='ui-icon-info'
 ,v4r_icon_style='{}'
 ,ts=UNIX_TIMESTAMP()
;
