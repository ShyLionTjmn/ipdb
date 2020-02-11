INSERT INTO v4nets SET
  v4net_addr=INET_ATON('8.0.0.0')
 ,v4net_mask=5
 ,v4net_last=INET_ATON('15.255.255.255')
 ,v4net_name='8.0.0.0/5'
 ,v4net_descr='Testing 8.0.0.0/5'
;

INSERT INTO v4nets SET
  v4net_addr=INET_ATON('172.16.0.0')
 ,v4net_mask=24
 ,v4net_last=INET_ATON('172.16.0.255')
 ,v4net_name='172.16.0.0/24'
 ,v4net_descr='Testing 172.16.0.0/24'
;
