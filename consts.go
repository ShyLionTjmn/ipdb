package main

//opt_p
const HTTP_PORT = uint(8888)
//opt_w
const WWW_ROOT = "/var/www/ipdb"

//opt_b
// see local.go

//opt_l
const APP_LOCATION = "/ipdb/"

//opt_g
const ADMIN_GROUP = "usr_netapp_ipdb_appadmins"

const (
  T_STRING int = iota
  T_UINT
  T_INT
  T_FLOAT
)
