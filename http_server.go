package main

import (
  "os"
  "math"
  "io/ioutil"
  "reflect"
  "sync"
  "strings"
  "strconv"
  "context"
  "time"
  "regexp"
  "encoding/json"
  "net"
  "fmt"
  "net/http"
  "errors"
  "golang.org/x/net/netutil"
  //wai "github.com/jimlawless/whereami"
  "runtime/debug"
  "github.com/davecgh/go-spew/spew"
  "database/sql"
  _ "github.com/go-sql-driver/mysql"
)

const (
  R_NAME uint64 = 1 // view net name and deny all other actions if not set
  R_VIEW_NET_INFO uint64 = 2 // view net info, must have R_NAME set
  R_VIEW_NET_IPS uint64 = 4 // view net ips, vlan_domain vlans
  R_EDIT_IP_VLAN uint64 = 8 // take/edit/delete vlan or ip data, must have R_NAME and R_VIEW_NET_IPS set
  R_IGNORE_R_DENY uint64 = 16 // ignore ranges denies (for network ACL only)
  R_MANAGE_NET uint64 = 32 // edit all network data, drop network
  R_DENYIP uint64 = 64 // deny ip take/edit, for network assigned ranges only
)

var g_rights map[uint64]M

const ADMIN_RIGHTS uint64 = R_NAME | R_VIEW_NET_INFO | R_VIEW_NET_IPS |
                          R_EDIT_IP_VLAN | R_IGNORE_R_DENY | R_MANAGE_NET

const OWNER_RIGHTS uint64 = R_NAME | R_VIEW_NET_INFO | R_VIEW_NET_IPS |
                          R_EDIT_IP_VLAN | R_IGNORE_R_DENY | R_MANAGE_NET

const MAX_SUBNETS_NAMES_LEN = 512

const PE = "Backend Program error"

var g_name_reg *regexp.Regexp
var g_num_reg *regexp.Regexp

func init() {
  _ = spew.Sprint()
  g_name_reg = regexp.MustCompile(`^\S.*\S$`)
  g_num_reg = regexp.MustCompile(`^\d+$`)

  g_rights = make(map[uint64]M)

  g_rights[R_NAME] = make(M)
  g_rights[R_NAME]["label"] = "ПрИмнСет"
  g_rights[R_NAME]["descr"] = "Просмотр имени сети в списке сетей"
  g_rights[R_NAME]["requred_by"] = [...]uint64{R_VIEW_NET_INFO, R_VIEW_NET_IPS, R_EDIT_IP_VLAN, R_MANAGE_NET}
  g_rights[R_NAME]["used_in"] = [...]string{"ext_v4net_range", "v4net_acl"}

  g_rights[R_VIEW_NET_INFO] = make(M)
  g_rights[R_VIEW_NET_INFO]["label"] = "ПрИнфСет"
  g_rights[R_VIEW_NET_INFO]["descr"] = "Просмотр информации о сети, кроме списка IP адресов"
  g_rights[R_VIEW_NET_INFO]["requred_by"] = [...]uint64{R_MANAGE_NET}
  g_rights[R_VIEW_NET_INFO]["used_in"] = [...]string{"ext_v4net_range", "v4net_acl"}

  g_rights[R_VIEW_NET_IPS] = make(M)
  g_rights[R_VIEW_NET_IPS]["label"] = "ПрАдрVLN"
  g_rights[R_VIEW_NET_IPS]["descr"] = "Просмотр IP адресов или VLAN-ов"
  g_rights[R_VIEW_NET_IPS]["requred_by"] = [...]uint64{R_EDIT_IP_VLAN, R_MANAGE_NET}
  g_rights[R_VIEW_NET_IPS]["used_in"] = [...]string{"ext_v4net_range", "v4net_acl", "vlan_range"}

  g_rights[R_EDIT_IP_VLAN] = make(M)
  g_rights[R_EDIT_IP_VLAN]["label"] = "ИзмАдрVL"
  g_rights[R_EDIT_IP_VLAN]["descr"] = "Занятие, редактирование, освобождение IP адресов или VLAN-ов"
  g_rights[R_EDIT_IP_VLAN]["requred_by"] = [...]uint64{R_MANAGE_NET}
  g_rights[R_EDIT_IP_VLAN]["used_in"] = [...]string{"ext_v4net_range", "v4net_acl", "vlan_range", "int_v4net_range"}

  g_rights[R_MANAGE_NET] = make(M)
  g_rights[R_MANAGE_NET]["label"] = "ИзмнСети"
  g_rights[R_MANAGE_NET]["descr"] = "Занятие, редактирование, освобождение сети"
  g_rights[R_MANAGE_NET]["requred_by"] = [...]uint64{}
  g_rights[R_MANAGE_NET]["used_in"] = [...]string{"ext_v4net_range", "v4net_acl"}

  g_rights[R_IGNORE_R_DENY] = make(M)
  g_rights[R_IGNORE_R_DENY]["label"] = "ИгнорЗпр"
  g_rights[R_IGNORE_R_DENY]["descr"] = "Игнорировать запрет в диапазонах"
  g_rights[R_IGNORE_R_DENY]["requred_by"] = [...]uint64{}
  g_rights[R_IGNORE_R_DENY]["used_in"] = [...]string{"ext_v4net_range", "v4net_acl"}

  g_rights[R_DENYIP] = make(M)
  g_rights[R_DENYIP]["label"] = "ЗпртРедт"
  g_rights[R_DENYIP]["descr"] = "Запрет занимать, редактировать, удалять IP/VLAN в диапазоне"
  g_rights[R_DENYIP]["requred_by"] = [...]uint64{}
  g_rights[R_DENYIP]["used_in"] = [...]string{"int_v4net_range", "vlan_range"}

}

func containsDotFile(name string) bool {
    parts := strings.Split(name, "/")
    for _, part := range parts {
        if strings.HasPrefix(part, ".") {
            return true
        }
    }
    return false
}

type dotFileHidingFile struct {
    http.File
}
func (f dotFileHidingFile) Readdir(n int) (fis []os.FileInfo, err error) {
    files, err := f.File.Readdir(n)
    for _, file := range files { // Filters out the dot files
        if !strings.HasPrefix(file.Name(), ".") {
            fis = append(fis, file)
        }
    }
    return
}

type dotFileHidingFileSystem struct {
    http.FileSystem
}

func (fsys dotFileHidingFileSystem) Open(name string) (http.File, error) {
    if containsDotFile(name) { // If dot file, return 403 response
        return nil, errors.New("No permission")
    }

    file, err := fsys.FileSystem.Open(name)
    if err != nil {
        return nil, err
    }
    return dotFileHidingFile{file}, err
}

func get_p_string(q M, name string, check interface{}, options ... interface{}) (string,error) { // options: (error on empty(true by default)), (default value) 
  val, exists := q[name]
  if !exists {
    if len(options) == 0 || options[0].(bool) {
      return "", errors.New("Missing parameter: "+name)
    }
    if len(options) > 1 {
      return options[1].(string), nil
    } else {
      return "", nil
    }
  }

  _val := fmt.Sprint(val)

  switch c := check.(type) {
  case nil:
    return _val, nil
  case string:
    reg, err := regexp.Compile(c)
    if err != nil {
      return "", err
    }
    if !reg.MatchString(_val) {
      return "",errors.New("Bad parameter value: "+name+": "+_val)
    }
  case *regexp.Regexp:
    if !c.MatchString(_val) {
      return "", errors.New("Bad parameter value: "+name+": "+_val)
    }
  case []string:
    found := false
    for _, v := range c {
      if _val == v {
        found = true
        break
      }
    }
    if !found {
      return "", errors.New("Bad parameter value: "+name+": "+_val)
    }
  default:
    return "", errors.New("Unknown param type")
  }

  return _val, nil
}

func get_p_uint32(q M, name string, options ... interface{}) (uint32,error) { // options: (error on empty(true by default)), (default value) 
  val, exists := q[name]
  if !exists {
    if len(options) == 0 || options[0].(bool) {
      return 0, errors.New("Missing parameter: "+name)
    }
    if len(options) > 1 {
      return options[1].(uint32), nil
    } else {
      return 0, nil
    }
  }

  _val := fmt.Sprint(val)

  if !g_num_reg.MatchString(_val) { return 0, errors.New("Bad number for parameter: "+name+": "+_val) }
  ret, err := strconv.ParseUint(_val, 10, 32)
  if err != nil { return 0, err }
  return uint32(ret), nil
}

func get_p_map(q M, name string, check interface{}, options ... interface{}) (map[string]string, error) { // options: (error on empty(true by default)), (dafault value) 
  val, exists := q[name]
  if !exists {
    if len(options) == 0 || options[0].(bool) {
      return nil, errors.New("Missing parameter: "+name)
    }
    if len(options) > 1 {
      return options[1].(map[string]string), nil
    } else {
      return make(map[string]string), nil
    }
  }

  if reflect.TypeOf(val).String() != "map[string]interface {}" {
    return nil, errors.New("Bad parameter type: "+name+": "+reflect.TypeOf(val).String())
  }

  _val := make(map[string]string)

  for k, vv := range val.(map[string]interface {}) {
    if reflect.TypeOf(vv).String() != "string" {
      return nil, errors.New("Bad map value type: "+name+": key: "+k+": "+reflect.TypeOf(vv).String())
    }
    _val[k] = vv.(string)
  }

  switch c := check.(type) {
  case nil:
    return _val, nil
  case string:
    reg, err := regexp.Compile(c)
    if err != nil {
      return nil, err
    }
    for k, vv := range _val {
      if !reg.MatchString(vv) {
        return nil, errors.New("Bad parameter value: "+name+": key: "+k+": "+vv)
      }
    }
  case *regexp.Regexp:
    for k, vv := range _val {
      if !c.MatchString(vv) {
        return nil, errors.New("Bad parameter value: "+name+": key: "+k+": "+vv)
      }
    }
  case []string:
    for k, vv := range _val {
      found := false
      for _, v := range c {
        if vv == v {
          found = true
          break
        }
      }
      if !found {
        return nil, errors.New("Bad parameter value: "+name+": key: "+k+": "+vv)
      }
    }
  default:
    return nil, errors.New("Unknown param check type")
  }

  return _val, nil
}

func get_p_array(q M, name string, check interface{}, options ... interface{}) ([]string,error) { // options: (error on empty(true by default)), (dafault value) 
  val, exists := q[name]
  if !exists {
    if len(options) == 0 || options[0].(bool) {
      return nil, errors.New("Missing parameter: "+name)
    }
    if len(options) > 1 {
      return options[1].([]string), nil
    } else {
      return make([]string,0), nil
    }
  }

  if reflect.TypeOf(val).String() != "[]interface {}" {
    return nil, errors.New("Bad parameter type: "+name+": "+reflect.TypeOf(val).String())
  }

  for _, vv := range val.([]interface{}) {
    if reflect.TypeOf(vv).String() != "string" {
      return nil, errors.New("Bad parameter type: "+name+": "+reflect.TypeOf(vv).String())
    }
  }

  _val := make([]string, len(val.([]interface{})))
  for i, vv := range val.([]interface{}) {
    _val[i] = vv.(string)
  }

  switch c := check.(type) {
  case nil:
    return _val, nil
  case string:
    reg, err := regexp.Compile(c)
    if err != nil {
      return nil, err
    }
    for _, vv := range _val {
      if !reg.MatchString(vv) {
        return nil, errors.New("Bad parameter value: "+name+": "+vv)
      }
    }
  case *regexp.Regexp:
    for _, vv := range _val {
      if !c.MatchString(vv) {
        return nil, errors.New("Bad parameter value: "+name+": "+vv)
      }
    }
  case []string:
    for _, vv := range _val {
      found := false
      for _, v := range c {
        if vv == v {
          found = true
          break
        }
      }
      if !found {
        return nil, errors.New("Bad parameter value: "+name+": "+vv)
      }
    }
  default:
    return nil, errors.New("Unknown param type")
  }

  return _val, nil
}

var epoch = time.Unix(0, 0).Format(time.RFC1123)

// Taken from https://github.com/mytrile/nocache
var noCacheHeaders = map[string]string{
	"Expires":         epoch,
	"Cache-Control":   "no-cache, private, max-age=0",
	"Pragma":          "no-cache",
	"X-Accel-Expires": "0",
}

var etagHeaders = []string{
	"ETag",
	"If-Modified-Since",
	"If-Match",
	"If-None-Match",
	"If-Range",
	"If-Unmodified-Since",
}

func NoCache(h http.Handler) http.Handler {
  fn := func(w http.ResponseWriter, r *http.Request) {

    if r.RequestURI == "/" {
      // Delete any ETag headers that may have been set
      for _, v := range etagHeaders {
        if r.Header.Get(v) != "" {
          r.Header.Del(v)
        }
      }

      // Set our NoCache headers
      for k, v := range noCacheHeaders {
        w.Header().Set(k, v)
      }

      //w.Header().Add("X-Debug-RequestURI", r.RequestURI)
    }

    h.ServeHTTP(w, r)
  }

  return http.HandlerFunc(fn)
}

func http_server(wg *sync.WaitGroup, stop_ch chan struct{}) {

  //fmt.Println(whereami.WhereAmI())

  defer wg.Done()

  s := &http.Server{
    Addr:       fmt.Sprintf("0.0.0.0:%d", opt_p),
  }

  server_shut := make(chan struct{})

  go func() {
    select {
    case <-stop_ch:
    }
    ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(500 * time.Millisecond))
    defer cancel()

    shut_err := s.Shutdown(ctx)
    if shut_err != nil {
    }
    close(server_shut)
  }()


  fsys := dotFileHidingFileSystem{http.Dir(opt_w)}

  http.Handle("/", NoCache(http.FileServer(fsys)))
  http.HandleFunc("/consts.js", handleConsts)
  http.HandleFunc("/ajax", handleAjax)

  listener, listen_err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", opt_p))
  if listen_err != nil {
    panic("Listening error: "+listen_err.Error())
  }

  defer listener.Close()
  listener = netutil.LimitListener(listener, 100)
  http_err := s.Serve(listener)
  if http_err != http.ErrServerClosed {
  }
  select {
  case <-server_shut:
  }
}

func handleConsts(w http.ResponseWriter, req *http.Request) {

  if req.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)
    return
  }

  w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")
  w.WriteHeader(http.StatusOK)

  w.Write([]byte(fmt.Sprintf("const R_NAME = %d;\n", R_NAME)))
  w.Write([]byte(fmt.Sprintf("const R_VIEW_NET_INFO = %d;\n", R_VIEW_NET_INFO)))
  w.Write([]byte(fmt.Sprintf("const R_VIEW_NET_IPS = %d;\n", R_VIEW_NET_IPS)))
  w.Write([]byte(fmt.Sprintf("const R_EDIT_IP_VLAN = %d;\n", R_EDIT_IP_VLAN)))
  w.Write([]byte(fmt.Sprintf("const R_IGNORE_R_DENY = %d;\n", R_IGNORE_R_DENY)))
  w.Write([]byte(fmt.Sprintf("const R_MANAGE_NET = %d;\n", R_MANAGE_NET)))
  w.Write([]byte(fmt.Sprintf("const R_DENYIP = %d;\n", R_DENYIP)))

  w.Write([]byte(fmt.Sprintf("const ADMIN_GROUP = \"%s\";\n", opt_g)))

  json, jerr := json.MarshalIndent(g_rights, "", "  ")
  if jerr != nil {
    panic(jerr)
  }

  w.Write([]byte("const g_rights = "))
  w.Write(json)
  w.Write([]byte(";\n"))

  w.Write([]byte("\n"))
}

func handle_error(r interface{}, w http.ResponseWriter, req *http.Request) {
  if r == nil {
    return
  }

  w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")
  w.WriteHeader(http.StatusOK)

  var out M

  switch v := r.(type) {
  case string:
    out = make(M)
    out["error"] = v + "\n\n" + string(debug.Stack())
  case error:
    out = make(M)
    out["error"] = v.Error() + "\n\n" + string(debug.Stack())
  case M:
    out = v
  default:
    out = make(M)
    out["error"] = "Unknown error\n\n" + string(debug.Stack())
  }

  if opt_d {
    fmt.Println("out")
    dj, _ := json.MarshalIndent(out, "", "  ")
    fmt.Println(string(dj))
  }
  json, jerr := json.MarshalIndent(out, "", "  ")
  if jerr != nil {
    panic(jerr)
  }

  w.Write(json)
  w.Write([]byte("\n"))
  return
}


func handleAjax(w http.ResponseWriter, req *http.Request) {

  if req.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "*")
    w.Header().Set("Access-Control-Allow-Headers", "*")
    w.WriteHeader(http.StatusOK)
    return
  }

  //fmt.Println(whereami.WhereAmI())

  defer func() { handle_error(recover(), w, req); } ()
  //mutex_locked := false
  //defer func() { if mutex_locked { globalMutex.Unlock(); mutex_locked = false; }; } ()

  var body []byte
  var err error

  if body, err = ioutil.ReadAll(req.Body); err != nil {
    panic(err)
  }

  ts := time.Now().Unix()

  var u64 uint64 //general use var for typecasting

  var user_sub string
  var user_name string
  var user_login string
  var user_groups_string string

  for header, header_values := range req.Header {
    if strings.ToLower(header) == "x-idp-sub" && len(header_values) > 0 {
      user_sub = strings.TrimSpace(header_values[0])
    } else if strings.ToLower(header) == "x-idp-name" && len(header_values) > 0 {
      user_name = strings.TrimSpace(header_values[0])
    } else if strings.ToLower(header) == "x-idp-username" && len(header_values) > 0 {
      user_login = strings.TrimSpace(header_values[0])
    } else if strings.ToLower(header) == "x-idp-groups" && len(header_values) > 0 {
      user_groups_string = strings.TrimSpace(header_values[0])
    }
  }

  if user_sub == "" {
    panic("No authentication headers present")
  }

  //if user_groups_string == "" {
    //panic("No groups header present or is empty")
  //}

  out := make(M)

  var db *sql.DB
  var dbres sql.Result

  var query string
  _ = query

  db, err = sql.Open("mysql", opt_b)
  if err != nil { panic(err) }

  defer db.Close()

  user_q_groups := make([]string, 0)
  user_groups_a := strings.Split(user_groups_string, ",")
  for _,v := range user_groups_a {
    if len(v) > 3 && v[0:2] == `"/` && v[len(v)-1:] == `"` {
      user_q_groups = append(user_q_groups, strings.ToLower(v[2:len(v)-1]) )
    }
  }

  user_is_admin := false

  for _, g := range user_q_groups {
    if g == opt_g {
      user_is_admin = true
    }
  }

  query = "SELECT * FROM gs"
  var groups M

  if groups, err = return_query_M(db, query, "g_name"); err != nil { panic(err) }

  user_groups := make([]string, 0)
  user_groups_in := "FALSE"

  for _, v := range user_q_groups {
    if m, ex := groups[v]; ex {
      var var_ok bool
      var group_id string
      if group_id, var_ok = m.(M).AnyString("g_id"); !var_ok { panic(PE) }
      user_groups = append(user_groups, group_id)
    }
  }

  if len(user_groups) > 0 {
    user_groups_in = strings.Join(user_groups, ",")
  }

  NoAccess := func() (M) {
    out_userinfo := make(M);
    out_userinfo["name"] = user_name
    out_userinfo["login"] = user_login
    out_userinfo["query_groups"] = user_q_groups
    out_userinfo["groups"] = user_groups

    na_out := make(M)
    na_out["fail"] = "noaccess"
    na_out["userinfo"] = out_userinfo

    ok_out := make(M)
    ok_out["ok"] = na_out
    return ok_out
  }

  if !user_is_admin && len(user_groups) == 0 {
    panic(NoAccess())
  }

  var user_r interface{}
  var user_row M

  query = "SELECT * FROM us WHERE u_sub = ?"
  if user_r, err = return_query(db, query, "u_sub", user_sub); err != nil { panic(err) }

  if _, ok := user_r.(M)[user_sub]; !ok {
    query = "INSERT INTO us SET"+
            " u_sub=?"+
            ",u_name=?"+
            ",u_login=?"+
            ",u_seen=?"+
            ",added=?"+
            ",ts=?"
    if _, err = db.Exec(query, user_sub, user_name, user_login, ts, ts, ts); err != nil { panic(err) }

    query = "SELECT * FROM us WHERE u_sub = ?"
    if user_r, err = return_query(db, query, "u_sub", user_sub); err != nil { panic(err) }

    if _, ok := user_r.(M)[user_sub]; !ok { panic("Cannot add user") }
  }

  user_row = user_r.(M)[user_sub].(M)

  var user_id string
  var user_id_var_ok bool
  if user_id, user_id_var_ok = user_row.UintString("u_id"); !user_id_var_ok { panic(PE) }

  if user_row["u_name"].(string) != user_name ||
     user_row["u_login"].(string) != user_login ||
     false {
    query = "UPDATE us SET u_name=?, u_login=?, ts=? WHERE u_id=?"
    if _, err = db.Exec(query, user_name, user_login, ts, user_id); err != nil { panic(err) }
  }

  query = "UPDATE us SET u_seen=? WHERE u_id=?"
  if _, err = db.Exec(query, ts, user_id); err != nil { panic(err) }

  var q M

  if req.Method == "GET" {
    q = make(M)
    values := req.URL.Query()
    for k, v := range values {
      if len(v) == 0 {
          q[k] = ""
      } else if len(v) == 1 {
          q[k] = v[0]
      } else {
        q[k] = v
      }
    }
  } else {
    if err = json.Unmarshal(body, &q); err != nil {
      panic(err)
    }
  }

  if _, action_ex := q["action"]; !action_ex {
    panic("no action in query")
  }

  action := q["action"].(string)
  _ = action


  // do something here to fill out with values

  if opt_d {
    dj, _ := json.MarshalIndent(q, "", "  ")
    fmt.Println(string(dj))
  }

  if action == "userinfo" {
    out["id"] = user_id
    out["sub"] = user_sub
    out["name"] = user_name
    out["login"] = user_login
    out["groups"] = user_groups
    out["is_admin"] = user_is_admin
  } else if action == "get_front" {

    var v4_favs interface{}
    v4_accessible := make(M)

    query = "SELECT v4net_addr, v4net_mask FROM v4favs WHERE v4fav_fk_u_id=?"

    if v4_favs, err = return_query(db, query, "", user_id); err != nil { panic(err) }

    out["v4favs"] = v4_favs
    out["v4accessible"] = v4_accessible
  } else if action == "get_groups" {

    query = "SELECT * FROM gs ORDER BY g_id"

    if out["gs"], err = return_query(db, query, ""); err != nil { panic(err) }

    query = "SELECT u_id, u_name, u_login FROM us WHERE u_id IN (SELECT fk_u_id FROM gs)"
    if out["users"], err = return_query(db, query, "u_id"); err != nil { panic(err) }

  } else if action == "add_group" {

    if !user_is_admin { panic(NoAccess()) }

    var g_name string
    var g_descr string

    if g_name, err = get_p_string(q, "g_name", g_name_reg); err != nil { panic(err) }
    if g_descr, err = get_p_string(q, "g_descr", nil); err != nil { panic(err) }

    if g_name == ADMIN_GROUP { panic("Cannot use ADMIN_GROUP") }

    query = "INSERT INTO gs(g_name, g_descr, added, ts, fk_u_id) VALUES(?,?,?,0,?)"

    if dbres, err = db.Exec(query, g_name, g_descr, ts, user_id); err != nil { panic(err) }
    var lid int64

    if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
    if lid <= 0 { panic("weird LastInsertId returned") }

    query = "SELECT * FROM gs WHERE g_id=?"
    if out["gs"], err = return_query(db, query, "", lid); err != nil { panic(err) }

    query = "SELECT u_id, u_name, u_login FROM us WHERE u_id IN (SELECT g_id FROM gs WHERE g_id=?)"
    if out["users"], err = return_query(db, query, "u_id", lid); err != nil { panic(err) }

  } else if action == "del_group" {

    if !user_is_admin { panic(NoAccess()) }

    var id string
    if id, err = get_p_string(q, "id", g_num_reg); err != nil { panic(err) }

    var confirmed string
    if confirmed, err = get_p_string(q, "confirmed", nil, false); err != nil { panic(err) }

    var g_used uint64 = 0
    var unum uint64

    //check vlan range rights
    query = "SELECT COUNT(*) as c FROM gvrrs WHERE gvrr_fk_g_id=?"
    if unum, err = must_return_one_uint(db, query, id); err != nil { panic(err) }
    g_used += unum

    //check v4 net groups rights
    query = "SELECT COUNT(*) as c FROM gn4rs WHERE gn4r_fk_g_id=?"
    if unum, err = must_return_one_uint(db, query, id); err != nil { panic(err) }
    g_used += unum

    //check v6 net groups rights
    query = "SELECT COUNT(*) as c FROM gn6rs WHERE gn6r_fk_g_id=?"
    if unum, err = must_return_one_uint(db, query, id); err != nil { panic(err) }
    g_used += unum

    //check v4 range groups rights
    query = "SELECT COUNT(*) as c FROM gr4rs WHERE gr4r_fk_g_id=?"
    if unum, err = must_return_one_uint(db, query, id); err != nil { panic(err) }
    g_used += unum

    //check v6 range groups rights
    query = "SELECT COUNT(*) as c FROM gr6rs WHERE gr6r_fk_g_id=?"
    if unum, err = must_return_one_uint(db, query, id); err != nil { panic(err) }
    g_used += unum

    if g_used > 0 && confirmed == "" {
      out["used"] = g_used
      goto OUT
    }

    query = "DELETE FROM gs WHERE g_id=?"
    if _, err = db.Exec(query, id); err != nil { panic(err) }

    out["done"] = 1

  } else if action == "save_all" {
    queue_i, exists := q["queue"]
    if !exists { panic("Missing parameter: queue") }

    queue := queue_i.([]interface{})

    if len(queue) == 0 { panic("Empty queue") }

    //pre-flight check

    var net_cols M
    var dbnet M
    var rows []M
    var dbnet_ranges_a []M
    var dbnet_rights uint64
    var dbnet_r_rights uint64
    var dbnet_owner string
    var net_id string

    for i, qm_i := range queue {
      qm := qm_i.(map[string]interface{})

      var value interface {}

      value = qm["value"].(string)

      data := M(qm["data"].(map[string]interface{}))
      _ = data

      var var_ok bool
      var object string
      var prop string
      var obj_id string

      if object, var_ok = data.String("object"); !var_ok { panic(fmt.Sprint("No object in queue item #", i)) }

      switch(object) {
      case "group":
        if !user_is_admin { panic(NoAccess()) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        _ = prop
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        _ = obj_id

        if prop != "g_name" && prop != "g_descr" { panic(fmt.Sprint("Bad property in queue item #", i)) }
        //-------group-------
      case "ip_value":
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }

        var col_id string
        if col_id, var_ok = data.UintString("col_id"); !var_ok { panic(fmt.Sprint("No col_id in queue item #", i)) }

        query = "SELECT v4ip_addr, v4ip_fk_v4net_id FROM v4ips WHERE v4ip_id=?"
        if rows, err = return_query_A(db, query, obj_id); err != nil { panic(err) }

        if len(rows) != 1 {
          panic("Адрес не существует, возможно был удален другим пользователем. Перезагрузите страницу")
        }

        if u64, var_ok = rows[0].Uint64("v4ip_addr"); !var_ok { panic(PE) }
        if u64 > math.MaxUint32 { panic(PE) }
        ip_addr := uint32(u64)

        var ip_addr_net_id string
        if ip_addr_net_id, var_ok = rows[0].UintString("v4ip_fk_v4net_id"); !var_ok { panic(PE) }


        if dbnet == nil {
          query = "SELECT"+
                  " v4nets.*"+
                  ", IFNULL((SELECT BIT_OR(gn4r_rmask)"+
                             " FROM gn4rs WHERE"+
                             " gn4r_fk_v4net_id=v4net_id"+
                             " AND gn4r_fk_g_id IN("+user_groups_in+")"+
                             "),0) as rights"+
                  ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                             " FROM gr4rs INNER JOIN v4rs ON gr4r_fk_v4r_id=v4r_id"+
                             " WHERE gr4r_fk_g_id IN("+user_groups_in+")"+
                             " AND v4r_fk_v4net_id IS NULL"+
                             " AND v4r_start <= v4net_addr AND v4r_stop >= v4net_last"+
                             "), 0) AS r_rights"+
                  " FROM v4nets INNER JOIN v4ips ON v4ip_fk_v4net_id = v4net_id WHERE v4ip_id = ?"
          if rows, err = return_query_A(db, query, obj_id); err != nil { panic(err) }
          if len(rows) != 1 { panic("No such IP") }

          dbnet = rows[0]

          if net_id, var_ok = dbnet.UintString("v4net_id"); !var_ok { panic(PE) }

          if dbnet_rights, var_ok = dbnet.Uint64("rights"); !var_ok { panic(PE) }

          if dbnet_r_rights, var_ok = dbnet.Uint64("r_rights"); !var_ok { panic(PE) }

          dbnet_rights |= dbnet_r_rights

          dbnet_owner, _ = dbnet.AnyString("v4net_owner")

          if dbnet_owner == user_id {
            dbnet_rights = dbnet_rights | OWNER_RIGHTS
          }

          if user_is_admin {
            dbnet_rights = dbnet_rights | ADMIN_RIGHTS
          }

          query = "SELECT v4rs.*"+
                  ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                            " FROM gr4rs WHERE"+
                            " gr4r_fk_g_id IN("+user_groups_in+")"+
                            " AND gr4r_fk_v4r_id=v4r_id"+
                            "), 0) AS rights"+
                  " FROM v4rs WHERE v4r_fk_v4net_id = ? ORDER BY v4r_start, v4r_id"
          if dbnet_ranges_a, err = return_query_A(db, query, dbnet["v4net_id"]);
          err != nil { panic(err) }

          query = "SELECT ic_type, ic_regexp, ic_id FROM ics INNER JOIN n4cs ON nc_fk_ic_id=ic_id WHERE nc_fk_v4net_id=?"
          if net_cols, err = return_query_M(db, query, "ic_id", dbnet["v4net_id"]); err != nil { panic(err) }
        }

        if ip_addr_net_id != net_id {
          panic(fmt.Sprintf("Адрес из другой сети: %s != %s", ip_addr_net_id, net_id))
        }

        if _, var_ok = net_cols[col_id]; !var_ok {
          panic("У сети нет такого поля, возможно оно было удалено другим пользователем. Перезагрузите страницу")
        }

        var ip_rights uint64
        ip_rights |= dbnet_rights

        for i, _ := range dbnet_ranges_a {

          var range_rights uint64
          if range_rights, var_ok = dbnet_ranges_a[i].Uint64("rights"); !var_ok { panic(PE) }

          range_rights |= dbnet_rights
          dbnet_ranges_a[i]["rights"] = range_rights

          var range_start uint32
          var range_stop uint32

          if u64, var_ok = dbnet_ranges_a[i].Uint64("v4r_start"); !var_ok { panic(PE) }
          if u64 > math.MaxUint32 { panic(PE) }
          range_start = uint32(u64)

          if u64, var_ok = dbnet_ranges_a[i].Uint64("v4r_stop"); !var_ok { panic(PE) }
          if u64 > math.MaxUint32 { panic(PE) }
          range_stop = uint32(u64)

          if range_start > range_stop { panic(PE) }

          if ip_addr >= range_start && ip_addr <= range_stop {
            ip_rights |= range_rights
            dbnet_ranges_a[i]["in_range"] = 1
          }
        }

        if (ip_rights & R_EDIT_IP_VLAN) == 0 ||
           ((ip_rights & R_DENYIP) > 0 &&
            (ip_rights & R_IGNORE_R_DENY) == 0) ||
        false {
          panic(NoAccess())
        }

        var val_regexp *regexp.Regexp
        var val_regexp_str string
        if val_regexp_str, var_ok = net_cols[col_id].(M)["ic_regexp"].(string); !var_ok { panic(PE) }
        if val_regexp_str != "" {
          if val_regexp, var_ok = net_cols[col_id].(M)["_regexp"].(*regexp.Regexp); !var_ok {
            if val_regexp, err = regexp.Compile(val_regexp_str); err != nil { panic(err) }
            net_cols[col_id].(M)["_regexp"] = val_regexp
          }
          if !val_regexp.MatchString(value.(string)) {
            panic("Значение поля не соответствует регулярному выражению: "+val_regexp_str)
          }
        }

      case "net":
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        _ = prop
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        _ = obj_id

        if prop != "v4net_name" && prop != "v4net_descr" &&
           prop != "v4net_owner" &&
        true { panic(fmt.Sprint("Bad property in queue item #", i)) }

        query = "SELECT"+
                " v4nets.*"+
                ", IFNULL((SELECT BIT_OR(gn4r_rmask)"+
                           " FROM gn4rs WHERE"+
                           " gn4r_fk_v4net_id=v4net_id"+
                           " AND gn4r_fk_g_id IN("+user_groups_in+")"+
                           "),0) as rights"+
                ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                           " FROM gr4rs INNER JOIN v4rs ON gr4r_fk_v4r_id=v4r_id"+
                           " WHERE gr4r_fk_g_id IN("+user_groups_in+")"+
                           " AND v4r_fk_v4net_id IS NULL"+
                           " AND v4r_start <= v4net_addr AND v4r_stop >= v4net_last"+
                           "), 0) AS r_rights"+
                " FROM v4nets WHERE v4net_id=?"
        if rows, err = return_query_A(db, query, obj_id); err != nil { panic(err) }
        if len(rows) != 1 { panic("No such network") }

        var _dbnet_rights uint64
        var _dbnet_r_rights uint64
        if _dbnet_rights, var_ok = rows[0].Uint64("rights"); !var_ok { panic(PE) }

        if _dbnet_r_rights, var_ok = rows[0].Uint64("r_rights"); !var_ok { panic(PE) }

        _dbnet_rights |= _dbnet_r_rights

        _dbnet_owner, _ := rows[0].AnyString("v4net_owner")

        if _dbnet_owner == user_id {
          _dbnet_rights = _dbnet_rights | OWNER_RIGHTS
        }

        if user_is_admin {
          _dbnet_rights = _dbnet_rights | ADMIN_RIGHTS
        }

        if (_dbnet_rights & R_MANAGE_NET) == 0 { panic(NoAccess()) }

      default:
        panic("Unknown object type: "+object)
      }
    }

    tx, tx_err := db.Begin()
    if tx_err != nil { panic(tx_err) }
    var commited bool = false
    defer func() {
      if !commited {
        tx.Rollback()
      }
    } ()

    for i, qm_i := range queue {
      qm := qm_i.(map[string]interface{})

      var value interface {}

      value = qm["value"].(string)

      data := M(qm["data"].(map[string]interface{}))
      _ = data

      var var_ok bool
      var object string
      var prop string
      var obj_id string

      if object, var_ok = data.String("object"); !var_ok { panic(fmt.Sprint("No object in queue item #", i)) }

      switch(object) {
      case "group":
        if !user_is_admin { panic(NoAccess()) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        _ = prop
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        _ = obj_id

        query = "UPDATE gs SET "+prop+"=?, ts=?, fk_u_id=? WHERE g_id=?"
        _, err = tx.Exec(query, value, ts, user_id, obj_id)
        if err != nil { panic(err) }
      case "ip_value":
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        var col_id string
        if col_id, var_ok = data.UintString("col_id"); !var_ok { panic(fmt.Sprint("No col_id in queue item #", i)) }

        query = "INSERT INTO i4vs SET"+
                " iv_fk_ic_id=?"+
                ",iv_fk_v4ip_id=?"+
                ",iv_value=?"+
                ",ts=?"+
                ",fk_u_id=?"+
                " ON DUPLICATE KEY UPDATE"+
                " iv_value=VALUES(iv_value)"+
                ",ts=VALUES(ts)"+
                ",fk_u_id=VALUES(fk_u_id)"
        _, err = tx.Exec(query, col_id, obj_id, value, ts, user_id)
        if err != nil { panic(err) }
      case "net":

        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }

        if prop == "v4net_owner" && value.(string) == "0" {
          value = nil
        }

        query = "UPDATE v4nets SET "+prop+"=?, ts=?, fk_u_id=? WHERE v4net_id=?"
        _, err = tx.Exec(query, value, ts, user_id, obj_id)
        if err != nil { panic(err) }
      default:
        panic("Unknown object type: "+object)
      }
    }

    err = tx.Commit()
    if err != nil { panic(err) }
    commited = true

    out["done"] = 1

  } else if action == "fav_v4" {

    var nav_net uint32
    var masklen uint32
    var fav uint32

    if nav_net, err = get_p_uint32(q, "net"); err != nil { panic(err) }
    if masklen, err = get_p_uint32(q, "masklen"); err != nil { panic(err) }
    if masklen > 31 { panic(errors.New("Too big masklen")) }

    if nav_net != ip4net(nav_net, masklen) { panic("Bad network/masklen") }

    if fav, err = get_p_uint32(q, "fav"); err != nil { panic(err) }
    if fav > 1 { panic(errors.New("Too big fav")) }

    if fav > 0 {
      query = "INSERT INTO v4favs SET"+
              " v4fav_fk_u_id=?"+
              ",v4net_addr=?"+
              ",v4net_mask=?"+
              ",ts=?"+
              ",fk_u_id=?"+
              " ON DUPLICATE KEY UPDATE"+
              " ts=VALUES(ts)"+
              ",fk_u_id=VALUES(fk_u_id)"
      if _, err = db.Exec(query, user_id, nav_net, masklen, ts, user_id); err != nil { panic(err) }
    } else {
      query = "DELETE FROM v4favs WHERE"+
              " v4fav_fk_u_id=?"+
              " AND v4net_addr=?"+
              " AND v4net_mask=?"
      if _, err = db.Exec(query, user_id, nav_net, masklen); err != nil { panic(err) }
    }

    out["done"] = 1

  } else if action == "nav_v4" {

    var nav_net uint32
    var masklen uint32

    if nav_net, err = get_p_uint32(q, "net"); err != nil { panic(err) }
    if masklen, err = get_p_uint32(q, "masklen"); err != nil { panic(err) }
    if masklen > 31 { panic(errors.New("Too big masklen")) }

    if nav_net != ip4net(nav_net, masklen) { panic("Bad network/masklen") }

    // check if network is taken and user should use view_v4 method, to access it

    query = "SELECT COUNT(*) as c FROM v4nets WHERE v4net_addr=? AND v4net_mask <= ?"
    var unum uint64

    if unum, err = must_return_one_uint(db, query, nav_net, masklen); err != nil { panic(err) }
    if unum != 0 {
      out["taken"] = 1
      goto OUT
    }

    query = "SELECT COUNT(*) as c FROM v4favs WHERE v4net_addr=? AND v4net_mask=? AND v4fav_fk_u_id=?"
    if unum, err = must_return_one_uint(db, query, nav_net, masklen, user_id); err != nil { panic(err) }

    out["fav"] = unum

    nav_last_addr := uint32(nav_net | (0xFFFFFFFF >> masklen))

    out["net_last_addr"] = nav_last_addr

    var dbnets_i interface{}
    query = "SELECT v4nets.*"+
            ", IFNULL((SELECT BIT_OR(gn4r_rmask)"+
                       " FROM gn4rs WHERE"+
                       " gn4r_fk_v4net_id=v4net_id"+
                       " AND gn4r_fk_g_id IN("+user_groups_in+")"+
                       " GROUP BY gn4r_fk_v4net_id),0) as rights"+
            " FROM v4nets"+
            " WHERE v4net_addr >= ? AND v4net_addr <= ?"
    if dbnets_i, err = return_query(db, query, "", nav_net, nav_last_addr); err != nil { panic(err) }
    dbnets := dbnets_i.([]M)

    var ranges_i interface{}
    query = "SELECT v4rs.*"+
            ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                       " FROM gr4rs WHERE"+
                       " gr4r_fk_v4r_id=v4r_id"+
                       " AND gr4r_fk_g_id IN("+user_groups_in+")"+
                       " GROUP BY gr4r_fk_v4r_id),0) as rights"+
            " FROM v4rs"+
            " WHERE v4r_fk_v4net_id IS NULL AND v4r_start <= ? AND v4r_stop >= ? ORDER BY v4r_start"
    if ranges_i, err = return_query(db, query, "", nav_last_addr, nav_net); err != nil { panic(err) }
    ranges := ranges_i.([]M)

    var lastmask uint32
    var stepmask uint32
    if masklen < 8 {
      lastmask = 8
      stepmask = 0xFF000000
    } else if masklen < 16 {
      lastmask = 16
      stepmask = 0x00FF0000
    } else if masklen < 24 {
      lastmask = 24
      stepmask = 0x0000FF00
    } else {
      lastmask = 32
      stepmask = 0x000000FF
    }

    first_octet := (nav_net & stepmask) >> (32 - lastmask)
    last_octet := (nav_last_addr & stepmask) >> (32 - lastmask)

    out["first_octet"] = first_octet
    out["last_octet"] = last_octet
    out["lastmask"] = lastmask

    out["ranges"] = ranges

    netrows := make([]M, (last_octet - first_octet) + 1)
    for octet := first_octet; octet <= last_octet; octet++ {
      netrows[octet - first_octet] = make(M)
      row_net := (octet << (32 - lastmask)) | (nav_net & ^stepmask)
      row_last_addr := uint32(row_net | (0xFFFFFFFF >> lastmask))
      netrows[octet - first_octet]["net"] = row_net
      netrows[octet - first_octet]["last_addr"] = row_last_addr

      netrows[octet - first_octet]["cols"] = make([]M, lastmask - masklen)
      netrows[octet - first_octet]["ranges"] = make([]M, len(ranges))

      for i, range_i := range ranges {
        netrows[octet - first_octet]["ranges"].([]M)[i] = make(M)
        var range_rights uint64
        var range_start uint32
        var range_stop uint32

        var var_ok bool

        if range_rights, var_ok = range_i.Uint64("rights"); !var_ok { panic(PE) }
        if u64, var_ok = range_i.Uint64("v4r_start"); !var_ok { panic(PE) }
        if u64 >= math.MaxUint32  { panic(PE) }
        range_start = uint32(u64)

        if u64, var_ok = range_i.Uint64("v4r_stop"); !var_ok { panic(PE) }
        if u64 >= math.MaxUint32 { panic(PE) }
        range_stop = uint32(u64)

        if range_start > range_stop { panic(PE) }


        ranges[i]["_rights"] = range_rights
        ranges[i]["_start"] = range_start
        ranges[i]["_stop"] = range_stop

        if range_start <= row_last_addr && range_stop >= row_net {
          netrows[octet - first_octet]["ranges"].([]M)[i]["in_range"] = 1
        }
      }
      for m := masklen+1; m <= lastmask; m++ {
        col_idx := m - masklen - 1

        netrows[octet - first_octet]["cols"].([]M)[col_idx] = make(M)

        if row_net == ip4net(row_net, m) {
          netrows[octet - first_octet]["cols"].([]M)[col_idx]["is_net"] = 1

          cell_net_last_addr := uint32(row_net | (0xFFFFFFFF >> m))
          var net_rights uint64 = 0
          if user_is_admin {
            net_rights = net_rights | ADMIN_RIGHTS
          }
          for i, _ := range ranges {

            range_rights := ranges[i]["_rights"].(uint64)
            range_start := ranges[i]["_start"].(uint32)
            range_stop := ranges[i]["_stop"].(uint32)

            if range_start <= row_net && range_stop >= cell_net_last_addr {
              net_rights = net_rights | range_rights
            }
          }
          netrows[octet - first_octet]["cols"].([]M)[col_idx]["ranges_rights"] = net_rights
        }
      }
    }

    for _, dbnet := range dbnets {
      var dbnet_net uint32
      var dbnet_masklen uint32
      var dbnet_id string
      var dbnet_name string
      var var_ok bool
      var dbnet_owner string
      var dbnet_rights uint64

      if u64, var_ok = dbnet.Uint64("v4net_addr"); !var_ok { panic(PE) }
      if u64 > 0xFFFFFFFF { panic(PE) }
      dbnet_net = uint32(u64)

      if u64, var_ok = dbnet.Uint64("v4net_mask"); !var_ok { panic(PE) }
      if u64 > 32 { panic(PE) }
      dbnet_masklen = uint32(u64)
      if dbnet_masklen <= masklen { panic(PE) }

      dbnet_last_addr := uint32(dbnet_net | (0xFFFFFFFF >> dbnet_masklen))
      dbnet_last_octet := (dbnet_last_addr & stepmask) >> (32 - lastmask)

      if dbnet_id, var_ok = dbnet.AnyString("v4net_id"); !var_ok { panic(PE) }
      _ = dbnet_id

      if dbnet_name, var_ok = dbnet.String("v4net_name"); !var_ok { panic(PE) }

      dbnet_owner, _ = dbnet.AnyString("v4net_owner")

      if dbnet_rights, var_ok = dbnet.Uint64("rights"); !var_ok { panic(PE) }

      if user_is_admin {
        dbnet_rights = dbnet_rights | ADMIN_RIGHTS
      }

      if dbnet_owner == user_id {
        dbnet_rights = dbnet_rights | OWNER_RIGHTS
      }

      for i, _ := range ranges {
        range_rights := ranges[i]["_rights"].(uint64)
        range_start := ranges[i]["_start"].(uint32)
        range_stop := ranges[i]["_stop"].(uint32)
        if range_start <= dbnet_net && range_stop >= dbnet_last_addr {
          dbnet_rights = dbnet_rights | range_rights
        }
      }

      dbnet_octet := (dbnet_net & stepmask) >> (32 - lastmask)
      if dbnet_octet > last_octet { panic(PE) }
      if dbnet_octet < first_octet { panic(PE) }
      if netrows[dbnet_octet - first_octet] == nil { panic(PE) }
      if _, var_ok = netrows[dbnet_octet - first_octet]["is_taken"]; var_ok { panic(PE) }
      if _, var_ok = netrows[dbnet_octet - first_octet]["is_part_of_taken"]; var_ok { panic(PE) }

      if dbnet_masklen > lastmask {
        // network is deeper in navigation plane
        if _, var_ok = netrows[dbnet_octet - first_octet]["cols"].([]M)[lastmask - masklen - 1]["is_net"]; !var_ok { panic(PE) }

        var octet_subnets uint64
        var octet_subnets_names string
        if octet_subnets, var_ok = netrows[dbnet_octet - first_octet].Uint64("subnets"); !var_ok {
          octet_subnets = 0
        }
        if octet_subnets_names, var_ok = netrows[dbnet_octet - first_octet].String("subnets_names"); !var_ok {
          octet_subnets_names = ""
        }
        octet_subnets++
        if len(octet_subnets_names) < MAX_SUBNETS_NAMES_LEN && (dbnet_rights & R_NAME) > 0 {
          octet_subnets_names += "\n" + dbnet_name
        }
        netrows[dbnet_octet - first_octet]["subnets"] = octet_subnets
        netrows[dbnet_octet - first_octet]["subnets_names"] = octet_subnets_names
      } else {
        if _, var_ok = netrows[dbnet_octet - first_octet].Uint64("subnets"); var_ok { panic(PE) }
        if _, var_ok = netrows[dbnet_octet - first_octet]["cols"].([]M)[dbnet_masklen - masklen - 1]["is_net"]; !var_ok { panic(PE) }

        netrows[dbnet_octet - first_octet]["is_taken"] = 1
        if (dbnet_rights & R_NAME) > 0 {
          netrows[dbnet_octet - first_octet]["net_name"] = dbnet_name
        } else {
          netrows[dbnet_octet - first_octet]["net_name"] = "HIDDEN"
        }
        netrows[dbnet_octet - first_octet]["cols"].([]M)[dbnet_masklen - masklen - 1]["is_taken"] = 1

        netrows[dbnet_octet - first_octet]["net_rights"] = dbnet_rights
        netrows[dbnet_octet - first_octet]["cols"].([]M)[dbnet_masklen - masklen - 1]["net_rights"] = dbnet_rights

        for dbnet_net_octet_i := dbnet_octet; dbnet_net_octet_i <= dbnet_last_octet; dbnet_net_octet_i++ {
          if netrows[dbnet_net_octet_i - first_octet] == nil { panic(PE) }
          if dbnet_net_octet_i != dbnet_octet {
            netrows[dbnet_net_octet_i - first_octet]["is_part_of_taken"] = 1
          }
          for dbnet_net_col_i := dbnet_masklen; dbnet_net_col_i <= lastmask; dbnet_net_col_i++ {
            if dbnet_net_octet_i != dbnet_octet || dbnet_net_col_i != dbnet_masklen {
              if _, var_ok = netrows[dbnet_net_octet_i - first_octet]["cols"].([]M)[dbnet_net_col_i - masklen - 1]["is_taken"]; var_ok {
                panic(PE)
              }
              if _, var_ok = netrows[dbnet_net_octet_i - first_octet]["cols"].([]M)[dbnet_net_col_i - masklen - 1]["is_part_of_taken"]; var_ok {
                panic(PE)
              }
              netrows[dbnet_net_octet_i - first_octet]["cols"].([]M)[dbnet_net_col_i - masklen - 1]["is_part_of_taken"] = 1
            }
          }
        }
      }

      for higher_masklen := dbnet_masklen - 1; higher_masklen >= masklen + 1; higher_masklen-- {
        if higher_masklen <= lastmask {
          higher_net := ip4net(dbnet_net, higher_masklen)
          higher_octet := (higher_net & stepmask) >> (32 - lastmask)


          if _, var_ok = netrows[higher_octet - first_octet]["cols"].([]M)[higher_masklen - masklen -1]["is_net"]; !var_ok {
            panic(PE)
          }
          if _, var_ok = netrows[higher_octet - first_octet]["cols"].([]M)[higher_masklen - masklen -1]["is_taken"]; var_ok {
            panic(PE)
          }
          if _, var_ok = netrows[higher_octet - first_octet]["cols"].([]M)[higher_masklen - masklen -1]["is_part_of_taken"]; var_ok {
            panic(PE)
          }

          netrows[higher_octet - first_octet]["cols"].([]M)[higher_masklen - masklen -1]["is_busy"] = 1
        }
      }
    }

    out["rows"] = netrows

  } else if action == "view_v4" {

    var nav_net uint32
    var masklen uint32

    var var_ok bool

    if nav_net, err = get_p_uint32(q, "net"); err != nil { panic(err) }
    if masklen, err = get_p_uint32(q, "masklen"); err != nil { panic(err) }
    if masklen > 32 { panic(errors.New("Too big masklen")) }

    if nav_net != ip4net(nav_net, masklen) { panic("Bad network/masklen") }

    // check if network is taken and user should use view_v4 method, to access it

    query = "SELECT"+
            " v4nets.*"+
            ", IFNULL((SELECT BIT_OR(gn4r_rmask)"+
                       " FROM gn4rs WHERE"+
                       " gn4r_fk_v4net_id=v4net_id"+
                       " AND gn4r_fk_g_id IN("+user_groups_in+")"+
                       "),0) as rights"+
            ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                       " FROM gr4rs INNER JOIN v4rs ON gr4r_fk_v4r_id=v4r_id"+
                       " WHERE gr4r_fk_g_id IN("+user_groups_in+")"+
                       " AND v4r_fk_v4net_id IS NULL"+
                       " AND v4r_start <= v4net_addr AND v4r_stop >= v4net_last"+
                       "), 0) AS r_rights"+
            " FROM v4nets WHERE v4net_addr=?"
    var dbnet_a []M
    if dbnet_a, err = return_query_A(db, query, nav_net); err != nil { panic(err) }
    if len(dbnet_a) == 0 {
      out["gone"] = 1
      goto OUT
    }

    dbnet := dbnet_a[0]

    var dbnet_masklen uint32
    if u64, var_ok = dbnet.Uint64("v4net_mask"); !var_ok { panic(PE) }
    if u64 > 32 { panic(PE) }

    dbnet_masklen = uint32(u64)

    if dbnet_masklen != masklen { panic(PE) }

    var dbnet_rights uint64
    if dbnet_rights, var_ok = dbnet.Uint64("rights"); !var_ok { panic(PE) }

    var dbnet_r_rights uint64
    if dbnet_r_rights, var_ok = dbnet.Uint64("r_rights"); !var_ok { panic(PE) }

    dbnet_rights |= dbnet_r_rights

    var dbnet_owner string
    dbnet_owner, _ = dbnet.AnyString("v4net_owner")

    if dbnet_owner == user_id {
      dbnet_rights = dbnet_rights | OWNER_RIGHTS
    }

    if user_is_admin {
      dbnet_rights = dbnet_rights | ADMIN_RIGHTS
    }

    if (dbnet_rights & R_NAME) == 0 { panic(NoAccess()) }
    if (dbnet_rights & (R_VIEW_NET_INFO | R_VIEW_NET_IPS)) == 0 { panic(NoAccess()) }

    query = "SELECT COUNT(*) as c FROM v4favs WHERE v4net_addr=? AND v4net_mask=? AND v4fav_fk_u_id=?"
    if u64, err = must_return_one_uint(db, query, nav_net, masklen, user_id); err != nil { panic(err) }

    out["fav"] = u64

    var dbnet_last_addr uint32
    if u64, var_ok = dbnet.Uint64("v4net_last"); !var_ok { panic(PE) }
    if u64 > math.MaxUint32 { panic(PE) }
    dbnet_last_addr = uint32(u64)

    out["net_id"] = dbnet["v4net_id"]
    out["net_addr"] = nav_net
    out["net_masklen"] = masklen
    out["net_last_addr"] = dbnet_last_addr
    out["ts"] = dbnet["ts"]
    out["taken_ts"] = dbnet["taken_ts"]
    out["taken_u_id"] = dbnet["taken_u_id"]
    out["net_rights"] = dbnet_rights
    out["net_vlan_id"] = dbnet["v4net_fk_vlan_id"]
    if dbnet["v4net_owner"] != nil {
      out["net_owner"] = dbnet["v4net_owner"]
    } else {
      out["net_owner"] = 0
    }
    out["net_u_id"] = dbnet["fk_u_id"]
    out["net_name"] = dbnet["v4net_name"]

    if (dbnet_rights & R_VIEW_NET_INFO) > 0 {
      out["net_descr"] = dbnet["v4net_descr"]
    } else {
      out["net_descr"] = "HIDDEN"
    }

    aux_userinfo := make(M)

    if (dbnet_rights & R_VIEW_NET_INFO) > 0 {
      u64, _ = dbnet.Uint64("v4net_fk_vlan_id")
      if u64 > 0 {
        query = "SELECT vlan_number, vlan_name, vlan_descr, vd_name, vd_descr, vd_id"+
                ", (SELECT BIT_OR(gvrr_rmask)"+
                  " FROM gvrrs INNER JOIN vrs ON gvrr_fk_vr_id=vr_id"+
                  " WHERE gvrr_fk_g_id IN("+user_groups_in+")"+
                  " AND vr_fk_vd_id=vd_id"+
                  " AND vr_start <= vlan_number"+
                  " AND vr_stop >= vlan_number"+
                " ) as rights"+
                " FROM vlans INNER JOIN vds ON vd_id=vlan_fk_vd_id"+
                " WHERE vlan_id=?"
        var dbnet_vlan_info_a []M
        if dbnet_vlan_info_a,err = return_query_A(db, query, dbnet["v4net_fk_vlan_id"]); err != nil { panic(err) }
        if len(dbnet_vlan_info_a) != 1 { panic(PE) }

        var vlan_rights uint64
        if vlan_rights, var_ok = dbnet_vlan_info_a[0].Uint64("rights"); !var_ok { panic(PE) }

        if user_is_admin { vlan_rights |= ADMIN_RIGHTS }

        if (vlan_rights & R_NAME) > 0 {
          if (vlan_rights & R_VIEW_NET_INFO) == 0 {
            dbnet_vlan_info_a[0]["vlan_name"] = "HIDDEN"
            dbnet_vlan_info_a[0]["vlan_descr"] = "HIDDEN"
            dbnet_vlan_info_a[0]["vd_name"] = "HIDDEN"
            dbnet_vlan_info_a[0]["vd_descr"] = "HIDDEN"
          } else if (vlan_rights & R_VIEW_NET_IPS) == 0 {
            dbnet_vlan_info_a[0]["vlan_name"] = "HIDDEN"
            dbnet_vlan_info_a[0]["vlan_descr"] = "HIDDEN"
          }
          out["vlan_info"] = dbnet_vlan_info_a[0]
        }
      }

      u64, _ = dbnet.Uint64("fk_u_id")
      if u64 > 0 {
        var dbnet_userinfo_a []M
        if dbnet_userinfo_a, err = return_query_A(db, "SELECT * FROM us WHERE u_id=?", u64); err != nil { panic(err) }
        if len(dbnet_userinfo_a) == 1 {
          aux_userinfo[strconv.FormatUint(u64, 10)] = dbnet_userinfo_a[0]
        }
      }

      if dbnet_owner != "" {
        var dbnet_ownerinfo_a []M
        if dbnet_ownerinfo_a, err = return_query_A(db, "SELECT * FROM us WHERE u_id=?", dbnet_owner); err != nil { panic(err) }
        if len(dbnet_ownerinfo_a) == 1 {
          aux_userinfo[dbnet_owner] = dbnet_ownerinfo_a[0]
        }
      }

      query = "SELECT v4rs.*"+
              ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                        " FROM gr4rs WHERE"+
                        " gr4r_fk_g_id IN("+user_groups_in+")"+
                        " AND gr4r_fk_v4r_id=v4r_id"+
                        "), 0) AS rights"+
                " FROM v4rs WHERE v4r_stop >= ? AND v4r_start <= ? AND v4r_fk_v4net_id IS NULL"
      var dbnet_in_ranges_a []M
      if dbnet_in_ranges_a, err = return_query_A(db, query, dbnet_last_addr, nav_net); err != nil { panic(err) }
      out["net_in_ranges"] = dbnet_in_ranges_a
    }

    var dbnet_ranges_a []M

    query = "SELECT v4rs.*"+
            ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                      " FROM gr4rs WHERE"+
                      " gr4r_fk_g_id IN("+user_groups_in+")"+
                      " AND gr4r_fk_v4r_id=v4r_id"+
                      "), 0) AS rights"+
            " FROM v4rs WHERE v4r_fk_v4net_id = ? ORDER BY v4r_start, v4r_id"
    if dbnet_ranges_a, err = return_query_A(db, query, dbnet["v4net_id"]);
    err != nil { panic(err) }

    var ranges_orig string

    for i, _ := range dbnet_ranges_a {

      ranges_orig += fmt.Sprintf("%d:%d:%d ", dbnet_ranges_a[i]["v4r_id"], dbnet_ranges_a[i]["v4r_start"], dbnet_ranges_a[i]["v4r_stop"])

      var range_rights uint64
      if range_rights, var_ok = dbnet_ranges_a[i].Uint64("rights"); !var_ok { panic(PE) }

      range_rights |= dbnet_rights
      dbnet_ranges_a[i]["rights"] = range_rights
    }

    out["ranges_orig"] = ranges_orig

    if (dbnet_rights & R_VIEW_NET_IPS) > 0 {

      var net_cols M
      query = "SELECT n4cs.ts AS ncs_ts, n4cs.fk_u_id AS ncs_u_id"+
              ", ics.*"+
              " FROM n4cs INNER JOIN ics ON nc_fk_ic_id=ic_id"+
              " WHERE nc_fk_v4net_id=?"
      if net_cols, err = return_query_M(db, query, "ic_id", dbnet["v4net_id"]); err != nil { panic(err) }

      out["net_cols"] = net_cols

      query = "SELECT * FROM v4ips WHERE v4ip_fk_v4net_id=? ORDER BY v4ip_addr ASC"
      var ips_a []M
      if ips_a, err = return_query_A(db, query, dbnet["v4net_id"]); err != nil { panic(err) }

      ip_index := make(map[uint64]int)
      addr_index := make(map[uint32]int)

      for i, ip := range ips_a {
        if u64, var_ok = ip.Uint64("v4ip_id"); !var_ok { panic(PE) }
        ip_index[u64] = i
        ips_a[i]["values"] = make(M)
        for k, _ := range net_cols {
          ips_a[i]["values"].(M)[k] = make(M)
        }
        if u64, var_ok = ip.Uint64("v4ip_addr"); !var_ok { panic(PE) }
        if u64 > math.MaxUint32 { panic(PE) }
        addr_index[uint32(u64)] = i
      }

      query = "SELECT i4vs.iv_value, i4vs.iv_fk_ic_id, i4vs.ts, i4vs.fk_u_id, v4ips.v4ip_id"+
              " FROM (i4vs INNER JOIN v4ips ON i4vs.iv_fk_v4ip_id=v4ips.v4ip_id)"+
//              " INNER JOIN n4cs ON nc_fk_ic_id=i4vs.iv_fk_ic_id AND nc_fk_v4net_id=v4ip_fk_v4net_id"+
              " WHERE v4ip_fk_v4net_id=?"
      var ips_data []M
      if ips_data, err = return_query_A(db, query, dbnet["v4net_id"]); err != nil { panic(err) }

      for _, ips_data_row := range ips_data {
        if u64, var_ok = ips_data_row.Uint64("v4ip_id"); !var_ok { panic(PE) }
        var ip_data_index int
        if ip_data_index, var_ok = ip_index[u64]; !var_ok { panic(PE) }

        var ip_data_c_id string
        if ip_data_c_id, var_ok = ips_data_row.AnyString("iv_fk_ic_id"); !var_ok { panic(PE) }

        if _, ex := ips_a[ip_data_index]["values"].(M)[ip_data_c_id]; !ex {
          panic(fmt.Sprintf("v4ip_id: %d, ip_data_c_id: %s, v4net_id: %d",
                u64, ip_data_c_id, dbnet["v4net_id"]))
        }
        ips_a[ip_data_index]["values"].(M)[ip_data_c_id].(M)["v"] = ips_data_row["iv_value"]

        if u64, var_ok = ips_data_row.Uint64("ts"); !var_ok { panic(PE) }
        ips_a[ip_data_index]["values"].(M)[ip_data_c_id].(M)["ts"] = u64

        var ip_data_u_id string
        ip_data_u_id, _ = ips_data_row.AnyString("fk_u_id")

        if ip_data_u_id != "" {
          ips_a[ip_data_index]["values"].(M)[ip_data_c_id].(M)["u_id"] = ip_data_u_id
          if _, var_ok = aux_userinfo[ip_data_u_id]; !var_ok {
            var _userinfo_a []M
            if _userinfo_a, err = return_query_A(db, "SELECT * FROM us WHERE u_id=?", ip_data_u_id);
            err != nil { panic(err) }
            if len(_userinfo_a) == 1 {
              aux_userinfo[ip_data_u_id] = _userinfo_a[0]
            }
          }
        }
      }

      out_ips := make([]M, 0)

      var pending M = nil

      for ip_addr := nav_net; ip_addr <= dbnet_last_addr; ip_addr++ {
        addr_idx, addr_taken := addr_index[ip_addr]
        var addr_rights uint64 = dbnet_rights
        addr_ranges := make([]M, len(dbnet_ranges_a))

        for i, _ := range dbnet_ranges_a {
          addr_ranges[i] = make(M)

          var range_start uint32
          if u64, var_ok = dbnet_ranges_a[i].Uint64("v4r_start"); !var_ok { panic(PE) }
          if u64 > math.MaxUint32 { panic(PE) }
          range_start = uint32(u64)

          var range_stop uint32
          if u64, var_ok = dbnet_ranges_a[i].Uint64("v4r_stop"); !var_ok { panic(PE) }
          if u64 > math.MaxUint32 { panic(PE) }
          range_stop = uint32(u64)
          if range_stop < range_start { panic(PE) }

          if ip_addr >= range_start && ip_addr <= range_stop {
            addr_ranges[i]["in_range"] = 1
            addr_rights |= dbnet_ranges_a[i]["rights"].(uint64)
          }
        }

        if addr_taken {
          if masklen <= 30 && ip_addr == nav_net { panic(PE) }
          if masklen <= 30 && ip_addr == dbnet_last_addr { panic(PE) }
          ips_a[addr_idx]["ranges"] = addr_ranges
          ips_a[addr_idx]["rights"] = addr_rights

          ips_a[addr_idx]["is_taken"] = 1

          if pending != nil {
            out_ips = append(out_ips, pending)
            pending = nil
          }

          out_ips = append(out_ips, ips_a[addr_idx])
        } else {
          if masklen <= 30 && ip_addr == nav_net {
            ip_m := make(M)
            ip_m["v4ip_addr"] = ip_addr
            ip_m["ranges"] = addr_ranges
            ip_m["rights"] = addr_rights
            ip_m["is_network"] = 1
            out_ips = append(out_ips, ip_m)
          } else if masklen <= 30 && ip_addr == dbnet_last_addr {
            if pending != nil {
              out_ips = append(out_ips, pending)
              pending = nil
            }
            ip_m := make(M)
            ip_m["v4ip_addr"] = ip_addr
            ip_m["ranges"] = addr_ranges
            ip_m["rights"] = addr_rights
            ip_m["is_broadcast"] = 1
            out_ips = append(out_ips, ip_m)
          } else {
            if pending == nil {
              pending = make(M)
              pending["is_empty"] = 1
              pending["start"] = ip_addr
              pending["stop"] = ip_addr
              pending["rights"] = addr_rights
              pending["ranges"] = addr_ranges
            } else {
              ranges_differ := false
              for i, _ := range dbnet_ranges_a {
                if len(pending["ranges"].([]M)[i]) != len(addr_ranges[i]) {
                  ranges_differ = true
                  break
                }
              }
              if !ranges_differ {
                pending["stop"] = ip_addr
              } else {
                out_ips = append(out_ips, pending)
                pending = make(M)
                pending["is_empty"] = 1
                pending["start"] = ip_addr
                pending["stop"] = ip_addr
                pending["rights"] = addr_rights
                pending["ranges"] = addr_ranges
              }
            }

            if ip_addr == dbnet_last_addr {
              out_ips = append(out_ips, pending)
              pending = nil
            }
          }
        }
      }

      out["ips"] = out_ips
    }

    out["net_ranges"] = dbnet_ranges_a

    aux_userinfo[user_id] = user_row
    out["aux_userinfo"] = aux_userinfo
  } else if action == "take_ip4" {
    var take_ip uint32
    var ranges_orig string
    var var_ok bool

    if take_ip, err = get_p_uint32(q, "take_ip"); err != nil { panic(err) }
    if ranges_orig, err = get_p_string(q, "ranges_orig", nil); err != nil { panic(err) }

    tx, tx_err := db.Begin()
    if tx_err != nil { panic(tx_err) }
    var commited bool = false
    defer func() {
      if !commited {
        tx.Rollback()
      }
    } ()

    query = "SELECT COUNT(*) as c FROM v4ips WHERE v4ip_addr=?"
    if u64,err  = must_return_one_uint(tx, query, take_ip); err != nil { panic(err) }
    if u64 == 1 {
      out["taken"] = 1
      goto OUT
    }

    if u64 != 0 { panic(PE) }

    var rows []M
    query = "SELECT"+
            " v4nets.*"+
            ", IFNULL((SELECT BIT_OR(gn4r_rmask)"+
                       " FROM gn4rs WHERE"+
                       " gn4r_fk_v4net_id=v4net_id"+
                       " AND gn4r_fk_g_id IN("+user_groups_in+")"+
                       "),0) as rights"+
            ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                       " FROM gr4rs INNER JOIN v4rs ON gr4r_fk_v4r_id=v4r_id"+
                       " WHERE gr4r_fk_g_id IN("+user_groups_in+")"+
                       " AND v4r_fk_v4net_id IS NULL"+
                       " AND v4r_start <= v4net_addr AND v4r_stop >= v4net_last"+
                       "), 0) AS r_rights"+
            " FROM v4nets WHERE v4net_addr <=? AND v4net_last >= ?"
    if rows, err = return_query_A(tx, query, take_ip, take_ip); err != nil { panic(err) }
    if len(rows) != 1 {
      out["gone"] = 1
      goto OUT
    }

    var dbnet_addr uint32
    var dbnet_last_addr uint32
    var masklen uint32

    dbnet := rows[0]

    if u64, var_ok = dbnet.Uint64("v4net_addr"); !var_ok { panic(PE) }
    if u64 > math.MaxUint32 { panic(PE) }
    dbnet_addr = uint32(u64)

    if u64, var_ok = dbnet.Uint64("v4net_last"); !var_ok { panic(PE) }
    if u64 > math.MaxUint32 { panic(PE) }
    dbnet_last_addr = uint32(u64)

    if u64, var_ok = dbnet.Uint64("v4net_mask"); !var_ok { panic(PE) }
    if u64 > 32 { panic(PE) }
    masklen = uint32(u64)

    if masklen > 30 && take_ip == dbnet_addr { panic(PE) }
    if masklen > 30 && take_ip == dbnet_last_addr { panic(PE) }

    var dbnet_rights uint64
    if dbnet_rights, var_ok = dbnet.Uint64("rights"); !var_ok { panic(PE) }

    var dbnet_r_rights uint64
    if dbnet_r_rights, var_ok = dbnet.Uint64("r_rights"); !var_ok { panic(PE) }

    dbnet_rights |= dbnet_r_rights

    var dbnet_owner string
    dbnet_owner, _ = dbnet.AnyString("v4net_owner")

    if dbnet_owner == user_id {
      dbnet_rights = dbnet_rights | OWNER_RIGHTS
    }

    if user_is_admin {
      dbnet_rights = dbnet_rights | ADMIN_RIGHTS
    }

    if (dbnet_rights & R_NAME) == 0 { panic(NoAccess()) }
    if (dbnet_rights & (R_VIEW_NET_INFO | R_VIEW_NET_IPS)) == 0 { panic(NoAccess()) }

    var dbnet_ranges_a []M

    query = "SELECT v4rs.*"+
            ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                      " FROM gr4rs WHERE"+
                      " gr4r_fk_g_id IN("+user_groups_in+")"+
                      " AND gr4r_fk_v4r_id=v4r_id"+
                      "), 0) AS rights"+
            " FROM v4rs WHERE v4r_fk_v4net_id = ? ORDER BY v4r_start, v4r_id"
    if dbnet_ranges_a, err = return_query_A(db, query, dbnet["v4net_id"]);
    err != nil { panic(err) }

    var ip_rights uint64

    ip_rights |= dbnet_rights

    var ranges_check string

    for i, _ := range dbnet_ranges_a {

      ranges_check += fmt.Sprintf("%d:%d:%d ", dbnet_ranges_a[i]["v4r_id"], dbnet_ranges_a[i]["v4r_start"], dbnet_ranges_a[i]["v4r_stop"])
      var range_rights uint64
      if range_rights, var_ok = dbnet_ranges_a[i].Uint64("rights"); !var_ok { panic(PE) }

      range_rights |= dbnet_rights
      dbnet_ranges_a[i]["rights"] = range_rights

      var range_start uint32
      var range_stop uint32

      if u64, var_ok = dbnet_ranges_a[i].Uint64("v4r_start"); !var_ok { panic(PE) }
      if u64 > math.MaxUint32 { panic(PE) }
      range_start = uint32(u64)

      if u64, var_ok = dbnet_ranges_a[i].Uint64("v4r_stop"); !var_ok { panic(PE) }
      if u64 > math.MaxUint32 { panic(PE) }
      range_stop = uint32(u64)

      if range_start > range_stop { panic(PE) }

      if take_ip >= range_start && take_ip <= range_stop {
        ip_rights |= range_rights
        dbnet_ranges_a[i]["in_range"] = 1
      }
    }

    if ranges_orig != ranges_check {
      out["ranges_changed"] = 1
      goto OUT
    }

    if (ip_rights & R_EDIT_IP_VLAN) == 0 ||
       ((ip_rights & R_DENYIP) > 0 &&
        (ip_rights & R_IGNORE_R_DENY) == 0) ||
    false {
      panic(NoAccess())
    }

    query = "INSERT INTO v4ips SET"+
            " v4ip_addr=?"+
            ",v4ip_fk_v4net_id=?"+
            ",ts=?"+
            ",fk_u_id=?"
    if dbres, err = tx.Exec(query, take_ip, dbnet["v4net_id"], ts, user_id); err != nil { panic(err) }

    query = "SELECT * from v4ips WHERE v4ip_addr=?"
    if rows, err = return_query_A(tx, query, take_ip); err != nil { panic(err) }
    if len(rows) != 1 { panic(PE) }

    ipdata := rows[0]

    addr_ranges := make([]M, len(dbnet_ranges_a))
    for i, _ := range dbnet_ranges_a {
      addr_ranges[i] = make(M)
      if _, var_ok = dbnet_ranges_a[i]["in_range"]; var_ok {
        addr_ranges[i]["in_range"] = 1
      }
    }

    ipdata["ranges"] = addr_ranges
    ipdata["rights"] = ip_rights
    ipdata["values"] = make(M)
    ipdata["is_taken"] = 1

    var net_cols M
    query = "SELECT n4cs.ts AS ncs_ts, n4cs.fk_u_id AS ncs_u_id"+
            ", ics.*"+
            " FROM n4cs INNER JOIN ics ON nc_fk_ic_id=ic_id"+
            " WHERE nc_fk_v4net_id=?"
    if net_cols, err = return_query_M(db, query, "ic_id", dbnet["v4net_id"]); err != nil { panic(err) }

    for k, _ := range net_cols {
      ipdata["values"].(M)[k] = make(M)
    }

    out["ipdata"] = ipdata

    err = tx.Commit()
    if err != nil { panic(err) }
    commited = true

  } else if action == "users_list" {
    var list []M
    query = "SELECT * FROM us WHERE u_sub NOT LIKE 'imported%'"
    if list, err = return_query_A(db, query); err != nil { panic(err) }

    out["users_list"] = list

  } else if action == "get_rights" {
    var object string
    var object_id string

    if object, err = get_p_string(q, "object", "^(?:v4net_acl)$"); err != nil { panic(err) }
    if object_id, err = get_p_string(q, "object_id", g_num_reg); err != nil { panic(err) }

    var dbnet M
    var dbnet_rights uint64

    var rquery string
    var var_ok bool

    var groups M

    query = "SELECT g_id, g_name, g_descr FROM gs"
    if groups, err = return_query_M(db, query, "g_id"); err != nil { panic(err) }

    switch object {
    case "v4net_acl":
      var rows []M
      query = "SELECT"+
              " v4nets.*"+
              ", IFNULL((SELECT BIT_OR(gn4r_rmask)"+
                         " FROM gn4rs WHERE"+
                         " gn4r_fk_v4net_id=v4net_id"+
                         " AND gn4r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                         " FROM gr4rs INNER JOIN v4rs ON gr4r_fk_v4r_id=v4r_id"+
                         " WHERE gr4r_fk_g_id IN("+user_groups_in+")"+
                         " AND v4r_fk_v4net_id IS NULL"+
                         " AND v4r_start <= v4net_addr AND v4r_stop >= v4net_last"+
                         "), 0) AS r_rights"+
              " FROM v4nets WHERE v4net_id=?"
      if rows, err = return_query_A(db, query, object_id); err != nil { panic(err) }
      if len(rows) != 1 {
        panic("Сеть не существует. Обновите страницу.")
      }
      dbnet = rows[0]

      if dbnet_rights, var_ok = dbnet.Uint64("rights"); !var_ok { panic(PE) }

      var dbnet_r_rights uint64
      if dbnet_r_rights, var_ok = dbnet.Uint64("r_rights"); !var_ok { panic(PE) }

      dbnet_rights |= dbnet_r_rights

      var dbnet_owner string
      dbnet_owner, _ = dbnet.AnyString("v4net_owner")

      if dbnet_owner == user_id {
        dbnet_rights = dbnet_rights | OWNER_RIGHTS
      }

      if user_is_admin {
        dbnet_rights = dbnet_rights | ADMIN_RIGHTS
      }

      if (dbnet_rights & R_NAME) == 0 { panic(NoAccess()) }
      if (dbnet_rights & R_VIEW_NET_INFO) == 0 { panic(NoAccess()) }

      rquery = "SELECT"+
               " gn4r_rmask as rights"+
               ", ts"+
               ", fk_u_id"+
               ", gn4r_fk_g_id as g_id"+
               " FROM gn4rs"+
               " WHERE gn4r_fk_v4net_id=?"
    default:
      panic(PE)
    }

    var aux_userinfo M
    user_ids := make([]string, 0)
    var rights M
    if rights, err = return_query_M(db, rquery, "g_id", object_id); err != nil { panic(err) }
    for g_id, _ := range groups {
      if _, ex := rights[g_id]; ex {
        var s string
        if s, var_ok = rights[g_id].(M).UintString("fk_u_id"); !var_ok { panic(PE) }
        user_ids = append(user_ids, s)
        groups[g_id].(M)["ts"] = rights[g_id].(M)["ts"]
        groups[g_id].(M)["fk_u_id"] = rights[g_id].(M)["fk_u_id"]
        groups[g_id].(M)["rights"] = rights[g_id].(M)["rights"]
      } else {
        groups[g_id].(M)["ts"] = nil
        groups[g_id].(M)["fk_u_id"] = nil
        groups[g_id].(M)["rights"] = uint64(0)
      }
    }

    if len(user_ids) > 0 {
      if aux_userinfo, err = return_query_M(db, "SELECT * FROM us WHERE u_id IN("+strings.Join(user_ids, ",")+")", "u_id");
      err != nil { panic(err) }
    } else {
      aux_userinfo = make(M)
    }

    out["groups"] = groups
    out["aux_userinfo"] = aux_userinfo

  } else if action == "set_rights" {
    var object string
    var object_id string
    var rights map[string]string

    if object, err = get_p_string(q, "object", "^(?:v4net_acl)$"); err != nil { panic(err) }
    if object_id, err = get_p_string(q, "object_id", g_num_reg); err != nil { panic(err) }
    if rights, err = get_p_map(q, "rights", g_num_reg); err != nil { panic(err) }

    tx, tx_err := db.Begin()
    if tx_err != nil { panic(tx_err) }
    var commited bool = false
    defer func() {
      if !commited {
        tx.Rollback()
      }
    } ()

    var dbnet M
    var dbnet_rights uint64

    var rquery string
    var var_ok bool

    var table string
    var group_key string
    var object_key string
    var right_mask_field string

    switch object {
    case "v4net_acl":
      table = "gn4rs"
      group_key = "gn4r_fk_g_id"
      object_key = "gn4r_fk_v4net_id"
      right_mask_field = "gn4r_rmask"

      var rows []M
      query = "SELECT"+
              " v4nets.*"+
              ", IFNULL((SELECT BIT_OR(gn4r_rmask)"+
                         " FROM gn4rs WHERE"+
                         " gn4r_fk_v4net_id=v4net_id"+
                         " AND gn4r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                         " FROM gr4rs INNER JOIN v4rs ON gr4r_fk_v4r_id=v4r_id"+
                         " WHERE gr4r_fk_g_id IN("+user_groups_in+")"+
                         " AND v4r_fk_v4net_id IS NULL"+
                         " AND v4r_start <= v4net_addr AND v4r_stop >= v4net_last"+
                         "), 0) AS r_rights"+
              " FROM v4nets WHERE v4net_id=?"
      if rows, err = return_query_A(tx, query, object_id); err != nil { panic(err) }
      if len(rows) != 1 {
        panic("Сеть не существует. Обновите страницу.")
      }
      dbnet = rows[0]

      if dbnet_rights, var_ok = dbnet.Uint64("rights"); !var_ok { panic(PE) }

      var dbnet_r_rights uint64
      if dbnet_r_rights, var_ok = dbnet.Uint64("r_rights"); !var_ok { panic(PE) }

      dbnet_rights |= dbnet_r_rights

      var dbnet_owner string
      dbnet_owner, _ = dbnet.AnyString("v4net_owner")

      if dbnet_owner == user_id {
        dbnet_rights = dbnet_rights | OWNER_RIGHTS
      }

      if user_is_admin {
        dbnet_rights = dbnet_rights | ADMIN_RIGHTS
      }

      for _, r := range [...]uint64{R_NAME, R_VIEW_NET_INFO, R_VIEW_NET_IPS, R_EDIT_IP_VLAN, R_MANAGE_NET} {
        if (dbnet_rights & r) == 0 { panic(NoAccess()) }
      }

    default:
      panic(PE)
    }

    rquery = "SELECT "+right_mask_field+" as rights"+
             ", "+group_key+" as g_id"+
             " FROM "+table+
             " WHERE "+object_key+"=?"

    var groups_rights M
    if groups_rights, err = return_query_M(tx, rquery, "g_id", object_id); err != nil { panic(err) }

    for g_id, m := range groups_rights {
      var current_rights string
      if current_rights, var_ok = m.(M).UintString("rights"); !var_ok { panic(PE) }

      if _, ex := rights[g_id]; !ex {
        // has to delete currently assigned right
        query = "DELETE FROM "+table+
                " WHERE "+group_key+"=? AND "+object_key+"=?"
        if _, err = tx.Exec(query, g_id, object_id); err != nil { panic(err) }
      } else if current_rights != rights[g_id] {
        query = "UPDATE "+table+
                " SET "+right_mask_field+"=?"+
                ", ts=?, fk_u_id=?"+
                " WHERE "+group_key+"=? AND "+object_key+"=?"
        if _, err = tx.Exec(query,  rights[g_id], ts, user_id, g_id, object_id); err != nil { panic(err) }
      }
    }

    for g_id, _ := range rights {
      if _, ex := groups_rights[g_id]; !ex {
        query = "INSERT INTO "+table+
                " SET "+right_mask_field+"=?"+
                ", ts=?, fk_u_id=?"+
                ", "+group_key+"=?"+
                ", "+object_key+"=?"
        if _, err = tx.Exec(query,  rights[g_id], ts, user_id, g_id, object_id); err != nil { panic(err) }
      }
    }

    out["done"] = 1

    err = tx.Commit()
    if err != nil { panic(err) }
    commited = true

  } else if action == "save_range" {
    var object string
    var object_id string
    var rights map[string]string

    if object, err = get_p_string(q, "object", "^(?:int_v4net_range)$"); err != nil { panic(err) }
    if object_id, err = get_p_string(q, "object_id", "^\\d*"); err != nil { panic(err) }
    if rights, err = get_p_map(q, "rights", g_num_reg); err != nil { panic(err) }

    var net_id string

    var r_start interface{}
    var r_stop interface{}

    var r_name string
    var r_descr string
    var r_style string
    var r_icon string
    var r_icon_style string

    if r_name, err = get_p_string(q, "r_name", nil); err != nil { panic(err) }
    if r_descr, err = get_p_string(q, "r_descr", nil); err != nil { panic(err) }
    if r_style, err = get_p_string(q, "r_style", nil); err != nil { panic(err) }
    if r_icon, err = get_p_string(q, "r_icon", nil); err != nil { panic(err) }
    if r_icon_style, err = get_p_string(q, "r_icon_style", nil); err != nil { panic(err) }

    tx, tx_err := db.Begin()
    if tx_err != nil { panic(tx_err) }
    var commited bool = false
    defer func() {
      if !commited {
        tx.Rollback()
      }
    } ()

    var dbnet M
    var dbnet_rights uint64

    var rquery string
    var var_ok bool

    var table string
    var group_key string
    var object_key string
    var right_mask_field string

    switch object {
    case "int_v4net_range":
      if net_id, err = get_p_string(q, "net_id", g_num_reg); err != nil { panic(err) }
      if r_start, err = get_p_uint32(q, "r_start"); err != nil { panic(err) }
      if r_stop, err = get_p_uint32(q, "r_stop"); err != nil { panic(err) }

      if r_start.(uint32) > r_stop.(uint32) { panic("Bad range") }

      table = "gr4rs"
      group_key = "gr4r_fk_g_id"
      object_key = "gr4r_fk_v4r_id"
      right_mask_field = "gr4r_rmask"

      var rows []M
      query = "SELECT"+
              " v4nets.*"+
              ", IFNULL((SELECT BIT_OR(gn4r_rmask)"+
                         " FROM gn4rs WHERE"+
                         " gn4r_fk_v4net_id=v4net_id"+
                         " AND gn4r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                         " FROM gr4rs INNER JOIN v4rs ON gr4r_fk_v4r_id=v4r_id"+
                         " WHERE gr4r_fk_g_id IN("+user_groups_in+")"+
                         " AND v4r_fk_v4net_id IS NULL"+
                         " AND v4r_start <= v4net_addr AND v4r_stop >= v4net_last"+
                         "), 0) AS r_rights"+
              " FROM v4nets WHERE v4net_id=?"
      if rows, err = return_query_A(tx, query, net_id); err != nil { panic(err) }
      if len(rows) != 1 {
        panic("Сеть не существует. Обновите страницу.")
      }
      dbnet = rows[0]

      var dbnet_addr uint64
      var dbnet_last_addr uint64

      if dbnet_addr, var_ok = dbnet.Uint64("v4net_addr"); !var_ok { panic(PE) }
      if dbnet_last_addr, var_ok = dbnet.Uint64("v4net_last"); !var_ok { panic(PE) }

      if uint64(r_start.(uint32)) < dbnet_addr || uint64(r_stop.(uint32)) > dbnet_last_addr { panic("Range is out of network bounds") }

      if dbnet_rights, var_ok = dbnet.Uint64("rights"); !var_ok { panic(PE) }

      var dbnet_r_rights uint64
      if dbnet_r_rights, var_ok = dbnet.Uint64("r_rights"); !var_ok { panic(PE) }

      dbnet_rights |= dbnet_r_rights

      var dbnet_owner string
      dbnet_owner, _ = dbnet.AnyString("v4net_owner")

      if dbnet_owner == user_id {
        dbnet_rights = dbnet_rights | OWNER_RIGHTS
      }

      if user_is_admin {
        dbnet_rights = dbnet_rights | ADMIN_RIGHTS
      }

      for _, r := range [...]uint64{R_NAME, R_VIEW_NET_INFO, R_VIEW_NET_IPS, R_EDIT_IP_VLAN, R_MANAGE_NET} {
        if (dbnet_rights & r) == 0 { panic(NoAccess()) }
      }

      if object_id == "" {
        query = "INSERT INTO v4rs SET"+
                " v4r_start=?"+
                ",v4r_stop=?"+
                ",v4r_name=?"+
                ",v4r_descr=?"+
                ",v4r_style=?"+
                ",v4r_icon=?"+
                ",v4r_icon_style=?"+
                ",v4r_fk_v4net_id=?"+
                ",ts=?"+
                ",fk_u_id=?"
        if dbres, err = tx.Exec(query, r_start, r_stop, r_name, r_descr, r_style, r_icon, r_icon_style, net_id, ts, user_id);
        err != nil { panic(err) }
        var lid int64

        if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
        if lid <= 0 { panic("weird LastInsertId returned") }

        object_id = strconv.FormatInt(lid, 10)
      } else {
        query = "UPDATE v4rs SET"+
                " v4r_start=?"+
                ",v4r_stop=?"+
                ",v4r_name=?"+
                ",v4r_descr=?"+
                ",v4r_style=?"+
                ",v4r_icon=?"+
                ",v4r_icon_style=?"+
                ",ts=?"+
                ",fk_u_id=?"+
                " WHERE v4r_fk_v4net_id=? AND v4r_id=?"
        if _, err = tx.Exec(query, r_start, r_stop, r_name, r_descr, r_style, r_icon, r_icon_style, ts, user_id, net_id, object_id);
        err != nil { panic(err) }
      }

    default:
      panic(PE)
    }

    rquery = "SELECT "+right_mask_field+" as rights"+
             ", "+group_key+" as g_id"+
             " FROM "+table+
             " WHERE "+object_key+"=?"

    var groups_rights M
    if groups_rights, err = return_query_M(tx, rquery, "g_id", object_id); err != nil { panic(err) }

    for g_id, m := range groups_rights {
      var current_rights string
      if current_rights, var_ok = m.(M).UintString("rights"); !var_ok { panic(PE) }

      if _, ex := rights[g_id]; !ex {
        // has to delete currently assigned right
        query = "DELETE FROM "+table+
                " WHERE "+group_key+"=? AND "+object_key+"=?"
        if _, err = tx.Exec(query, g_id, object_id); err != nil { panic(err) }
      } else if current_rights != rights[g_id] {
        query = "UPDATE "+table+
                " SET "+right_mask_field+"=?"+
                ", ts=?, fk_u_id=?"+
                " WHERE "+group_key+"=? AND "+object_key+"=?"
        if _, err = tx.Exec(query,  rights[g_id], ts, user_id, g_id, object_id); err != nil { panic(err) }
      }
    }

    for g_id, _ := range rights {
      if _, ex := groups_rights[g_id]; !ex {
        query = "INSERT INTO "+table+
                " SET "+right_mask_field+"=?"+
                ", ts=?, fk_u_id=?"+
                ", "+group_key+"=?"+
                ", "+object_key+"=?"
        if _, err = tx.Exec(query,  rights[g_id], ts, user_id, g_id, object_id); err != nil { panic(err) }
      }
    }

    out["done"] = 1

    err = tx.Commit()
    if err != nil { panic(err) }
    commited = true
  } else if action == "get_net_range" {
    var object string
    var object_id string

    if object, err = get_p_string(q, "object", "^(?:int_v4net_range)$"); err != nil { panic(err) }
    if object_id, err = get_p_string(q, "object_id", g_num_reg); err != nil { panic(err) }

    var net_id string
    var dbnet M
    var dbnet_rights uint64

    var rquery string
    var var_ok bool

    var table string
    var group_key string
    var object_key string
    var right_mask_field string

    switch object {
    case "int_v4net_range":
      table = "gr4rs"
      group_key = "gr4r_fk_g_id"
      object_key = "gr4r_fk_v4r_id"
      right_mask_field = "gr4r_rmask"

      var rows []M

      query = "SELECT * FROM v4rs WHERE v4r_id=?"
      if rows, err = return_query_A(db, query, object_id); err != nil { panic(err) }
      if len(rows) != 1 { panic("Диапазон удален другим пользователем, обновите страницу") }
      out = rows[0]

      if net_id, var_ok = rows[0].UintString("v4r_fk_v4net_id"); !var_ok { panic(PE) }

      query = "SELECT"+
              " v4nets.*"+
              ", IFNULL((SELECT BIT_OR(gn4r_rmask)"+
                         " FROM gn4rs WHERE"+
                         " gn4r_fk_v4net_id=v4net_id"+
                         " AND gn4r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr4r_rmask)"+
                         " FROM gr4rs INNER JOIN v4rs ON gr4r_fk_v4r_id=v4r_id"+
                         " WHERE gr4r_fk_g_id IN("+user_groups_in+")"+
                         " AND v4r_fk_v4net_id IS NULL"+
                         " AND v4r_start <= v4net_addr AND v4r_stop >= v4net_last"+
                         "), 0) AS r_rights"+
              " FROM v4nets WHERE v4net_id=?"
      if rows, err = return_query_A(db, query, net_id); err != nil { panic(err) }
      if len(rows) != 1 {
        panic("Сеть не существует. Обновите страницу.")
      }
      dbnet = rows[0]

      if dbnet_rights, var_ok = dbnet.Uint64("rights"); !var_ok { panic(PE) }

      var dbnet_r_rights uint64
      if dbnet_r_rights, var_ok = dbnet.Uint64("r_rights"); !var_ok { panic(PE) }

      dbnet_rights |= dbnet_r_rights

      var dbnet_owner string
      dbnet_owner, _ = dbnet.AnyString("v4net_owner")

      if dbnet_owner == user_id {
        dbnet_rights = dbnet_rights | OWNER_RIGHTS
      }

      if user_is_admin {
        dbnet_rights = dbnet_rights | ADMIN_RIGHTS
      }

      for _, r := range [...]uint64{R_NAME, R_VIEW_NET_IPS} {
        if (dbnet_rights & r) == 0 { panic(NoAccess()) }
      }


    default:
      panic(PE)
    }

    rquery = "SELECT "+right_mask_field+" as rights"+
             ", "+group_key+" as g_id"+
             ", ts"+
             ", fk_u_id"+
             " FROM "+table+
             " WHERE "+object_key+"=?"

    var groups M

    query = "SELECT g_id, g_name, g_descr FROM gs"
    if groups, err = return_query_M(db, query, "g_id"); err != nil { panic(err) }

    var aux_userinfo M
    user_ids := make([]string, 0)

    var rights M
    if rights, err = return_query_M(db, rquery, "g_id", object_id); err != nil { panic(err) }

    for g_id, _ := range groups {
      if _, ex := rights[g_id]; ex {
        var s string
        if s, var_ok = rights[g_id].(M).UintString("fk_u_id"); !var_ok { panic(PE) }
        user_ids = append(user_ids, s)
        groups[g_id].(M)["ts"] = rights[g_id].(M)["ts"]
        groups[g_id].(M)["fk_u_id"] = rights[g_id].(M)["fk_u_id"]
        groups[g_id].(M)["rights"] = rights[g_id].(M)["rights"]
      } else {
        groups[g_id].(M)["ts"] = nil
        groups[g_id].(M)["fk_u_id"] = nil
        groups[g_id].(M)["rights"] = uint64(0)
      }
    }

    if len(user_ids) > 0 {
      if aux_userinfo, err = return_query_M(db, "SELECT * FROM us WHERE u_id IN("+strings.Join(user_ids, ",")+")", "u_id");
      err != nil { panic(err) }
    } else {
      aux_userinfo = make(M)
    }

    out["groups"] = groups
    out["aux_userinfo"] = aux_userinfo

  } else if action == "query" {
    out["_query"] = q
  } else {
    panic("unknown action: "+action)
  }

OUT:

  ok_out := make(M)
  ok_out["ok"] = out
  if opt_d {
    fmt.Println("out")
    dj, _ := json.MarshalIndent(ok_out, "", "  ")
    fmt.Println(string(dj))
  }
  json, jerr := json.MarshalIndent(ok_out, "", "  ")
  if jerr != nil {
    panic(jerr)
  }

  w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
  w.Header().Set("Cache-Control", "no-cache")
  w.Header().Set("Access-Control-Allow-Origin", "*")
  w.Header().Set("Access-Control-Allow-Methods", "*")
  w.Header().Set("Access-Control-Allow-Headers", "*")
  w.WriteHeader(http.StatusOK)

  w.Write(json)
  w.Write([]byte("\n"))
}
