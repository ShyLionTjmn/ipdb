package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/netutil"

	//wai "github.com/jimlawless/whereami"
	"database/sql"
	"runtime/debug"

	"github.com/davecgh/go-spew/spew"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/exp/slices"
)

const API_KEY_DICT = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890_-"
const API_KEY_LEN = 32

const (
  R_NAME uint64 = 1 // view net name and deny all other actions if not set
  R_VIEW_NET_INFO uint64 = 2 // view net info, must have R_NAME set
  R_VIEW_NET_IPS uint64 = 4 // view net ips, vlan_domain vlans
  R_EDIT_IP_VLAN uint64 = 8 // take/edit/delete vlan or ip data, must have R_NAME and R_VIEW_NET_IPS set
  R_IGNORE_R_DENY uint64 = 16 // ignore ranges denies
  R_MANAGE_NET uint64 = 32 // edit all network data, drop network
  R_DENYIP uint64 = 64 // deny ip/vlan take/edit
)

const (
  F_ALLOW_LEAFS uint64 = 1 << iota // allow to create leafs off non-root tag
  F_DENY_SELECT // deny selection as value
  F_DISPLAY // display in root-> ... -> final_tag chain in popup title
  F_IN_LABEL // display in tag label, before tag name, root-> ... -> final_tag chain
)

var g_rights map[uint64]M
var g_tag_flags map[uint64]M

const MAX_TREE_LEN int = 100

const ADMIN_NET_RIGHTS uint64 = R_NAME | R_VIEW_NET_INFO | R_VIEW_NET_IPS |
                          R_EDIT_IP_VLAN | R_MANAGE_NET

const OWNER_RIGHTS uint64 = R_NAME | R_VIEW_NET_INFO | R_VIEW_NET_IPS |
                          R_EDIT_IP_VLAN | R_MANAGE_NET

const ADMIN_VLAN_RIGHTS uint64 = R_VIEW_NET_IPS | R_EDIT_IP_VLAN

const ADMIN_TAG_RIGHTS uint64 = R_VIEW_NET_IPS | R_EDIT_IP_VLAN | R_MANAGE_NET

const ADMIN_OOB_RIGHTS uint64 = R_VIEW_NET_IPS | R_EDIT_IP_VLAN

const MAX_SUBNETS_NAMES_LEN = 512

const PE = "Backend Program error"

var g_rights_obj M

var g_name_reg *regexp.Regexp
var g_num_reg *regexp.Regexp
var g_num_list_reg *regexp.Regexp
var g_api_name_reg *regexp.Regexp

var g_mac_free_reg *regexp.Regexp

var g_data_key_reg *regexp.Regexp
var g_remote_ip_reg *regexp.Regexp
var g_ip_reg *regexp.Regexp
var g_ip_range_reg *regexp.Regexp
var g_ip_net_reg *regexp.Regexp
var g_ips_split_reg *regexp.Regexp

type RangeV4 struct {
  Start uint32
  End   uint32
}

func init() {
  _ = spew.Sprint()
  g_name_reg = regexp.MustCompile(`^\S.*\S$`)
  g_num_reg = regexp.MustCompile(`^\d+$`)
  g_num_list_reg = regexp.MustCompile(`^(?:\d+(,\d+)*)?$`)
  g_api_name_reg = regexp.MustCompile(`^[0-9a-zA-Z_\-]+$`)
  g_mac_free_reg = regexp.MustCompile(`^([\da-fA-F]{2})`+strings.Repeat(`[\-\.:_]([\da-fA-F]{2})`, 5)+`$`)

  g_data_key_reg = regexp.MustCompile(`^data\.([a-zA-Z_\-0-9]+)$`)
  g_remote_ip_reg = regexp.MustCompile(`^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):\d+$`)

  g_ip_reg = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)
  g_ip_range_reg = regexp.MustCompile(`^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*-\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$`)
  g_ip_net_reg = regexp.MustCompile(`^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/([0-9]{1,2})$`)
  g_ips_split_reg = regexp.MustCompile(`[\s,;\n\r]+`)

  g_rights_obj = make(M)
  g_rights_obj["nets"] = "Права на все сети и IP адреса"
  g_rights_obj["vlans"] = "Права на все VLAN"
  g_rights_obj["tags"] = "Права на все Теги"
  g_rights_obj["oobs"] = "Права на все Внешние сети"

  g_rights = make(map[uint64]M)

  g_rights[R_NAME] = make(M)
  g_rights[R_NAME]["label"] = "ПрИмнСет"
  g_rights[R_NAME]["descr"] = "Просмотр имени сети в списке сетей"
  g_rights[R_NAME]["required_by"] = [...]uint64{R_VIEW_NET_INFO, R_VIEW_NET_IPS, R_EDIT_IP_VLAN, R_MANAGE_NET}
  g_rights[R_NAME]["used_in"] = [...]string{"ext_v4net_range", "v4net_acl", "nets"}
  g_rights[R_NAME]["conflict_with"] = [...]uint64{}

  g_rights[R_VIEW_NET_INFO] = make(M)
  g_rights[R_VIEW_NET_INFO]["label"] = "ПрИнфСет"
  g_rights[R_VIEW_NET_INFO]["descr"] = "Просмотр информации о сети, кроме списка IP адресов"
  g_rights[R_VIEW_NET_INFO]["required_by"] = [...]uint64{R_MANAGE_NET}
  g_rights[R_VIEW_NET_INFO]["used_in"] = [...]string{"ext_v4net_range", "v4net_acl", "nets"}
  g_rights[R_VIEW_NET_INFO]["conflict_with"] = [...]uint64{}

  g_rights[R_VIEW_NET_IPS] = make(M)
  g_rights[R_VIEW_NET_IPS]["label"] = "ПрАдрVLT"
  g_rights[R_VIEW_NET_IPS]["descr"] = "Просмотр IP адресов, VLAN-ов, Тегов"
  g_rights[R_VIEW_NET_IPS]["required_by"] = [...]uint64{R_EDIT_IP_VLAN, R_MANAGE_NET}
  g_rights[R_VIEW_NET_IPS]["used_in"] = [...]string{"ext_v4net_range", "v4net_acl", "vlan_range",
                                                    "tag", "nets", "vlans", "tags", "oobs"}
  g_rights[R_VIEW_NET_IPS]["conflict_with"] = [...]uint64{}

  g_rights[R_EDIT_IP_VLAN] = make(M)
  g_rights[R_EDIT_IP_VLAN]["label"] = "ИзмАдрVT"
  g_rights[R_EDIT_IP_VLAN]["descr"] = "Занятие, редактирование, освобождение IP адресов, VLAN-ов, вложенных тегов"
  g_rights[R_EDIT_IP_VLAN]["required_by"] = [...]uint64{R_MANAGE_NET}
  g_rights[R_EDIT_IP_VLAN]["used_in"] = [...]string{"ext_v4net_range", "v4net_acl", "vlan_range",
                                                    "int_v4net_range", "tag", "nets", "vlans", "tags", "oobs"}
  g_rights[R_EDIT_IP_VLAN]["conflict_with"] = [...]uint64{R_DENYIP}

  g_rights[R_MANAGE_NET] = make(M)
  g_rights[R_MANAGE_NET]["label"] = "ИзмнСетT"
  g_rights[R_MANAGE_NET]["descr"] = "Полные права на сеть, тег"
  g_rights[R_MANAGE_NET]["required_by"] = [...]uint64{}
  g_rights[R_MANAGE_NET]["used_in"] = [...]string{"ext_v4net_range", "v4net_acl", "tag", "nets", "tags"}
  g_rights[R_MANAGE_NET]["conflict_with"] = [...]uint64{}

  g_rights[R_IGNORE_R_DENY] = make(M)
  g_rights[R_IGNORE_R_DENY]["label"] = "ИгнорЗпр"
  g_rights[R_IGNORE_R_DENY]["descr"] = "Игнорировать запрет в диапазонах"
  g_rights[R_IGNORE_R_DENY]["required_by"] = [...]uint64{}
  g_rights[R_IGNORE_R_DENY]["used_in"] = [...]string{"int_v4net_range", "vlan_range"}
  g_rights[R_IGNORE_R_DENY]["conflict_with"] = [...]uint64{R_DENYIP}

  g_rights[R_DENYIP] = make(M)
  g_rights[R_DENYIP]["label"] = "ЗпртРедт"
  g_rights[R_DENYIP]["descr"] = "Запрет занимать, редактировать, удалять IP/VLAN в диапазоне"
  g_rights[R_DENYIP]["required_by"] = [...]uint64{}
  g_rights[R_DENYIP]["used_in"] = [...]string{"int_v4net_range", "vlan_range"}
  g_rights[R_DENYIP]["conflict_with"] = [...]uint64{R_EDIT_IP_VLAN,R_IGNORE_R_DENY}

  g_tag_flags = make(map[uint64]M)

  g_tag_flags[F_ALLOW_LEAFS] = make(M)
  g_tag_flags[F_ALLOW_LEAFS]["label"] = "РзрДоч"
  g_tag_flags[F_ALLOW_LEAFS]["descr"] = "Разрешать создавать дочерние теги"
  g_tag_flags[F_ALLOW_LEAFS]["required_by"] = [...]uint64{}
  g_tag_flags[F_ALLOW_LEAFS]["conflict_with"] = [...]uint64{}

  g_tag_flags[F_DENY_SELECT] = make(M)
  g_tag_flags[F_DENY_SELECT]["label"] = "ЗпрВыб"
  g_tag_flags[F_DENY_SELECT]["descr"] = "Запретить выбирать тег для значения, например для родительского тега"
  g_tag_flags[F_DENY_SELECT]["required_by"] = [...]uint64{}
  g_tag_flags[F_DENY_SELECT]["conflict_with"] = [...]uint64{}

  g_tag_flags[F_DISPLAY] = make(M)
  g_tag_flags[F_DISPLAY]["label"] = "ВклЦеп"
  g_tag_flags[F_DISPLAY]["descr"] = "Отображать в цепочке Корневой-> ... -> Конечный тег во всплывающей подсказке"
  g_tag_flags[F_DISPLAY]["required_by"] = [...]uint64{}
  g_tag_flags[F_DISPLAY]["conflict_with"] = [...]uint64{}

  g_tag_flags[F_IN_LABEL] = make(M)
  g_tag_flags[F_IN_LABEL]["label"] = "ВклЯрл"
  g_tag_flags[F_IN_LABEL]["descr"] = "Отображать прямо в ярлыке тега"
  g_tag_flags[F_IN_LABEL]["required_by"] = [...]uint64{}
  g_tag_flags[F_IN_LABEL]["conflict_with"] = [...]uint64{}
}

func genApiKey() string {
  ret := ""
  c := 0
  for c < API_KEY_LEN {
    c++

    idx := rand.Intn(len(API_KEY_DICT))
    ret += string(API_KEY_DICT[idx])
  }

  return ret
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

func var_dump(vars ... interface{}) string {
  format := strings.Repeat("%v\n", len(vars))
  return fmt.Sprintf(format, vars...)
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

func get_p_uint64(q M, name string, options ... interface{}) (uint64,error) { // options: (error on empty(true by default)), (default value) 
  val, exists := q[name]
  if !exists {
    if len(options) == 0 || options[0].(bool) {
      return 0, errors.New("Missing parameter: "+name)
    }
    if len(options) > 1 {
      return options[1].(uint64), nil
    } else {
      return 0, nil
    }
  }

  _val := fmt.Sprint(val)

  if !g_num_reg.MatchString(_val) { return 0, errors.New("Bad number for parameter: "+name+": "+_val) }
  ret, err := strconv.ParseUint(_val, 10, 64)
  if err != nil { return 0, err }
  return uint64(ret), nil
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
  http.HandleFunc("/api", handleApi)

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

  w.Write([]byte(fmt.Sprintf("const F_ALLOW_LEAFS = %d;\n", F_ALLOW_LEAFS)))
  w.Write([]byte(fmt.Sprintf("const F_DENY_SELECT = %d;\n", F_DENY_SELECT)))
  w.Write([]byte(fmt.Sprintf("const F_DISPLAY = %d;\n", F_DISPLAY)))
  w.Write([]byte(fmt.Sprintf("const F_IN_LABEL = %d;\n", F_IN_LABEL)))

  jstr, jerr := json.MarshalIndent(g_rights, "", "  ")
  if jerr != nil {
    panic(jerr)
  }

  w.Write([]byte("const g_rights = "))
  w.Write(jstr)
  w.Write([]byte(";\n"))

  jstr, jerr = json.MarshalIndent(g_tag_flags, "", "  ")
  if jerr != nil {
    panic(jerr)
  }

  w.Write([]byte("const g_tag_flags = "))
  w.Write(jstr)
  w.Write([]byte(";\n"))

  jstr, jerr = json.MarshalIndent(g_rights_obj, "", "  ")
  if jerr != nil {
    panic(jerr)
  }

  w.Write([]byte("const g_rights_obj = "))
  w.Write(jstr)
  w.Write([]byte(";\n"))

  w.Write([]byte(fmt.Sprintf("const g_autosave_timeout = %d;\n", g_autosave_timeout)))

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
    out["error"] = "Server message:\n"+v;
    if v == PE {
      out["error"] = out["error"].(string) + "\n\n" + string(debug.Stack())
    }
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

  if _, ex := groups[opt_g]; !ex { panic("No "+opt_g+" group in DB") }

  var any_g_id string
  for _, g := range groups {
    var var_ok bool
    if u64, var_ok = g.(M).Uint64("any"); !var_ok { panic(PE) }
    if u64 > 0 {
      if any_g_id != "" { panic(PE) }
      if any_g_id, var_ok = g.(M).UintString("g_id"); !var_ok { panic(PE) }
    }
  }

  if any_g_id == "" { panic("No Any group found in DB") }

  user_groups := make([]string, 1)
  user_groups[0] = any_g_id

  user_groups_in := "FALSE"

  for _, v := range user_q_groups {
    if m, ex := groups[v]; ex {
      var var_ok bool
      var group_id string
      if group_id, var_ok = m.(M).AnyString("g_id"); !var_ok { panic(PE) }
      if group_id != any_g_id {
        user_groups = append(user_groups, group_id)
      }
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

  if !user_is_admin && len(user_groups) == 1 {
    panic(NoAccess())
  }

  var prev_data interface{}
  var new_data interface{}

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

    user_row["u_name"] = user_name
    user_row["u_login"] = user_login
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

  if opt_d {
    dj, _ := json.MarshalIndent(q, "", "  ")
    fmt.Println(string(dj))
  }

  var var_ok bool

  var g_nets_rights uint64
  var g_vlans_rights uint64
  var g_tags_rights uint64
  var g_oobs_rights uint64

  query = "SELECT IFNULL(BIT_OR(glr_rmask), CAST(0 AS UNSIGNED)) FROM glrs WHERE glr_object=?"+
          " AND glr_fk_g_id IN("+user_groups_in+")"

  if g_nets_rights, err = must_return_one_uint(db, query, "nets"); err != nil { panic(err) }
  if g_vlans_rights, err = must_return_one_uint(db, query, "vlans"); err != nil { panic(err) }
  if g_tags_rights, err = must_return_one_uint(db, query, "tags"); err != nil { panic(err) }
  if g_oobs_rights, err = must_return_one_uint(db, query, "oobs"); err != nil { panic(err) }

  if user_is_admin {
    g_nets_rights |= ADMIN_NET_RIGHTS
    g_vlans_rights |= ADMIN_VLAN_RIGHTS
    g_tags_rights |= ADMIN_TAG_RIGHTS
    g_oobs_rights |= ADMIN_OOB_RIGHTS
  }

  var tags_cache M

  audit_log := func(db interface{}, al_subject string, al_subject_id interface{},
                    al_query string, al_prev_data, al_new_data interface{}) (error) {
    table_name := time.Now().Format("audit_200601")
    var e error

    if _, e = db_exec(db, "CREATE TABLE IF NOT EXISTS "+table_name+" LIKE log_template");
    e != nil { return e }

    var prev_json []byte
    if al_prev_data != nil {
      if prev_json, e = json.MarshalIndent(al_prev_data, "", "  "); e != nil { return e }
    } else {
      prev_json = make([]byte, 0)
    }

    var new_json []byte
    if al_new_data != nil {
      if new_json, e = json.MarshalIndent(al_new_data, "", "  "); e != nil { return e }
    } else {
      new_json = make([]byte, 0)
    }

    if _, e = db_exec(db, "INSERT INTO "+table_name+"(ts,fk_u_id,al_subject,al_subject_id"+
                      ",al_query,al_prev_data,al_new_data) VALUES(?,?,?,?,?,?,?)",
                      ts, user_id, al_subject, al_subject_id, al_query,
                      string(prev_json),string(new_json));
    e != nil { return e }

    return nil
  }

  var get_tag = func(db interface{}, _tag_id interface{}) (M, error) {
    var tag_id string
    switch v := _tag_id.(type) {
    case string:
      tag_id = v
    case uint8:
      tag_id = strconv.FormatUint(uint64(v), 10)
    case uint16:
      tag_id = strconv.FormatUint(uint64(v), 10)
    case uint32:
      tag_id = strconv.FormatUint(uint64(v), 10)
    case uint64:
      tag_id = strconv.FormatUint(uint64(v), 10)
    case int8:
      tag_id = strconv.FormatInt(int64(v), 10)
    case int16:
      tag_id = strconv.FormatInt(int64(v), 10)
    case int32:
      tag_id = strconv.FormatInt(int64(v), 10)
    case int64:
      tag_id = strconv.FormatInt(int64(v), 10)
    default:
      return nil, errors.New("Unsupported tag_id type in get_tag")
    }

    if tags_cache == nil {
      tags_cache = make(M)
    }

    if ret, ex := tags_cache[tag_id]; ex { return ret.(M), nil }

    query = "SELECT tags.*"+
            ", CAST(("+
            " (SELECT COUNT(*) FROM v4nets WHERE FIND_IN_SET(tag_id,v4net_tags))+"+
            " (SELECT COUNT(*) FROM v6nets WHERE FIND_IN_SET(tag_id,v6net_tags))+"+
            " (SELECT COUNT(*) FROM v4oobs WHERE FIND_IN_SET(tag_id,v4oob_tags))+"+
            " (SELECT COUNT(*) FROM v6oobs WHERE FIND_IN_SET(tag_id,v6oob_tags))+"+
            " (SELECT COUNT(*) FROM i4vs INNER JOIN ics ON iv_fk_ic_id=ic_id WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " (SELECT COUNT(*) FROM i6vs INNER JOIN ics ON iv_fk_ic_id=ic_id WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " 0) AS UNSIGNED) AS used"+
            ", IFNULL((SELECT BIT_OR(tgr_rmask) FROM tgrs WHERE tgr_fk_g_id IN("+user_groups_in+") AND tgr_fk_tag_id=tag_id"+
                      " GROUP BY tgr_fk_tag_id), CAST(0 AS UNSIGNED)) as rights"+
            " FROM tags WHERE tag_id=?"

    if ret, err := must_return_one_M(db, query, tag_id); err != nil {
      return nil, err
    } else {
      tags_cache[tag_id] = ret
      return ret, nil
    }
  }

  var tag_usage func(interface{}, interface{}, int) (uint64, error)
  tag_usage = func(db interface{}, tag_id interface{}, counter int) (uint64, error) {
    var tag M

    if tag, err = get_tag(db, tag_id); err != nil { return 0, err }

    var used uint64
    if used, var_ok = tag.Uint64("used"); !var_ok { return 0, fmt.Errorf("No used in tag %v", tag_id) }

    query = "SELECT tag_id FROM tags WHERE tag_fk_tag_id=?"
    if rows, err := return_query_A(db, query, tag_id); err != nil {
      return 0, err
    } else {
      for _, row := range rows {
        if child_id, var_ok := row.UintString("tag_id"); !var_ok {
          return 0, errors.New("No child tag_id")
        } else {
          if child_used, err := tag_usage(db, child_id, counter+1); err != nil {
            return 0, err
          } else {
            used += child_used
          }
        }
      }
    }

    return used, nil
  }

  var get_root_tag func(interface{}, interface{}, int) (M, error)
  get_root_tag = func(db interface{}, tag_id interface{}, counter int) (M, error) {
    if counter > MAX_TREE_LEN { return nil, errors.New("Tags loop detected") }
    var err error
    var tag M

    if tag, err = get_tag(db, tag_id); err != nil { return nil, err }
    if tag["tag_fk_tag_id"] == nil { return tag, nil }

    var var_ok bool
    var parent_id string
    if parent_id, var_ok = tag.UintString("tag_fk_tag_id"); !var_ok { return nil, fmt.Errorf("No tag_fk_tag_id for tag_id: %v", tag_id) }

    return get_root_tag(db, parent_id, counter + 1)
  }

  var get_tag_rights func(interface{}, interface{}, int) (uint64, error)
  get_tag_rights = func(db interface{}, tag_id interface{}, counter int) (uint64, error) {
    if counter > MAX_TREE_LEN { return 0, errors.New("Tags loop detected") }

    if tag, err := get_tag(db, tag_id); err != nil {
      return 0, err
    } else {
      if tag_rights, var_ok := tag.Uint64("rights"); !var_ok {
        return 0, fmt.Errorf("No rights for tag_id: %v", tag_id)
      } else {
        if tag["tag_fk_tag_id"] != nil {
          if parent_id, var_ok := tag.UintString("tag_fk_tag_id"); !var_ok {
            return 0, fmt.Errorf("No tag_fk_tag_id for tag_id: %v", tag_id)
          } else {
            if parent_rights, err := get_tag_rights(db, parent_id, counter+1); err != nil {
              return 0, err
            } else {
              tag_rights |= parent_rights
            }
          }
        }
        tag_rights |= g_tags_rights
        return tag_rights, nil
      }
    }
  }

  var update_tag = func(db interface{}, tag_id interface{}, update_fields M) (error) {
    query := "UPDATE tags SET "
    sets := make([]string, 2)
    values := make([]interface{}, 2)

    var err error

    if prev_data, err = must_return_one_M(db, "SELECT * FROM tags WHERE tag_id=?", tag_id); err != nil { return err }

    sets[0] = "ts=?"
    sets[1] = "fk_u_id=?"

    values[0] = ts
    values[1] = user_id

    if update_fields != nil {
      for k, v := range update_fields {
        sets = append(sets, k+"=?")
        values = append(values, v)
      }
    }

    query += strings.Join(sets, ",")+" WHERE tag_id=?"
    values = append(values, tag_id)

    switch db.(type) {
    case *sql.DB:
      _, err = db.(*sql.DB).Exec(query, values...)
    case *sql.Tx:
      _, err = db.(*sql.Tx).Exec(query, values...)
    default:
      err = errors.New("Bad db handle type:"+reflect.TypeOf(db).String())
    }

    if err != nil { return err }

    if new_data, err = must_return_one_M(db, "SELECT * FROM tags WHERE tag_id=?", tag_id); err != nil { return err }
    if err = audit_log(db, "tag", tag_id, query, prev_data, new_data); err != nil { return err }

    return err
  }

  get_net_rights := func(db interface{}, net_id interface{}, v string, netrow M) (uint64, M, error) {
    var net M
    if netrow != nil {
      net = netrow
    } else {
      query = "SELECT"+
              " v"+v+"nets.*"+
              ", IFNULL((SELECT BIT_OR(gn"+v+"r_rmask)"+
                         " FROM gn"+v+"rs WHERE"+
                         " gn"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND gn"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id IS NULL"+
                         " AND v"+v+"r_start <= v"+v+"net_addr AND v"+v+"r_stop >= v"+v+"net_last"+
                         "), 0) AS r_rights"+
              " FROM v"+v+"nets WHERE v"+v+"net_id=?"
      if net, err = must_return_one_M(db, query, net_id); err != nil { return 0, nil, err }
    }

    var ret uint64
    if ret, var_ok = net.Uint64("rights"); !var_ok { return 0, nil, errors.New("No rights in get_net_rights call") }
    if u64, var_ok = net.Uint64("r_rights"); !var_ok { return 0, nil, errors.New("No rights in get_net_rights call") }

    owner, _ := net.AnyString("v"+v+"net_owner")

    ret |= u64

    if owner == user_id {
      ret |= OWNER_RIGHTS
    }

    ret |= g_nets_rights

    return ret, net, nil
  }

  get_addr_rights := func(db interface{}, ip_addr interface{}, v string, netrow M) (uint64, M, error) {
    var net M
    if netrow != nil {
      net = netrow
    } else {
      query = "SELECT"+
              " v"+v+"nets.*"+
              ", IFNULL((SELECT BIT_OR(gn"+v+"r_rmask)"+
                         " FROM gn"+v+"rs WHERE"+
                         " gn"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND gn"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id IS NULL"+
                         " AND v"+v+"r_start <= v"+v+"net_addr AND v"+v+"r_stop >= v"+v+"net_last"+
                         "), 0) AS r_rights"+
              " FROM v"+v+"nets WHERE v"+v+"net_addr <=? AND v"+v+"net_last >=?"
      if net, err = must_return_one_M(db, query, ip_addr, ip_addr); err != nil { return 0, nil, err }
    }

    var ret uint64
    if ret, var_ok = net.Uint64("rights"); !var_ok { return 0, nil, errors.New("No rights in get_net_rights call") }
    if u64, var_ok = net.Uint64("r_rights"); !var_ok { return 0, nil, errors.New("No r_rights in get_net_rights call") }
    ret |= u64

    owner, _ := net.AnyString("v"+v+"net_owner")

    if owner == user_id {
      ret |= OWNER_RIGHTS
    }

    ret |= g_nets_rights

    query = "SELECT IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND v"+v+"r_start <= ? AND v"+v+"r_stop >= ?"+
                         "), CAST(0 AS UNSIGNED)) as ip_rights "+
            " FROM v"+v+"nets WHERE v"+v+"net_id=?"

    if u64, err = must_return_one_uint(db, query, ip_addr, ip_addr, net["v"+v+"net_id"]); err != nil { return 0, nil, err }

    ret |= u64

    return ret, net, nil
  }

  get_ip_rights := func(db interface{}, ip_id interface{}, v string, netrow M) (uint64, M, error) {
    var net M
    if netrow != nil {
      net = netrow
    } else {
      query = "SELECT"+
              " v"+v+"nets.*"+
              ", IFNULL((SELECT BIT_OR(gn"+v+"r_rmask)"+
                         " FROM gn"+v+"rs WHERE"+
                         " gn"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND gn"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id IS NULL"+
                         " AND v"+v+"r_start <= v"+v+"net_addr AND v"+v+"r_stop >= v"+v+"net_last"+
                         "), 0) AS r_rights"+
              " FROM v"+v+"nets INNER JOIN v"+v+"ips ON v"+v+"ip_fk_v"+v+"net_id=v"+v+"net_id WHERE v"+v+"ip_id=?"
      if net, err = must_return_one_M(db, query, ip_id); err != nil { return 0, nil, err }
    }

    var ret uint64
    if ret, var_ok = net.Uint64("rights"); !var_ok { return 0, nil, errors.New("No rights in get_net_rights call") }
    if u64, var_ok = net.Uint64("r_rights"); !var_ok { return 0, nil, errors.New("No r_rights in get_net_rights call") }
    ret |= u64

    owner, _ := net.AnyString("v"+v+"net_owner")

    if owner == user_id {
      ret |= OWNER_RIGHTS
    }

    ret |= g_nets_rights

    var ip_rows []M
    query = "SELECT v"+v+"net_id"+
            ",IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND v"+v+"r_start <= v"+v+"ip_addr AND v"+v+"r_stop >= v"+v+"ip_addr"+
                         "), 0) as ip_rights "+
            " FROM v"+v+"nets INNER JOIN v"+v+"ips ON v"+v+"ip_fk_v"+v+"net_id=v"+v+"net_id WHERE v"+v+"ip_id=?"

    if ip_rows, err = return_query_A(db, query, ip_id); err != nil { return 0, nil, err }

    if len(ip_rows) != 1 { return 0, nil, errors.New("Адреса не существует. Вероятно он был удален другим пользователем.\nОбновите страницу") }

    if ip_rows[0]["v"+v+"net_id"] != net["v"+v+"net_id"] {
      return 0, nil, errors.New("Адрес из другой сети")
    }

    if u64, var_ok = ip_rows[0].Uint64("ip_rights"); !var_ok { return 0, nil, errors.New("No ip_rights") }

    ret |= u64

    return ret, net, nil
  }

  query = ""

  if action == "userinfo" {
    out["id"] = user_id
    out["sub"] = user_sub
    out["name"] = user_name
    out["login"] = user_login
    out["groups"] = user_groups
    out["is_admin"] = user_is_admin

    out["g_nets_rights"] = g_nets_rights
    out["g_vlans_rights"] = g_vlans_rights
    out["g_tags_rights"] = g_tags_rights
    out["g_oobs_rights"] = g_oobs_rights

    has_vlans_access := false

    query = "SELECT BIT_OR(gvrr_rmask) as rights FROM"+
            " gvrrs WHERE gvrr_fk_g_id IN("+user_groups_in+")"

    var rows []M

    vlans_rights := g_vlans_rights

    if rows, err = return_query_A(db, query); err != nil { panic(err) }

    for _, row := range rows {
      if u64, var_ok = row.Uint64("rights"); !var_ok { panic(PE) }

      vlans_rights |= u64
    }

    if (vlans_rights & R_VIEW_NET_IPS) > 0 {
      has_vlans_access = true
    }

    out["has_vlans_access"] = has_vlans_access

    has_tags_access := false

    query = "SELECT tags.*"+
            ", IFNULL((SELECT BIT_OR(tgr_rmask) FROM tgrs WHERE tgr_fk_g_id IN("+user_groups_in+") AND tgr_fk_tag_id=tag_id"+
                      " GROUP BY tgr_fk_tag_id), CAST(0 AS UNSIGNED)) as rights"+
            " FROM tags WHERE tag_fk_tag_id IS NULL"

    tags_rights := g_tags_rights

    if rows, err = return_query_A(db, query); err != nil { panic(err) }

    for _, row := range rows {
      if u64, var_ok = row.Uint64("rights"); !var_ok { panic(PE) }

      tags_rights |= u64
    }

    if (tags_rights & R_VIEW_NET_IPS) > 0 {
      has_tags_access = true
    }

    out["has_tags_access"] = has_tags_access

    has_oobs_access := false

    oobs_rights := g_oobs_rights

    if (oobs_rights & R_VIEW_NET_IPS) > 0 {
      has_oobs_access = true
    }

    out["has_oobs_access"] = has_oobs_access

  } else if action == "get_front" {

    var v4_favs interface{}
    v4_accessible := make(M)

    query = "SELECT f.v4net_addr, f.v4net_mask, IFNULL(n.v4net_name, '') as name, GROUP_CONCAT(v4fav_fk_u_id) as u_ids FROM"+
      " v4favs f LEFT JOIN v4nets n ON f.v4net_addr = n.v4net_addr AND f.v4net_mask = n.v4net_mask"+
      " WHERE f.v4fav_fk_u_id=? OR v4fav_fk_u_id=0 GROUP BY f.v4net_addr,f.v4net_mask,name"

    if v4_favs, err = return_query(db, query, "", user_id); err != nil { panic(err) }

    out["v4favs"] = v4_favs
    out["v4accessible"] = v4_accessible

    query = "SELECT tags.*"+
            ", CAST(("+
            " (SELECT COUNT(*) FROM v4nets WHERE FIND_IN_SET(tag_id,v4net_tags))+"+
            " (SELECT COUNT(*) FROM v6nets WHERE FIND_IN_SET(tag_id,v6net_tags))+"+
            " (SELECT COUNT(*) FROM v4oobs WHERE FIND_IN_SET(tag_id,v4oob_tags))+"+
            " (SELECT COUNT(*) FROM v6oobs WHERE FIND_IN_SET(tag_id,v6oob_tags))+"+
            " (SELECT COUNT(*) FROM i4vs INNER JOIN ics ON iv_fk_ic_id=ic_id"+
              " WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " (SELECT COUNT(*) FROM i6vs INNER JOIN ics ON iv_fk_ic_id=ic_id"+
              " WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " 0) AS UNSIGNED) AS used"+
            ", IFNULL((SELECT BIT_OR(tgr_rmask) FROM tgrs WHERE tgr_fk_g_id IN("+user_groups_in+") AND tgr_fk_tag_id=tag_id"+
                      " GROUP BY tgr_fk_tag_id), CAST(0 AS UNSIGNED)) as rights"+
            " FROM tags"
    if tags_cache, err = return_query_M(db, query, "tag_id"); err != nil { panic(err) }

    for tag_id, _ := range tags_cache {
      if u64, err = get_tag_rights(db, tag_id, 0); err != nil { panic(err) }
      tags_cache[tag_id].(M)["rights"] = u64
      if (tags_cache[tag_id].(M)["rights"].(uint64) & R_VIEW_NET_IPS) == 0 {
        tags_cache[tag_id].(M)["tag_name"] = "HIDDEN"
        tags_cache[tag_id].(M)["tag_descr"] = "HIDDEN"
        tags_cache[tag_id].(M)["tag_options"] = "HIDDEN"
        tags_cache[tag_id].(M)["tag_api_name"] = nil
      }
    }

    out["tags"] = tags_cache

  } else if action == "search" {
    var search_string string
    var search_tags string
    var search_vlans string

    if search_string, err = get_p_string(q, "search_string", nil); err != nil { panic(err) }
    if search_tags, err = get_p_string(q, "search_tags", g_num_list_reg); err != nil { panic(err) }
    if search_vlans, err = get_p_string(q, "search_vlans", g_num_list_reg); err != nil { panic(err) }

    search_string = strings.ToLower(strings.TrimSpace(search_string))
    search_tags = strings.TrimSpace(search_tags)
    search_vlans = strings.TrimSpace(search_vlans)

    out["rows"] = make([]M, 0)

    if search_string == "" && search_tags == "" && search_vlans == "" {
      goto OUT
    }

    var tags_list []string

    if search_tags != "" {

      query = "SELECT tags.*"+
              ", IFNULL((SELECT BIT_OR(tgr_rmask) FROM tgrs WHERE tgr_fk_g_id IN("+user_groups_in+") AND tgr_fk_tag_id=tag_id"+
                        " GROUP BY tgr_fk_tag_id), CAST(0 AS UNSIGNED)) as rights"+
              " FROM tags"
      if tags_cache, err = return_query_M(db, query, "tag_id"); err != nil { panic(err) }

      for tag_id, _ := range tags_cache {
        if u64, err = get_tag_rights(db, tag_id, 0); err != nil { panic(err) }
        tags_cache[tag_id].(M)["rights"] = u64
        if (tags_cache[tag_id].(M)["rights"].(uint64) & R_VIEW_NET_IPS) == 0 {
          tags_cache[tag_id].(M)["tag_name"] = "HIDDEN"
          tags_cache[tag_id].(M)["tag_descr"] = "HIDDEN"
          tags_cache[tag_id].(M)["tag_options"] = "HIDDEN"
          tags_cache[tag_id].(M)["tag_api_name"] = nil
        }

        if parent_id, _ := tags_cache[tag_id].(M).UintString("tag_fk_tag_id"); parent_id != "" {
          if tags_cache[parent_id].(M)["_children"] == nil {
            tags_cache[parent_id].(M)["_children"] = make([]string, 0)
          }
          tags_cache[parent_id].(M)["_children"] = append(tags_cache[parent_id].(M)["_children"].([]string), tag_id)
        }
      }
      tags_list = make([]string, 0)
      var append_tag_children func(string, int) (error)
      append_tag_children = func(tag_id string, counter int) (error) {
        if counter > MAX_TREE_LEN { return errors.New("Tag tree loop detected") }
        if tags_cache[tag_id].(M)["_children"] != nil {
          for _, child_id := range tags_cache[tag_id].(M)["_children"].([]string) {
            tags_list = append(tags_list, child_id)
            if e := append_tag_children(child_id, counter + 1); e != nil { return e }
          }
        }

        return nil
      }
      for _, tag_id := range strings.Split(search_tags, ",") {
        tags_list = append(tags_list, tag_id)
        if err = append_tag_children(tag_id, 0); err != nil { panic(err) }
      }
    }

    for _, v := range [...]string{"4", "6"} {

      var rows []M

      // search networks
      query = "SELECT v"+v+"nets.*"+
              ", IFNULL((SELECT BIT_OR(gn"+v+"r_rmask)"+
                         " FROM gn"+v+"rs WHERE"+
                         " gn"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND gn"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id IS NULL"+
                         " AND v"+v+"r_start <= v"+v+"net_addr AND v"+v+"r_stop >= v"+v+"net_last"+
                         "), 0) AS r_rights"+
              " FROM v"+v+"nets"+
              " WHERE TRUE"
      args := make([]interface{}, 0)
      if search_string != "" {
        query += " AND (v"+v+"net_name LIKE CONCAT('%',?,'%') OR v"+v+"net_descr LIKE CONCAT('%',?,'%'))"
        args = append(args, search_string, search_string)
      }

      if search_tags != "" && tags_list != nil && len(tags_list) > 0 {
        query += " AND ( FALSE"
        for _, tag_id := range tags_list {
          query += " OR (FIND_IN_SET('"+tag_id+"',v"+v+"net_tags) > 0)"
        }
        query += ")"
      }

      if search_vlans != "" {
        query += " AND v"+v+"net_fk_vlan_id IN("+search_vlans+")"
      }

      query += " ORDER BY v"+v+"net_addr"

      if rows, err = return_query_A(db, query, args...); err != nil { panic(err.Error() + "\n\n"+query) }

      for _, row := range rows {
        if u64, _, err = get_net_rights(nil, nil, v, row); err != nil { panic(err) }

        include := false

        if (u64 & R_VIEW_NET_INFO) == 0 && (u64 & R_NAME) > 0 && search_string !="" &&
        strings.Index(row["v"+v+"net_name"].(string), search_string) >= 0 {
          //only name matched and there is no details access
          row["v"+v+"net_descr"] = "HIDDEN"
          row["v"+v+"net_fk_vlan_id"] = nil
          row["v"+v+"net_owner"] = nil
          row["v"+v+"net_tags"] = ""

          include = true
        } else if (u64 & R_VIEW_NET_INFO) > 0 {
          include = true
        }

        if include {
          if row["v"+v+"net_fk_vlan_id"] != nil {
            var vlan_row M
            vlan_rights := g_vlans_rights

            query = "SELECT vd_name, vd_descr, vlan_name, vlan_descr, vlan_number"+
                    ", IFNULL((SELECT BIT_OR(gvrr_rmask) FROM"+
                               " gvrrs INNER JOIN vrs ON vr_id=gvrr_fk_vr_id WHERE"+
                               " gvrr_fk_g_id IN("+user_groups_in+")"+
                               " AND vr_fk_vd_id=vd_id"+
                               " AND vr_start <= vlan_number AND vr_stop >= vlan_number"+
                               "), 0) as rights"+
                    " FROM vlans INNER JOIN vds ON vd_id=vlan_fk_vd_id"+
                    " WHERE vlan_id=?"
            if vlan_row, err = must_return_one_M(db, query, row["v"+v+"net_fk_vlan_id"]); err != nil { panic(err) }
            if u64, var_ok = vlan_row.Uint64("rights"); !var_ok { panic(PE) }

            vlan_rights |= u64

            if (vlan_rights & R_VIEW_NET_IPS) == 0 {
              vlan_row["vd_name"] = "HIDDEN"
              vlan_row["vd_descr"] = "HIDDEN"
              vlan_row["vlan_name"] = "HIDDEN"
              vlan_row["vlan_descr"] = "HIDDEN"
            }
            row["net_vlan_data"] = vlan_row
          }
          ret_row := make(M)
          ret_row["v"] = v
          ret_row["type"] = "net"
          ret_row["data"] = row

          out["rows"] = append(out["rows"].([]M), ret_row)
        }
      }

      // search ips
      query = "SELECT v"+v+"nets.*, v"+v+"ip_addr"+
              ", v"+v+"ip_id"+
              ", v"+v+"ip_fk_vlan_id"+
              ", IFNULL((SELECT BIT_OR(gn"+v+"r_rmask)"+
                         " FROM gn"+v+"rs WHERE"+
                         " gn"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND gn"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id IS NULL"+
                         " AND v"+v+"r_start <= v"+v+"net_addr AND v"+v+"r_stop >= v"+v+"net_last"+
                         "), 0) AS r_rights"+
              " FROM v"+v+"nets INNER JOIN v"+v+"ips ON v"+v+"ip_fk_v"+v+"net_id=v"+v+"net_id"+
              " WHERE TRUE"

      args = make([]interface{}, 0)
      if search_string != "" {
        query += " AND (SELECT COUNT(*) FROM i"+v+"vs INNER JOIN ics ON iv_fk_ic_id=ic_id"+
                       " WHERE (ic_type='text' OR ic_type='textarea') AND iv_fk_v"+v+"ip_id=v"+v+"ip_id"+
                       " AND iv_value LIKE CONCAT('%',?,'%')) > 0"
        args = append(args, search_string)
      }

      if search_tags != "" && tags_list != nil && len(tags_list) > 0 {
        query += " AND ( FALSE"
        for _, tag_id := range tags_list {
          query += " OR (SELECT COUNT(*) FROM i"+v+"vs INNER JOIN ics ON iv_fk_ic_id=ic_id"+
                         " WHERE (ic_type='tag' OR ic_type='multitag') AND iv_fk_v"+v+"ip_id=v"+v+"ip_id"+
                         " AND FIND_IN_SET('"+tag_id+"', iv_value) > 0) > 0"
        }
        query += ")"
      }

      if search_vlans != "" {
        query += " AND v"+v+"ip_fk_vlan_id IN("+search_vlans+")"
      }

      query += " ORDER BY v"+v+"ip_addr"

      if rows, err = return_query_A(db, query, args...); err != nil { panic(err.Error() + "\n\n"+query) }

      for _, row := range rows {
        if u64, _, err = get_net_rights(nil, nil, v, row); err != nil { panic(err) }

        include := false

        if (u64 & R_VIEW_NET_IPS) > 0 {
          include = true
        }

        if include {
          query = "SELECT ic_name, ic_type, iv_value"+
                  " FROM ics INNER JOIN i"+v+"vs ON ic_id=iv_fk_ic_id"+
                  " WHERE iv_fk_v"+v+"ip_id=? ORDER BY ic_sort"
          var ip_values []M

          if ip_values, err = return_query_A(db, query, row["v"+v+"ip_id"]); err != nil { panic(err) }

          row["values"] = ip_values

          if row["v"+v+"net_fk_vlan_id"] != nil {
            var vlan_row M
            vlan_rights := g_vlans_rights

            query = "SELECT vd_name, vd_descr, vlan_name, vlan_descr, vlan_number"+
                    ", IFNULL((SELECT BIT_OR(gvrr_rmask) FROM"+
                               " gvrrs INNER JOIN vrs ON vr_id=gvrr_fk_vr_id WHERE"+
                               " gvrr_fk_g_id IN("+user_groups_in+")"+
                               " AND vr_fk_vd_id=vd_id"+
                               " AND vr_start <= vlan_number AND vr_stop >= vlan_number"+
                               "), 0) as rights"+
                    " FROM vlans INNER JOIN vds ON vd_id=vlan_fk_vd_id"+
                    " WHERE vlan_id=?"
            if vlan_row, err = must_return_one_M(db, query, row["v"+v+"net_fk_vlan_id"]); err != nil { panic(err) }
            if u64, var_ok = vlan_row.Uint64("rights"); !var_ok { panic(PE) }

            vlan_rights |= u64

            if (vlan_rights & R_VIEW_NET_IPS) == 0 {
              vlan_row["vd_name"] = "HIDDEN"
              vlan_row["vd_descr"] = "HIDDEN"
              vlan_row["vlan_name"] = "HIDDEN"
              vlan_row["vlan_descr"] = "HIDDEN"
            }
            row["net_vlan_data"] = vlan_row
          }

          if row["v"+v+"ip_fk_vlan_id"] != nil {
            var vlan_row M
            vlan_rights := g_vlans_rights

            query = "SELECT vd_name, vd_descr, vlan_name, vlan_descr, vlan_number"+
                    ", IFNULL((SELECT BIT_OR(gvrr_rmask) FROM"+
                               " gvrrs INNER JOIN vrs ON vr_id=gvrr_fk_vr_id WHERE"+
                               " gvrr_fk_g_id IN("+user_groups_in+")"+
                               " AND vr_fk_vd_id=vd_id"+
                               " AND vr_start <= vlan_number AND vr_stop >= vlan_number"+
                               "), 0) as rights"+
                    " FROM vlans INNER JOIN vds ON vd_id=vlan_fk_vd_id"+
                    " WHERE vlan_id=?"
            if vlan_row, err = must_return_one_M(db, query, row["v"+v+"ip_fk_vlan_id"]); err != nil { panic(err) }
            if u64, var_ok = vlan_row.Uint64("rights"); !var_ok { panic(PE) }

            vlan_rights |= u64

            if (vlan_rights & R_VIEW_NET_IPS) == 0 {
              vlan_row["vd_name"] = "HIDDEN"
              vlan_row["vd_descr"] = "HIDDEN"
              vlan_row["vlan_name"] = "HIDDEN"
              vlan_row["vlan_descr"] = "HIDDEN"
            }
            row["ip_vlan_data"] = vlan_row
          }
          ret_row := make(M)
          ret_row["type"] = "ip"
          ret_row["v"] = v
          ret_row["data"] = row

          out["rows"] = append(out["rows"].([]M), ret_row)
        }
      }

      if (g_oobs_rights & R_VIEW_NET_IPS) > 0 &&
        (search_string != "" || search_tags != "") &&
      true {
        query = "SELECT * FROM v"+v+"oobs"+
                " WHERE TRUE"

        args = make([]interface{}, 0)

        if search_string != "" {
          query += " AND v"+v+"oob_descr LIKE CONCAT('%', ?, '%')"
          args = append(args, search_string)
        }

        if search_tags != "" {
          query += " AND ( FALSE"
          for _, tag_id := range tags_list {
            query += " OR (FIND_IN_SET('"+tag_id+"',v"+v+"oob_tags) > 0)"
          }
          query += ")"
        }

        if rows, err = return_query_A(db, query, args...); err != nil { panic(err) }
        for _, row := range rows {
          ret_row := make(M)
          ret_row["type"] = "oob"
          ret_row["v"] = v
          ret_row["data"] = row

          out["rows"] = append(out["rows"].([]M), ret_row)
        }
      }
    }

  } else if action == "get_groups" {

    query = "SELECT * FROM gs ORDER BY g_id"

    if out["gs"], err = return_query(db, query, ""); err != nil { panic(err) }

    query = "SELECT u_id, u_name, u_login FROM us WHERE u_id IN (SELECT fk_u_id FROM gs)"
    if out["users"], err = return_query(db, query, "u_id"); err != nil { panic(err) }
    if out["users"].(M)[user_id], err = must_return_one_M(db, "SELECT * FROM us WHERE u_id=?", user_id);
    err != nil { panic(err) }

  } else if action == "add_group" {

    if !user_is_admin { panic(NoAccess()) }

    var g_name string
    var g_descr string

    if g_name, err = get_p_string(q, "g_name", g_name_reg); err != nil { panic(err) }
    if g_descr, err = get_p_string(q, "g_descr", nil); err != nil { panic(err) }

    if g_name == opt_g { panic("Cannot use ADMIN_GROUP") }

    query = "INSERT INTO gs(g_name, g_descr, added, ts, fk_u_id) VALUES(?,?,?,0,?)"

    log_query := query

    if dbres, err = db.Exec(query, g_name, g_descr, ts, user_id); err != nil { panic(err) }
    var lid int64

    if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
    if lid <= 0 { panic("weird LastInsertId returned") }

    query = "SELECT * FROM gs WHERE g_id=?"
    if out["gs"], err = must_return_one_M(db, query, lid); err != nil { panic(err) }

    if err = audit_log(db, "group", lid, log_query, nil, out["gs"].(M)); err != nil { panic(err) }

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

    //check global rights
    query = "SELECT COUNT(*) as c FROM glrs WHERE glr_fk_g_id=?"
    if unum, err = must_return_one_uint(db, query, id); err != nil { panic(err) }
    g_used += unum

    if g_used > 0 && confirmed == "" {
      out["used"] = g_used
      goto OUT
    }

    if prev_data, err = must_return_one_M(db, "SELECT * FROM gs WHERE g_id=?", id); err != nil { panic(err) }


    query = "DELETE FROM gs WHERE g_id=?"
    log_query := query
    if _, err = db.Exec(query, id); err != nil { panic(err) }

    if err = audit_log(db, "group", id, log_query, prev_data, nil); err != nil { panic(err) }

    out["done"] = 1

  } else if action == "save_all" {
    queue_i, exists := q["queue"]
    if !exists { panic("Missing parameter: queue") }

    queue := queue_i.([]interface{})

    if len(queue) == 0 { panic("Empty queue") }

    //pre-flight check

    var net_cols M
    var dbnet M
    var dbnet_rights uint64

    var vdom M
    var vd_id string
    var vd_ranges []M

    for i, qm_i := range queue {
      qm := qm_i.(map[string]interface{})

      var value interface {}

      value = qm["value"].(string)

      data := M(qm["data"].(map[string]interface{}))
      _ = data

      var object string
      var prop string
      var obj_id string

      var ip_rights uint64

      if object, var_ok = data.String("object"); !var_ok { panic(fmt.Sprint("No object in queue item #", i)) }

      switch(object) {
      case "ip", "ip_value":
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        if ip_rights, dbnet, err = get_ip_rights(db, obj_id, "4", dbnet); err != nil { panic(err) }
      case "net":
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        if dbnet_rights, dbnet, err = get_net_rights(db, obj_id, "4", dbnet); err != nil { panic(err) }
      }

      switch(object) {
      case "ip_value":
        if net_cols == nil {
          query = "SELECT ic_type, ic_regexp, ic_id, ic_options FROM ics INNER JOIN n4cs ON nc_fk_ic_id=ic_id WHERE nc_fk_v4net_id=?"
          if net_cols, err = return_query_M(db, query, "ic_id", dbnet["v4net_id"]); err != nil { panic(err) }
        }
      }

      switch(object) {
      case "global_rights":
        if !user_is_admin { panic(NoAccess()) }
        objects_rights := make(map[string]map[string]string)
        if err = json.Unmarshal([]byte(value.(string)), &objects_rights); err != nil { panic(err) }
        for obj, _ := range g_rights_obj {
          if _, ex := objects_rights[obj]; !ex { panic("No object: "+obj+" in data") }
        }
      case "group":
        if !user_is_admin { panic(NoAccess()) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        _ = prop
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        _ = obj_id

        if prop != "g_name" && prop != "g_descr" { panic(fmt.Sprint("Bad property in queue item #", i)) }
        //-------group-------
      case "ip":
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }

        if prop != "vlan" &&
        true { panic(fmt.Sprint("Bad property in queue item #", i)) }

        if (ip_rights & R_EDIT_IP_VLAN) == 0 ||
           (ip_rights & R_VIEW_NET_IPS) == 0 ||
           ((ip_rights & R_DENYIP) > 0 &&
            (ip_rights & R_IGNORE_R_DENY) == 0) ||
        false {
          panic(NoAccess())
        }

      case "ip_value":
        var col_id string
        if col_id, var_ok = data.UintString("col_id"); !var_ok { panic(fmt.Sprint("No col_id in queue item #", i)) }

        if _, var_ok = net_cols[col_id]; !var_ok {
          panic("У сети нет такого поля, возможно оно было удалено другим пользователем. Перезагрузите страницу")
        }

        if (ip_rights & R_EDIT_IP_VLAN) == 0 ||
           (ip_rights & R_VIEW_NET_IPS) == 0 ||
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

        var ic_options_json string
        if ic_options_json, var_ok = net_cols[col_id].(M)["ic_options"].(string); !var_ok { panic(PE) }
        ic_options_json = strings.TrimSpace(ic_options_json)
        if strings.TrimSpace(value.(string)) != "" && len(ic_options_json) > 0 && ic_options_json[0] == '{' {
          var ic_options M
          if err = json.Unmarshal([]byte(ic_options_json), &ic_options); err != nil { panic(err) }
          if unique, var_ok := ic_options["unique"].(string); var_ok && unique == "mac" {
            if a := g_mac_free_reg.FindStringSubmatch(value.(string)); a != nil {
              value_mac := strings.ToLower(a[1]+a[2]+a[3]+a[4]+a[5]+a[6])
              query = "SELECT DISTINCT iv_value FROM i4vs WHERE iv_fk_ic_id=?"
              macs_a, err := return_arrays(db, query, col_id)
              if err != nil { panic(err) }
              for _, mac_m := range macs_a {
                mac := mac_m[0].(string)
                if a := g_mac_free_reg.FindStringSubmatch(mac); a != nil {
                  if strings.ToLower(a[1]+a[2]+a[3]+a[4]+a[5]+a[6]) == value_mac {
                    panic("Такой MAC адрес уже есть в БД. Воспользуйтесь поиском для информации")
                  }
                }
              }
            }
          }
        }

      case "net":
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        _ = prop

        if prop != "v4net_name" && prop != "v4net_descr" &&
           prop != "v4net_owner" && prop != "vlan" &&
           prop != "v4net_tags" &&
        true { panic(fmt.Sprint("Bad property in queue item #", i)) }

        if (dbnet_rights & R_MANAGE_NET) == 0 { panic(NoAccess()) }

      case "vdom":
        if !user_is_admin { panic(NoAccess()) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        if _, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        if prop != "vd_name" && prop != "vd_descr" { panic(fmt.Sprint("Bad property in queue item #", i)) }

      case "vlan_value":
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        if prop != "vlan_name" && prop != "vlan_descr" { panic(fmt.Sprint("Bad property in queue item #", i)) }

        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }

        var m M
        if m, err = must_return_one_M(db, "SELECT vlan_number, vlan_fk_vd_id FROM vlans WHERE vlan_id=?", obj_id); err != nil { panic(err) }

        var vlan_number uint64
        if vlan_number, var_ok = m.Uint64("vlan_number"); !var_ok { panic(PE) }

        var vlan_fk_vd_id string
        if vlan_fk_vd_id, var_ok = m.UintString("vlan_fk_vd_id"); !var_ok { panic(PE) }

        if vdom == nil {
          if vdom, err = must_return_one_M(db, "SELECT * FROM vds WHERE vd_id=?", vlan_fk_vd_id); err != nil { panic(err) }
          vd_id = vlan_fk_vd_id

          query = "SELECT vrs.*"+
                  ", IFNULL((SELECT BIT_OR(gvrr_rmask)"+
                             " FROM gvrrs WHERE gvrr_fk_g_id IN("+user_groups_in+")"+
                             " AND vr_id=gvrr_fk_vr_id"+
                             "), 0) AS rights"+
                  " FROM vrs WHERE vr_fk_vd_id=? ORDER BY vr_id"

          if vd_ranges, err = return_query_A(db, query, vd_id); err != nil { panic(err) }
        } else {
          if vlan_fk_vd_id != vd_id { panic("Cannot update different vdoms at the same time") }
        }

        vlan_rights := g_vlans_rights

        for _, r := range vd_ranges {
          var r_start uint64
          var r_stop uint64
          var r_rights uint64

          if r_start, var_ok = r.Uint64("vr_start"); !var_ok { panic(PE) }
          if r_stop, var_ok = r.Uint64("vr_stop"); !var_ok { panic(PE) }
          if r_rights, var_ok = r.Uint64("rights"); !var_ok { panic(PE) }

          if r_start <= vlan_number && r_stop >= vlan_number {
            vlan_rights |= r_rights
          }

        }

        if (vlan_rights & R_EDIT_IP_VLAN) == 0 ||
           (vlan_rights & R_VIEW_NET_IPS) == 0 ||
        false { panic(NoAccess()) }

      case "ics":
        if !user_is_admin { panic(NoAccess()) }

        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        if prop != "sort" { panic(fmt.Sprint("Bad property in queue item #", i)) }

        if !g_num_list_reg.MatchString(value.(string)) { panic(fmt.Sprint("Bad value in queue item #", i)) }

      case "ic":
        if !user_is_admin { panic(NoAccess()) }

        if _, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }

        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        prop_list := [...]string{"ic_default","ic_name","ic_type","ic_api_name","ic_regexp","ic_icon","ic_icon_style",
                                 "ic_descr","ic_view_style","ic_style", "ic_options"}
        found := false
        for _, p := range prop_list {
          if prop == p {
            found = true
            break
          }
        }

        if !found { panic(fmt.Sprint("Bad property in queue item #", i)) }

        switch(prop) {
        case "ic_regexp":
          if _, err = regexp.Compile(value.(string)); err != nil { panic(err) }
        case "ic_default":
          if !g_num_reg.MatchString(value.(string)) { panic(fmt.Sprint("Bad value in queue item #", i)) }
        }

      case "tp":
        if !user_is_admin { panic(NoAccess()) }

        if _, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }

        if prop != "tp_name" &&
           prop != "tp_descr" &&
           prop != "fields" &&
        true { panic(fmt.Sprint("Bad property in queue item #", i)) }

        if prop == "fields" && !g_num_list_reg.MatchString(value.(string)) {
          panic(fmt.Sprint("Bad value in queue item #", i))
        }

      case "oob":
        if (g_oobs_rights & R_EDIT_IP_VLAN) == 0 { panic(NoAccess()) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        if prop != "descr" && prop != "tags" { panic(fmt.Sprint("Bad property in queue item #", i)) }
        if _, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        var v string
        if v, var_ok = data.String("v"); !var_ok { panic(fmt.Sprint("No v in queue item #", i)) }
        if v != "4" && v != "6" { panic(fmt.Sprint("Bad v in queue item #", i)) }

      case "api":
        if !user_is_admin { panic(NoAccess()) }

        if _, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }

        if prop != "api_name" &&
           prop != "api_descr" &&
           prop != "api_nets" &&
           prop != "api_groups" &&
        true { panic(fmt.Sprint("Bad property in queue item #", i)) }

        if prop == "api_groups" && !g_num_list_reg.MatchString(value.(string)) {
          panic(fmt.Sprint("Bad value in queue item #", i))
        }


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

      value = strings.ReplaceAll(qm["value"].(string), "\r\n", "\n")

      data := M(qm["data"].(map[string]interface{}))
      _ = data

      var object string
      var prop string
      var obj_id string

      if object, var_ok = data.String("object"); !var_ok { panic(fmt.Sprint("No object in queue item #", i)) }

      switch(object) {
      case "global_rights":
        objects_rights := make(map[string]map[string]string)
        if err = json.Unmarshal([]byte(value.(string)), &objects_rights); err != nil { panic(err) }

        prev_data = make(M)
        changes := 0

        for obj, _ := range g_rights_obj {
          prev_data.(M)[obj] = make(M)

          query = "SELECT glr_fk_g_id as g_id, glr_rmask as rights FROM glrs WHERE glr_object=? ORDER BY g_id"
          var rows []M
          if rows, err = return_query_A(tx, query, obj); err != nil { panic(err) }
          for _, row := range rows {
            g_id, _ := row.UintString("g_id")
            prev_rights, _ := row.UintString("rights")
            prev_data.(M)[obj].(M)[g_id] = prev_rights

            if new_rights, ex := objects_rights[obj][g_id]; !ex {
              query = "DELETE FROM glrs WHERE glr_object=? AND glr_fk_g_id=?"
              if _, err = db_exec(tx, query, obj, g_id); err != nil { panic(err) }
              changes ++
            } else if new_rights != prev_rights {
              query = "UPDATE glrs SET"+
                      " glr_rmask=?"+
                      ",ts=?"+
                      ",fk_u_id=?"+
                      " WHERE glr_object=? AND glr_fk_g_id=?"
              if _, err = db_exec(tx, query, new_rights, ts, user_id, obj, g_id); err != nil { panic(err) }
              changes ++
            }
          }

          for g_id, new_rights := range objects_rights[obj] {
            if _, ex := prev_data.(M)[obj].(M)[g_id]; !ex {
              query = "INSERT INTO glrs SET"+
                      " glr_rmask=?"+
                      ",ts=?"+
                      ",fk_u_id=?"+
                      ",glr_object=?"+
                      ",glr_fk_g_id=?"
              if _, err = db_exec(tx, query, new_rights, ts, user_id, obj, g_id); err != nil { panic(err) }
              changes ++
            }
          }
        }
        if changes > 0 {
          if err = audit_log(tx, object, 0, "set rights", prev_data, objects_rights); err != nil { panic(err) }
        }
      case "group":
        if !user_is_admin { panic(NoAccess()) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }

        if prev_data, err = must_return_one_M(tx, "SELECT "+prop+" FROM gs WHERE g_id=?", obj_id); err != nil { panic(err) }

        query = "UPDATE gs SET "+prop+"=?, ts=?, fk_u_id=? WHERE g_id=?"

        _, err = tx.Exec(query, value, ts, user_id, obj_id)
        if err != nil { panic(err) }

        if err = audit_log(tx, object, obj_id, query, prev_data, value); err != nil { panic(err) }

      case "vdom":
        if !user_is_admin { panic(NoAccess()) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }

        if prev_data, err = must_return_one_M(tx, "SELECT "+prop+" FROM vds WHERE vd_id=?", obj_id); err != nil { panic(err) }

        query = "UPDATE vds SET "+prop+"=?, ts=?, fk_u_id=? WHERE vd_id=?"

        _, err = tx.Exec(query, value, ts, user_id, obj_id)
        if err != nil { panic(err) }

        if err = audit_log(tx, object, obj_id, query, prev_data, value); err != nil { panic(err) }

      case "ip":
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }

        if prop == "vlan" {
          prop = "v4ip_fk_vlan_id"
          if value.(string) == "" {
            value = nil
          }
        }

        if prev_data, err = must_return_one_M(tx, "SELECT "+prop+" FROM v4ips WHERE v4ip_id=?", obj_id); err != nil { panic(err) }

        query = "UPDATE v4ips SET "+prop+"=?, ts=?, fk_u_id=? WHERE v4ip_id=?"
        _, err = tx.Exec(query, value, ts, user_id, obj_id)
        if err != nil { panic(err) }

        if err = audit_log(tx, object, obj_id, query, prev_data, value); err != nil { panic(err) }

      case "ip_value":
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        var col_id string
        if col_id, var_ok = data.UintString("col_id"); !var_ok { panic(fmt.Sprint("No col_id in queue item #", i)) }

        prev_data, _ = must_return_one_M(tx, "SELECT iv_value FROM i4vs WHERE iv_fk_ic_id=? AND iv_fk_v4ip_id=?", col_id, obj_id)

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

        if err = audit_log(tx, object, obj_id, query, prev_data, value); err != nil { panic(err) }

      case "net":

        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }

        if prop == "v4net_owner" && value.(string) == "0" {
          value = nil
        }

        if prop == "vlan" {
          prop = "v4net_fk_vlan_id"
          if value.(string) == "" {
            value = nil
          }
        }

        if prev_data, err = must_return_one_M(tx, "SELECT "+prop+" FROM v4nets WHERE v4net_id=?", obj_id); err != nil { panic(err) }

        query = "UPDATE v4nets SET "+prop+"=?, ts=?, fk_u_id=? WHERE v4net_id=?"
        _, err = tx.Exec(query, value, ts, user_id, obj_id)
        if err != nil { panic(err) }

        if err = audit_log(tx, object, obj_id, query, prev_data, value); err != nil { panic(err) }

      case "vlan_value":
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }

        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }

        if prev_data, err = must_return_one_M(tx, "SELECT "+prop+" FROM vlans WHERE vlan_id=?", obj_id); err != nil { panic(err) }

        query = "UPDATE vlans SET "+prop+"=?, ts=?, fk_u_id=? WHERE vlan_id=?"
        _, err = tx.Exec(query, value, ts, user_id, obj_id)
        if err != nil { panic(err) }

        if err = audit_log(tx, object, obj_id, query, prev_data, value); err != nil { panic(err) }

      case "ics":
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }

        ids := strings.Split(value.(string), ",")
        for i, id := range ids {
          query = "UPDATE ics SET ic_sort=? WHERE ic_id=?"
          if _, err = tx.Exec(query, i, id); err != nil { panic(err) }
        }

        if err = audit_log(tx, object, 0, query, nil, value); err != nil { panic(err) }

      case "ic":
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }

        if prev_data, err = must_return_one_M(tx, "SELECT "+prop+" FROM ics WHERE ic_id=?", obj_id); err != nil { panic(err) }

        query = "UPDATE ics SET "+prop+"=?, ts=?, fk_u_id=? WHERE ic_id=?"
        if _, err = tx.Exec(query, value, ts, user_id, obj_id); err != nil {
          panic(err)
        }

        if err = audit_log(tx, object, obj_id, query, prev_data, value); err != nil { panic(err) }

      case "tp":
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }

        switch(prop) {
        case "tp_name","tp_descr":
          if prev_data, err = must_return_one_M(tx, "SELECT "+prop+" FROM tps WHERE tp_id=?", obj_id); err != nil { panic(err) }

          query = "UPDATE tps SET "+prop+"=?, ts=?, fk_u_id=? WHERE tp_id=?"
          if _, err = tx.Exec(query, value, ts, user_id, obj_id); err != nil { panic(err) }

          if err = audit_log(tx, object, obj_id, query, prev_data, value); err != nil { panic(err) }

        case "fields":
          if value.(string) == "" {
            query = "DELETE FROM tcs WHERE tc_fk_tp_id=?"
            if _, err = tx.Exec(query, obj_id); err != nil { panic(err) }

            if err = audit_log(tx, object, obj_id, query, nil, nil); err != nil { panic(err) }

          } else {
            query = "DELETE FROM tcs WHERE tc_fk_tp_id=? AND tc_fk_ic_id NOT IN("+value.(string)+")"
            if _, err = tx.Exec(query, obj_id); err != nil { panic(err) }

            if err = audit_log(tx, object, obj_id, query, nil, nil); err != nil { panic(err) }

          }
          if value.(string) != "" {
            query = "INSERT IGNORE INTO tcs(tc_fk_ic_id, tc_fk_tp_id, ts, fk_u_id)"+
                    " SELECT ic_id, ?, ?, ? FROM ics WHERE ic_id IN("+value.(string)+")"
            if _, err = tx.Exec(query, obj_id, ts, user_id); err != nil { panic(err) }

            if err = audit_log(tx, object, obj_id, query, nil, nil); err != nil { panic(err) }

          }
        default:
          panic("Unknown object prop")
        }

      case "oob":
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        var v string
        if v, var_ok = data.String("v"); !var_ok { panic(fmt.Sprint("No v in queue item #", i)) }

        if prev_data, err = must_return_one_M(tx, "SELECT v"+v+"oob_"+prop+" FROM v"+v+"oobs WHERE v"+v+"oob_id=?", obj_id);
        err != nil { panic(err) }

        query = "UPDATE v"+v+"oobs SET"+
                " v"+v+"oob_"+prop+"=?"+
                ",ts=?"+
                ",fk_u_id=?"+
                " WHERE v"+v+"oob_id=?"
        if _, err = tx.Exec(query, value, ts, user_id, obj_id); err != nil { panic(err) }

        if err = audit_log(tx, object, obj_id, query, prev_data, value); err != nil { panic(err) }

      case "api":
        if obj_id, var_ok = data.UintString("id"); !var_ok { panic(fmt.Sprint("No id in queue item #", i)) }
        if prop, var_ok = data.String("prop"); !var_ok { panic(fmt.Sprint("No prop in queue item #", i)) }

        switch(prop) {
        case "api_name","api_descr", "api_nets":
          if prev_data, err = must_return_one_M(tx, "SELECT "+prop+" FROM apis WHERE api_id=?", obj_id); err != nil { panic(err) }

          query = "UPDATE apis SET "+prop+"=?, ts=?, fk_u_id=? WHERE api_id=?"
          if _, err = tx.Exec(query, value, ts, user_id, obj_id); err != nil { panic(err) }

          if err = audit_log(tx, object, obj_id, query, prev_data, value); err != nil { panic(err) }

        case "api_groups":
          if value.(string) == "" {
            query = "DELETE FROM ags WHERE ag_fk_api_id=?"
            if _, err = tx.Exec(query, obj_id); err != nil { panic(err) }

            if err = audit_log(tx, object, obj_id, query, nil, nil); err != nil { panic(err) }

          } else {
            query = "DELETE FROM ags WHERE ag_fk_api_id=? AND ag_fk_g_id NOT IN("+value.(string)+")"
            if _, err = tx.Exec(query, obj_id); err != nil { panic(err) }

            if err = audit_log(tx, object, obj_id, query, nil, nil); err != nil { panic(err) }

          }
          if value.(string) != "" {
            query = "INSERT IGNORE INTO ags(ag_fk_g_id, ag_fk_api_id, ts, fk_u_id)"+
                    " SELECT g_id, ?, ?, ? FROM gs WHERE g_id IN("+value.(string)+")"
            if _, err = tx.Exec(query, obj_id, ts, user_id); err != nil { panic(err) }

            if err = audit_log(tx, object, obj_id, query, nil, nil); err != nil { panic(err) }

          }
        default:
          panic("Unknown object prop")
        }

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

  } else if action == "fav_all_v4" {

    if !user_is_admin { panic(NoAccess()) }

    var nav_net uint32
    var masklen uint32
    var fav uint32

    if nav_net, err = get_p_uint32(q, "net"); err != nil { panic(err) }
    if masklen, err = get_p_uint32(q, "masklen"); err != nil { panic(err) }
    if masklen > 31 { panic(errors.New("Too big masklen")) }

    if nav_net != ip4net(nav_net, masklen) { panic("Bad network/masklen") }

    if fav, err = get_p_uint32(q, "fav_all"); err != nil { panic(err) }
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
      if _, err = db.Exec(query, uint64(0), nav_net, masklen, ts, user_id); err != nil { panic(err) }
    } else {
      query = "DELETE FROM v4favs WHERE"+
              " v4fav_fk_u_id=?"+
              " AND v4net_addr=?"+
              " AND v4net_mask=?"
      if _, err = db.Exec(query, uint64(0), nav_net, masklen); err != nil { panic(err) }
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

    query = "SELECT COUNT(*) as c FROM v4favs WHERE v4net_addr=? AND v4net_mask=? AND v4fav_fk_u_id=?"
    if unum, err = must_return_one_uint(db, query, nav_net, masklen, uint64(0)); err != nil { panic(err) }

    out["fav_all"] = unum

    nav_last_addr := uint32(nav_net | (0xFFFFFFFF >> masklen))

    out["net_addr"] = nav_net
    out["net_masklen"] = masklen
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

      query = "SELECT COUNT(*) FROM v4arps WHERE v4arp_ip >=? AND v4arp_ip <= ?"
      var arp_count uint64
      if arp_count, err = must_return_one_uint(db, query, row_net, row_last_addr); err != nil { panic(err) }

      netrows[octet - first_octet]["arp_count"] = arp_count

      netrows[octet - first_octet]["cols"] = make([]M, lastmask - masklen)
      netrows[octet - first_octet]["ranges"] = make([]M, len(ranges))

      for i, range_i := range ranges {
        netrows[octet - first_octet]["ranges"].([]M)[i] = make(M)
        var range_rights uint64
        var range_start uint32
        var range_stop uint32


        if range_rights, var_ok = range_i.Uint64("rights"); !var_ok { panic(PE) }
        if u64, var_ok = range_i.Uint64("v4r_start"); !var_ok { panic(PE) }
        if u64 > math.MaxUint32  { panic(PE) }
        range_start = uint32(u64)

        if u64, var_ok = range_i.Uint64("v4r_stop"); !var_ok { panic(PE) }
        if u64 > math.MaxUint32 { panic(PE) }
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
          var net_rights uint64 = g_nets_rights
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

      if dbnet_owner == user_id {
        dbnet_rights = dbnet_rights | OWNER_RIGHTS
      }

      dbnet_rights |= g_nets_rights

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

        var vlan_id string
        if vlan_id, var_ok = dbnet.UintString("v4net_fk_vlan_id"); var_ok {
          query = "SELECT vlans.*"+
                  ", vds.vd_id, vds.vd_name"+
                  ", IFNULL((SELECT BIT_OR(gvrr_rmask) FROM"+
                             " gvrrs INNER JOIN vrs ON vr_id=gvrr_fk_vr_id WHERE"+
                             " gvrr_fk_g_id IN("+user_groups_in+")"+
                             " AND vr_fk_vd_id=vd_id"+
                             " AND vr_start <= vlan_number AND vr_stop >= vlan_number"+
                             "), 0) as rights"+
                  " FROM vlans INNER JOIN vds ON vd_id=vlan_fk_vd_id"+
                  " WHERE vlan_id=?"
          var vlan_data M
          if vlan_data, err = must_return_one_M(db, query, vlan_id); err != nil { panic(err) }

          var vlan_rights uint64
          if vlan_rights, var_ok = vlan_data.Uint64("rights"); !var_ok { panic(PE) }

          vlan_rights |= g_vlans_rights

          if (vlan_rights & R_VIEW_NET_IPS) == 0 {
            vlan_data["vd_name"] = "HIDDEN"
            vlan_data["vd_descr"] = "HIDDEN"
            vlan_data["vlan_name"] = "HIDDEN"
            vlan_data["vlan_descr"] = "HIDDEN"
          }

          netrows[dbnet_octet - first_octet]["vlan_data"] = vlan_data
        }

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
    if dbnet_rights, _, err = get_net_rights(nil, nil, "v", dbnet); err != nil { panic(err) }

    if (dbnet_rights & R_NAME) == 0 { panic(NoAccess()) }
    if (dbnet_rights & (R_VIEW_NET_INFO | R_VIEW_NET_IPS)) == 0 { panic(NoAccess()) }

    query = "SELECT COUNT(*) as c FROM v4favs WHERE v4net_addr=? AND v4net_mask=? AND v4fav_fk_u_id=?"
    if u64, err = must_return_one_uint(db, query, nav_net, masklen, user_id); err != nil { panic(err) }

    out["fav"] = u64

    query = "SELECT COUNT(*) as c FROM v4favs WHERE v4net_addr=? AND v4net_mask=? AND v4fav_fk_u_id=?"
    if u64, err = must_return_one_uint(db, query, nav_net, masklen, uint64(0)); err != nil { panic(err) }

    out["fav_all"] = u64

    var dbnet_last_addr uint32
    if u64, var_ok = dbnet.Uint64("v4net_last"); !var_ok { panic(PE) }
    if u64 > math.MaxUint32 { panic(PE) }
    dbnet_last_addr = uint32(u64)

    out["v"] = "4"
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
    out["fk_u_id"] = dbnet["fk_u_id"]
    out["net_name"] = dbnet["v4net_name"]
    out["net_tags"] = dbnet["v4net_tags"]

    if (dbnet_rights & R_VIEW_NET_INFO) > 0 {
      out["net_descr"] = dbnet["v4net_descr"]
    } else {
      out["net_descr"] = "HIDDEN"
    }

    var net_arps M

    query = "SELECT * FROM v4arps WHERE v4arp_ip >= ? AND v4arp_ip <= ?"
    if net_arps, err = return_query_M(db, query, "v4arp_ip", dbnet["v4net_addr"], dbnet["v4net_last"]); err != nil { panic(err) }

    aux_userinfo := make(M)

    if (dbnet_rights & R_VIEW_NET_INFO) > 0 {

      u64, _ = dbnet.Uint64("v4net_fk_vlan_id")
      if u64 > 0 {
        query = "SELECT vlan_number, vlan_name, vlan_descr, vd_name, vd_descr, vd_id, vlan_id, vlan_fk_vd_id"+
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

        vlan_rights |= g_vlans_rights

        if (vlan_rights & R_VIEW_NET_IPS) == 0 {
          dbnet_vlan_info_a[0]["vlan_name"] = "HIDDEN"
          dbnet_vlan_info_a[0]["vlan_descr"] = "HIDDEN"
          dbnet_vlan_info_a[0]["vd_name"] = "HIDDEN"
          dbnet_vlan_info_a[0]["vd_descr"] = "HIDDEN"
          dbnet_vlan_info_a[0]["vlan_name"] = "HIDDEN"
          dbnet_vlan_info_a[0]["vlan_descr"] = "HIDDEN"
        }
        out["vlan_data"] = dbnet_vlan_info_a[0]
      }

      u64, _ = dbnet.Uint64("fk_u_id")
      if u64 > 0 {
        var dbnet_userinfo_a []M
        if dbnet_userinfo_a, err = return_query_A(db, "SELECT * FROM us WHERE u_id=?", u64); err != nil { panic(err) }
        if len(dbnet_userinfo_a) == 1 {
          aux_userinfo[strconv.FormatUint(u64, 10)] = dbnet_userinfo_a[0]
        }
      }

      dbnet_owner, _ := dbnet.AnyString("v4net_owner")

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

      vlan_cache := make(M)

      query = "SELECT tags.*"+
              ", CAST(("+
              " (SELECT COUNT(*) FROM v4nets WHERE FIND_IN_SET(tag_id,v4net_tags))+"+
              " (SELECT COUNT(*) FROM v6nets WHERE FIND_IN_SET(tag_id,v6net_tags))+"+
              " (SELECT COUNT(*) FROM v4oobs WHERE FIND_IN_SET(tag_id,v4oob_tags))+"+
              " (SELECT COUNT(*) FROM v6oobs WHERE FIND_IN_SET(tag_id,v6oob_tags))+"+
              " (SELECT COUNT(*) FROM i4vs INNER JOIN ics ON iv_fk_ic_id=ic_id"+
                " WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
              " (SELECT COUNT(*) FROM i6vs INNER JOIN ics ON iv_fk_ic_id=ic_id"+
                " WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
              " 0) AS UNSIGNED) AS used"+
              ", IFNULL((SELECT BIT_OR(tgr_rmask) FROM tgrs WHERE tgr_fk_g_id IN("+user_groups_in+") AND tgr_fk_tag_id=tag_id"+
                        " GROUP BY tgr_fk_tag_id), CAST(0 AS UNSIGNED)) as rights"+
              " FROM tags"
      if tags_cache, err = return_query_M(db, query, "tag_id"); err != nil { panic(err) }

      for tag_id, _ := range tags_cache {
        if u64, err = get_tag_rights(db, tag_id, 0); err != nil { panic(err) }
        tags_cache[tag_id].(M)["rights"] = u64
        if (tags_cache[tag_id].(M)["rights"].(uint64) & R_VIEW_NET_IPS) == 0 {
          tags_cache[tag_id].(M)["tag_name"] = "HIDDEN"
          tags_cache[tag_id].(M)["tag_descr"] = "HIDDEN"
          tags_cache[tag_id].(M)["tag_options"] = "HIDDEN"
          tags_cache[tag_id].(M)["tag_api_name"] = nil
        }
      }

      out["tags"] = tags_cache

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

        var vlan_id string
        if vlan_id, var_ok = ip.UintString("v4ip_fk_vlan_id"); var_ok {
          if _, ex := vlan_cache[vlan_id]; !ex {
            query = "SELECT vlan_number, vlan_name, vlan_descr, vd_name, vd_descr, vd_id, vlan_id, vlan_fk_vd_id"+
                    ", (SELECT BIT_OR(gvrr_rmask)"+
                      " FROM gvrrs INNER JOIN vrs ON gvrr_fk_vr_id=vr_id"+
                      " WHERE gvrr_fk_g_id IN("+user_groups_in+")"+
                      " AND vr_fk_vd_id=vd_id"+
                      " AND vr_start <= vlan_number"+
                      " AND vr_stop >= vlan_number"+
                    " ) as rights"+
                    " FROM vlans INNER JOIN vds ON vd_id=vlan_fk_vd_id"+
                    " WHERE vlan_id=?"
            if vlan_cache[vlan_id], err = must_return_one_M(db, query, vlan_id); err != nil { panic(err) }

            var vlan_rights uint64
            if vlan_rights, var_ok = vlan_cache[vlan_id].(M).Uint64("rights"); !var_ok { panic(PE) }

            vlan_rights |= g_vlans_rights

            if (vlan_rights & R_VIEW_NET_IPS) == 0 {
              vlan_cache[vlan_id].(M)["vlan_name"] = "HIDDEN"
              vlan_cache[vlan_id].(M)["vlan_descr"] = "HIDDEN"
              vlan_cache[vlan_id].(M)["vd_name"] = "HIDDEN"
              vlan_cache[vlan_id].(M)["vd_descr"] = "HIDDEN"
              vlan_cache[vlan_id].(M)["vlan_name"] = "HIDDEN"
              vlan_cache[vlan_id].(M)["vlan_descr"] = "HIDDEN"
            }
          }
          ips_a[i]["vlan_data"] = vlan_cache[vlan_id]
        }
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
        addr_rights := dbnet_rights
        addr_ranges := make([]M, len(dbnet_ranges_a))

        addr_str := strconv.FormatUint(uint64(ip_addr), 10)

        arp, arp_ex := net_arps[addr_str].(M)

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

          if arp_ex {
            ips_a[addr_idx]["arp"] = arp
          }

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

            if arp_ex {
              ip_m["arp"] = arp
            }
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

            if arp_ex {
              ip_m["arp"] = arp
            }
            out_ips = append(out_ips, ip_m)
          } else {
            if pending == nil {
              pending = make(M)
              pending["is_empty"] = 1
              pending["start"] = ip_addr
              pending["stop"] = ip_addr
              pending["rights"] = addr_rights
              pending["ranges"] = addr_ranges
              if arp_ex {
                pending["arp_count"] = uint64(1)
                pending["arp"] = []M{ arp }
              }
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
                if arp_ex {
                  if arp_count, arp_count_ex := pending["arp_count"].(uint64); !arp_count_ex {
                    pending["arp_count"] = uint64(1)
                    pending["arp"] = []M{ arp }
                  } else {
                    pending["arp_count"] = arp_count + 1
                    pending["arp"] = append(pending["arp"].([]M), arp)
                  }
                }
              } else {
                out_ips = append(out_ips, pending)
                pending = make(M)
                pending["is_empty"] = 1
                pending["start"] = ip_addr
                pending["stop"] = ip_addr
                pending["rights"] = addr_rights
                pending["ranges"] = addr_ranges
                if arp_ex {
                  pending["arp_count"] = uint64(1)
                  pending["arp"] = []M{ arp }
                }
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

    var dbnet_rights uint64
    var ip_rights uint64

    var dbnet M

    if ip_rights, dbnet, err = get_addr_rights(tx, take_ip, "4", nil); err != nil { panic(err) }
    if dbnet_rights, _, err = get_net_rights(nil, nil, "4", dbnet); err != nil { panic(err) }

    var dbnet_addr uint32
    var dbnet_last_addr uint32
    var masklen uint32

    if u64, var_ok = dbnet.Uint64("v4net_addr"); !var_ok { panic(PE) }
    if u64 > math.MaxUint32 { panic(PE) }
    dbnet_addr = uint32(u64)

    if u64, var_ok = dbnet.Uint64("v4net_last"); !var_ok { panic(PE) }
    if u64 > math.MaxUint32 { panic(PE) }
    dbnet_last_addr = uint32(u64)

    if u64, var_ok = dbnet.Uint64("v4net_mask"); !var_ok { panic(PE) }
    if u64 > 32 { panic(PE) }
    masklen = uint32(u64)

    if masklen <= 30 && take_ip == dbnet_addr { panic(PE) }
    if masklen <= 30 && take_ip == dbnet_last_addr { panic(PE) }

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

    log_query := query
    if dbres, err = tx.Exec(query, take_ip, dbnet["v4net_id"], ts, user_id); err != nil { panic(err) }

    var rows []M

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

    var arp []M
    if arp, err = return_query_A(tx, "SELECT * FROM v4arps WHERE v4arp_ip=?", take_ip); err != nil { panic(err) }

    if len(arp) == 1 {
      ipdata["arp"] = arp[0]
    }

    out["ipdata"] = ipdata

    if err = audit_log(tx, "v4ip", ipdata["v4ip_id"], log_query, nil, ipdata); err != nil { panic(err) }

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

    var dbnet_rights uint64

    var rquery string

    var groups M

    query = "SELECT g_id, g_name, g_descr FROM gs"
    if groups, err = return_query_M(db, query, "g_id"); err != nil { panic(err) }

    switch object {
    case "v4net_acl":

      if dbnet_rights, _, err = get_net_rights(db, object_id, "4", nil); err != nil { panic(err) }

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
        if s, var_ok = rights[g_id].(M).UintString("fk_u_id"); var_ok {
          user_ids = append(user_ids, s)
        }
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

    var dbnet_rights uint64

    var rquery string

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

      if dbnet_rights, _, err = get_net_rights(tx, object_id, "4", nil); err != nil { panic(err) }

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

    if err = audit_log(tx, object, object_id, "set rights", groups_rights, rights); err != nil { panic(err) }

    out["done"] = 1

    err = tx.Commit()
    if err != nil { panic(err) }
    commited = true

  } else if action == "save_range" {
    var object string
    var object_id string
    var rights map[string]string

    if object, err = get_p_string(q, "object", "^(?:int_v4net_range|ext_v4net_range)$"); err != nil { panic(err) }
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

      if dbnet_rights, dbnet, err = get_net_rights(tx, net_id, "4", nil); err != nil { panic(err) }

      var dbnet_addr uint64
      var dbnet_last_addr uint64

      if dbnet_addr, var_ok = dbnet.Uint64("v4net_addr"); !var_ok { panic(PE) }
      if dbnet_last_addr, var_ok = dbnet.Uint64("v4net_last"); !var_ok { panic(PE) }

      if uint64(r_start.(uint32)) < dbnet_addr || uint64(r_stop.(uint32)) > dbnet_last_addr { panic("Range is out of network bounds") }

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

        if new_data, err = must_return_one_M(tx, "SELECT * FROM v4rs WHERE v4r_id=?", lid); err != nil { panic(err) }
        if err = audit_log(tx, object, object_id, query, nil, new_data); err != nil { panic(err) }

      } else {
        if prev_data, err = must_return_one_M(tx, "SELECT * FROM v4rs WHERE v4r_id=?", object_id); err != nil { panic(err) }
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

        if new_data, err = must_return_one_M(tx, "SELECT * FROM v4rs WHERE v4r_id=?", object_id); err != nil { panic(err) }
        if err = audit_log(tx, object, object_id, query, prev_data, new_data); err != nil { panic(err) }

      }

    case "ext_v4net_range":
      if !user_is_admin { panic(NoAccess()) }

      if r_start, err = get_p_uint32(q, "r_start"); err != nil { panic(err) }
      if r_stop, err = get_p_uint32(q, "r_stop"); err != nil { panic(err) }

      if r_start.(uint32) > r_stop.(uint32) { panic("Bad range") }

      table = "gr4rs"
      group_key = "gr4r_fk_g_id"
      object_key = "gr4r_fk_v4r_id"
      right_mask_field = "gr4r_rmask"

      if object_id == "" {
        query = "INSERT INTO v4rs SET"+
                " v4r_start=?"+
                ",v4r_stop=?"+
                ",v4r_name=?"+
                ",v4r_descr=?"+
                ",v4r_style=?"+
                ",v4r_icon=?"+
                ",v4r_icon_style=?"+
                ",v4r_fk_v4net_id=NULL"+
                ",ts=?"+
                ",fk_u_id=?"
        if dbres, err = tx.Exec(query, r_start, r_stop, r_name, r_descr, r_style, r_icon, r_icon_style, ts, user_id);
        err != nil { panic(err) }
        var lid int64

        if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
        if lid <= 0 { panic("weird LastInsertId returned") }

        object_id = strconv.FormatInt(lid, 10)

        if new_data, err = must_return_one_M(tx, "SELECT * FROM v4rs WHERE v4r_id=?", object_id); err != nil { panic(err) }
        if err = audit_log(tx, object, object_id, query, nil, new_data); err != nil { panic(err) }

      } else {
        if prev_data, err = must_return_one_M(tx, "SELECT * FROM v4rs WHERE v4r_id=?", object_id); err != nil { panic(err) }
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
                " WHERE v4r_fk_v4net_id IS NULL AND v4r_id=?"
        if _, err = tx.Exec(query, r_start, r_stop, r_name, r_descr, r_style, r_icon, r_icon_style, ts, user_id, object_id);
        err != nil { panic(err) }

        if new_data, err = must_return_one_M(tx, "SELECT * FROM v4rs WHERE v4r_id=?", object_id); err != nil { panic(err) }
        if err = audit_log(tx, object, object_id, query, prev_data, new_data); err != nil { panic(err) }

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

    if err = audit_log(tx, object, object_id, "set rights", groups_rights, rights); err != nil { panic(err) }

    out["done"] = 1

    err = tx.Commit()
    if err != nil { panic(err) }
    commited = true

  } else if action == "get_net_range" {
    var object string
    var object_id string

    if object, err = get_p_string(q, "object", "^(?:int_v4net_range|ext_v4net_range)$"); err != nil { panic(err) }
    if object_id, err = get_p_string(q, "object_id", g_num_reg); err != nil { panic(err) }

    var net_id string
    var dbnet_rights uint64

    var rquery string

    var table string
    var group_key string
    var object_key string
    var right_mask_field string

    user_ids := make([]string, 0)

    user_ids = append(user_ids, user_id)

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

      var range_user_id string
      if range_user_id, var_ok = rows[0].UintString("fk_i_ud"); var_ok {
        user_ids = append(user_ids, range_user_id)
      }

      if net_id, var_ok = rows[0].UintString("v4r_fk_v4net_id"); !var_ok { panic(PE) }

      if dbnet_rights, _, err = get_net_rights(db, net_id, "4", nil); err != nil { panic(err) }

      for _, r := range [...]uint64{R_NAME, R_VIEW_NET_IPS} {
        if (dbnet_rights & r) == 0 { panic(NoAccess()) }
      }

    case "ext_v4net_range":
      table = "gr4rs"
      group_key = "gr4r_fk_g_id"
      object_key = "gr4r_fk_v4r_id"
      right_mask_field = "gr4r_rmask"

      var rows []M

      query = "SELECT * FROM v4rs WHERE v4r_id=?"
      if rows, err = return_query_A(db, query, object_id); err != nil { panic(err) }
      if len(rows) != 1 { panic("Диапазон удален другим пользователем, обновите страницу") }
      out = rows[0]

      var range_user_id string
      if range_user_id, var_ok = rows[0].UintString("fk_i_ud"); var_ok {
        user_ids = append(user_ids, range_user_id)
      }

      if net_id, var_ok = rows[0].UintString("v4r_fk_v4net_id"); var_ok { panic(PE) }

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

  } else if action == "del_net_range" {
    var object string
    var object_id string

    if object, err = get_p_string(q, "object", "^(?:int_v4net_range|ext_v4net_range)$"); err != nil { panic(err) }
    if object_id, err = get_p_string(q, "object_id", g_num_reg); err != nil { panic(err) }

    var net_id string
    var dbnet_rights uint64


    var table string
    var key_field string
    var prev_rights M

    switch object {
    case "int_v4net_range":

      table = "v4rs"
      key_field = "v4r_id"

      var rows []M

      query = "SELECT * FROM v4rs WHERE v4r_id=?"
      if rows, err = return_query_A(db, query, object_id); err != nil { panic(err) }
      if len(rows) != 1 { panic("Диапазон удален другим пользователем, обновите страницу") }
      out = rows[0]

      if net_id, var_ok = rows[0].UintString("v4r_fk_v4net_id"); !var_ok { panic(PE) }

      if dbnet_rights, _, err = get_net_rights(db, net_id, "4", nil); err != nil { panic(err) }

      for _, r := range [...]uint64{R_NAME, R_VIEW_NET_INFO, R_VIEW_NET_IPS, R_EDIT_IP_VLAN, R_MANAGE_NET} {
        if (dbnet_rights & r) == 0 { panic(NoAccess()) }
      }

      query = "SELECT gr4r_fk_g_id as g_id, gr4r_rmask as rights FROM gr4rs WHERE gr4r_fk_v4r_id=?"
      if prev_rights, err = return_query_M(db, query, "g_id", object_id); err != nil { panic(err) }

    case "ext_v4net_range":

      if !user_is_admin { panic(NoAccess()) }

      table = "v4rs"
      key_field = "v4r_id"

      var rows []M

      query = "SELECT * FROM v4rs WHERE v4r_id=?"
      if rows, err = return_query_A(db, query, object_id); err != nil { panic(err) }
      if len(rows) != 1 { panic("Диапазон удален другим пользователем, обновите страницу") }
      out = rows[0]

      if net_id, var_ok = rows[0].UintString("v4r_fk_v4net_id"); var_ok { panic(PE) }

      query = "SELECT gr4r_fk_g_id as g_id, gr4r_rmask as rights FROM gr4rs WHERE gr4r_fk_v4r_id=?"
      if prev_rights, err = return_query_M(db, query, "g_id", object_id); err != nil { panic(err) }

    default:
      panic(PE)
    }

    if prev_data, err = must_return_one_M(db, "SELECT * FROM "+table+" WHERE "+key_field+"=?", object_id);
    err != nil { panic(err) }

    prev_data.(M)["rights"] = prev_rights

    query = "DELETE FROM "+table+" WHERE "+key_field+"=?"
    if _, err = db.Exec(query, object_id); err != nil { panic(err) }

    if err = audit_log(db, object, object_id, query, prev_data, nil); err != nil { panic(err) }

    out["done"] = 1


  } else if action == "del_net" {
    var net_id string
    if net_id, err = get_p_string(q, "net_id", g_num_reg); err != nil { panic(err) }

    var v string
    if v, err = get_p_string(q, "v", "^[46]{1}$"); err != nil { panic(err) }

    var dbnet_rights uint64


    tx, tx_err := db.Begin()
    if tx_err != nil { panic(tx_err) }
    var commited bool = false
    defer func() {
      if !commited {
        tx.Rollback()
      }
    } ()

    if dbnet_rights, _, err = get_net_rights(tx, net_id, v, nil); err != nil { panic(err) }

    for _, r := range [...]uint64{R_NAME, R_VIEW_NET_INFO, R_VIEW_NET_IPS, R_EDIT_IP_VLAN, R_MANAGE_NET} {
      if (dbnet_rights & r) == 0 { panic(NoAccess()) }
    }

    if prev_data, err = must_return_one_M(tx, "SELECT * FROM v"+v+"nets WHERE v"+v+"net_id=?", net_id); err != nil { panic(err) }

    var prev_rights M
    query = "SELECT gn4r_fk_g_id as g_id, gn4r_rmask as rights FROM gn4rs WHERE gn4r_fk_v4net_id=?"
    if prev_rights, err = return_query_M(tx, query, "g_id", net_id); err != nil { panic(err) }

    prev_data.(M)["rights"] = prev_rights

    query = "DELETE FROM v"+v+"nets WHERE v"+v+"net_id=?"
    if _,err = tx.Exec(query, net_id); err != nil { panic(err) }

    if err = audit_log(tx, "v"+v+"net", net_id, query, prev_data, nil); err != nil { panic(err) }

    /*
    TODO Cleanup dependable tables
    query = "DELETE FROM atvs WHERE atv_object_id=? AND (SELECT att_object FROM atts WHERE att_id=atv_fk_att_id)=?"
    if _,err = tx.Exec(query, net_id, "v"+v+"net"); err != nil { panic(err) }
    */

    out["done"] = 1

    err = tx.Commit()
    if err != nil { panic(err) }
    commited = true

  } else if action == "free_ip" {
    var ip_id string
    if ip_id, err = get_p_string(q, "id", g_num_reg); err != nil { panic(err) }

    var v string
    if v, err = get_p_string(q, "v", "^[46]{1}$"); err != nil { panic(err) }

    tx, tx_err := db.Begin()
    if tx_err != nil { panic(tx_err) }
    var commited bool = false
    defer func() {
      if !commited {
        tx.Rollback()
      }
    } ()

    var ip_rights uint64
    if ip_rights, _, err = get_ip_rights(tx, ip_id, v, nil); err != nil { panic(err) }

    if (ip_rights & R_VIEW_NET_IPS) == 0 ||
       (ip_rights & R_EDIT_IP_VLAN) == 0 ||
       ((ip_rights & R_DENYIP) > 0 &&
        (ip_rights & R_IGNORE_R_DENY) == 0) ||
    false {
      panic(NoAccess())
    }

    query = "SELECT ic_name, iv_value FROM i"+v+"vs INNER JOIN ics ON ic_id=iv_fk_ic_id WHERE iv_fk_v"+v+"ip_id=?"
    var rows []M
    if rows, err = return_query_A(tx, query, ip_id); err != nil { panic(err) }

    if prev_data, err = must_return_one_M(tx, "SELECT * FROM v"+v+"ips WHERE v"+v+"ip_id=?", ip_id);
    err != nil { panic(err) }

    prev_data.(M)["values"] = rows

    query = "DELETE FROM v"+v+"ips WHERE v"+v+"ip_id=?"
    if _, err = tx.Exec(query, ip_id); err != nil { panic(err) }


    if err = audit_log(tx, "v"+v+"ip", ip_id, query, prev_data, nil); err != nil { panic(err) }

    err = tx.Commit()
    if err != nil { panic(err) }
    commited = true

    out["done"] = 1

  } else if action == "list_net_templates" {
    if out["templates"], err = return_query_A(db, "SELECT tp_id, tp_name FROM tps ORDER BY tp_name");
    err != nil { panic(err) }

  } else if action == "take_net" {
    var v string
    if v, err = get_p_string(q, "v", "^[46]{1}$"); err != nil { panic(err) }

    var tp_id string
    if tp_id, err = get_p_string(q, "tp_id", g_num_reg); err != nil { panic(err) }

    var template M
    if template, err = must_return_one_M(db, "SELECT tp_descr FROM tps WHERE tp_id=?", tp_id); err != nil { panic(err) }

    var template_cols []M
    query = "SELECT tc_fk_ic_id FROM tcs WHERE tc_fk_tp_id=?"
    if template_cols, err = return_query_A(db, query, tp_id); err != nil { panic(err) }

    var masklen uint32
    if masklen, err = get_p_uint32(q, "masklen"); err != nil { panic(err) }

    var net_addr interface{}
    var net_last_addr interface{}

    if v == "4" {
      if masklen > 32 { panic("Bad mask len") }

      var v4net_addr uint32
      if v4net_addr, err = get_p_uint32(q, "net"); err != nil { panic(err) }

      if v4net_addr != ip4net(v4net_addr, masklen) { panic("Wrong network/mask") }

      net_last_addr = uint32(v4net_addr | (0xFFFFFFFF >> masklen))
      net_addr = v4net_addr

    } else {
      //v6
      panic("not implemented yet")
    }

    tx, tx_err := db.Begin()
    if tx_err != nil { panic(tx_err) }
    var commited bool = false
    defer func() {
      if !commited {
        tx.Rollback()
      }
    } ()

    query = "SELECT COUNT(*) AS c FROM v"+v+"nets"+
            " WHERE v"+v+"net_addr <= ? AND v"+v+"net_last >= ?"
    if u64, err = must_return_one_uint(tx, query, net_last_addr, net_addr); err != nil { panic(err) }
    if u64 > 0 { panic("Сеть пересекается с существующими. Обновите страницу!") }

    query = "INSERT INTO v"+v+"nets SET"+
            " v"+v+"net_addr=?"+
            ",v"+v+"net_last=?"+
            ",v"+v+"net_mask=?"+
            ",v"+v+"net_owner=?"+
            ",v"+v+"net_descr=?"+
            ",ts=?"+
            ",taken_ts=?"+
            ",fk_u_id=?"+
            ",taken_u_id=?"
    log_query := query
    if dbres, err = tx.Exec(query, net_addr, net_last_addr, masklen, user_id, template["tp_descr"], ts, ts, user_id, user_id);
    err != nil { panic(err) }

    var lid int64

    if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
    if lid <= 0 { panic("weird LastInsertId returned") }

    if new_data, err = must_return_one_M(tx, "SELECT * FROM v"+v+"nets WHERE v"+v+"net_id=?", lid); err != nil { panic(err) }

    for _, tc := range template_cols {
      if _, err = tx.Exec("INSERT INTO n"+v+"cs SET nc_fk_v"+v+"net_id=?, nc_fk_ic_id=?, ts=?, fk_u_id=?",
                          lid, tc["tc_fk_ic_id"], ts, user_id);
      err != nil { panic(err) }
    }

    if err = audit_log(tx, "v"+v+"net", lid, log_query, nil, new_data); err != nil { panic(err) }

    out["done"] = 1

    if err = tx.Commit(); err != nil { panic(err) }
    commited = true

  } else if action == "get_netcols" {

    query = "SELECT * FROM ics ORDER BY ic_sort"
    if out["netcols"], err = return_query_A(db, query); err != nil { panic(err) }

  } else if action == "net_set_cols" {
    var net_id string
    if net_id, err = get_p_string(q, "net_id", g_num_reg); err != nil { panic(err) }

    var v string
    if v, err = get_p_string(q, "v", "^[46]{1}$"); err != nil { panic(err) }

    var on []string
    if on, err = get_p_array(q, "on", g_num_reg); err != nil { panic(err) }

    var off []string
    if off, err = get_p_array(q, "off", g_num_reg); err != nil { panic(err) }

    var dbnet_rights uint64

    tx, tx_err := db.Begin()
    if tx_err != nil { panic(tx_err) }
    var commited bool = false
    defer func() {
      if !commited {
        tx.Rollback()
      }
    } ()

    if dbnet_rights, _, err = get_net_rights(tx, net_id, v, nil); err != nil { panic(err) }

    for _, r := range [...]uint64{R_NAME, R_VIEW_NET_INFO, R_VIEW_NET_IPS, R_EDIT_IP_VLAN, R_MANAGE_NET} {
      if (dbnet_rights & r) == 0 { panic(NoAccess()) }
    }

    if len(on) == 0 && len(off) == 0 {
      out["nothing_to_do"] = 1
      goto OUT
    }

    u64 = 0
    if len(on) > 0 {
      query = "SELECT COUNT(*) FROM n"+v+"cs WHERE"+
              " nc_fk_v"+v+"net_id=?"+
              " AND nc_fk_ic_id IN("+strings.Join(on, ",")+")"
      if u64, err = must_return_one_uint(tx, query, net_id); err != nil { panic(err) }

      if u64 > 0 { panic("Состав полей у сети был изменен другим пользователем. Обновите страницу!") }
    }

    u64 = 0
    if len(off) > 0 {
      query = "SELECT COUNT(*) FROM n"+v+"cs WHERE"+
              " nc_fk_v"+v+"net_id=?"+
              " AND nc_fk_ic_id IN("+strings.Join(off, ",")+")"
      if u64, err = must_return_one_uint(tx, query, net_id); err != nil { panic(err) }

      if u64 != uint64(len(off)) { panic("Состав полей у сети был изменен другим пользователем. Обновите страницу!") }
    }

    for _, ic_id := range on {
      query = "INSERT INTO n"+v+"cs SET nc_fk_v"+v+"net_id=?, nc_fk_ic_id=?, ts=?, fk_u_id=?"
      if _, err = tx.Exec(query, net_id, ic_id, ts, user_id); err != nil { panic(err) }
    }

    for _, ic_id := range off {
      query = "DELETE FROM n"+v+"cs WHERE nc_fk_v"+v+"net_id=? AND nc_fk_ic_id=?"
      if _, err = tx.Exec(query, net_id, ic_id); err != nil { panic(err) }

      query = "DELETE FROM i"+v+"vs WHERE"+
              " (SELECT v"+v+"ip_fk_v"+v+"net_id FROM v"+v+"ips WHERE iv_fk_v"+v+"ip_id=v"+v+"ip_id) = ?"+
              " AND iv_fk_ic_id=?"
      if _, err = tx.Exec(query, net_id, ic_id); err != nil { panic(err) }
    }

    query = "UPDATE v"+v+"nets SET ts=?, fk_u_id=? WHERE v"+v+"net_id=?"
    if _, err = tx.Exec(query, ts, user_id, net_id); err != nil { panic(err) }

    if err = audit_log(tx, "v"+v+"net", net_id, "set columns", nil, q); err != nil { panic(err) }

    if err = tx.Commit(); err != nil { panic(err) }
    commited = true

    out["done"] = 1

  } else if action == "list_vlan_domains" {

    query = "SELECT vds.*"+
            ", (SELECT COUNT(*) FROM vlans WHERE vlan_fk_vd_id=vd_id) AS num_taken"+
            ", (SELECT COUNT(*) FROM v4nets INNER JOIN vlans ON v4net_fk_vlan_id=vlan_id WHERE vlan_fk_vd_id=vd_id) AS v4nets"+
            ", (SELECT COUNT(*) FROM v6nets INNER JOIN vlans ON v6net_fk_vlan_id=vlan_id WHERE vlan_fk_vd_id=vd_id) AS v6nets"+
            ", (SELECT COUNT(*) FROM v4ips INNER JOIN vlans ON v4ip_fk_vlan_id=vlan_id WHERE vlan_fk_vd_id=vd_id) AS v4ips"+
            ", (SELECT COUNT(*) FROM v6ips INNER JOIN vlans ON v6ip_fk_vlan_id=vlan_id WHERE vlan_fk_vd_id=vd_id) AS v6ips"+
            ", IFNULL((SELECT BIT_OR(gvrr_rmask)"+
                       " FROM gvrrs INNER JOIN vrs ON vr_id=gvrr_fk_vr_id"+
                       " WHERE gvrr_fk_g_id IN("+user_groups_in+")"+
                       " AND vr_fk_vd_id=vd_id"+
                       "), 0) AS rights"+
            " FROM vds ORDER BY vd_name"
    var rows []M

    if rows, err = return_query_A(db, query); err != nil { panic(err) }

    ret := make([]M, 0)

    for _, row := range rows {
      if u64, var_ok = row.Uint64("rights"); !var_ok { panic(PE) }

      u64 |= g_vlans_rights

      if (u64 & R_VIEW_NET_IPS) > 0 {
        row["rights"] = u64
        ret = append(ret, row)
      }
    }

    out["vds"] = ret

  } else if action == "view_vlan_domain" {
    var vd_id string


    if vd_id, err = get_p_string(q, "id", g_num_reg); err != nil { panic(err) }

    query = "SELECT vds.*"+
            ", (SELECT COUNT(*) FROM v4nets INNER JOIN vlans ON v4net_fk_vlan_id=vlan_id WHERE vlan_fk_vd_id=vd_id) AS v4nets"+
            ", (SELECT COUNT(*) FROM v6nets INNER JOIN vlans ON v6net_fk_vlan_id=vlan_id WHERE vlan_fk_vd_id=vd_id) AS v6nets"+
            ", (SELECT COUNT(*) FROM v4ips INNER JOIN vlans ON v4ip_fk_vlan_id=vlan_id WHERE vlan_fk_vd_id=vd_id) AS v4ips"+
            ", (SELECT COUNT(*) FROM v6ips INNER JOIN vlans ON v6ip_fk_vlan_id=vlan_id WHERE vlan_fk_vd_id=vd_id) AS v6ips"+
            ", IFNULL((SELECT BIT_OR(gvrr_rmask)"+
                       " FROM gvrrs INNER JOIN vrs ON vr_id=gvrr_fk_vr_id"+
                       " WHERE gvrr_fk_g_id IN("+user_groups_in+")"+
                       " AND vr_fk_vd_id=vd_id"+
                       "), 0) AS rights"+
            " FROM vds WHERE vd_id=?"
    var vd M

    if vd, err = must_return_one_M(db, query, vd_id); err != nil { panic(err) }

    if u64, var_ok = vd.Uint64("rights"); !var_ok { panic(PE) }

    u64 |= g_vlans_rights

    if (u64 & R_VIEW_NET_IPS) == 0 { panic(NoAccess()) }

    var vd_max_num uint64
    if vd_max_num, var_ok = vd.Uint64("vd_max_num"); !var_ok { panic(PE) }

    var dbvlans M
    query = "SELECT vlans.*"+
            ", (SELECT COUNT(*) FROM v4nets WHERE v4net_fk_vlan_id=vlan_id) AS v4nets"+
            ", (SELECT COUNT(*) FROM v6nets WHERE v6net_fk_vlan_id=vlan_id) AS v6nets"+
            ", (SELECT COUNT(*) FROM v4ips WHERE v4ip_fk_vlan_id=vlan_id) AS v4ips"+
            ", (SELECT COUNT(*) FROM v6ips WHERE v6ip_fk_vlan_id=vlan_id) AS v6ips"+
            " FROM vlans WHERE vlan_fk_vd_id=?"

    if dbvlans, err = return_query_M(db, query, "vlan_number", vd_id); err != nil { panic(err) }

    var dbranges []M
    query = "SELECT vrs.*"+
            ", IFNULL((SELECT BIT_OR(gvrr_rmask)"+
                       " FROM gvrrs WHERE gvrr_fk_g_id IN("+user_groups_in+")"+
                       " AND vr_id=gvrr_fk_vr_id"+
                       "), 0) AS rights"+
            " FROM vrs WHERE vr_fk_vd_id=? ORDER BY vr_id"

    if dbranges, err = return_query_A(db, query, vd_id); err != nil { panic(err) }

    vlans := make([]M, 0)
    var pending M = nil

    for v := uint64(1); v <= vd_max_num; v++ {
      vlan_number := strconv.FormatUint(v, 10)
      _, taken := dbvlans[vlan_number]

      vlan_rights := g_vlans_rights

      vlan_ranges := make([]M, len(dbranges))

      for i, _ := range dbranges {
        vlan_ranges[i] = make(M)

        var range_start uint64
        var range_stop uint64
        var range_rights uint64
        if range_start, var_ok = dbranges[i].Uint64("vr_start"); !var_ok { panic(PE) }
        if range_stop, var_ok = dbranges[i].Uint64("vr_stop"); !var_ok { panic(PE) }
        if range_rights, var_ok = dbranges[i].Uint64("rights"); !var_ok { panic(PE) }

        if range_start <= v && range_stop >= v {
          vlan_ranges[i]["in_range"] = 1
          vlan_rights |= range_rights
        }
      }

      if taken {
        if pending != nil {
          vlans = append(vlans, pending)
          pending = nil
        }

        dbvlans[vlan_number].(M)["rights"] = vlan_rights
        dbvlans[vlan_number].(M)["ranges"] = vlan_ranges
        dbvlans[vlan_number].(M)["is_taken"] = 1

        if (vlan_rights & R_VIEW_NET_IPS) == 0 {
          dbvlans[vlan_number].(M)["vlan_name"] = "HIDDEN"
          dbvlans[vlan_number].(M)["vlan_descr"] = "HIDDEN"
        }

        vlans = append(vlans, dbvlans[vlan_number].(M))
      } else {
        if pending == nil {
          pending = make(M)
          pending["is_empty"] = 1
          pending["start"] = v
          pending["stop"] = v
          pending["rights"] = vlan_rights
          pending["ranges"] = vlan_ranges
        } else {
          ranges_differ := false
          for i, _ := range dbranges {
            if len(pending["ranges"].([]M)[i]) != len(vlan_ranges[i]) {
              ranges_differ = true
              break
            }
          }
          if !ranges_differ {
            pending["stop"] = v
          } else {
            vlans = append(vlans, pending)
            pending = make(M)
            pending["is_empty"] = 1
            pending["start"] = v
            pending["stop"] = v
            pending["rights"] = vlan_rights
            pending["ranges"] = vlan_ranges
          }
        }

        if v == vd_max_num {
          vlans = append(vlans, pending)
          pending = nil
        }
      }
    }

    out = vd
    out["vlans"] = vlans
    out["vdom_ranges"] = dbranges

    aux_userinfo := make(M)

    var fk_u_id string

    if fk_u_id, var_ok = out.UintString("fk_u_id"); var_ok && !aux_userinfo.Has(fk_u_id) {
      if aux_userinfo[fk_u_id], err = must_return_one_M(db, "SELECT * FROM us WHERE u_id=?", fk_u_id); err != nil { panic(err) }
    }

    for _, vlan := range vlans {
      if fk_u_id, var_ok = vlan.UintString("fk_u_id"); var_ok && !aux_userinfo.Has(fk_u_id) {
        if aux_userinfo[fk_u_id], err = must_return_one_M(db, "SELECT * FROM us WHERE u_id=?", fk_u_id); err != nil { panic(err) }
      }
    }

    var ranges_orig string

    for _, r := range dbranges {
      ranges_orig += fmt.Sprintf("%d:%d:%d ", r["vr_id"], r["vr_start"], r["vr_stop"])

      if fk_u_id, var_ok = r.UintString("fk_u_id"); var_ok && !aux_userinfo.Has(fk_u_id) {
        if aux_userinfo[fk_u_id], err = must_return_one_M(db, "SELECT * FROM us WHERE u_id=?", fk_u_id); err != nil { panic(err) }
      }
    }

    out["ranges_orig"] = ranges_orig

    out["aux_userinfo"] = aux_userinfo

  } else if action == "take_vlan" {
    var take_vlan uint64

    var ranges_orig string
    var vd_id string

    if take_vlan, err = get_p_uint64(q, "take_vlan"); err != nil { panic(err) }
    if ranges_orig, err = get_p_string(q, "ranges_orig", nil); err != nil { panic(err) }
    if vd_id, err = get_p_string(q, "vd_id", g_num_reg); err != nil { panic(err) }

    var vd M
    var vd_ranges []M

    tx, tx_err := db.Begin()
    if tx_err != nil { panic(tx_err) }
    var commited bool = false
    defer func() {
      if !commited {
        tx.Rollback()
      }
    } ()

    if vd, err = must_return_one_M(tx, "SELECT * FROM vds WHERE vd_id=?", vd_id); err != nil { panic(err) }

    if u64, var_ok = vd.Uint64("vd_max_num"); !var_ok { panic(PE) }
    if take_vlan == 0 || take_vlan > u64 { panic("Vlan out of range") }

    if u64, err = must_return_one_uint(tx, "SELECT COUNT(*) FROM vlans WHERE vlan_number=? AND vlan_fk_vd_id=?", take_vlan, vd_id);
    err != nil { panic(err) }

    if u64 > 0 { panic("VLAN уже занят, обновите страницу") }

    ranges_check := ""
    vlan_rights := g_vlans_rights

    query = "SELECT vrs.*"+
            ", IFNULL((SELECT BIT_OR(gvrr_rmask)"+
                       " FROM gvrrs WHERE gvrr_fk_g_id IN("+user_groups_in+")"+
                       " AND vr_id=gvrr_fk_vr_id"+
                       "), 0) AS rights"+
            " FROM vrs WHERE vr_fk_vd_id=? ORDER BY vr_id"

    if vd_ranges, err = return_query_A(tx, query, vd_id); err != nil { panic(err) }

    for i, r := range vd_ranges {
      ranges_check += fmt.Sprintf("%d:%d:%d ", r["vr_id"], r["vr_start"], r["vr_stop"])

      var r_start uint64
      var r_stop uint64
      var r_rights uint64

      if r_start, var_ok = r.Uint64("vr_start"); !var_ok { panic(PE) }
      if r_stop, var_ok = r.Uint64("vr_stop"); !var_ok { panic(PE) }
      if r_rights, var_ok = r.Uint64("rights"); !var_ok { panic(PE) }

      if r_start <= take_vlan && r_stop >= take_vlan {
        vlan_rights |= r_rights
        vd_ranges[i]["in_range"] = 1
      }
    }

    if ranges_check != ranges_orig {
      panic("В данные внесены изменения другим пользователем. Обновите страницу.")
    }

    if (vlan_rights & R_VIEW_NET_IPS) == 0 ||
       (vlan_rights & R_EDIT_IP_VLAN) == 0 ||
    false { panic(NoAccess()) }

    query = "INSERT INTO vlans SET"+
            " vlan_number=?"+
            ",vlan_fk_vd_id=?"+
            ",vlan_name=?"+
            ",ts=?"+
            ",fk_u_id=?"
    log_query := query

    if _, err = tx.Exec(query, take_vlan, vd_id, fmt.Sprintf("VLAN%04d", take_vlan), ts, user_id); err != nil { panic(err) }

    var row_data M
    if row_data, err = must_return_one_M(tx, "SELECT * FROM vlans WHERE vlan_number=? AND vlan_fk_vd_id=?", take_vlan, vd_id);
    err != nil { panic(err) }

    if err = audit_log(tx, "vlan", row_data["vlan_id"], log_query, nil, row_data); err != nil { panic(err) }

    vlan_ranges := make([]M, len(vd_ranges))
    for i, _ := range vd_ranges {
      vlan_ranges[i] = make(M)
      if _, var_ok = vd_ranges[i]["in_range"]; var_ok {
        vlan_ranges[i]["in_range"] = 1
      }
    }

    row_data["ranges"] = vlan_ranges
    row_data["rights"] = vlan_rights
    row_data["is_taken"] = 1


    if err = tx.Commit(); err != nil { panic(err) }
    commited = true


    out["row_data"] = row_data

  } else if action == "free_vlan" {
    var vlan_id string
    var vlan_number uint64
    var vlan M
    var vd_ranges []M

    if vlan_id, err = get_p_string(q, "id", g_num_reg); err != nil { panic(err) }

    if vlan, err = must_return_one_M(db, "SELECT * FROM vlans WHERE vlan_id=?", vlan_id); err != nil { panic(err) }

    if vlan_number, var_ok = vlan.Uint64("vlan_number"); !var_ok { panic(PE) }

    query = "SELECT vrs.*"+
            ", IFNULL((SELECT BIT_OR(gvrr_rmask)"+
                       " FROM gvrrs WHERE gvrr_fk_g_id IN("+user_groups_in+")"+
                       " AND vr_id=gvrr_fk_vr_id"+
                       "), 0) AS rights"+
            " FROM vrs WHERE vr_fk_vd_id=? ORDER BY vr_id"

    if vd_ranges, err = return_query_A(db, query, vlan["vlan_fk_vd_id"]); err != nil { panic(err) }

    vlan_rights := g_vlans_rights

    for _, r := range vd_ranges {
      var r_start uint64
      var r_stop uint64
      var r_rights uint64

      if r_start, var_ok = r.Uint64("vr_start"); !var_ok { panic(PE) }
      if r_stop, var_ok = r.Uint64("vr_stop"); !var_ok { panic(PE) }
      if r_rights, var_ok = r.Uint64("rights"); !var_ok { panic(PE) }

      if r_start <= vlan_number && r_stop >= vlan_number {
        vlan_rights |= r_rights
      }
    }

    if (vlan_rights & R_VIEW_NET_IPS) == 0 ||
       (vlan_rights & R_EDIT_IP_VLAN) == 0 ||
    false { panic(NoAccess()) }

    if _, err = db.Exec("DELETE FROM vlans WHERE vlan_id=?", vlan_id); err != nil { panic(err) }

    if err = audit_log(db, "vlan", vlan_id, "DELETE FROM vlans WHERE vlan_id=?", vlan, nil); err != nil { panic(err) }

    out["done"] = 1

  } else if action == "save_vdom_range" {

    if !user_is_admin { panic(NoAccess()) }

    var object_id string
    var rights map[string]string

    if object_id, err = get_p_string(q, "object_id", "^\\d*"); err != nil { panic(err) }
    if rights, err = get_p_map(q, "rights", g_num_reg); err != nil { panic(err) }

    var vd_id string

    var r_start uint64
    var r_stop uint64

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


    if vd_id, err = get_p_string(q, "vd_id", g_num_reg); err != nil { panic(err) }
    if r_start, err = get_p_uint64(q, "r_start"); err != nil { panic(err) }
    if r_stop, err = get_p_uint64(q, "r_stop"); err != nil { panic(err) }

    if r_start > r_stop { panic("Bad range") }

    var vd M
    if vd, err = must_return_one_M(tx, "SELECT * FROM vds WHERE vd_id=?", vd_id); err != nil { panic(err) }
    if u64, var_ok = vd.Uint64("vd_max_num"); !var_ok { panic(PE) }
    if r_stop > u64 { panic("Vlan out of range") }

    if object_id == "" {
      query = "INSERT INTO vrs SET"+
              " vr_start=?"+
              ",vr_stop=?"+
              ",vr_name=?"+
              ",vr_descr=?"+
              ",vr_style=?"+
              ",vr_icon=?"+
              ",vr_icon_style=?"+
              ",vr_fk_vd_id=?"+
              ",ts=?"+
              ",fk_u_id=?"
      if dbres, err = tx.Exec(query, r_start, r_stop, r_name, r_descr, r_style, r_icon, r_icon_style, vd_id, ts, user_id);
      err != nil { panic(err) }
      var lid int64

      if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
      if lid <= 0 { panic("weird LastInsertId returned") }

      object_id = strconv.FormatInt(lid, 10)

      if new_data, err = must_return_one_M(tx, "SELECT * FROM vrs WHERE vr_id=?", object_id); err != nil { panic(err) }
      if err = audit_log(tx, "vr", object_id, query, nil, new_data); err != nil { panic(err) }
    } else {
      if prev_data, err = must_return_one_M(tx, "SELECT * FROM vrs WHERE vr_id=?", object_id); err != nil { panic(err) }
      query = "UPDATE vrs SET"+
              " vr_start=?"+
              ",vr_stop=?"+
              ",vr_name=?"+
              ",vr_descr=?"+
              ",vr_style=?"+
              ",vr_icon=?"+
              ",vr_icon_style=?"+
              ",ts=?"+
              ",fk_u_id=?"+
              " WHERE vr_fk_vd_id=? AND vr_id=?"
      if _, err = tx.Exec(query, r_start, r_stop, r_name, r_descr, r_style, r_icon, r_icon_style, ts, user_id, vd_id, object_id);
      err != nil { panic(err) }

      if new_data, err = must_return_one_M(tx, "SELECT * FROM vrs WHERE vr_id=?", object_id); err != nil { panic(err) }
      if err = audit_log(tx, "vr", object_id, query, prev_data, new_data); err != nil { panic(err) }
    }

    query = "SELECT gvrr_rmask as rights"+
            ", gvrr_fk_g_id as g_id"+
            " FROM gvrrs"+
            " WHERE gvrr_fk_vr_id=?"

    var groups_rights M
    if groups_rights, err = return_query_M(tx, query, "g_id", object_id); err != nil { panic(err) }

    for g_id, m := range groups_rights {
      var current_rights string
      if current_rights, var_ok = m.(M).UintString("rights"); !var_ok { panic(PE) }

      if _, ex := rights[g_id]; !ex {
        // has to delete currently assigned right
        query = "DELETE FROM gvrrs"+
                " WHERE gvrr_fk_g_id=? AND gvrr_fk_vr_id=?"
        if _, err = tx.Exec(query, g_id, object_id); err != nil { panic(err) }
      } else if current_rights != rights[g_id] {
        query = "UPDATE gvrrs"+
                " SET gvrr_rmask=?"+
                ", ts=?, fk_u_id=?"+
                " WHERE gvrr_fk_g_id=? AND gvrr_fk_vr_id=?"
        if _, err = tx.Exec(query,  rights[g_id], ts, user_id, g_id, object_id); err != nil { panic(err) }
      }
    }

    for g_id, _ := range rights {
      if _, ex := groups_rights[g_id]; !ex {
        query = "INSERT INTO gvrrs"+
                " SET gvrr_rmask=?"+
                ", ts=?, fk_u_id=?"+
                ", gvrr_fk_g_id=?"+
                ", gvrr_fk_vr_id=?"
        if _, err = tx.Exec(query,  rights[g_id], ts, user_id, g_id, object_id); err != nil { panic(err) }
      }
    }

    if err = audit_log(tx, "vr", object_id, "set rights", groups_rights, rights); err != nil { panic(err) }

    out["done"] = 1

    err = tx.Commit()
    if err != nil { panic(err) }
    commited = true

  } else if action == "get_vdom_range" {
    var object_id string

    if object_id, err = get_p_string(q, "object_id", g_num_reg); err != nil { panic(err) }

    var vd_id string

    var rquery string

    user_ids := make([]string, 0)

    user_ids = append(user_ids, user_id)

    query = "SELECT * FROM vrs WHERE vr_id=?"
    if out, err = must_return_one_M(db, query, object_id); err != nil { panic(err) }


    var range_user_id string
    if range_user_id, var_ok = out.UintString("fk_i_ud"); var_ok {
      user_ids = append(user_ids, range_user_id)
    }

    if vd_id, var_ok = out.UintString("vr_fk_vd_id"); !var_ok { panic(PE) }

    var rows []M

    query = "SELECT BIT_OR(gvrr_rmask) as rights FROM gvrrs INNER JOIN vrs ON gvrr_fk_vr_id=vr_id"+
            " WHERE vr_fk_vd_id=? AND gvrr_fk_g_id IN("+user_groups_in+")"

    if rows, err = return_query_A(db, query, vd_id); err != nil { panic(err) }

    vd_rights := g_vlans_rights

    for _, row := range rows {
      var r_rights uint64
      if r_rights, var_ok = row.Uint64("rights"); !var_ok { panic(PE) }
      vd_rights |= r_rights
    }

    if (vd_rights & R_VIEW_NET_IPS) == 0 { panic(NoAccess()) }

    rquery = "SELECT gvrr_rmask as rights"+
             ", gvrr_fk_g_id as g_id"+
             ", ts"+
             ", fk_u_id"+
             " FROM gvrrs"+
             " WHERE gvrr_fk_vr_id=?"

    var groups M

    query = "SELECT g_id, g_name, g_descr FROM gs"
    if groups, err = return_query_M(db, query, "g_id"); err != nil { panic(err) }

    var aux_userinfo M

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

  } else if action == "del_vdom_range" {
    if !user_is_admin { panic(NoAccess()) }
    var object_id string

    if object_id, err = get_p_string(q, "object_id", g_num_reg); err != nil { panic(err) }

    if prev_data, err = must_return_one_M(db, "SELECT * FROM vrs WHERE vr_id=?", object_id); err != nil { panic(err) }
    if _, err = db.Exec("DELETE FROM vrs WHERE vr_id=?", object_id); err != nil { panic(err) }

    var prev_rights M
    query = "SELECT gvrr_fk_g_id as g_id, gvrr_rmask as rights FROM gvrrs WHERE gvrr_fk_vr_id=?"
    if prev_rights, err = return_query_M(db, query, "g_id", object_id); err != nil { panic(err) }

    prev_data.(M)["rights"] = prev_rights

    if err = audit_log(db, "vr", object_id, "DELETE FROM vrs WHERE vr_id=?", prev_data, nil); err != nil { panic(err) }
    out["done"] = 1

  } else if action == "del_vdom" {
    if !user_is_admin { panic(NoAccess()) }
    var object_id string

    if object_id, err = get_p_string(q, "object_id", g_num_reg); err != nil { panic(err) }

    if prev_data, err = must_return_one_M(db, "SELECT * FROM vds WHERE vd_id=?", object_id); err != nil { panic(err) }
    if _, err = db.Exec("DELETE FROM vds WHERE vd_id=?", object_id); err != nil {
      if strings.Index(err.Error(), "1451") >= 0 { panic("В домене есть VLANы. Удалите сперва их.") }
      panic(err)
    }

    if err = audit_log(db, "vd", object_id, "DELETE FROM vds WHERE vd_id=?", prev_data, nil); err != nil { panic(err) }
    out["done"] = 1

  } else if action == "add_vdom" {
    if !user_is_admin { panic(NoAccess()) }
    var name string

    if name, err = get_p_string(q, "name", "^[a-zA-Z][a-zA-Z0-9_]*$"); err != nil { panic(err) }

    if dbres, err = db.Exec("INSERT INTO vds SET vd_name=?, ts=?, fk_u_id=?", name, ts, user_id); err != nil { panic(err) }

    var lid int64

    if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
    if lid <= 0 { panic("weird LastInsertId returned") }

    if new_data, err = must_return_one_M(db, "SELECT * FROM vds WHERE vd_id=?", lid); err != nil { panic(err) }
    if err = audit_log(db, "vd", lid, "INSERT INTO vds SET vd_name=?, ts=?, fk_u_id=?", nil, new_data); err != nil { panic(err) }

    out["vd_id"] = lid

  } else if action == "get_fields" {

    var aux_userinfo M
    var ics M

    if aux_userinfo, err = return_query_M(db, "SELECT us.* FROM us WHERE u_id IN(SELECT fk_u_id FROM ics WHERE fk_u_id IS NOT NULL)", "u_id");
    err != nil { panic(err) }

    if aux_userinfo[user_id], err = must_return_one_M(db, "SELECT * FROM us WHERE u_id=?", user_id); err != nil { panic(err) }

    query = "SELECT ics.*"+
            ", CAST(((SELECT COUNT(*) FROM tcs WHERE tc_fk_ic_id = ic_id)+"+
               "(SELECT COUNT(*) FROM n4cs WHERE nc_fk_ic_id = ic_id)+"+
               "(SELECT COUNT(*) FROM n6cs WHERE nc_fk_ic_id = ic_id)"+
            ") AS UNSIGNED) as used"+
            " FROM ics"

    if ics, err = return_query_M(db, query, "ic_id"); err != nil { panic(err) }

    out["aux_userinfo"] = aux_userinfo
    out["ics"] = ics

  } else if action == "add_ic" {
    if !user_is_admin { panic(NoAccess()) }

    var ic_name string
    var ic_api_name string

    if ic_name, err = get_p_string(q, "ic_name", nil); err != nil { panic(err) }
    if ic_api_name, err = get_p_string(q, "ic_api_name", "^[a-z0-9_]+$"); err != nil { panic(err) }

    ic_name = strings.TrimSpace(ic_name)

    if ic_name == "" { panic("Bad ic_name") }

    query = "INSERT INTO ics SET ic_name=?, ic_api_name=?"+
            ", ic_sort=IFNULL((SELECT MAX(_ics.ic_sort) FROM ics as _ics)+1, 0)"+
            ", ts=?, fk_u_id=?"

    if dbres, err = db.Exec(query, ic_name, ic_api_name, ts, user_id); err != nil { panic(err) }

    var lid int64

    if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
    if lid <= 0 { panic("weird LastInsertId returned") }

    if new_data, err = must_return_one_M(db, "SELECT ics.*, CAST(0 AS UNSIGNED) as used FROM ics WHERE ic_id=?", lid);
    err != nil { panic(err) }

    if err = audit_log(db, "ic", lid, query, nil, new_data); err != nil { panic(err) }

    out["ic"] = new_data

  } else if action == "del_ic" {
    if !user_is_admin { panic(NoAccess()) }

    var ic_id string

    if ic_id, err = get_p_string(q, "ic_id", g_num_reg); err != nil { panic(err) }

    if prev_data, err = must_return_one_M(db, "SELECT * FROM ics WHERE ic_id=?", ic_id);
    err != nil { panic(err) }

    if _, err = db.Exec("DELETE FROM ics WHERE ic_id=?", ic_id); err != nil { panic(err) }
    if err = audit_log(db, "ic", ic_id, "DELETE FROM ics WHERE ic_id=?", prev_data, nil); err != nil { panic(err) }

    out["done"] = 1

  } else if action == "get_templates" {
    if !user_is_admin { panic(NoAccess()) }

    var aux_userinfo M
    var tps M

    if aux_userinfo, err = return_query_M(db, "SELECT us.* FROM us WHERE u_id IN(SELECT fk_u_id FROM tps WHERE fk_u_id IS NOT NULL)", "u_id");
    err != nil { panic(err) }

    if aux_userinfo[user_id], err = must_return_one_M(db, "SELECT * FROM us WHERE u_id=?", user_id); err != nil { panic(err) }

    query = "SELECT tps.*"+
            ",(SELECT GROUP_CONCAT(ic_id ORDER BY ic_id) FROM tcs INNER JOIN ics ON tc_fk_ic_id=ic_id WHERE tc_fk_tp_id=tp_id) as fields"+
            " FROM tps"

    if tps, err = return_query_M(db, query, "tp_id"); err != nil { panic(err) }

    out["aux_userinfo"] = aux_userinfo
    out["tps"] = tps

  } else if action == "add_tp" {
    if !user_is_admin { panic(NoAccess()) }

    var tp_name string

    if tp_name, err = get_p_string(q, "tp_name", nil); err != nil { panic(err) }

    tp_name = strings.TrimSpace(tp_name)

    if tp_name == "" { panic("Bad tp_name") }

    query = "INSERT INTO tps SET tp_name=?"+
            ", ts=?, fk_u_id=?"
    log_query := query

    if dbres, err = db.Exec(query, tp_name, ts, user_id); err != nil { panic(err) }

    var lid int64

    if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
    if lid <= 0 { panic("weird LastInsertId returned") }

    query = "INSERT INTO tcs(tc_fk_ic_id, tc_fk_tp_id, ts, fk_u_id) SELECT ic_id, ?, ?, ? FROM ics WHERE ic_default > 0"
    if _, err = db.Exec(query, lid, ts, user_id); err != nil { panic(err) }

    query = "SELECT tps.*"+
            ",(SELECT GROUP_CONCAT(ic_id ORDER BY ic_id) FROM tcs INNER JOIN ics ON tc_fk_ic_id=ic_id WHERE tc_fk_tp_id=tp_id) as fields"+
            " FROM tps WHERE tp_id=?"
    if out["tp"], err = must_return_one_M(db, query, lid); err != nil { panic(err) }

    if err = audit_log(db, "tp", lid, log_query, nil, out["tp"]); err != nil { panic(err) }

  } else if action == "del_tp" {
    if !user_is_admin { panic(NoAccess()) }

    var tp_id string

    if tp_id, err = get_p_string(q, "tp_id", g_num_reg); err != nil { panic(err) }

    if prev_data, err = must_return_one_M(db, "SELECT * FROM tps WHERE tp_id=?", tp_id); err != nil { panic(err) }

    if _, err = db.Exec("DELETE FROM tps WHERE tp_id=?", tp_id); err != nil { panic(err) }
    if err = audit_log(db, "tp", tp_id, "DELETE FROM tps WHERE tp_id=?", prev_data, nil); err != nil { panic(err) }

    out["done"] = 1

  } else if action == "get_tags" {

    users_index := make(map[string]bool)

    var dbtags []M
    query = "SELECT tags.*"+
            ", CAST(("+
            " (SELECT COUNT(*) FROM v4nets WHERE FIND_IN_SET(tag_id,v4net_tags))+"+
            " (SELECT COUNT(*) FROM v6nets WHERE FIND_IN_SET(tag_id,v6net_tags))+"+
            " (SELECT COUNT(*) FROM v4oobs WHERE FIND_IN_SET(tag_id,v4oob_tags))+"+
            " (SELECT COUNT(*) FROM v6oobs WHERE FIND_IN_SET(tag_id,v6oob_tags))+"+
            " (SELECT COUNT(*) FROM i4vs INNER JOIN ics ON iv_fk_ic_id=ic_id WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " (SELECT COUNT(*) FROM i6vs INNER JOIN ics ON iv_fk_ic_id=ic_id WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " 0) AS UNSIGNED) AS used"+
            ", IFNULL((SELECT BIT_OR(tgr_rmask) FROM tgrs WHERE tgr_fk_g_id IN("+user_groups_in+") AND tgr_fk_tag_id=tag_id"+
                      " GROUP BY tgr_fk_tag_id), CAST(0 AS UNSIGNED)) as rights"+
            " FROM tags ORDER BY tag_sort"
    if dbtags, err = return_query_A(db, query); err != nil { panic(err) }

    tags_groups_rights := make(M)

    var groups_rights_rows []M
    query = "SELECT tgr_fk_tag_id, tgr_fk_g_id, tgr_rmask, ts, fk_u_id FROM tgrs ORDER BY tgr_fk_g_id"
    if groups_rights_rows, err = return_query_A(db, query); err != nil { panic(err) }

    for _, row := range groups_rights_rows {
      var tag_id string
      if tag_id, var_ok = row.UintString("tgr_fk_tag_id"); !var_ok { panic(PE) }
      var g_id string
      if g_id, var_ok = row.UintString("tgr_fk_g_id"); !var_ok { panic(PE) }
      var rights string
      if rights, var_ok = row.UintString("tgr_rmask"); !var_ok { panic(PE) }
      m := make(M)

      m["g_id"] = g_id
      m["rights"] = rights
      m["ts"] = row["ts"]
      m["fk_u_id"] = row["fk_u_id"]

      if _, ex := tags_groups_rights[tag_id]; !ex {
        tags_groups_rights[tag_id] = make([]M, 0)
      }

      tags_groups_rights[tag_id] = append(tags_groups_rights[tag_id].([]M), m)
    }

    dbtags_index := make(map[string]int)

    root_tags := make([]int, 0)

    tags_list := make([]M, len(dbtags))

    for i, dbtag := range dbtags {

      tags_list[i] = make(M)

      var tag_id string
      if tag_id, var_ok = dbtag.UintString("tag_id"); !var_ok { panic(fmt.Sprint("no tag_id in", dbtag)) }
      tags_list[i]["id"] = tag_id

      var parent_id string
      if parent_id, var_ok = dbtag.UintString("tag_parent_id"); !var_ok { panic(fmt.Sprint("no parent_tag_id in", dbtag)) }
      dbtag["_parent_id"] = parent_id

      dbtags_index[tag_id] = i

      tag_data := make(M)

      tag_data["fk_u_id"] = dbtag["fk_u_id"]
      tag_data["ts"] = dbtag["ts"]
      tag_data["name"] = dbtag["tag_name"]
      tag_data["descr"] = dbtag["tag_descr"]
      tag_data["options"] = dbtag["tag_options"]
      tag_data["flags"] = dbtag["tag_flags"]
      tag_data["api_name"] = dbtag["tag_api_name"]

      tag_data["orig_name"] = dbtag["tag_name"]
      tag_data["orig_descr"] = dbtag["tag_descr"]
      tag_data["orig_options"] = dbtag["tag_options"]
      tag_data["orig_flags"] = dbtag["tag_flags"]
      tag_data["orig_api_name"] = dbtag["tag_api_name"]

      if u64, var_ok = dbtag.Uint64("used"); !var_ok { panic(PE) }
      tag_data["used"] = u64
      tag_data["used_children"] = uint64(0)

      if _, ex := tags_groups_rights[tag_id]; !ex {
        tag_data["groups_rights"] = make([]interface{}, 0)
        tag_data["orig_groups_rights"] = make([]interface{}, 0)
      } else {
        tag_data["groups_rights"] = tags_groups_rights[tag_id]
        tag_data["orig_groups_rights"] = tags_groups_rights[tag_id]
      }

      var tag_rights uint64
      if tag_rights, var_ok = dbtag.Uint64("rights"); !var_ok { panic(PE) }

      tag_rights |= g_tags_rights

      tag_data["rights"] = tag_rights

      if parent_id == "0" {
        if (tag_rights & R_VIEW_NET_IPS) > 0 {
          root_tags = append(root_tags, i)
        }
      }

      if _, ex := tags_list[i]["children"]; !ex {
        tags_list[i]["children"] = make([]M, 0)
      }

      tags_list[i]["data"] = tag_data
      tag_text := dbtag["tag_name"].(string)
      if dbtag["tag_api_name"] != nil {
        tag_text += " ("+dbtag["tag_api_name"].(string)+")"
      }
      tags_list[i]["text"] = tag_text
    }


    for i, dbtag := range dbtags {
      parent_id := dbtag["_parent_id"].(string)

      if parent_index, ex := dbtags_index[parent_id]; ex {
        parent := tags_list[parent_index]

        parent["children"] = append(parent["children"].([]M), tags_list[i])
      }
    }

    var traverse_tree func(M,uint64,int) (uint64, error)
    traverse_tree = func(t M, parent_rights uint64, c int) (uint64, error) {
      if c > MAX_TREE_LEN { return 0, errors.New("Tags loop detected") }
      used_children := uint64(0)
      t["data"].(M)["rights"] = t["data"].(M)["rights"].(uint64) | parent_rights
      for _, child := range t["children"].([]M) {
        if fk_u_id, _ := child["data"].(M).UintString("fk_u_id"); fk_u_id != "" { users_index[fk_u_id] = true }
        if child_used, e := traverse_tree(child, t["data"].(M)["rights"].(uint64), c+1); e != nil {
          return 0, e
        } else {
          used_children += child_used
        }
      }
      t["data"].(M)["used_children"] = used_children
      return used_children+t["data"].(M)["used"].(uint64), nil
    }

    tags := make(M)
    tags["children"] = make([]M, 0)

    tags["data"] = make(M)
    tags["data"].(M)["rights"] = uint64(g_tags_rights)

    tags["data"].(M)["flags"] = F_ALLOW_LEAFS | F_DENY_SELECT

    for _, root_tag_index := range root_tags {
      tags_list[root_tag_index]["type"] = "root"
      tags["children"] = append(tags["children"].([]M), tags_list[root_tag_index])
      if _, err = traverse_tree(tags_list[root_tag_index], 0, 0); err != nil { panic(err) }
    }

    user_ids := make([]string, len(users_index))
    i := 0
    for fk_u_id, _ := range users_index {
      user_ids[i] = fk_u_id
      i++
    }

    var aux_userinfo M

    if len(user_ids) > 0 {
      if aux_userinfo, err = return_query_M(db, "SELECT * FROM us WHERE u_id IN("+strings.Join(user_ids, ",")+")", "u_id");
      err != nil { panic(err) }
    } else {
      aux_userinfo = make(M)
    }
    aux_userinfo[user_id] = user_row

    out["aux_userinfo"] = aux_userinfo
    out["tags"] = tags
    if out["gs"], err = return_query_M(db, "SELECT * FROM gs", "g_id"); err != nil { panic(err) }

  } else if action == "set_tag_descr" || action == "rename_tag" || action == "set_tag_flags" || action == "set_tag_options" {
    var tag_id string
    if tag_id, err = get_p_string(q, "id", g_num_reg); err != nil { panic(err) }

    var tag M
    if tag, err = get_tag(db, tag_id); err != nil { panic(err) }

    var tag_rights uint64
    if tag_rights, err = get_tag_rights(db, tag_id, 0); err != nil { panic(err) }

    var parent_rights uint64 = g_tags_rights
    if tag["tag_fk_tag_id"] != nil {
      parent_id, _ := tag.UintString("tag_fk_tag_id")
      if parent_rights, err = get_tag_rights(db, parent_id, 0); err != nil { panic(err) }
    }

    if (parent_rights & R_EDIT_IP_VLAN) == 0 { panic(NoAccess()) }

    can_manage := (tag_rights & R_MANAGE_NET) > 0

    update_fields := make(M)

    if action == "set_tag_descr" {
      var tag_value interface{}
      if tag_value, err = get_p_string(q, "descr", nil); err != nil { panic(err) }

      update_fields["tag_descr"] = tag_value
    } else if action == "set_tag_options" {
      if !can_manage { panic("Только менеджер может менять опции") }
      var tag_value interface{}
      if tag_value, err = get_p_string(q, "options", nil); err != nil { panic(err) }

      update_fields["tag_options"] = tag_value
    } else if action == "rename_tag" {

      var used uint64
      if used, err = tag_usage(db, tag_id, 0); err != nil { panic(PE) }

      if used > 0 && !can_manage { panic("Только менеджер может переименовывать используемые теги") }

      var tag_value interface{}
      if tag_value, err = get_p_string(q, "name", "^\\S"); err != nil { panic(err) }

      update_fields["tag_name"] = tag_value

      tag_value = nil
      if q["api_name"] != nil {
        if tag_value, err = get_p_string(q, "api_name", g_api_name_reg); err != nil { panic(err) }
      }

      if tag["tag_api_name"] != tag_value && !can_manage {
        panic("API имя может менять только менеджер")
      }

      update_fields["tag_api_name"] = tag_value
    } else if action == "set_tag_flags" {

      if !can_manage { panic("Только менеджер может менять флаги") }

      var tag_value interface{}
      if tag_value, err = get_p_string(q, "flags", g_num_reg); err != nil { panic(err) }

      update_fields["tag_flags"] = tag_value
    } else {
      panic(PE)
    }

    if err = update_tag(db, tag_id, update_fields); err != nil { panic(err) }

    out["done"] = 1

  } else if action == "del_tag" {
    var tag_id string
    if tag_id, err = get_p_string(q, "id", g_num_reg); err != nil { panic(err) }

    var tag M
    if tag, err = get_tag(db, tag_id); err != nil { panic(err) }

    var tag_rights uint64
    if tag_rights, err = get_tag_rights(db, tag_id, 0); err != nil { panic(err) }

    var parent_rights uint64 = g_tags_rights
    if tag["tag_fk_tag_id"] != nil {
      parent_id, _ := tag.UintString("tag_fk_tag_id")
      if parent_rights, err = get_tag_rights(db, parent_id, 0); err != nil { panic(err) }
    }

    if (parent_rights & R_EDIT_IP_VLAN) == 0 { panic(NoAccess()) }

    can_manage := (tag_rights & R_MANAGE_NET) > 0

    var used uint64
    if used, err = tag_usage(db, tag_id, 0); err != nil { panic(PE) }

    if used > 0 && !can_manage { panic("Только менеджер может удалять используемые теги") }

    //check rights for affected objects
    //nets v4

    var rows []M

    del_from_ips := make(map[string]map[string]string)
    del_from_ips["4"] = make(map[string]string)
    del_from_ips["6"] = make(map[string]string)

    del_from_nets := make(map[string]map[string]string)
    del_from_nets["4"] = make(map[string]string)
    del_from_nets["6"] = make(map[string]string)

    del_from_oobs := make(map[string]map[string]string)
    del_from_oobs["4"] = make(map[string]string)
    del_from_oobs["6"] = make(map[string]string)

    for _, v := range [...]string{"4","6"} {
      query = "SELECT v"+v+"net_id as net_id, v"+v+"net_tags as tags FROM v"+v+"nets WHERE FIND_IN_SET(?,v"+v+"net_tags) > 0"
      if rows, err = return_query_A(db, query, tag_id); err != nil { panic(err) }

      for _, row := range rows {
        var net_id string
        if net_id, var_ok = row.UintString("net_id"); !var_ok { panic(PE) }

        var net_rights uint64
        if net_rights, _, err = get_net_rights(db, net_id, v, nil); err != nil { panic(err) }

        if (net_rights & R_MANAGE_NET) == 0 { panic("Тег связан с сетью, к которой у Вас нет доступа на изменение. v"+v+"net_id="+net_id) }

        del_from_nets[v][net_id] = row["tags"].(string)
      }

      query = "SELECT v"+v+"oob_id as oob_id, v"+v+"oob_tags as tags FROM v"+v+"oobs WHERE FIND_IN_SET(?,v"+v+"oob_tags) > 0"
      if rows, err = return_query_A(db, query, tag_id); err != nil { panic(err) }

      for _, row := range rows {
        var oob_id string
        if oob_id, var_ok = row.UintString("oob_id"); !var_ok { panic(PE) }

        if !user_is_admin {
          panic("Тег связан с внешним объектом, к которому у Вас нет доступа.")
        }

        del_from_oobs[v][oob_id] = row["tags"].(string)
      }

      query = "SELECT iv_fk_v"+v+"ip_id as ip_id, iv_id, iv_value FROM i"+v+"vs INNER JOIN ics ON iv_fk_ic_id=ic_id WHERE (ic_type='tag' OR ic_type='multitag')"+
              " AND FIND_IN_SET(?,iv_value) > 0"

      if rows, err = return_query_A(db, query, tag_id); err != nil { panic(err) }

      for _, row := range rows {
        var ip_id string
        if ip_id, var_ok = row.UintString("ip_id"); !var_ok { panic(PE) }

        var iv_id string
        if iv_id, var_ok = row.UintString("iv_id"); !var_ok { panic(PE) }

        var ip_rights uint64
        if ip_rights, _, err = get_ip_rights(db, ip_id, v, nil); err != nil { panic(err) }

        if (ip_rights & R_EDIT_IP_VLAN) == 0 ||
           (ip_rights & R_VIEW_NET_IPS) == 0 ||
           ((ip_rights & R_DENYIP) > 0 &&
            (ip_rights & R_IGNORE_R_DENY) == 0) ||
        false { panic("Тег связан с IP, к которому у Вас нет доступа на изменение. v"+v+"ip_id="+ip_id) }

        del_from_ips[v][iv_id] = row["iv_value"].(string)
      }


    } //4,6

//
    var delete_tag_tree func(interface{}, interface{}, int) (error)
    delete_tag_tree = func(db interface{}, tag_id interface{}, counter int) (error) {
      if counter > MAX_TREE_LEN { return errors.New("Tag tree loop detected") }
      query = "SELECT tag_id FROM tags WHERE tag_fk_tag_id=?"
      var rows [][]interface{}
      var err error
      if rows, err = return_arrays(db, query, tag_id); err != nil { return err }
      for _, row := range rows {
        if err = delete_tag_tree(db, row[0], counter + 1); err != nil { return err }
      }

      if prev_data, err = must_return_one_M(db, "SELECT * FROM tags WHERE tag_id=?", tag_id); err != nil { return err }
      query = "DELETE FROM tags WHERE tag_id=?"
      if _, err = db_exec(db, query, tag_id); err != nil { return err }
      if err = audit_log(db, "tag", tag_id, query, prev_data, nil); err != nil { return err }

      return nil
    }

    if err = delete_tag_tree(db, tag_id, 0); err != nil { panic(err) }

    for _, v := range [...]string{"4","6"} {
      for id, old_value := range del_from_ips[v] {
        list := strings.Split(old_value, ",")
        index := slices.Index(list, tag_id)
        if index < 0 { panic(PE) }
        list = slices.Delete(list, index, index+1)

        query = "UPDATE i"+v+"vs SET"+
                " iv_value=?"+
                ",ts=?"+
                ",fk_u_id=?"+
                " WHERE iv_id=?"
        if _, err = db.Exec(query, strings.Join(list, ","), ts, user_id, id); err != nil { panic(err) }
      }

      for id, old_value := range del_from_nets[v] {
        list := strings.Split(old_value, ",")
        index := slices.Index(list, tag_id)
        if index < 0 { panic(PE) }
        list = slices.Delete(list, index, index+1)

        query = "UPDATE v"+v+"nets SET"+
                " v"+v+"net_tags=?"+
                ",ts=?"+
                ",fk_u_id=?"+
                " WHERE v"+v+"net_id=?"
        if _, err = db.Exec(query, strings.Join(list, ","), ts, user_id, id); err != nil { panic(err) }
      }

      for id, old_value := range del_from_nets[v] {
        list := strings.Split(old_value, ",")
        index := slices.Index(list, tag_id)
        if index < 0 { panic(PE) }
        list = slices.Delete(list, index, index+1)

        query = "UPDATE v"+v+"oobs SET"+
                " v"+v+"oob_tags=?"+
                ",ts=?"+
                ",fk_u_id=?"+
                " WHERE v"+v+"oob_id=?"
        if _, err = db.Exec(query, strings.Join(list, ","), ts, user_id, id); err != nil { panic(err) }
      }
    }

    out["done"] = 1

  } else if action == "add_tag" {
    var parent_id string
    if parent_id, err = get_p_string(q, "parent_id", "^(?:\\d+|#)$"); err != nil { panic(err) }

    var tag_name string
    if tag_name, err = get_p_string(q, "name", "^\\S"); err != nil { panic(err) }

    var tag_descr string
    if tag_descr, err = get_p_string(q, "descr", nil); err != nil { panic(err) }

    var tag_api_name interface{} = nil
    if q["api_name"] != nil {
      if tag_api_name, err = get_p_string(q, "api_name", g_api_name_reg); err != nil { panic(err) }
    }

    var tag_temp_id string
    if tag_temp_id, err = get_p_string(q, "temp_id", "^\\S+$"); err != nil { panic(err) }

    var sort map[string]string
    if sort, err = get_p_map(q, "sort", g_num_reg); err != nil { panic(err) }

    var p_id interface{}
    var tag_parent_id string

    var parent_flags uint64
    var parent_rights uint64

    if parent_id == "#" {
      tag_parent_id = "0"
      p_id = nil

      parent_flags = F_ALLOW_LEAFS
      parent_rights = g_tags_rights

    } else {
      tag_parent_id = parent_id
      p_id = parent_id

      var parent_node M
      if parent_node, err = get_tag(db, parent_id); err != nil { panic(err) }

      if parent_flags, var_ok = parent_node.Uint64("tag_flags"); !var_ok { panic(PE) }

      if parent_rights, err = get_tag_rights(db, parent_id, 0); err != nil { panic(err) }

    }

    if (parent_flags & F_ALLOW_LEAFS) == 0 { panic("Родительский тег не допускает создание потомков. Проверьте флаги") }
    if (parent_rights & R_EDIT_IP_VLAN) == 0 { panic(NoAccess()) }

    var flags interface {}

    var rows []M

    query = "SELECT tag_flags FROM tags WHERE tag_parent_id=?"
    if rows, err = return_query_A(db, query, tag_parent_id); err != nil { panic(err) }

    for _, row := range rows {
      if u64, var_ok = row.Uint64("tag_flags"); !var_ok { panic(PE) }
      if flags == nil {
        flags = u64
      } else {
        flags = flags.(uint64) & u64
      }
    }

    if flags == nil { flags = uint64(0) }

    query = "INSERT INTO tags SET"+
            " tag_name=?"+
            ",tag_descr=?"+
            ",tag_api_name=?"+
            ",tag_flags=?"+
            ",tag_fk_tag_id=?"+
            ",tag_parent_id=?"+
            ",ts=?"+
            ",fk_u_id=?"
    log_query := query
    if dbres, err = db.Exec(query, tag_name, tag_descr, tag_api_name, flags, p_id, tag_parent_id, ts, user_id);
    err != nil { panic(err) }

    var lid int64

    if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
    if lid <= 0 { panic("weird LastInsertId returned") }

    new_tag_id := strconv.FormatInt(lid, 10)

    var tag_index string
    if tag_index, var_ok = sort[tag_temp_id]; !var_ok { panic(PE) }

    delete(sort, tag_temp_id)
    sort[new_tag_id] = tag_index

    query = "UPDATE tags SET tag_sort=? WHERE tag_id=?"
    for tag_id, tag_sort := range sort {
      if _, err = db.Exec(query, tag_sort, tag_id); err != nil { panic(err) }
    }

    if new_data, err = must_return_one_M(db, "SELECT * FROM tags WHERE tag_id=?", new_tag_id); err != nil { panic(err) }
    if err = audit_log(db, "tag", new_tag_id, log_query, nil, new_data); err != nil { panic(err) }

    out["done"] = 1
    out["new_id"] = new_tag_id
    out["flags"] = flags

  } else if action == "move_tag" {
    var tag_id string
    if tag_id, err = get_p_string(q, "id", g_num_reg); err != nil { panic(err) }

    var new_parent_id interface{}
    if new_parent_id, err = get_p_string(q, "new_parent", "^(?:\\d+|#)$"); err != nil { panic(err) }
    if new_parent_id.(string) == "#" {
      new_parent_id = nil
    }

    var sort map[string]string
    if sort, err = get_p_map(q, "sort", g_num_reg); err != nil { panic(err) }

    var tag M
    if tag, err = get_tag(db, tag_id); err != nil { panic(err) }

    if (tag["tag_fk_tag_id"] == nil && new_parent_id != nil) ||
       (tag["tag_fk_tag_id"] != nil && new_parent_id == nil) {
      panic("Нельзя перемещать коллекции внутрь друг друга")
    }

    var old_parent_rights uint64

    if tag["tag_fk_tag_id"] != nil {
      if old_parent_rights, err = get_tag_rights(db, tag["tag_fk_tag_id"], 0); err != nil { panic(err) }
    } else {
      old_parent_rights = g_tags_rights
    }

    if (old_parent_rights & R_EDIT_IP_VLAN) == 0 { panic(NoAccess()) }

    var new_parent_rights uint64

    if new_parent_id != nil {
      if new_parent_rights, err = get_tag_rights(db, new_parent_id, 0); err != nil { panic(err) }
    } else {
      new_parent_rights = g_tags_rights
    }

    if (new_parent_rights & R_EDIT_IP_VLAN) == 0 { panic(NoAccess()) }

    var old_parent_id interface{}
    if tag["tag_fk_tag_id"] != nil {
      old_parent_id, _ = tag.UintString("tag_fk_tag_id")
    } else {
      old_parent_id = nil
    }

    if old_parent_id != new_parent_id {
      if (new_parent_rights & R_MANAGE_NET) == 0 {
        panic(fmt.Errorf("Переносить между ветками может только менеджер (%v,%v)", tag["tag_fk_tag_id"], new_parent_id))
      }
      if (old_parent_rights & R_MANAGE_NET) == 0 {
        panic(fmt.Errorf("Переносить между ветками может только менеджер (%v,%v)", tag["tag_fk_tag_id"], new_parent_id))
      }

      var new_parent_tag M
      if new_parent_tag, err = get_tag(db, new_parent_id); err != nil { panic(err) }

      var new_parent_flags uint64
      if new_parent_flags, var_ok = new_parent_tag.Uint64("tag_flags"); !var_ok { panic(PE) }

      if (new_parent_flags & F_ALLOW_LEAFS) == 0 { panic("Целевой тег не допускает дочерних") }

      var current_root M
      if current_root, err = get_root_tag(db, tag_id, 0); err != nil { panic(err) }

      var new_root M
      if new_root, err = get_root_tag(db, new_parent_id, 0); err != nil { panic(err) }

      if current_root["tag_id"] != new_root["tag_id"] {
        panic("Нельзя перемещать теги между коллекциями")
      }

      query = "UPDATE tags SET tag_fk_tag_id=?, tag_parent_id=IFNULL(?, 0), ts=?, fk_u_id=? WHERE tag_id=?"
      if _, err = db.Exec(query, new_parent_id, new_parent_id, ts, user_id, tag_id); err != nil { panic(err) }

      if err = audit_log(db, "tag", tag_id, query, old_parent_id, new_parent_id); err != nil { panic(err) }

      if _, err = db.Exec("UPDATE tags SET ts=?, fk_u_id=? WHERE tag_id=?", ts, user_id, new_parent_id); err != nil { panic(err) }
      if _, err = db.Exec("UPDATE tags SET ts=?, fk_u_id=? WHERE tag_id=?", ts, user_id, tag["tag_fk_tag_id"]); err != nil { panic(err) }
    }

    query = "UPDATE tags SET tag_sort=? WHERE tag_id=?"
    for tag_id, tag_sort := range sort {
      if _, err = db.Exec(query, tag_sort, tag_id); err != nil { panic(err) }
    }

    out["done"] = 1
  } else if action == "set_tag_rights" {
    var tag_id string
    if tag_id, err = get_p_string(q, "id", g_num_reg); err != nil { panic(err) }

    var new_rights map[string]string
    if new_rights, err = get_p_map(q, "rights", g_num_reg); err != nil { panic(err) }

    var tag_rights uint64
    if tag_rights, err = get_tag_rights(db, tag_id, 0); err != nil { panic(err) }

    if (tag_rights & R_MANAGE_NET) == 0 { panic(NoAccess()) }

    query = "SELECT tgr_fk_g_id as g_id, tgr_rmask as rights FROM tgrs WHERE tgr_fk_tag_id=?"
    var current_rights M

    if current_rights, err = return_query_M(db, query, "g_id", tag_id); err != nil { panic(err) }

    for g_id, _ := range new_rights {
      if _, ex := current_rights[g_id]; !ex {
        query = "INSERT INTO tgrs(tgr_fk_tag_id, tgr_fk_g_id, tgr_rmask, ts, fk_u_id) VALUES(?,?,?,?,?)"
        if _, err = db.Exec(query, tag_id, g_id, new_rights[g_id], ts, user_id); err != nil { panic(err) }
      } else {
        var current_right string
        if current_right, var_ok = current_rights[g_id].(M).UintString("rights"); !var_ok { panic(PE) }
        if current_right != new_rights[g_id] {
          query = "UPDATE tgrs SET tgr_rmask=?, ts=?, fk_u_id=? WHERE tgr_fk_g_id=? AND tgr_fk_tag_id=?"
          if _, err = db.Exec(query, new_rights[g_id], ts, user_id, g_id, tag_id); err != nil { panic(err) }
        }
      }
    }

    for g_id, _ := range current_rights {
      if _, ex := new_rights[g_id]; !ex {
        if _, err = db.Exec("DELETE FROM tgrs WHERE tgr_fk_g_id=? AND tgr_fk_tag_id=?", g_id, tag_id); err != nil { panic(err) }
      }
    }

    if err = audit_log(db, "tag", tag_id, "set rights", current_rights, new_rights); err != nil { panic(err) }

    out["done"] = 1

  } else if action == "get_tags_subtree" {
    var root_api_name interface{} = nil
    if v, ex := q["root_api_name"]; ex && v != nil {
      if root_api_name, err = get_p_string(q, "root_api_name", g_api_name_reg); err != nil { panic(err) }
    } else {
      if !ex { panic("No root_api_name in query") }
    }

    users_index := make(map[string]bool)

    var dbtags []M
    query = "SELECT tags.*"+
            ", CAST(("+
            " (SELECT COUNT(*) FROM v4nets WHERE FIND_IN_SET(tag_id,v4net_tags))+"+
            " (SELECT COUNT(*) FROM v6nets WHERE FIND_IN_SET(tag_id,v6net_tags))+"+
            " (SELECT COUNT(*) FROM v4oobs WHERE FIND_IN_SET(tag_id,v4oob_tags))+"+
            " (SELECT COUNT(*) FROM v6oobs WHERE FIND_IN_SET(tag_id,v6oob_tags))+"+
            " (SELECT COUNT(*) FROM i4vs INNER JOIN ics ON iv_fk_ic_id=ic_id WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " (SELECT COUNT(*) FROM i6vs INNER JOIN ics ON iv_fk_ic_id=ic_id WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " 0) AS UNSIGNED) AS used"+
            ", IFNULL((SELECT BIT_OR(tgr_rmask) FROM tgrs WHERE tgr_fk_g_id IN("+user_groups_in+") AND tgr_fk_tag_id=tag_id"+
                      " GROUP BY tgr_fk_tag_id), CAST(0 AS UNSIGNED)) as rights"+
            " FROM tags ORDER BY tag_sort"
    if dbtags, err = return_query_A(db, query); err != nil { panic(err) }

    tags_groups_rights := make(M)

    var groups_rights_rows []M
    query = "SELECT tgr_fk_tag_id, tgr_fk_g_id, tgr_rmask, ts, fk_u_id FROM tgrs ORDER BY tgr_fk_g_id"
    if groups_rights_rows, err = return_query_A(db, query); err != nil { panic(err) }

    for _, row := range groups_rights_rows {
      var tag_id string
      if tag_id, var_ok = row.UintString("tgr_fk_tag_id"); !var_ok { panic(PE) }
      var g_id string
      if g_id, var_ok = row.UintString("tgr_fk_g_id"); !var_ok { panic(PE) }
      var rights string
      if rights, var_ok = row.UintString("tgr_rmask"); !var_ok { panic(PE) }
      m := make(M)

      m["g_id"] = g_id
      m["rights"] = rights
      m["ts"] = row["ts"]
      m["fk_u_id"] = row["fk_u_id"]

      if _, ex := tags_groups_rights[tag_id]; !ex {
        tags_groups_rights[tag_id] = make([]M, 0)
      }

      tags_groups_rights[tag_id] = append(tags_groups_rights[tag_id].([]M), m)
    }

    dbtags_index := make(map[string]int)

    api_name_index := make(map[string]int)

    root_tags := make([]int, 0)

    tags_list := make([]M, len(dbtags))

    for i, dbtag := range dbtags {

      tags_list[i] = make(M)

      var tag_id string
      if tag_id, var_ok = dbtag.UintString("tag_id"); !var_ok { panic(fmt.Sprint("no tag_id in", dbtag)) }
      tags_list[i]["id"] = tag_id

      var parent_id string
      if parent_id, var_ok = dbtag.UintString("tag_parent_id"); !var_ok { panic(fmt.Sprint("no parent_tag_id in", dbtag)) }
      dbtag["_parent_id"] = parent_id

      dbtags_index[tag_id] = i

      if dbtag["tag_api_name"] != nil {
        api_name_index[ dbtag["tag_api_name"].(string) ] = i
      }

      tag_data := make(M)

      tag_data["fk_u_id"] = dbtag["fk_u_id"]
      tag_data["ts"] = dbtag["ts"]
      tag_data["name"] = dbtag["tag_name"]
      tag_data["descr"] = dbtag["tag_descr"]
      tag_data["options"] = dbtag["tag_options"]
      tag_data["flags"] = dbtag["tag_flags"]
      tag_data["api_name"] = dbtag["tag_api_name"]

      tag_data["orig_name"] = dbtag["tag_name"]
      tag_data["orig_descr"] = dbtag["tag_descr"]
      tag_data["orig_options"] = dbtag["tag_options"]
      tag_data["orig_flags"] = dbtag["tag_flags"]
      tag_data["orig_api_name"] = dbtag["tag_api_name"]

      if u64, var_ok = dbtag.Uint64("used"); !var_ok { panic(PE) }
      tag_data["used"] = u64
      tag_data["used_children"] = uint64(0)

      if _, ex := tags_groups_rights[tag_id]; !ex {
        tag_data["groups_rights"] = make([]interface{}, 0)
        tag_data["orig_groups_rights"] = make([]interface{}, 0)
      } else {
        tag_data["groups_rights"] = tags_groups_rights[tag_id]
        tag_data["orig_groups_rights"] = tags_groups_rights[tag_id]
      }

      var tag_rights uint64
      if tag_rights, var_ok = dbtag.Uint64("rights"); !var_ok { panic(PE) }

      tag_rights |= g_tags_rights

      tag_data["rights"] = tag_rights

      if parent_id == "0" {
        if (tag_rights & R_VIEW_NET_IPS) > 0 {
          root_tags = append(root_tags, i)
        }
      }

      if _, ex := tags_list[i]["children"]; !ex {
        tags_list[i]["children"] = make([]M, 0)
      }

      tags_list[i]["data"] = tag_data
      tag_text := dbtag["tag_name"].(string)
      if dbtag["tag_api_name"] != nil {
        tag_text += " ("+dbtag["tag_api_name"].(string)+")"
      }
      tags_list[i]["text"] = tag_text
    }


    for i, dbtag := range dbtags {
      parent_id := dbtag["_parent_id"].(string)

      if parent_index, ex := dbtags_index[parent_id]; ex {
        parent := tags_list[parent_index]

        parent["children"] = append(parent["children"].([]M), tags_list[i])
      }
    }

    var traverse_tree func(M,uint64,int) (uint64, error)
    traverse_tree = func(t M, parent_rights uint64, c int) (uint64, error) {
      if c > MAX_TREE_LEN { return 0, errors.New("Tags loop detected") }
      used_children := uint64(0)
      t["data"].(M)["rights"] = t["data"].(M)["rights"].(uint64) | parent_rights
      for _, child := range t["children"].([]M) {
        if fk_u_id, _ := child["data"].(M).UintString("fk_u_id"); fk_u_id != "" { users_index[fk_u_id] = true }
        if child_used, e := traverse_tree(child, t["data"].(M)["rights"].(uint64), c+1); e != nil {
          return 0, e
        } else {
          used_children += child_used
        }
      }
      t["data"].(M)["used_children"] = used_children
      return used_children+t["data"].(M)["used"].(uint64), nil
    }

    var tags M

    if root_api_name == nil {
      tags = make(M)
      tags["children"] = make([]M, 0)

      tags["data"] = make(M)
      tags["data"].(M)["rights"] = uint64(g_tags_rights)

      tags["data"].(M)["flags"] = F_ALLOW_LEAFS | F_DENY_SELECT

      for _, root_tag_index := range root_tags {
        tags_list[root_tag_index]["type"] = "root"
        tags["children"] = append(tags["children"].([]M), tags_list[root_tag_index])
        if _, err = traverse_tree(tags_list[root_tag_index], 0, 0); err != nil { panic(err) }
      }
    } else {
      if _, ex := api_name_index[ root_api_name.(string) ]; !ex {
        panic("В БД нет тега с API именем \""+root_api_name.(string)+"\"")
      }

      tags = tags_list[ api_name_index[ root_api_name.(string) ] ]
      if dbtags[api_name_index[ root_api_name.(string) ] ]["tag_fk_tag_id"] == nil {
        tags["type"] = "root"
      }

      if (tags["data"].(M)["rights"].(uint64) & R_VIEW_NET_IPS) == 0 { panic(NoAccess()) }

      if _, err = traverse_tree(tags, 0, 0); err != nil { panic(err) }
    }

    user_ids := make([]string, len(users_index))
    i := 0
    for fk_u_id, _ := range users_index {
      user_ids[i] = fk_u_id
      i++
    }

    var aux_userinfo M

    if len(user_ids) > 0 {
      if aux_userinfo, err = return_query_M(db, "SELECT * FROM us WHERE u_id IN("+strings.Join(user_ids, ",")+")", "u_id");
      err != nil { panic(err) }
    } else {
      aux_userinfo = make(M)
    }
    aux_userinfo[user_id] = user_row

    out["aux_userinfo"] = aux_userinfo
    out["tags"] = tags
    if out["gs"], err = return_query_M(db, "SELECT * FROM gs", "g_id"); err != nil { panic(err) }

  } else if action == "get_oobs" {
    oobs_rights := g_oobs_rights

    if (oobs_rights & R_VIEW_NET_IPS) == 0 {
      panic(NoAccess())
    }

    query = "SELECT tags.*"+
            ", CAST(("+
            " (SELECT COUNT(*) FROM v4nets WHERE FIND_IN_SET(tag_id,v4net_tags))+"+
            " (SELECT COUNT(*) FROM v6nets WHERE FIND_IN_SET(tag_id,v6net_tags))+"+
            " (SELECT COUNT(*) FROM v4oobs WHERE FIND_IN_SET(tag_id,v4oob_tags))+"+
            " (SELECT COUNT(*) FROM v6oobs WHERE FIND_IN_SET(tag_id,v6oob_tags))+"+
            " (SELECT COUNT(*) FROM i4vs INNER JOIN ics ON iv_fk_ic_id=ic_id"+
              " WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " (SELECT COUNT(*) FROM i6vs INNER JOIN ics ON iv_fk_ic_id=ic_id"+
              " WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " 0) AS UNSIGNED) AS used"+
            ", IFNULL((SELECT BIT_OR(tgr_rmask) FROM tgrs WHERE tgr_fk_g_id IN("+user_groups_in+") AND tgr_fk_tag_id=tag_id"+
                      " GROUP BY tgr_fk_tag_id), CAST(0 AS UNSIGNED)) as rights"+
            " FROM tags"
    if tags_cache, err = return_query_M(db, query, "tag_id"); err != nil { panic(err) }

    for tag_id, _ := range tags_cache {
      if u64, err = get_tag_rights(db, tag_id, 0); err != nil { panic(err) }
      tags_cache[tag_id].(M)["rights"] = u64
      if (tags_cache[tag_id].(M)["rights"].(uint64) & R_VIEW_NET_IPS) == 0 {
        tags_cache[tag_id].(M)["tag_name"] = "HIDDEN"
        tags_cache[tag_id].(M)["tag_descr"] = "HIDDEN"
        tags_cache[tag_id].(M)["tag_options"] = "HIDDEN"
        tags_cache[tag_id].(M)["tag_api_name"] = nil
      }
    }

    out["tags"] = tags_cache
    out["oobs"] = make(M)

    users_index := make(map[string]bool)

    for _, v := range [...]string{"4","6"} {
      query = "SELECT * FROM v"+v+"oobs ORDER BY v"+v+"oob_addr, v"+v+"oob_mask"
      if out["oobs"].(M)[v], err = return_query_A(db, query); err != nil { panic(err) }
      for _, row := range out["oobs"].(M)[v].([]M) {
        u_id, _ := row.UintString("fk_u_id")
        if u_id != "" { users_index[u_id] = true }
      }
    }

    user_ids := make([]string, len(users_index))
    i := 0
    for fk_u_id, _ := range users_index {
      user_ids[i] = fk_u_id
      i++
    }

    var aux_userinfo M

    if len(user_ids) > 0 {
      if aux_userinfo, err = return_query_M(db, "SELECT * FROM us WHERE u_id IN("+strings.Join(user_ids, ",")+")", "u_id");
      err != nil { panic(err) }
    } else {
      aux_userinfo = make(M)
    }
    aux_userinfo[user_id] = user_row

    out["aux_userinfo"] = aux_userinfo

  } else if action == "add_oob" {
    oobs_rights := g_oobs_rights

    if (oobs_rights & R_EDIT_IP_VLAN) == 0 {
      panic(NoAccess())
    }

    var v string
    if v, err = get_p_string(q, "v", "^[46]{1}$"); err != nil { panic(err) }

    var descr string
    if descr, err = get_p_string(q, "descr", nil); err != nil { panic(err) }

    var tags string
    if tags, err = get_p_string(q, "tags", g_num_list_reg); err != nil { panic(err) }

    var masklen uint32
    if masklen, err = get_p_uint32(q, "masklen"); err != nil { panic(err) }

    if (v == "4" && masklen > 32) ||
       (v == "6" && masklen > 128) ||
    false { panic("Bad masklen") }

    var addr interface {}

    if v == "4" {
      if addr, err = get_p_uint32(q, "addr"); err != nil { panic(err) }
      if addr.(uint32) != ip4net(addr.(uint32), masklen) { panic("Bad network") }
    } else {
      panic("Not implemented yet")
    }

    query = "INSERT INTO v"+v+"oobs SET"+
            " v"+v+"oob_addr=?"+
            ",v"+v+"oob_mask=?"+
            ",v"+v+"oob_descr=?"+
            ",v"+v+"oob_tags=?"+
            ",ts=?"+
            ",fk_u_id=?"
    if dbres, err = db.Exec(query, addr, masklen, descr, tags, ts, user_id); err != nil { panic(err) }

    var lid int64

    if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
    if lid <= 0 { panic("weird LastInsertId returned") }

    if out["oob"], err = must_return_one_M(db, "SELECT * FROM v"+v+"oobs WHERE v"+v+"oob_id=?", lid); err != nil { panic(err) }

    if err = audit_log(db, "v"+v+"oob", lid, query, nil, out["oob"]); err != nil { panic(err) }

  } else if action == "del_oob" {
    oobs_rights := g_oobs_rights

    if (oobs_rights & R_EDIT_IP_VLAN) == 0 {
      panic(NoAccess())
    }

    var v string
    if v, err = get_p_string(q, "v", "^[46]{1}$"); err != nil { panic(err) }

    var id string
    if id, err = get_p_string(q, "id", g_num_reg); err != nil { panic(err) }

    if prev_data, err = must_return_one_M(db, "SELECT * FROM v"+v+"oobs WHERE v"+v+"oob_id=?", id); err != nil { panic(err) }

    if _, err = db.Exec("DELETE FROM v"+v+"oobs WHERE v"+v+"oob_id=?", id); err != nil { panic(err) }

    if err = audit_log(db, "v"+v+"oob", id, "DELETE FROM v"+v+"oobs WHERE v"+v+"oob_id=?", prev_data, nil); err != nil { panic(err) }

    out["done"] = 1

  } else if action == "find_net" {
    var v string
    if v, err = get_p_string(q, "v", "^[46]{1}$"); err != nil { panic(err) }

    if v == "4" {
      var addr uint32
      if addr, err = get_p_uint32(q, "addr"); err != nil { panic(err) }

      var rows []M

      if _, ex := q["masklen"]; ex {
        var masklen uint32
        if masklen, err = get_p_uint32(q, "masklen"); err != nil { panic(err) }
        if masklen > 32 { panic(PE) }

        query = "SELECT v4net_addr, v4net_mask FROM v4nets WHERE v4net_addr <= ? AND v4net_last >= ? AND v4net_mask <= ?"
        if rows, err = return_query_A(db, query, addr, addr, masklen); err != nil { panic(err) }
      } else {
        query = "SELECT v4net_addr, v4net_mask FROM v4nets WHERE v4net_addr <= ? AND v4net_last >= ?"
        if rows, err = return_query_A(db, query, addr, addr); err != nil { panic(err) }
      }

      if len(rows) > 1 { panic(PE) }

      if len(rows) == 0 {
        if _, ex := q["masklen"]; ex {
          var masklen uint32
          if masklen, err = get_p_uint32(q, "masklen"); err != nil { panic(err) }
          if masklen > 32 { panic(PE) }

          if masklen == 32 { masklen = 31 }

          net := ip4net(addr, masklen)

          out["nav"] = 1
          out["net"] = net
          out["masklen"] = masklen
        } else {
          notfound := true
          for _, octet_mask := range []uint32{ 8, 16, 24 } {
            if net := ip4net(addr, octet_mask); net == addr {
              out["nav"] = 1
              out["net"] = net
              out["masklen"] = octet_mask
              notfound = false
              break
            }
          }
          if notfound {
            out["notfound"] = 1
          }
        }
      } else {
        out["net"] = rows[0]["v4net_addr"]
        out["masklen"] = rows[0]["v4net_mask"]
        out["focuson"] = addr
      }
    } else {
      panic("Not implemented yet")
    }

  } else if action == "get_global_rights" {
    if !user_is_admin { panic(NoAccess()) }

    out["objects"] = make(M)

    for object, _ := range g_rights_obj {
      query = "SELECT glr_fk_g_id as g_id, glr_rmask as rights FROM glrs WHERE glr_object=?"
      if out["objects"].(M)[object], err = return_query_M(db, query, "g_id", object);
      err != nil { panic(err) }
    }

    query = "SELECT * FROM us WHERE u_sub NOT LIKE 'imported%'"
    if out["users"], err = return_query_M(db, query, "u_id"); err != nil { panic(err) }

    query = "SELECT * FROM gs WHERE g_name != ?"
    if out["groups"], err = return_query_M(db, query, "g_id", opt_g); err != nil { panic(err) }

  } else if action == "flush_arp" {
    var addr uint32
    if addr, err = get_p_uint32(q, "addr"); err != nil { panic(err) }

    var dbnet_rights uint64
    var dbnet M

    if _, dbnet, err = get_addr_rights(db, addr, "4", nil); err != nil { panic(err) }
    if dbnet_rights, _, err = get_net_rights(nil, nil, "4", dbnet); err != nil { panic(err) }
    if (dbnet_rights & R_MANAGE_NET) == 0 { panic(NoAccess()) }

    var arp []M
    query = "SELECT * FROM v4arps WHERE v4arp_ip=?"

    if arp, err = return_query_A(db, query, addr); err != nil { panic(err) }
    if len(arp) == 0 {
      out["nodata"] = 1
      goto OUT
    }

    query = "DELETE FROM v4arps WHERE v4arp_ip=?"
    if _, err = db.Exec(query, addr); err != nil { panic(err) }

    if err = audit_log(db, "v4arp", addr, query, arp[0], nil); err != nil { panic(err) }

    out["done"] = 1


  } else if action == "get_apis" {
    if !user_is_admin { panic(NoAccess()) }

    query = "SELECT apis.*, u_login, u_name"+
            ", IFNULL((SELECT GROUP_CONCAT(ag_fk_g_id) FROM ags WHERE ag_fk_api_id = api_id), '') as api_groups"+
            " FROM apis LEFT JOIN us ON u_id = apis.fk_u_id"

    if out["apis"], err = return_query_M(db, query, "api_id"); err != nil { panic(err) }

    query = "SELECT * FROM gs WHERE g_name != ? AND any = 0"

    if out["groups"], err = return_query_M(db, query, "g_id", opt_g); err != nil { panic(err) }

  } else if action == "del_api" {
    if !user_is_admin { panic(NoAccess()) }

    var id string
    if id, err = get_p_string(q, "id", g_num_reg); err != nil { panic(err) }

    query = "SELECT apis.*"+
      ", IFNULL((SELECT GROUP_CONCAT(ag_fk_g_id) FROM ags WHERE ag_fk_api_id = api_id), '') as api_groups"+
      " FROM apis WHERE api_id=?"
    if prev_data, err = must_return_one_M(db, query, id); err != nil { panic(err) }

    if _, err = db.Exec("DELETE FROM apis WHERE api_id=?", id); err != nil { panic(err) }

    if err = audit_log(db, "api", id, "DELETE FROM apis WHERE api_id=?", prev_data, nil); err != nil { panic(err) }

    out["done"] = 1

  } else if action == "add_api" {
    if !user_is_admin { panic(NoAccess()) }

    var name string
    if name, err = get_p_string(q, "name", g_api_name_reg); err != nil { panic(err) }

    var key = genApiKey()

    query = "INSERT INTO apis(api_name, api_key, added, ts, fk_u_id) VALUES(?,?,?,0,?)"

    if dbres, err = db.Exec(query, name, key, ts, user_id); err != nil { panic(err) }

    log_query := query

    var lid int64

    if lid, err = dbres.LastInsertId(); err != nil { panic(err) }
    if lid <= 0 { panic("weird LastInsertId returned") }

    query = "SELECT apis.*"+
            ", IFNULL((SELECT GROUP_CONCAT(ag_fk_g_id) FROM ags WHERE ag_fk_api_id = api_id), '') as api_groups"+
            " FROM apis WHERE api_id=?"
    if out["api"], err = must_return_one_M(db, query, lid); err != nil { panic(err) }

    if err = audit_log(db, "api", lid, log_query, nil, out["api"]); err != nil { panic(err) }

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

func handleApi(w http.ResponseWriter, req *http.Request) {

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

  if _, key_ex := q["key"]; !key_ex {
    panic("no key in query")
  }

  key := q["key"].(string)
  _ = key

  var user_sub string
  var user_name string
  var user_login string

  //if user_groups_string == "" {
    //panic("No groups header present or is empty")
  //}

  out := make(M)

  var db *sql.DB
  var dbres sql.Result
  _ = dbres

  var query string
  _ = query

  db, err = sql.Open("mysql", opt_b)
  if err != nil { panic(err) }

  defer db.Close()

  user_is_admin := false

  query = "SELECT apis.*, ifnull((select group_concat(ag_fk_g_id) from ags where ag_fk_api_id=api_id), '') as groups"
  query += " FROM apis"
  query += " WHERE api_key=?"

  var key_row M
  var rows []M

  rows, err = return_query_A(db, query, key)

  if err != nil { panic(err) }
  if len(rows) == 0 {
    panic("Bad key")
  }

  if len(rows) > 1 {
    panic("Too many keys")
  }

  key_row = rows[0]

  var g_var_ok bool

  u64, g_var_ok = key_row.Uint64("api_id")
  if !g_var_ok {
    panic("No api_id")
  }

  user_sub = fmt.Sprintf("api_%d", u64)
  user_name = key_row["api_name"].(string)
  user_login = user_name

  // check key ip

  var client_ip string

  for header, header_values := range req.Header {
    if strings.ToLower(header) == "x-forwarded-for" && len(header_values) > 0 {
      client_ip = strings.TrimSpace(header_values[0])
    }
  }

  if m := g_remote_ip_reg.FindStringSubmatch(req.RemoteAddr); m != nil && client_ip == "" {
    client_ip = m[1]
  }

  var has_filter bool

  filter_v4ranges := make([]RangeV4, 0)

  for _, filter_str := range g_ips_split_reg.Split(key_row["api_nets"].(string), -1) {
    filter_str = strings.TrimSpace(filter_str)

    if g_ip_reg.MatchString(filter_str) {
      if ip, ip_err := v4ip2long(filter_str); ip_err == nil {
        has_filter = true
        filter_v4ranges = append(filter_v4ranges, RangeV4{ip,ip})
      }
    } else if m := g_ip_range_reg.FindStringSubmatch(filter_str); m != nil {
      ip_start, ip1_err := v4ip2long(m[1])
      ip_end, ip2_err := v4ip2long(m[2])

      if ip_start <= ip_end && ip1_err == nil && ip2_err == nil {
        has_filter = true
        filter_v4ranges = append(filter_v4ranges, RangeV4{ip_start, ip_end})
      }
    } else if m := g_ip_net_reg.FindStringSubmatch(filter_str); m != nil {
      ip, ip_err := v4ip2long(m[1])
      masklen, m_err := strconv.ParseUint(m[2], 10, 8)

      if ip_err == nil && m_err == nil && masklen <= 32 &&
         ip == ip4net(ip, uint32(masklen)) &&
      true {
        end_ip := ip | (0xFFFFFFFF >> masklen)
        has_filter = true
        filter_v4ranges = append(filter_v4ranges, RangeV4{ip, end_ip})
      }
    }
  }

  if has_filter {
    var filer_passed bool

    var client_v4addr uint32

    if client_v4addr, err = v4ip2long(client_ip); err == nil {
      for _, r := range filter_v4ranges {
        if client_v4addr >= r.Start && client_v4addr <= r.End {
          filer_passed = true
          break
        }
      }
    }

    if !filer_passed { panic("No access") }
  }

  query = "SELECT * FROM gs"
  var groups M

  if groups, err = return_query_M(db, query, "g_name"); err != nil { panic(err) }

  if _, ex := groups[opt_g]; !ex { panic("No "+opt_g+" group in DB") }

  var any_g_id string
  for _, g := range groups {
    var var_ok bool
    if u64, var_ok = g.(M).Uint64("any"); !var_ok { panic(PE) }
    if u64 > 0 {
      if any_g_id != "" { panic(PE) }
      if any_g_id, var_ok = g.(M).UintString("g_id"); !var_ok { panic(PE) }
    }
  }

  if any_g_id == "" { panic("No Any group found in DB") }

  user_groups := make([]string, 1)
  user_groups[0] = any_g_id

  user_groups_in := "FALSE"

  if key_row["groups"].(string) != "" {
    user_groups = append(user_groups, strings.Split(key_row["groups"].(string), ",")...)
  }

  if len(user_groups) > 0 {
    user_groups_in = strings.Join(user_groups, ",")
  }

  NoAccess := func() (M) {
    _out := make(M)
    _out["name"] = user_name
    _out["login"] = user_login
    _out["groups"] = user_groups

    _out["error"] = "No access"
    return _out
  }

  if !user_is_admin && len(user_groups) == 1 {
    panic(NoAccess())
  }

  var prev_data interface{}
  var new_data interface{}

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

    user_row["u_name"] = user_name
    user_row["u_login"] = user_login
  }

  query = "UPDATE us SET u_seen=? WHERE u_id=?"
  if _, err = db.Exec(query, ts, user_id); err != nil { panic(err) }

  if opt_d {
    dj, _ := json.MarshalIndent(q, "", "  ")
    fmt.Println(string(dj))
  }

  var var_ok bool

  var g_nets_rights uint64
  var g_vlans_rights uint64
  var g_tags_rights uint64
  var g_oobs_rights uint64

  query = "SELECT IFNULL(BIT_OR(glr_rmask), CAST(0 AS UNSIGNED)) FROM glrs WHERE glr_object=?"+
          " AND glr_fk_g_id IN("+user_groups_in+")"

  if g_nets_rights, err = must_return_one_uint(db, query, "nets"); err != nil { panic(err) }
  if g_vlans_rights, err = must_return_one_uint(db, query, "vlans"); err != nil { panic(err) }
  if g_tags_rights, err = must_return_one_uint(db, query, "tags"); err != nil { panic(err) }
  if g_oobs_rights, err = must_return_one_uint(db, query, "oobs"); err != nil { panic(err) }

  if user_is_admin {
    g_nets_rights |= ADMIN_NET_RIGHTS
    g_vlans_rights |= ADMIN_VLAN_RIGHTS
    g_tags_rights |= ADMIN_TAG_RIGHTS
    g_oobs_rights |= ADMIN_OOB_RIGHTS
  }

  var tags_cache M

  audit_log := func(db interface{}, al_subject string, al_subject_id interface{},
                    al_query string, al_prev_data, al_new_data interface{}) (error) {
    table_name := time.Now().Format("audit_200601")
    var e error

    if _, e = db_exec(db, "CREATE TABLE IF NOT EXISTS "+table_name+" LIKE log_template");
    e != nil { return e }

    var prev_json []byte
    if al_prev_data != nil {
      if prev_json, e = json.MarshalIndent(al_prev_data, "", "  "); e != nil { return e }
    } else {
      prev_json = make([]byte, 0)
    }

    var new_json []byte
    if al_new_data != nil {
      if new_json, e = json.MarshalIndent(al_new_data, "", "  "); e != nil { return e }
    } else {
      new_json = make([]byte, 0)
    }

    if _, e = db_exec(db, "INSERT INTO "+table_name+"(ts,fk_u_id,al_subject,al_subject_id"+
                      ",al_query,al_prev_data,al_new_data) VALUES(?,?,?,?,?,?,?)",
                      ts, user_id, al_subject, al_subject_id, al_query,
                      string(prev_json),string(new_json));
    e != nil { return e }

    return nil
  }

  var get_tag = func(db interface{}, _tag_id interface{}) (M, error) {
    var tag_id string
    switch v := _tag_id.(type) {
    case string:
      tag_id = v
    case uint8:
      tag_id = strconv.FormatUint(uint64(v), 10)
    case uint16:
      tag_id = strconv.FormatUint(uint64(v), 10)
    case uint32:
      tag_id = strconv.FormatUint(uint64(v), 10)
    case uint64:
      tag_id = strconv.FormatUint(uint64(v), 10)
    case int8:
      tag_id = strconv.FormatInt(int64(v), 10)
    case int16:
      tag_id = strconv.FormatInt(int64(v), 10)
    case int32:
      tag_id = strconv.FormatInt(int64(v), 10)
    case int64:
      tag_id = strconv.FormatInt(int64(v), 10)
    default:
      return nil, errors.New("Unsupported tag_id type in get_tag")
    }

    if tags_cache == nil {
      tags_cache = make(M)
    }

    if ret, ex := tags_cache[tag_id]; ex { return ret.(M), nil }

    query = "SELECT tags.*"+
            ", CAST(("+
            " (SELECT COUNT(*) FROM v4nets WHERE FIND_IN_SET(tag_id,v4net_tags))+"+
            " (SELECT COUNT(*) FROM v6nets WHERE FIND_IN_SET(tag_id,v6net_tags))+"+
            " (SELECT COUNT(*) FROM v4oobs WHERE FIND_IN_SET(tag_id,v4oob_tags))+"+
            " (SELECT COUNT(*) FROM v6oobs WHERE FIND_IN_SET(tag_id,v6oob_tags))+"+
            " (SELECT COUNT(*) FROM i4vs INNER JOIN ics ON iv_fk_ic_id=ic_id WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " (SELECT COUNT(*) FROM i6vs INNER JOIN ics ON iv_fk_ic_id=ic_id WHERE FIND_IN_SET(tag_id,iv_value) > 0 AND (ic_type='tag' OR ic_type='multitag'))+"+
            " 0) AS UNSIGNED) AS used"+
            ", IFNULL((SELECT BIT_OR(tgr_rmask) FROM tgrs WHERE tgr_fk_g_id IN("+user_groups_in+") AND tgr_fk_tag_id=tag_id"+
                      " GROUP BY tgr_fk_tag_id), CAST(0 AS UNSIGNED)) as rights"+
            " FROM tags WHERE tag_id=?"

    if ret, err := must_return_one_M(db, query, tag_id); err != nil {
      return nil, err
    } else {
      tags_cache[tag_id] = ret
      return ret, nil
    }
  }

  var tag_usage func(interface{}, interface{}, int) (uint64, error)
  tag_usage = func(db interface{}, tag_id interface{}, counter int) (uint64, error) {
    var tag M

    if tag, err = get_tag(db, tag_id); err != nil { return 0, err }

    var used uint64
    if used, var_ok = tag.Uint64("used"); !var_ok { return 0, fmt.Errorf("No used in tag %v", tag_id) }

    query = "SELECT tag_id FROM tags WHERE tag_fk_tag_id=?"
    if rows, err := return_query_A(db, query, tag_id); err != nil {
      return 0, err
    } else {
      for _, row := range rows {
        if child_id, var_ok := row.UintString("tag_id"); !var_ok {
          return 0, errors.New("No child tag_id")
        } else {
          if child_used, err := tag_usage(db, child_id, counter+1); err != nil {
            return 0, err
          } else {
            used += child_used
          }
        }
      }
    }

    return used, nil
  }

  var get_root_tag func(interface{}, interface{}, int) (M, error)
  get_root_tag = func(db interface{}, tag_id interface{}, counter int) (M, error) {
    if counter > MAX_TREE_LEN { return nil, errors.New("Tags loop detected") }
    var err error
    var tag M

    if tag, err = get_tag(db, tag_id); err != nil { return nil, err }
    if tag["tag_fk_tag_id"] == nil { return tag, nil }

    var var_ok bool
    var parent_id string
    if parent_id, var_ok = tag.UintString("tag_fk_tag_id"); !var_ok { return nil, fmt.Errorf("No tag_fk_tag_id for tag_id: %v", tag_id) }

    return get_root_tag(db, parent_id, counter + 1)
  }

  var get_tag_rights func(interface{}, interface{}, int) (uint64, error)
  get_tag_rights = func(db interface{}, tag_id interface{}, counter int) (uint64, error) {
    if counter > MAX_TREE_LEN { return 0, errors.New("Tags loop detected") }

    if tag, err := get_tag(db, tag_id); err != nil {
      return 0, err
    } else {
      if tag_rights, var_ok := tag.Uint64("rights"); !var_ok {
        return 0, fmt.Errorf("No rights for tag_id: %v", tag_id)
      } else {
        if tag["tag_fk_tag_id"] != nil {
          if parent_id, var_ok := tag.UintString("tag_fk_tag_id"); !var_ok {
            return 0, fmt.Errorf("No tag_fk_tag_id for tag_id: %v", tag_id)
          } else {
            if parent_rights, err := get_tag_rights(db, parent_id, counter+1); err != nil {
              return 0, err
            } else {
              tag_rights |= parent_rights
            }
          }
        }
        tag_rights |= g_tags_rights
        return tag_rights, nil
      }
    }
  }

  var update_tag = func(db interface{}, tag_id interface{}, update_fields M) (error) {
    query := "UPDATE tags SET "
    sets := make([]string, 2)
    values := make([]interface{}, 2)

    var err error

    if prev_data, err = must_return_one_M(db, "SELECT * FROM tags WHERE tag_id=?", tag_id); err != nil { return err }

    sets[0] = "ts=?"
    sets[1] = "fk_u_id=?"

    values[0] = ts
    values[1] = user_id

    if update_fields != nil {
      for k, v := range update_fields {
        sets = append(sets, k+"=?")
        values = append(values, v)
      }
    }

    query += strings.Join(sets, ",")+" WHERE tag_id=?"
    values = append(values, tag_id)

    switch db.(type) {
    case *sql.DB:
      _, err = db.(*sql.DB).Exec(query, values...)
    case *sql.Tx:
      _, err = db.(*sql.Tx).Exec(query, values...)
    default:
      err = errors.New("Bad db handle type:"+reflect.TypeOf(db).String())
    }

    if err != nil { return err }

    if new_data, err = must_return_one_M(db, "SELECT * FROM tags WHERE tag_id=?", tag_id); err != nil { return err }
    if err = audit_log(db, "tag", tag_id, query, prev_data, new_data); err != nil { return err }

    return err
  }

  _ = update_tag

  get_net_rights := func(db interface{}, net_id interface{}, v string, netrow M) (uint64, M, error) {
    var net M
    if netrow != nil {
      net = netrow
    } else {
      query = "SELECT"+
              " v"+v+"nets.*"+
              ", IFNULL((SELECT BIT_OR(gn"+v+"r_rmask)"+
                         " FROM gn"+v+"rs WHERE"+
                         " gn"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND gn"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id IS NULL"+
                         " AND v"+v+"r_start <= v"+v+"net_addr AND v"+v+"r_stop >= v"+v+"net_last"+
                         "), 0) AS r_rights"+
              " FROM v"+v+"nets WHERE v"+v+"net_id=?"
      if net, err = must_return_one_M(db, query, net_id); err != nil { return 0, nil, err }
    }

    var ret uint64
    if ret, var_ok = net.Uint64("rights"); !var_ok { return 0, nil, errors.New("No rights in get_net_rights call") }
    if u64, var_ok = net.Uint64("r_rights"); !var_ok { return 0, nil, errors.New("No rights in get_net_rights call") }

    owner, _ := net.AnyString("v"+v+"net_owner")

    ret |= u64

    if owner == user_id {
      ret |= OWNER_RIGHTS
    }

    ret |= g_nets_rights

    return ret, net, nil
  }

  _ = get_net_rights

  get_addr_rights := func(db interface{}, ip_addr interface{}, v string, netrow M) (uint64, M, error) {
    var net M
    if netrow != nil {
      net = netrow
    } else {
      query = "SELECT"+
              " v"+v+"nets.*"+
              ", IFNULL((SELECT BIT_OR(gn"+v+"r_rmask)"+
                         " FROM gn"+v+"rs WHERE"+
                         " gn"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND gn"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id IS NULL"+
                         " AND v"+v+"r_start <= v"+v+"net_addr AND v"+v+"r_stop >= v"+v+"net_last"+
                         "), 0) AS r_rights"+
              " FROM v"+v+"nets WHERE v"+v+"net_addr <=? AND v"+v+"net_last >=?"
      if net, err = must_return_one_M(db, query, ip_addr, ip_addr); err != nil { return 0, nil, err }
    }

    var ret uint64
    if ret, var_ok = net.Uint64("rights"); !var_ok { return 0, nil, errors.New("No rights in get_net_rights call") }
    if u64, var_ok = net.Uint64("r_rights"); !var_ok { return 0, nil, errors.New("No r_rights in get_net_rights call") }
    ret |= u64

    owner, _ := net.AnyString("v"+v+"net_owner")

    if owner == user_id {
      ret |= OWNER_RIGHTS
    }

    ret |= g_nets_rights

    query = "SELECT IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND v"+v+"r_start <= ? AND v"+v+"r_stop >= ?"+
                         "), CAST(0 AS UNSIGNED)) as ip_rights "+
            " FROM v"+v+"nets WHERE v"+v+"net_id=?"

    if u64, err = must_return_one_uint(db, query, ip_addr, ip_addr, net["v"+v+"net_id"]); err != nil { return 0, nil, err }

    ret |= u64

    return ret, net, nil
  }

  _ = get_addr_rights

  get_ip_rights := func(db interface{}, ip_id interface{}, v string, netrow M) (uint64, M, error) {
    var net M
    if netrow != nil {
      net = netrow
    } else {
      query = "SELECT"+
              " v"+v+"nets.*"+
              ", IFNULL((SELECT BIT_OR(gn"+v+"r_rmask)"+
                         " FROM gn"+v+"rs WHERE"+
                         " gn"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND gn"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         "),0) as rights"+
              ", IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id IS NULL"+
                         " AND v"+v+"r_start <= v"+v+"net_addr AND v"+v+"r_stop >= v"+v+"net_last"+
                         "), 0) AS r_rights"+
              " FROM v"+v+"nets INNER JOIN v"+v+"ips ON v"+v+"ip_fk_v"+v+"net_id=v"+v+"net_id WHERE v"+v+"ip_id=?"
      if net, err = must_return_one_M(db, query, ip_id); err != nil { return 0, nil, err }
    }

    var ret uint64
    if ret, var_ok = net.Uint64("rights"); !var_ok { return 0, nil, errors.New("No rights in get_net_rights call") }
    if u64, var_ok = net.Uint64("r_rights"); !var_ok { return 0, nil, errors.New("No r_rights in get_net_rights call") }
    ret |= u64

    owner, _ := net.AnyString("v"+v+"net_owner")

    if owner == user_id {
      ret |= OWNER_RIGHTS
    }

    ret |= g_nets_rights

    var ip_rows []M
    query = "SELECT v"+v+"net_id"+
            ",IFNULL((SELECT BIT_OR(gr"+v+"r_rmask)"+
                         " FROM gr"+v+"rs INNER JOIN v"+v+"rs ON gr"+v+"r_fk_v"+v+"r_id=v"+v+"r_id"+
                         " WHERE gr"+v+"r_fk_g_id IN("+user_groups_in+")"+
                         " AND v"+v+"r_fk_v"+v+"net_id=v"+v+"net_id"+
                         " AND v"+v+"r_start <= v"+v+"ip_addr AND v"+v+"r_stop >= v"+v+"ip_addr"+
                         "), 0) as ip_rights "+
            " FROM v"+v+"nets INNER JOIN v"+v+"ips ON v"+v+"ip_fk_v"+v+"net_id=v"+v+"net_id WHERE v"+v+"ip_id=?"

    if ip_rows, err = return_query_A(db, query, ip_id); err != nil { return 0, nil, err }

    if len(ip_rows) != 1 { return 0, nil, errors.New("Адреса не существует. Вероятно он был удален другим пользователем.\nОбновите страницу") }

    if ip_rows[0]["v"+v+"net_id"] != net["v"+v+"net_id"] {
      return 0, nil, errors.New("Адрес из другой сети")
    }

    if u64, var_ok = ip_rows[0].Uint64("ip_rights"); !var_ok { return 0, nil, errors.New("No ip_rights") }

    ret |= u64

    return ret, net, nil
  }

  _ = get_ip_rights

  query = ""

  if action == "userinfo" {
    out["id"] = user_id
    out["sub"] = user_sub
    out["name"] = user_name
    out["login"] = user_login
    out["groups"] = user_groups
    out["is_admin"] = user_is_admin

    out["ip"] = client_ip
    out["remote_addr"] = req.RemoteAddr
    out["has_filter"] = has_filter
    out["v4filter"] = filter_v4ranges

    out["g_nets_rights"] = g_nets_rights
    out["g_vlans_rights"] = g_vlans_rights
    out["g_tags_rights"] = g_tags_rights
    out["g_oobs_rights"] = g_oobs_rights

    has_vlans_access := false

    query = "SELECT BIT_OR(gvrr_rmask) as rights FROM"+
            " gvrrs WHERE gvrr_fk_g_id IN("+user_groups_in+")"

    var rows []M

    vlans_rights := g_vlans_rights

    if rows, err = return_query_A(db, query); err != nil { panic(err) }

    for _, row := range rows {
      if u64, var_ok = row.Uint64("rights"); !var_ok { panic(PE) }

      vlans_rights |= u64
    }

    if (vlans_rights & R_VIEW_NET_IPS) > 0 {
      has_vlans_access = true
    }

    out["has_vlans_access"] = has_vlans_access

    has_tags_access := false

    query = "SELECT tags.*"+
            ", IFNULL((SELECT BIT_OR(tgr_rmask) FROM tgrs WHERE tgr_fk_g_id IN("+user_groups_in+") AND tgr_fk_tag_id=tag_id"+
                      " GROUP BY tgr_fk_tag_id), CAST(0 AS UNSIGNED)) as rights"+
            " FROM tags WHERE tag_fk_tag_id IS NULL"

    tags_rights := g_tags_rights

    if rows, err = return_query_A(db, query); err != nil { panic(err) }

    for _, row := range rows {
      if u64, var_ok = row.Uint64("rights"); !var_ok { panic(PE) }

      tags_rights |= u64
    }

    if (tags_rights & R_VIEW_NET_IPS) > 0 {
      has_tags_access = true
    }

    out["has_tags_access"] = has_tags_access

    has_oobs_access := false

    oobs_rights := g_oobs_rights

    if (oobs_rights & R_VIEW_NET_IPS) > 0 {
      has_oobs_access = true
    }

    out["has_oobs_access"] = has_oobs_access

  } else if action == "get_ip" {
    var v string
    if v, err = get_p_string(q, "v", "^[46]{1}$"); err != nil { panic(err) }

    var ip_str string
    var v4ip uint32
    var ip_rows []M
    var ip_rights uint64

    if v == "4" {

      if ip_str, err = get_p_string(q, "ip", nil); err != nil { panic(err) }

      if v4ip, err = v4ip2long(ip_str); err != nil { panic(err) }

      query = "SELECT v4ip_id FROM v4ips WHERE v4ip_addr=?"

      ip_rows, err = return_query_A(db, query, v4ip)
      if err != nil { panic(err) }

      if len(ip_rows) != 1 {
        panic("IP not found")
      } else {
        var ip_id uint64
        var _var_ok bool

        if ip_id, _var_ok = ip_rows[0].Uint64("v4ip_id"); !_var_ok { panic("no desired key") }
        if ip_rights, _, err = get_ip_rights(db, ip_id, v, nil); err != nil { panic(err) }

        if (ip_rights & R_VIEW_NET_IPS) == 0 ||
        false {
          panic(NoAccess())
        }

        query = "SELECT IFNULL(i4vs.iv_value, '') as value"
        query += ", ic_api_name as field_api_name, ic_type as type, ic_name as field_human_name"
        query += " FROM ((v4ips INNER JOIN n4cs ON nc_fk_v4net_id=v4ip_fk_v4net_id)"
        query += " LEFT JOIN i4vs ON v4ip_id=iv_fk_v4ip_id AND iv_fk_ic_id=nc_fk_ic_id)"
        query += " INNER JOIN ics ON nc_fk_ic_id=ic_id"
        query += " WHERE v4ip_id=?"

        out["data"], err = return_query_M(db, query, "field_api_name", ip_id)
        if err != nil { panic(err) }

        out["rights"] = ip_rights
        out["ip_id"] = ip_id
      }


    } else {
      panic("Unsupported IP version")
    }
  } else if action == "edit_ip" {
    var v string
    if v, err = get_p_string(q, "v", "^[46]{1}$"); err != nil { panic(err) }

    var ip_str string
    var v4ip uint32
    var ip_rows []M
    var ip_rights uint64

    tx, tx_err := db.Begin()
    if tx_err != nil { panic(tx_err) }
    var commited bool = false
    defer func() {
      if !commited {
        tx.Rollback()
      }
    } ()

    if v == "4" {

      if ip_str, err = get_p_string(q, "ip", nil); err != nil { panic(err) }

      if v4ip, err = v4ip2long(ip_str); err != nil { panic(err) }

      query = "SELECT v4ip_id FROM v4ips WHERE v4ip_addr=?"

      ip_rows, err = return_query_A(tx, query, v4ip)
      if err != nil { panic(err) }

      if len(ip_rows) != 1 {
        panic("IP not found")
      } else {
        var ip_id uint64
        var _var_ok bool

        if ip_id, _var_ok = ip_rows[0].Uint64("v4ip_id"); !_var_ok { panic("no desired key") }
        if ip_rights, _, err = get_ip_rights(tx, ip_id, v, nil); err != nil { panic(err) }

        if (ip_rights & R_EDIT_IP_VLAN) == 0 ||
           (ip_rights & R_VIEW_NET_IPS) == 0 ||
           ((ip_rights & R_DENYIP) > 0 &&
            (ip_rights & R_IGNORE_R_DENY) == 0) ||
        false {
          panic(NoAccess())
        }

        ip_data := make(map[string]string)
        ip_data_ic_id := make(map[string]string)

        for q_key, _ := range q {
          m := g_data_key_reg.FindStringSubmatch(q_key)
          if m != nil {
            if data_val, data_ok := q.AnyString(q_key); !data_ok {
              panic("Bad value type")
            } else {
              ip_data[m[1]] = data_val

              query = "SELECT ic_id FROM ("
              query += "v4ips INNER JOIN n4cs ON nc_fk_v4net_id=v4ip_fk_v4net_id)"
              query += " INNER JOIN ics ON nc_fk_ic_id=ic_id"
              query += " WHERE ic_api_name=? AND v4ip_id=?"

              var ic_rows []M
              if ic_rows, err = return_query_A(tx, query, m[1], ip_id); err != nil { panic(err) }
              if len(ic_rows) != 1 { panic("No such api field for ip") }
              if ic_id, _ok := ic_rows[0].AnyString("ic_id"); !_ok {
                panic("No key")
              } else {
                ip_data_ic_id[m[1]] = ic_id
              }

            }
          }
        }

        for data_key, data_value := range ip_data {
          query = "SELECT iv_value FROM i4vs WHERE iv_fk_ic_id=? AND iv_fk_v4ip_id=?"
          prev_data, _ := must_return_one_M(tx, query, ip_data_ic_id[data_key], ip_id)

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
          _, err = tx.Exec(query, ip_data_ic_id[data_key], ip_id, data_value, ts, user_id)
          if err != nil { panic(err) }

          if err = audit_log(tx, "ip_value", ip_id, query, prev_data, data_value); err != nil { panic(err) }

        }

        err = tx.Commit()
        if err != nil { panic(err) }
        commited = true

        out["rights"] = ip_rights
        out["ip_id"] = ip_id

      }
    } else {
      panic("Unsupported IP version")
    }

  } else if action == "query" {
    out["_query"] = q
  } else {
    panic("unknown action: "+action)
  }

 //API_OUT:

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
