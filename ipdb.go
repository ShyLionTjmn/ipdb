package main

import (
  "fmt"
  "sync"
  "time"
  "os"
  "log"
  "flag"
  "syscall"
  "strings"
  "encoding/json"
  "os/signal"
  "github.com/marcsauter/single"
)

const DEFAULT_CONFIG_FILE = "/etc/ipdb/ipdb.config"
const DEFAULT_HTTP_PORT = uint(8888)
const DEFAULT_WWW_ROOT = "/opt/ipdb/www"
const DEFAULT_APP_LOCATION = "/ipdb/"
const DEFAULT_ADMIN_GROUP = "usr_netapp_ipdb_appadmins"
const DEFAULT_DSN = "ipdb_ajax:@unix(/var/lib/mysql/mysql.sock)/ipdb"

const DEFAULT_AUTOSAVE_TIMEOUT = 1000


type FG struct {
  Name string `json:"name"`
  Addr string `json:"addr"`
  Rest_key string `json:"rest_key"`
}

type Config struct {
  Db_dsn string `json:"DSN"` //opt_b
  Autofg_tag string `json:"autofg_tag"` //used by ipdb2fg
  Http_port uint `json:"http_port"` //opt_p
  Www_root string `json:"www_root"` //opt_w
  App_location string `json:"app_location"` //opt_l
  Admin_group string `json:"admin_group"` //opt_g
  Autosave_timeout uint `json:"autosave_timeout"`
  Fortigates []FG `json:"fortigates"`
}


var opt_d bool= false
var opt_b string
var opt_p uint
var opt_w string
var opt_l string
var opt_g string
var opt_C string
var g_autosave_timeout uint

func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
  c := make(chan struct{})
  go func() {
    defer close(c)
    wg.Wait()
  }()

  select {
    case <-c:
      return false // completed normally
    case <-time.After(timeout):
      return true // timed out
  }
}

func logError(source string, message string) {
  fmt.Fprintln(os.Stderr, source, message)
}

func isFlagPassed(name string) bool {
  found := false
  flag.Visit(func(f *flag.Flag) {
    if f.Name == name {
      found = true
    }
  })
  return found
}

func main() {
  single_run := single.New("ipdb")
  sr_err := single_run.CheckLock();

  if sr_err != nil && sr_err == single.ErrAlreadyRunning {
    log.Fatal("another instance of the app is already running, exiting")
  } else if sr_err != nil {
    // Another error occurred, might be worth handling it as well
    log.Fatalf("failed to acquire exclusive app lock: %v", sr_err)
  }
  defer single_run.TryUnlock()

  var f_opt_d *bool = flag.Bool("d", opt_d, "Debug output")
  var f_opt_b *string = flag.String("b", DEFAULT_DSN, "Database DSN")

  var f_opt_p *uint = flag.Uint("p", DEFAULT_HTTP_PORT, "Listen port")
  var f_opt_w *string = flag.String("w", DEFAULT_WWW_ROOT, "WWW root dir")
  var f_opt_l *string = flag.String("l", DEFAULT_APP_LOCATION, "Application Location (root URI)")

  var f_opt_g *string = flag.String("g", strings.ToLower(DEFAULT_ADMIN_GROUP), "Admin group (\"samaccountname\")")

  var f_opt_C *string = flag.String("C", DEFAULT_CONFIG_FILE, "Config file location")

  g_autosave_timeout = DEFAULT_AUTOSAVE_TIMEOUT

  flag.Parse()

  if *f_opt_p >= uint(65535) {
    log.Fatal("Wrong port number:", *f_opt_p)
  }

  opt_C = *f_opt_C

  if fstat, ferr := os.Stat(opt_C); ferr == nil && fstat.Mode().IsRegular() {
    var config Config

    var err error
    var conf_json []byte
    if conf_json, err = os.ReadFile(opt_C); err != nil { log.Fatal(err.Error()) }

    if err = json.Unmarshal(conf_json, &config); err != nil { log.Fatal(err.Error()) }

    if config.Db_dsn != "" {
      opt_b = config.Db_dsn
    } else {
      opt_b = DEFAULT_DSN
    }
    if config.Http_port != 0 {
      opt_p = config.Http_port
    } else {
      opt_p = DEFAULT_HTTP_PORT
    }
    if config.Www_root != "" {
      opt_w = config.Www_root
    } else {
      opt_w = DEFAULT_WWW_ROOT
    }
    if config.App_location != "" {
      opt_l = config.App_location
    } else {
      opt_l = DEFAULT_APP_LOCATION
    }
    if config.Admin_group != "" {
      opt_g = strings.ToLower(config.Admin_group)
    } else {
      opt_g = strings.ToLower(DEFAULT_ADMIN_GROUP)
    }

    if config.Autosave_timeout != 0 {
      g_autosave_timeout = config.Autosave_timeout
    }

  } else if isFlagPassed("C") {
    log.Fatal("Error opening config file: ", opt_C)
  }

  opt_d = *f_opt_d //debug

  if isFlagPassed("b") { opt_b = *f_opt_b }
  if isFlagPassed("p") { opt_p = *f_opt_p }
  if isFlagPassed("w") { opt_w = *f_opt_w }
  if isFlagPassed("l") { opt_l = *f_opt_l }
  if isFlagPassed("g") { opt_g = strings.ToLower(*f_opt_g) }

  if opt_g == "" {
    log.Fatal("Bad Admin group specified")
  }

  if opt_p >= uint(65535) || opt_p == 0 {
    log.Fatal("Wrong port number:", opt_p)
  }

  sig_ch := make(chan os.Signal, 1)

  signal.Notify(sig_ch, syscall.SIGHUP)
  signal.Notify(sig_ch, syscall.SIGINT)
  signal.Notify(sig_ch, syscall.SIGTERM)
  signal.Notify(sig_ch, syscall.SIGQUIT)

  var wg sync.WaitGroup

  stop_ch := make(chan struct{}, 1)

  wg.Add(1)
  go http_server(&wg, stop_ch)

  log.Println("Started")

  MAIN_LOOP: for {
    select {
    case s := <-sig_ch:
      if s == syscall.SIGHUP || s == syscall.SIGUSR1 {
        continue MAIN_LOOP
      }
      break MAIN_LOOP
    }
  }
  close(stop_ch)
  if waitTimeout(&wg, 10 * time.Second) {
    fmt.Println("main: workers wait timeout!")
  }
}
