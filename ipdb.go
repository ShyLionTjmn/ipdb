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
  "os/signal"
  "github.com/marcsauter/single"
)

var opt_d bool= false
var opt_b string
var opt_p uint
var opt_w string
var opt_l string
var opt_g string

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
  var f_opt_b *string = flag.String("b", DSN, "Database DSN")

  var f_opt_p *uint = flag.Uint("p", HTTP_PORT, "Listen port")
  var f_opt_w *string = flag.String("w", WWW_ROOT, "WWW root dir")
  var f_opt_l *string = flag.String("l", APP_LOCATION, "Application Location (root URI)")

  var f_opt_g *string = flag.String("g", ADMIN_GROUP, "Admin group (\"samaccountname\")")

  flag.Parse()

  if *f_opt_p >= uint(65535) {
    log.Fatal("Wrong port number:", f_opt_p)
  }

  opt_d = *f_opt_d
  opt_b = *f_opt_b
  opt_p = *f_opt_p
  opt_w = *f_opt_w
  opt_l = *f_opt_l
  opt_g = strings.ToLower(*f_opt_g)

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
