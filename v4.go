package main

import (
  "fmt"
  "errors"
  "regexp"
  "strconv"
)

var v4ip_reg *regexp.Regexp

func init() {
  v4ip_reg = regexp.MustCompile(`^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$`)
}

func v4masklen2mask(masklen uint32) uint32 {
  return uint32(0xFFFFFFFF << (32 - masklen))
}

func ip4net(ip uint32, masklen uint32) uint32 {
  return ip & uint32(0xFFFFFFFF << (32 - masklen))
}

func v4long2ip(ip uint32) string {
  o1 := (ip & uint32(0xFF000000)) >> 24
  o2 := (ip & uint32(0xFF0000)) >> 16
  o3 := (ip & uint32(0xFF00)) >> 8
  o4 := ip & uint32(0xFF)

  return fmt.Sprintf("%d.%d.%d.%d", o1, o2, o3, o4)
}

func v4ip2long(ip_str string) (uint32, error) {
  ip_a := v4ip_reg.FindStringSubmatch(ip_str)
  if ip_a == nil {
    return 0, errors.New("Bad IP Address, reg")
  }

  var u64 uint64
  var err error

  var o1,o2,o3,o4 uint32

  if u64, err = strconv.ParseUint(ip_a[1], 10, 8); err != nil {
    return 0, errors.New("Bad IP Address")
  }

  o1 = uint32(u64)

  if u64, err = strconv.ParseUint(ip_a[2], 10, 8); err != nil {
    return 0, errors.New("Bad IP Address")
  }

  o2 = uint32(u64)

  if u64, err = strconv.ParseUint(ip_a[3], 10, 8); err != nil {
    return 0, errors.New("Bad IP Address")
  }

  o3 = uint32(u64)

  if u64, err = strconv.ParseUint(ip_a[4], 10, 8); err != nil {
    return 0, errors.New("Bad IP Address")
  }

  o4 = uint32(u64)

  return ((o1 << 24) + (o2 << 16) + (o3 << 8) + o4), nil
}
