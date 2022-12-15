package main

func v4masklen2mask(masklen uint32) uint32 {
  return uint32(0xFFFFFFFF << (32 - masklen))
}

func ip4net(ip uint32, masklen uint32) uint32 {
  return ip & uint32(0xFFFFFFFF << (32 - masklen))
}
