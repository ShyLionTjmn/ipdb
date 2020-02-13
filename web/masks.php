<?php

for($i=0; $i <= 32; $i++) {
  $mask= 0x0FFFFFFFF & (0xFFFFFFFF << (32-$i));
  echo "  $mask, //".long2ip($mask)."\n";
};

?>
