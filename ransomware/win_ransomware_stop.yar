/*
author = "Vishal Thakur - malienist.medium.com"
date = "2021-12-20"
version = "1"
description = "Detects STOP Windows Ransomware"
info = "Generated from information extracted from the malware sample by manual analysis."
*/

rule stopRansomwareStatic
{
  strings:
  $block1 = { 43 3a 5c 6d 6f 7a 5c 76 69 64 61 6a 2e 70 64 62 }
  $block2 = { 39 2d 39 35 39 45 39 56 39 69 39 34 3a 3c 3a 43 3a 4f 3a }
  $block3 = { 32 25 32 2f 32 39 32 4a 32 53 32 5f 32 67 32 75 32 }
  $block4 = { 32 2a 33 2f 33 34 33 57 33 78 33 7d 33 }
  $block5 = { 3e 20 3e 37 3e 40 3e 48 3e 4f 3e 6c 3e }
  
  condition:
      filesize < 1500KB and all of them
}
