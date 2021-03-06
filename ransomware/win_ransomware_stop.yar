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
  $header = { 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 }
  $block1 = { 43 3a 5c 6d 6f 7a 5c 76 69 64 61 6a 2e 70 64 62 }
  $block2 = { 39 2d 39 35 39 45 39 56 39 69 39 34 3a 3c 3a 43 3a 4f 3a }
  $block3 = { 32 25 32 2f 32 39 32 4a 32 53 32 5f 32 67 32 75 32 }
  $block4 = { 32 2a 33 2f 33 34 33 57 33 78 33 7d 33 }
  $block5 = { 3e 20 3e 37 3e 40 3e 48 3e 4f 3e 6c 3e }
    $str1 = { 66 3a 5c 64 64 5c 76 63 74 6f 6f 6c 73 5c 63 72 74 5f 62 6c 64 5c 73 65 6c 66 5f 78 38 36 5c 63 72 74 5c 73 72 63 5c 5f 66 69 6c 65 2e 63 }
    $str2 = { 73 66 74 62 75 66 2e 63 } 
    $str3 = { 69 6f 69 6e 69 74 2e 63 }
    $str4 = { 73 74 64 65 6e 76 70 2e 63 }
    $str5 = { 78 38 36 5c 63 72 74 5c 73 72 63 5c 73 74 64 61 72 67 76 2e 63 }
    $str6 = { 63 5c 77 5f 65 6e 76 2e 63 }
    $str7 = { 66 5f 78 38 36 5c 63 72 74 5c 73 72 63 5c 6d 62 63 74 79 70 65 2e 63 } 
    $str8 = { 48 61 74 61 7a 75 79 69 20 6a 75 62 6f 6b 20 79 69 62 2e 20 54 75 6d 61 6a 75 73 6f 20 6e 69 6e 69 74 6f 66 75 20 6c 65 6b 69 78 69 67 20 76 61 62 69 73 69 70 2e 20 57 6f 63 6f 64 61 74 65 70 6f 67 6f 76 69 20 6d 75 73 6f 72 6f 6a 69 70 20 79 69 6e 69 70 6f 78 65 77 69 62 75 20 6b 69 63 61 63 69 72 75 76 69 20 77 61 66 75 77 6f 6e 61 6c 69 79 2e 20 46 61 77 69 74 75 72 69 7a 6f 72 61 66 6f 2e 20 59 69 6d 69 63 2e 20 4d 61 77 65 78 61 74 75 6a 6f 73 2e 20 58 61 70 6f 6b 69 6e 6f 74 75 20 68 6f 6a 61 72 75 66 61 6d 65 72 61 20 78 75 6c 69 77 69 70 61 63 69 70 69 6d 20 72 6f 6e 69 68 61 73 65 6a 65 70 6f 64 6f 6b 20 6d 69 7a 69 76 2e 20 48 75 72 61 6d 6f 20 68 6f 7a 20 68 61 72 75 77 69 72 69 76 6f 6d 69 79 20 64 61 7a 65 77 69 74 75 62 61 67 20 6c 61 70 69 62 6f 62 2e 20 4e 69 67 65 67 6f 74 61 72 75 78 75 20 68 61 6e 6f 66 20 73 61 7a 61 67 6f 6d 75 20 66 65 64 69 76 69 68 6f 67 69 63 6f 68 61 6a 2e 20 }
    $str9 = "%s%s%s%s%s%s%s%s%s%s%s%s" 
    $str10 = { 78 38 36 5c 63 72 74 5c 73 72 63 5c 6d 62 63 74 79 70 65 2e 63 }
  
  condition:
      filesize < 1500KB and all of them
}
