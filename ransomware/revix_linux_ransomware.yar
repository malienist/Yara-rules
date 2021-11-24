/*
author = "Vishal Thakur - malienist.medium.com"
date = "2021-11-15"
version = "1"
description = "Detects Revix-1.2a and earlier versions of Revix"
info = "Generated from information extracted from the malware sample by manual analysis."
*/

import "pe"
rule revixStatic {

  strings:
	$header = { 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3e 00 01 00 00 00 50 16 40 00 00 00 00 00 }
	$config = { 7B 22 76 65 72 22 3A ?? ?? 2C 22 70 69 64 22 3A 22 ?? ?? 22 2C 22 73 75 62 22 3A 22 ?? ?? 22 2C 22 70 6B 22 3A 22 ?? ?? 22 2C 22 75 69 64 22 3A 22 ?? ?? 22 2C 22 73 6B 22 3A 22 ?? ?? 22 2C 22 6F 73 22 3A 22 ?? ?? 22 2C 22 65 78 74 22 3A 22 ?? ?? 22 7D }
	$uname = { 75 6E 61 6D 65 20 2D 61 20 26 26 20 65 63 68 6F }
  condition:
	all of them and
	filesize < 250KB
}

rule revixCode {
  
  strings:
	$err1 = { 45 72 72 6F 72 20 6F 70 65 6E 20 75 72 61 6E 64 6D }
	$err2 = { 45 72 72 6F 72 20 64 65 63 6F 64 69 6E 67 20 6D 61 73 74 65 72 5F 70 6B }
	$err3 = { 66 61 74 61 6C 20 65 72 72 6F 72 2C 6D 61 73 74 65 72 5F 70 6B 20 73 69 7A 65 20 69 73 20 62 61 64 }
	$err4 = { 45 72 72 6F 72 20 64 65 63 6F 64 69 6E 67 20 75 73 65 72 5F 69 64 }
	$err5 = { 45 72 72 6F 72 20 64 65 63 6F 64 69 6E 67 20 6E 6F 74 65 5F 62 6F 64 79 }
    $form1 = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 ?? ?? }
	$form2 = { 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 ?? ?? }
	$config = { 7B 22 76 65 72 22 3A ?? ?? 2C 22 70 69 64 22 3A 22 ?? ?? 22 2C 22 73 75 62 22 3A 22 ?? ?? 22 2C 22 70 6B 22 3A 22 ?? ?? 22 2C 22 75 69 64 22 3A 22 ?? ?? 22 2C 22 73 6B 22 3A 22 ?? ?? 22 2C 22 6F 73 22 3A 22 ?? ?? 22 2C 22 65 78 74 22 3A 22 ?? ?? 22 7D }

  condition:
	all of them and
	filesize < 250KB
}

rule revixESX {

  strings:
	$cmd1 = { 65 73 78 63 6C 69 }
	$cmd2 = { 2D 66 6F 72 6D 61 74 74 65 72 3D ?? ?? ?? }
	$cmd3 = { 2D 2D 66 6F 72 6D 61 74 2D 70 61 72 61 6D }
	$cmd4 = { 76 6D 20 70 72 6F 63 65 73 73 20 6C 69 73 74 }
	$cmd5 = { 65 73 78 63 6C 69 20 76 6D 20 70 72 6F 63 65 73 73 20 6B 69 6C 6C }
	$cmd6 = { 2D 2D 77 6F 72 6C 64 2D 69 64 3D 22 ?? ?? ?? }
	$config = { 7B 22 76 65 72 22 3A ?? ?? 2C 22 70 69 64 22 3A 22 ?? ?? 22 2C 22 73 75 62 22 3A 22 ?? ?? 22 2C 22 70 6B 22 3A 22 ?? ?? 22 2C 22 75 69 64 22 3A 22 ?? ?? 22 2C 22 73 6B 22 3A 22 ?? ?? 22 2C 22 6F 73 22 3A 22 ?? ?? 22 2C 22 65 78 74 22 3A 22 ?? ?? 22 7D }

  condition:
	all of them and
	filesize < 250KB
}

rule revixPE {

  condition:
	pe.entry_point == 0x401650
}
