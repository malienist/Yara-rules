/*
author = "Vishal Thakur - malienist.medium.com"
date = "2021-12-20"
version = "1"
description = "Detects STOP Windows Ransomware"
info = "Generated from information extracted from the malware sample by manual analysis."
*/
rule stopStatic {   
  strings:
    $header = { 4d	5a }
    $str1 = { 9c	58	??	10	d8	39	53	43	d8	39	53	43	??	39	53	43 }
    $str2 = { b7	4f	cd	43	c3	39	53	43	b7	4f	f9	??	a3	39	53	43 } 
    $str3 = { 77	75	67	??	68	65	63	75	6a	69	6a	69	79	69	67	61 }
    $str4 = { 77	69	6e	69	62	61	6e	00	68	61	72	65	77	69	6e	69 }
    $str5 = { 6f	6e	75	6a	6f	??	65	79	61	72	00	00	5a	75	79	61 }
    $str6 = { 77	??	6b	6f	20	6d	6f	64	69	20	76	61	74	75	6a	75 }
    $str7 = { 69	79	61	6c	6f	67	69	00	46	75	76	61	76	61	6a	6f } 
    $str8 = { 63	75	73	??	78	75	76	75	63	65	74	69	6a	75	68	69 }
    $str9 = { 70	61	6d	69	??	61	6d	69	76	61	64	61	64	61	6d	69 }
    $str10 = { 66	??	5c	64	64	5c	76	63	74	6f	6f	6c	73	5c	63	72 }
    $str11 = { 74	5f	62	6c	64	5c	73	65	??	66	5f	78	38	36	5c	63 }
    $str12 = { 72	??	5c	73	72	63	5c	6f	6e	65	78	??	74	2e	63	?? }
   condition:
    filesize < 1.55MB and 
    all of them
}
