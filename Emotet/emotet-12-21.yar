/*
author = "Vishal Thakur - malienist.medium.com"
date = "2021-12-15"
version = "1"
description = "Detects Emotet"
info = "Generated from information extracted from the malware sample by manual analysis."
*/

rule emotet-12-21 {

  strings: 
    $1 = { 4e	9e	9c	6b	0a	ff	f2	38	0a	ff	f2	38	??	ff	f2	38	67	a2	f1	39	07	ff	f2	??	??	??	f7	39	99	ff	f2	38	67	a2	f6	39	17	ff	f2	38	58	97	f7	39	4e	ff	f2	38	58	97	f6	39	2a	ff	f2	38	??	??	??	39	1d	ff	f2	38	67	a2	f4	39 }
    $2 = { ??	45	00	00	4c	01	05	00	57	4f	97	61	00	00	00	00 }
    $3 = { ??	39	34	39	3c	39	44	39	4c	39	54	39	5c	39	64	39 }
    $4 = { 48	37	50	37	58	37	60	37	68	37	70	37	78	37	80	37 }
    $5 = { ??	32	3c	32	40	32	44	32	48	32	4c	32	50	32	54	32 }
    $6 = { ??	34	38	34	3c	34	40	34	44	34	48	34	4c	34	50	34 }
    $7 = { 74	34	94	34	b4	34	d4	34	f0	34	08	35	28	35	40	35 } 
    $8 = { 30	31	50	31	70	31	90	31	b0	31	d0	31	f0	31	10	32 } 
    $9 = { 50	3e	58	3e	64	3e	84	3e	90	3e	c4	3e	c8	3e	d8	3e } 
    $10 = { 44	33	50	33	58	33	78	33	94	33	a4	33	b0	33	b8	33 } 
    
  conditions:
    filesize < 500KB and 
    all of them
}
