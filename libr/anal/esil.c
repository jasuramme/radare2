/* radare - LGPL - Copyright 2014-2018 - pancake, condret */

#include <r_anal.h>
#include <r_types.h>
#include <r_util.h>
#include <r_bind.h>

#define IFDBG if (esil && esil->verbose > 1)
#define IFVBS if (esil && esil->verbose > 0)
#define FLG(x) R_ANAL_ESIL_FLAG_##x
#define cpuflag(x, y)\
if (esil) {\
	if (y) { \
		R_BIT_SET (&esil->flags, FLG (x));\
	} else { \
		R_BIT_UNSET (&esil->flags, FLG (x));\
	} \
}

void check_for_register(int addr){
	if(addr==0xFFFFE400) { eprintf("HCAN0_MCR"); eprintf(" Master control register(0x%x)\n",addr);
	} else if(addr==0xFFFFE401) { eprintf("HCAN0_GSR"); eprintf(" General status register(0x%x)\n",addr);
	} else if(addr==0xFFFFE402) { eprintf("HCAN0_BCR"); eprintf(" Bit configuration register(0x%x)\n",addr);
	} else if(addr==0xFFFFE404) { eprintf("HCAN0_MBCR"); eprintf(" Mailbox configuration register(0x%x)\n",addr);
	} else if(addr==0xFFFFE406) { eprintf("HCAN0_TXPR"); eprintf(" Transmit wait register(0x%x)\n",addr);
	} else if(addr==0xFFFFE408) { eprintf("HCAN0_TXCR"); eprintf(" Transmit wait cancel register(0x%x)\n",addr);
	} else if(addr==0xFFFFE40A) { eprintf("HCAN0_TXACK"); eprintf(" Transmit acknowledge register(0x%x)\n",addr);
	} else if(addr==0xFFFFE40C) { eprintf("HCAN0_ABACK"); eprintf(" Abort acknowledge register(0x%x)\n",addr);
	} else if(addr==0xFFFFE40E) { eprintf("HCAN0_RXPR"); eprintf(" Receive complete register(0x%x)\n",addr);
	} else if(addr==0xFFFFE410) { eprintf("HCAN0_RFPR"); eprintf(" Remote request register(0x%x)\n",addr);
	} else if(addr==0xFFFFE412) { eprintf("HCAN0_IRR"); eprintf(" Interrupt register(0x%x)\n",addr);
	} else if(addr==0xFFFFE414) { eprintf("HCAN0_MBIMR"); eprintf(" Mailbox interrupt mask register(0x%x)\n",addr);
	} else if(addr==0xFFFFE416) { eprintf("HCAN0_IMR"); eprintf(" Interrupt mask register(0x%x)\n",addr);
	} else if(addr==0xFFFFE418) { eprintf("HCAN0_REC"); eprintf(" Receive error counter(0x%x)\n",addr);
	} else if(addr==0xFFFFE419) { eprintf("HCAN0_TEC"); eprintf(" Transmit error counter(0x%x)\n",addr);
	} else if(addr==0xFFFFE41A) { eprintf("HCAN0_UMSR"); eprintf(" Unread message status register(0x%x)\n",addr);
	} else if(addr==0xFFFFE41C) { eprintf("HCAN0_LAFML"); eprintf(" Local acceptance filter mask L(0x%x)\n",addr);
	} else if(addr==0xFFFFE41E) { eprintf("HCAN0_LAFMH"); eprintf(" Local acceptance filter mask H(0x%x)\n",addr);
	} else if(addr==0xFFFFE420) { eprintf("HCAN0_MC0"); eprintf(" Message control 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE428) { eprintf("HCAN0_MC1"); eprintf(" Message control 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE430) { eprintf("HCAN0_MC2_0"); eprintf(" Message control 2 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE431) { eprintf("HCAN0_MC2_1"); eprintf(" Message control 2 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE432) { eprintf("HCAN0_MC2_2"); eprintf(" Message control 2 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE433) { eprintf("HCAN0_MC2_3"); eprintf(" Message control 2 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE434) { eprintf("HCAN0_MC2_4"); eprintf(" Message control 2 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE435) { eprintf("HCAN0_MC2_5"); eprintf(" Message control 2 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE436) { eprintf("HCAN0_MC2_6"); eprintf(" Message control 2 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE437) { eprintf("HCAN0_MC2_7"); eprintf(" Message control 2 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE438) { eprintf("HCAN0_MC3_0"); eprintf(" Message control 3 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE439) { eprintf("HCAN0_MC3_1"); eprintf(" Message control 3 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE43A) { eprintf("HCAN0_MC3_2"); eprintf(" Message control 3 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE43B) { eprintf("HCAN0_MC3_3"); eprintf(" Message control 3 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE43C) { eprintf("HCAN0_MC3_4"); eprintf(" Message control 3 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE43D) { eprintf("HCAN0_MC3_5"); eprintf(" Message control 3 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE43E) { eprintf("HCAN0_MC3_6"); eprintf(" Message control 3 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE43F) { eprintf("HCAN0_MC3_7"); eprintf(" Message control 3 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE440) { eprintf("HCAN0_MC4_0"); eprintf(" Message control 4 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE441) { eprintf("HCAN0_MC4_1"); eprintf(" Message control 4 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE442) { eprintf("HCAN0_MC4_2"); eprintf(" Message control 4 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE443) { eprintf("HCAN0_MC4_3"); eprintf(" Message control 4 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE444) { eprintf("HCAN0_MC4_4"); eprintf(" Message control 4 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE445) { eprintf("HCAN0_MC4_5"); eprintf(" Message control 4 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE446) { eprintf("HCAN0_MC4_6"); eprintf(" Message control 4 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE447) { eprintf("HCAN0_MC4_7"); eprintf(" Message control 4 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE448) { eprintf("HCAN0_MC5_0"); eprintf(" Message control 5 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE449) { eprintf("HCAN0_MC5_1"); eprintf(" Message control 5 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE44A) { eprintf("HCAN0_MC5_2"); eprintf(" Message control 5 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE44B) { eprintf("HCAN0_MC5_3"); eprintf(" Message control 5 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE44C) { eprintf("HCAN0_MC5_4"); eprintf(" Message control 5 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE44D) { eprintf("HCAN0_MC5_5"); eprintf(" Message control 5 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE44E) { eprintf("HCAN0_MC5_6"); eprintf(" Message control 5 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE44F) { eprintf("HCAN0_MC5_7"); eprintf(" Message control 5 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE450) { eprintf("HCAN0_MC6_0"); eprintf(" Message control 6 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE451) { eprintf("HCAN0_MC6_1"); eprintf(" Message control 6 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE452) { eprintf("HCAN0_MC6_2"); eprintf(" Message control 6 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE453) { eprintf("HCAN0_MC6_3"); eprintf(" Message control 6 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE454) { eprintf("HCAN0_MC6_4"); eprintf(" Message control 6 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE455) { eprintf("HCAN0_MC6_5"); eprintf(" Message control 6 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE456) { eprintf("HCAN0_MC6_6"); eprintf(" Message control 6 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE457) { eprintf("HCAN0_MC6_7"); eprintf(" Message control 6 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE458) { eprintf("HCAN0_MC7_0"); eprintf(" Message control 7 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE459) { eprintf("HCAN0_MC7_1"); eprintf(" Message control 7 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE45A) { eprintf("HCAN0_MC7_2"); eprintf(" Message control 7 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE45B) { eprintf("HCAN0_MC7_3"); eprintf(" Message control 7 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE45C) { eprintf("HCAN0_MC7_4"); eprintf(" Message control 7 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE45D) { eprintf("HCAN0_MC7_5"); eprintf(" Message control 7 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE45E) { eprintf("HCAN0_MC7_6"); eprintf(" Message control 7 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE45F) { eprintf("HCAN0_MC7_7"); eprintf(" Message control 7 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE460) { eprintf("HCAN0_MC8_0"); eprintf(" Message control 8 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE461) { eprintf("HCAN0_MC8_1"); eprintf(" Message control 8 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE462) { eprintf("HCAN0_MC8_2"); eprintf(" Message control 8 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE463) { eprintf("HCAN0_MC8_3"); eprintf(" Message control 8 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE464) { eprintf("HCAN0_MC8_4"); eprintf(" Message control 8 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE465) { eprintf("HCAN0_MC8_5"); eprintf(" Message control 8 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE466) { eprintf("HCAN0_MC8_6"); eprintf(" Message control 8 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE467) { eprintf("HCAN0_MC8_7"); eprintf(" Message control 8 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE468) { eprintf("HCAN0_MC9_0"); eprintf(" Message control 9 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE469) { eprintf("HCAN0_MC9_1"); eprintf(" Message control 9 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE46A) { eprintf("HCAN0_MC9_2"); eprintf(" Message control 9 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE46B) { eprintf("HCAN0_MC9_3"); eprintf(" Message control 9 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE46C) { eprintf("HCAN0_MC9_4"); eprintf(" Message control 9 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE46D) { eprintf("HCAN0_MC9_5"); eprintf(" Message control 9 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE46E) { eprintf("HCAN0_MC9_6"); eprintf(" Message control 9 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE46F) { eprintf("HCAN0_MC9_7"); eprintf(" Message control 9 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE470) { eprintf("HCAN0_MC10_0"); eprintf(" Message control 10 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE471) { eprintf("HCAN0_MC10_1"); eprintf(" Message control 10 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE472) { eprintf("HCAN0_MC10_2"); eprintf(" Message control 10 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE473) { eprintf("HCAN0_MC10_3"); eprintf(" Message control 10 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE474) { eprintf("HCAN0_MC10_4"); eprintf(" Message control 10 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE475) { eprintf("HCAN0_MC10_5"); eprintf(" Message control 10 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE476) { eprintf("HCAN0_MC10_6"); eprintf(" Message control 10 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE477) { eprintf("HCAN0_MC10_7"); eprintf(" Message control 10 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE478) { eprintf("HCAN0_MC11_0"); eprintf(" Message control 11 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE479) { eprintf("HCAN0_MC11_1"); eprintf(" Message control 11 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE47A) { eprintf("HCAN0_MC11_2"); eprintf(" Message control 11 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE47B) { eprintf("HCAN0_MC11_3"); eprintf(" Message control 11 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE47C) { eprintf("HCAN0_MC11_4"); eprintf(" Message control 11 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE47D) { eprintf("HCAN0_MC11_5"); eprintf(" Message control 11 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE47E) { eprintf("HCAN0_MC11_6"); eprintf(" Message control 11 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE47F) { eprintf("HCAN0_MC11_7"); eprintf(" Message control 11 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE480) { eprintf("HCAN0_MC12_0"); eprintf(" Message control 12 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE481) { eprintf("HCAN0_MC12_1"); eprintf(" Message control 12 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE482) { eprintf("HCAN0_MC12_2"); eprintf(" Message control 12 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE483) { eprintf("HCAN0_MC12_3"); eprintf(" Message control 12 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE484) { eprintf("HCAN0_MC12_4"); eprintf(" Message control 12 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE485) { eprintf("HCAN0_MC12_5"); eprintf(" Message control 12 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE486) { eprintf("HCAN0_MC12_6"); eprintf(" Message control 12 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE487) { eprintf("HCAN0_MC12_7"); eprintf(" Message control 12 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE488) { eprintf("HCAN0_MC13_0"); eprintf(" Message control 13 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE489) { eprintf("HCAN0_MC13_1"); eprintf(" Message control 13 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE48A) { eprintf("HCAN0_MC13_2"); eprintf(" Message control 13 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE48B) { eprintf("HCAN0_MC13_3"); eprintf(" Message control 13 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE48C) { eprintf("HCAN0_MC13_4"); eprintf(" Message control 13 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE48D) { eprintf("HCAN0_MC13_5"); eprintf(" Message control 13 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE48E) { eprintf("HCAN0_MC13_6"); eprintf(" Message control 13 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE48F) { eprintf("HCAN0_MC13_7"); eprintf(" Message control 13 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE490) { eprintf("HCAN0_MC14_0"); eprintf(" Message control 14 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE491) { eprintf("HCAN0_MC14_1"); eprintf(" Message control 14 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE492) { eprintf("HCAN0_MC14_2"); eprintf(" Message control 14 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE493) { eprintf("HCAN0_MC14_3"); eprintf(" Message control 14 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE494) { eprintf("HCAN0_MC14_4"); eprintf(" Message control 14 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE495) { eprintf("HCAN0_MC14_5"); eprintf(" Message control 14 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE496) { eprintf("HCAN0_MC14_6"); eprintf(" Message control 14 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE497) { eprintf("HCAN0_MC14_7"); eprintf(" Message control 14 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE498) { eprintf("HCAN0_MC15_0"); eprintf(" Message control 15 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE499) { eprintf("HCAN0_MC15_1"); eprintf(" Message control 15 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE49A) { eprintf("HCAN0_MC15_2"); eprintf(" Message control 15 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE49B) { eprintf("HCAN0_MC15_3"); eprintf(" Message control 15 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE49C) { eprintf("HCAN0_MC15_4"); eprintf(" Message control 15 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE49D) { eprintf("HCAN0_MC15_5"); eprintf(" Message control 15 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE49E) { eprintf("HCAN0_MC15_6"); eprintf(" Message control 15 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE49F) { eprintf("HCAN0_MC15_7"); eprintf(" Message control 15 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE4B0) { eprintf("HCAN0_MD0_0"); eprintf(" Message data 0 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE4B1) { eprintf("HCAN0_MD0_1"); eprintf(" Message data 0 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE4B2) { eprintf("HCAN0_MD0_2"); eprintf(" Message data 0 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE4B3) { eprintf("HCAN0_MD0_3"); eprintf(" Message data 0 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE4B4) { eprintf("HCAN0_MD0_4"); eprintf(" Message data 0 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE4B5) { eprintf("HCAN0_MD0_5"); eprintf(" Message data 0 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE4B6) { eprintf("HCAN0_MD0_6"); eprintf(" Message data 0 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE4B7) { eprintf("HCAN0_MD0_7"); eprintf(" Message data 0 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE4B8) { eprintf("HCAN0_MD1_0"); eprintf(" Message data 1 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE4B9) { eprintf("HCAN0_MD1_1"); eprintf(" Message data 1 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE4BA) { eprintf("HCAN0_MD1_2"); eprintf(" Message data 1 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE4BB) { eprintf("HCAN0_MD1_3"); eprintf(" Message data 1 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE4BC) { eprintf("HCAN0_MD1_4"); eprintf(" Message data 1 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE4BD) { eprintf("HCAN0_MD1_5"); eprintf(" Message data 1 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE4BE) { eprintf("HCAN0_MD1_6"); eprintf(" Message data 1 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE4BF) { eprintf("HCAN0_MD1_7"); eprintf(" Message data 1 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE4C0) { eprintf("HCAN0_MD2_0"); eprintf(" Message data 2 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE4C1) { eprintf("HCAN0_MD2_1"); eprintf(" Message data 2 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE4C2) { eprintf("HCAN0_MD2_2"); eprintf(" Message data 2 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE4C3) { eprintf("HCAN0_MD2_3"); eprintf(" Message data 2 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE4C4) { eprintf("HCAN0_MD2_4"); eprintf(" Message data 2 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE4C5) { eprintf("HCAN0_MD2_5"); eprintf(" Message data 2 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE4C6) { eprintf("HCAN0_MD2_6"); eprintf(" Message data 2 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE4C7) { eprintf("HCAN0_MD2_7"); eprintf(" Message data 2 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE4C8) { eprintf("HCAN0_MD3_0"); eprintf(" Message data 3 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE4C9) { eprintf("HCAN0_MD3_1"); eprintf(" Message data 3 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE4CA) { eprintf("HCAN0_MD3_2"); eprintf(" Message data 3 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE4CB) { eprintf("HCAN0_MD3_3"); eprintf(" Message data 3 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE4CC) { eprintf("HCAN0_MD3_4"); eprintf(" Message data 3 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE4CD) { eprintf("HCAN0_MD3_5"); eprintf(" Message data 3 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE4CE) { eprintf("HCAN0_MD3_6"); eprintf(" Message data 3 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE4CF) { eprintf("HCAN0_MD3_7"); eprintf(" Message data 3 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE4D0) { eprintf("HCAN0_MD4_0"); eprintf(" Message data 4 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE4D1) { eprintf("HCAN0_MD4_1"); eprintf(" Message data 4 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE4D2) { eprintf("HCAN0_MD4_2"); eprintf(" Message data 4 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE4D3) { eprintf("HCAN0_MD4_3"); eprintf(" Message data 4 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE4D4) { eprintf("HCAN0_MD4_4"); eprintf(" Message data 4 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE4D5) { eprintf("HCAN0_MD4_5"); eprintf(" Message data 4 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE4D6) { eprintf("HCAN0_MD4_6"); eprintf(" Message data 4 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE4D7) { eprintf("HCAN0_MD4_7"); eprintf(" Message data 4 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE4D8) { eprintf("HCAN0_MD5_0"); eprintf(" Message data 5 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE4D9) { eprintf("HCAN0_MD5_1"); eprintf(" Message data 5 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE4DA) { eprintf("HCAN0_MD5_2"); eprintf(" Message data 5 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE4DB) { eprintf("HCAN0_MD5_3"); eprintf(" Message data 5 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE4DC) { eprintf("HCAN0_MD5_4"); eprintf(" Message data 5 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE4DD) { eprintf("HCAN0_MD5_5"); eprintf(" Message data 5 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE4DE) { eprintf("HCAN0_MD5_6"); eprintf(" Message data 5 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE4DF) { eprintf("HCAN0_MD5_7"); eprintf(" Message data 5 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE4E0) { eprintf("HCAN0_MD6_0"); eprintf(" Message data 6 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE4E1) { eprintf("HCAN0_MD6_1"); eprintf(" Message data 6 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE4E2) { eprintf("HCAN0_MD6_2"); eprintf(" Message data 6 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE4E3) { eprintf("HCAN0_MD6_3"); eprintf(" Message data 6 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE4E4) { eprintf("HCAN0_MD6_4"); eprintf(" Message data 6 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE4E5) { eprintf("HCAN0_MD6_5"); eprintf(" Message data 6 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE4E6) { eprintf("HCAN0_MD6_6"); eprintf(" Message data 6 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE4E7) { eprintf("HCAN0_MD6_7"); eprintf(" Message data 6 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE4E8) { eprintf("HCAN0_MD7_0"); eprintf(" Message data 7 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE4E9) { eprintf("HCAN0_MD7_1"); eprintf(" Message data 7 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE4EA) { eprintf("HCAN0_MD7_2"); eprintf(" Message data 7 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE4EB) { eprintf("HCAN0_MD7_3"); eprintf(" Message data 7 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE4EC) { eprintf("HCAN0_MD7_4"); eprintf(" Message data 7 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE4ED) { eprintf("HCAN0_MD7_5"); eprintf(" Message data 7 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE4EE) { eprintf("HCAN0_MD7_6"); eprintf(" Message data 7 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE4EF) { eprintf("HCAN0_MD7_7"); eprintf(" Message data 7 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE4F0) { eprintf("HCAN0_MD8_0"); eprintf(" Message data 8 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE4F1) { eprintf("HCAN0_MD8_1"); eprintf(" Message data 8 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE4F2) { eprintf("HCAN0_MD8_2"); eprintf(" Message data 8 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE4F3) { eprintf("HCAN0_MD8_3"); eprintf(" Message data 8 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE4F4) { eprintf("HCAN0_MD8_4"); eprintf(" Message data 8 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE4F5) { eprintf("HCAN0_MD8_5"); eprintf(" Message data 8 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE4F6) { eprintf("HCAN0_MD8_6"); eprintf(" Message data 8 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE4F7) { eprintf("HCAN0_MD8_7"); eprintf(" Message data 8 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE4F8) { eprintf("HCAN0_MD9_0"); eprintf(" Message data 9 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE4F9) { eprintf("HCAN0_MD9_1"); eprintf(" Message data 9 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE4FA) { eprintf("HCAN0_MD9_2"); eprintf(" Message data 9 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE4FB) { eprintf("HCAN0_MD9_3"); eprintf(" Message data 9 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE4FC) { eprintf("HCAN0_MD9_4"); eprintf(" Message data 9 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE4FD) { eprintf("HCAN0_MD9_5"); eprintf(" Message data 9 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE4FE) { eprintf("HCAN0_MD9_6"); eprintf(" Message data 9 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE4FF) { eprintf("HCAN0_MD9_7"); eprintf(" Message data 9 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE500) { eprintf("HCAN0_MD10_0"); eprintf(" Message data 10 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE501) { eprintf("HCAN0_MD10_1"); eprintf(" Message data 10 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE502) { eprintf("HCAN0_MD10_2"); eprintf(" Message data 10 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE503) { eprintf("HCAN0_MD10_3"); eprintf(" Message data 10 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE504) { eprintf("HCAN0_MD10_4"); eprintf(" Message data 10 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE505) { eprintf("HCAN0_MD10_5"); eprintf(" Message data 10 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE506) { eprintf("HCAN0_MD10_6"); eprintf(" Message data 10 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE507) { eprintf("HCAN0_MD10_7"); eprintf(" Message data 10 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE508) { eprintf("HCAN0_MD11_0"); eprintf(" Message data 11 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE509) { eprintf("HCAN0_MD11_1"); eprintf(" Message data 11 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE50A) { eprintf("HCAN0_MD11_2"); eprintf(" Message data 11 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE50B) { eprintf("HCAN0_MD11_3"); eprintf(" Message data 11 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE50C) { eprintf("HCAN0_MD11_4"); eprintf(" Message data 11 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE50D) { eprintf("HCAN0_MD11_5"); eprintf(" Message data 11 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE50E) { eprintf("HCAN0_MD11_6"); eprintf(" Message data 11 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE50F) { eprintf("HCAN0_MD11_7"); eprintf(" Message data 11 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE510) { eprintf("HCAN0_MD12_0"); eprintf(" Message data 12 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE511) { eprintf("HCAN0_MD12_1"); eprintf(" Message data 12 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE512) { eprintf("HCAN0_MD12_2"); eprintf(" Message data 12 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE513) { eprintf("HCAN0_MD12_3"); eprintf(" Message data 12 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE514) { eprintf("HCAN0_MD12_4"); eprintf(" Message data 12 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE515) { eprintf("HCAN0_MD12_5"); eprintf(" Message data 12 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE516) { eprintf("HCAN0_MD12_6"); eprintf(" Message data 12 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE517) { eprintf("HCAN0_MD12_7"); eprintf(" Message data 12 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE518) { eprintf("HCAN0_MD13_0"); eprintf(" Message data 13 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE519) { eprintf("HCAN0_MD13_1"); eprintf(" Message data 13 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE51A) { eprintf("HCAN0_MD13_2"); eprintf(" Message data 13 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE51B) { eprintf("HCAN0_MD13_3"); eprintf(" Message data 13 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE51C) { eprintf("HCAN0_MD13_4"); eprintf(" Message data 13 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE51D) { eprintf("HCAN0_MD13_5"); eprintf(" Message data 13 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE51E) { eprintf("HCAN0_MD13_6"); eprintf(" Message data 13 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE51F) { eprintf("HCAN0_MD13_7"); eprintf(" Message data 13 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE520) { eprintf("HCAN0_MD14_0"); eprintf(" Message data 14 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE521) { eprintf("HCAN0_MD14_1"); eprintf(" Message data 14 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE522) { eprintf("HCAN0_MD14_2"); eprintf(" Message data 14 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE523) { eprintf("HCAN0_MD14_3"); eprintf(" Message data 14 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE524) { eprintf("HCAN0_MD14_4"); eprintf(" Message data 14 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE525) { eprintf("HCAN0_MD14_5"); eprintf(" Message data 14 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE526) { eprintf("HCAN0_MD14_6"); eprintf(" Message data 14 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE527) { eprintf("HCAN0_MD14_7"); eprintf(" Message data 14 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE528) { eprintf("HCAN0_MD15_0"); eprintf(" Message data 15 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE529) { eprintf("HCAN0_MD15_1"); eprintf(" Message data 15 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE52A) { eprintf("HCAN0_MD15_2"); eprintf(" Message data 15 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE52B) { eprintf("HCAN0_MD15_3"); eprintf(" Message data 15 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE52C) { eprintf("HCAN0_MD15_4"); eprintf(" Message data 15 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE52D) { eprintf("HCAN0_MD15_5"); eprintf(" Message data 15 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE52E) { eprintf("HCAN0_MD15_6"); eprintf(" Message data 15 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE52F) { eprintf("HCAN0_MD15_7"); eprintf(" Message data 15 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE600) { eprintf("HCAN1_MCR"); eprintf(" Master control register(0x%x)\n",addr);
	} else if(addr==0xFFFFE601) { eprintf("HCAN1_GSR"); eprintf(" General status register(0x%x)\n",addr);
	} else if(addr==0xFFFFE602) { eprintf("HCAN1_BCR"); eprintf(" Bit configuration register(0x%x)\n",addr);
	} else if(addr==0xFFFFE604) { eprintf("HCAN1_MBCR"); eprintf(" Mailbox configuration register(0x%x)\n",addr);
	} else if(addr==0xFFFFE606) { eprintf("HCAN1_TXPR"); eprintf(" Transmit wait register(0x%x)\n",addr);
	} else if(addr==0xFFFFE608) { eprintf("HCAN1_TXCR"); eprintf(" Transmit wait cancel  register(0x%x)\n",addr);
	} else if(addr==0xFFFFE60A) { eprintf("HCAN1_TXACK"); eprintf(" Transmit acknowledge register(0x%x)\n",addr);
	} else if(addr==0xFFFFE60C) { eprintf("HCAN1_ABACK"); eprintf(" Abort acknowledge register(0x%x)\n",addr);
	} else if(addr==0xFFFFE60E) { eprintf("HCAN1_RXPR"); eprintf(" Receive complete register(0x%x)\n",addr);
	} else if(addr==0xFFFFE610) { eprintf("HCAN1_RFPR"); eprintf(" Remote request register(0x%x)\n",addr);
	} else if(addr==0xFFFFE612) { eprintf("HCAN1_IRR"); eprintf(" Interrupt register(0x%x)\n",addr);
	} else if(addr==0xFFFFE614) { eprintf("HCAN1_MBIMR"); eprintf(" Mailbox interrupt mask register(0x%x)\n",addr);
	} else if(addr==0xFFFFE616) { eprintf("HCAN1_IMR"); eprintf(" Interrupt mask register(0x%x)\n",addr);
	} else if(addr==0xFFFFE618) { eprintf("HCAN1_REC"); eprintf(" Receive error counter(0x%x)\n",addr);
	} else if(addr==0xFFFFE619) { eprintf("HCAN1_TEC"); eprintf(" Transmit error counter(0x%x)\n",addr);
	} else if(addr==0xFFFFE61A) { eprintf("HCAN1_UMSR"); eprintf(" Unread message status register(0x%x)\n",addr);
	} else if(addr==0xFFFFE61C) { eprintf("HCAN1_LAFML"); eprintf(" Local acceptance filter mask L(0x%x)\n",addr);
	} else if(addr==0xFFFFE61E) { eprintf("HCAN1_LAFMH"); eprintf(" Local acceptance filter mask H(0x%x)\n",addr);
	} else if(addr==0xFFFFE620) { eprintf("HCAN1_MC0_0"); eprintf(" Message control 0 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE621) { eprintf("HCAN1_MC0_1"); eprintf(" Message control 0 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE622) { eprintf("HCAN1_MC0_2"); eprintf(" Message control 0 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE623) { eprintf("HCAN1_MC0_3"); eprintf(" Message control 0 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE624) { eprintf("HCAN1_MC0_4"); eprintf(" Message control 0 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE625) { eprintf("HCAN1_MC0_5"); eprintf(" Message control 0 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE626) { eprintf("HCAN1_MC0_6"); eprintf(" Message control 0 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE627) { eprintf("HCAN1_MC0_7"); eprintf(" Message control 0 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE628) { eprintf("HCAN1_MC1_0"); eprintf(" Message control 1 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE629) { eprintf("HCAN1_MC1_1"); eprintf(" Message control 1 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE62A) { eprintf("HCAN1_MC1_2"); eprintf(" Message control 1 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE62B) { eprintf("HCAN1_MC1_3"); eprintf(" Message control 1 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE62C) { eprintf("HCAN1_MC1_4"); eprintf(" Message control 1 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE62D) { eprintf("HCAN1_MC1_5"); eprintf(" Message control 1 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE62E) { eprintf("HCAN1_MC1_6"); eprintf(" Message control 1 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE62F) { eprintf("HCAN1_MC1_7"); eprintf(" Message control 1 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE630) { eprintf("HCAN1_MC2_0"); eprintf(" Message control 2 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE631) { eprintf("HCAN1_MC2_1"); eprintf(" Message control 2 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE632) { eprintf("HCAN1_MC2_2"); eprintf(" Message control 2 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE633) { eprintf("HCAN1_MC2_3"); eprintf(" Message control 2 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE634) { eprintf("HCAN1_MC2_4"); eprintf(" Message control 2 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE635) { eprintf("HCAN1_MC2_5"); eprintf(" Message control 2 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE636) { eprintf("HCAN1_MC2_6"); eprintf(" Message control 2 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE637) { eprintf("HCAN1_MC2_7"); eprintf(" Message control 2 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE638) { eprintf("HCAN1_MC3_0"); eprintf(" Message control 3 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE639) { eprintf("HCAN1_MC3_1"); eprintf(" Message control 3 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE63A) { eprintf("HCAN1_MC3_2"); eprintf(" Message control 3 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE63B) { eprintf("HCAN1_MC3_3"); eprintf(" Message control 3 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE63C) { eprintf("HCAN1_MC3_4"); eprintf(" Message control 3 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE63D) { eprintf("HCAN1_MC3_5"); eprintf(" Message control 3 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE63E) { eprintf("HCAN1_MC3_6"); eprintf(" Message control 3 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE63F) { eprintf("HCAN1_MC3_7"); eprintf(" Message control 3 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE640) { eprintf("HCAN1_MC4_0"); eprintf(" Message control 4 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE641) { eprintf("HCAN1_MC4_1"); eprintf(" Message control 4 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE642) { eprintf("HCAN1_MC4_2"); eprintf(" Message control 4 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE643) { eprintf("HCAN1_MC4_3"); eprintf(" Message control 4 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE644) { eprintf("HCAN1_MC4_4"); eprintf(" Message control 4 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE645) { eprintf("HCAN1_MC4_5"); eprintf(" Message control 4 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE646) { eprintf("HCAN1_MC4_6"); eprintf(" Message control 4 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE647) { eprintf("HCAN1_MC4_7"); eprintf(" Message control 4 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE648) { eprintf("HCAN1_MC5_0"); eprintf(" Message control 5 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE649) { eprintf("HCAN1_MC5_1"); eprintf(" Message control 5 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE64A) { eprintf("HCAN1_MC5_2"); eprintf(" Message control 5 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE64B) { eprintf("HCAN1_MC5_3"); eprintf(" Message control 5 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE64C) { eprintf("HCAN1_MC5_4"); eprintf(" Message control 5 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE64D) { eprintf("HCAN1_MC5_5"); eprintf(" Message control 5 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE64E) { eprintf("HCAN1_MC5_6"); eprintf(" Message control 5 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE64F) { eprintf("HCAN1_MC5_7"); eprintf(" Message control 5 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE650) { eprintf("HCAN1_MC6_0"); eprintf(" Message control 6 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE651) { eprintf("HCAN1_MC6_1"); eprintf(" Message control 6 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE652) { eprintf("HCAN1_MC6_2"); eprintf(" Message control 6 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE653) { eprintf("HCAN1_MC6_3"); eprintf(" Message control 6 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE654) { eprintf("HCAN1_MC6_4"); eprintf(" Message control 6 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE655) { eprintf("HCAN1_MC6_5"); eprintf(" Message control 6 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE656) { eprintf("HCAN1_MC6_6"); eprintf(" Message control 6 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE657) { eprintf("HCAN1_MC6_7"); eprintf(" Message control 6 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE658) { eprintf("HCAN1_MC7_0"); eprintf(" Message control 7 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE659) { eprintf("HCAN1_MC7_1"); eprintf(" Message control 7 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE65A) { eprintf("HCAN1_MC7_2"); eprintf(" Message control 7 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE65B) { eprintf("HCAN1_MC7_3"); eprintf(" Message control 7 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE65C) { eprintf("HCAN1_MC7_4"); eprintf(" Message control 7 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE65D) { eprintf("HCAN1_MC7_5"); eprintf(" Message control 7 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE65E) { eprintf("HCAN1_MC7_6"); eprintf(" Message control 7 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE65F) { eprintf("HCAN1_MC7_7"); eprintf(" Message control 7 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE660) { eprintf("HCAN1_MC8_0"); eprintf(" Message control 8 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE661) { eprintf("HCAN1_MC8_1"); eprintf(" Message control 8 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE662) { eprintf("HCAN1_MC8_2"); eprintf(" Message control 8 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE663) { eprintf("HCAN1_MC8_3"); eprintf(" Message control 8 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE664) { eprintf("HCAN1_MC8_4"); eprintf(" Message control 8 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE665) { eprintf("HCAN1_MC8_5"); eprintf(" Message control 8 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE666) { eprintf("HCAN1_MC8_6"); eprintf(" Message control 8 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE667) { eprintf("HCAN1_MC8_7"); eprintf(" Message control 8 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE668) { eprintf("HCAN1_MC9_0"); eprintf(" Message control 9 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE669) { eprintf("HCAN1_MC9_1"); eprintf(" Message control 9 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE66A) { eprintf("HCAN1_MC9_2"); eprintf(" Message control 9 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE66B) { eprintf("HCAN1_MC9_3"); eprintf(" Message control 9 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE66C) { eprintf("HCAN1_MC9_4"); eprintf(" Message control 9 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE66D) { eprintf("HCAN1_MC9_5"); eprintf(" Message control 9 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE66E) { eprintf("HCAN1_MC9_6"); eprintf(" Message control 9 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE66F) { eprintf("HCAN1_MC9_7"); eprintf(" Message control 9 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE670) { eprintf("HCAN1_MC10_0"); eprintf(" Message control 10 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE671) { eprintf("HCAN1_MC10_1"); eprintf(" Message control 10 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE672) { eprintf("HCAN1_MC10_2"); eprintf(" Message control 10 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE673) { eprintf("HCAN1_MC10_3"); eprintf(" Message control 10 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE674) { eprintf("HCAN1_MC10_4"); eprintf(" Message control 10 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE675) { eprintf("HCAN1_MC10_5"); eprintf(" Message control 10 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE676) { eprintf("HCAN1_MC10_6"); eprintf(" Message control 10 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE677) { eprintf("HCAN1_MC10_7"); eprintf(" Message control 10 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE678) { eprintf("HCAN1_MC11_0"); eprintf(" Message control 11 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE679) { eprintf("HCAN1_MC11_1"); eprintf(" Message control 11 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE67A) { eprintf("HCAN1_MC11_2"); eprintf(" Message control 11 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE67B) { eprintf("HCAN1_MC11_3"); eprintf(" Message control 11 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE67C) { eprintf("HCAN1_MC11_4"); eprintf(" Message control 11 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE67D) { eprintf("HCAN1_MC11_5"); eprintf(" Message control 11 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE67E) { eprintf("HCAN1_MC11_6"); eprintf(" Message control 11 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE67F) { eprintf("HCAN1_MC11_7"); eprintf(" Message control 11 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE680) { eprintf("HCAN1_MC12_0"); eprintf(" Message control 12 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE681) { eprintf("HCAN1_MC12_1"); eprintf(" Message control 12 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE682) { eprintf("HCAN1_MC12_2"); eprintf(" Message control 12 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE683) { eprintf("HCAN1_MC12_3"); eprintf(" Message control 12 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE684) { eprintf("HCAN1_MC12_4"); eprintf(" Message control 12 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE685) { eprintf("HCAN1_MC12_5"); eprintf(" Message control 12 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE686) { eprintf("HCAN1_MC12_6"); eprintf(" Message control 12 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE687) { eprintf("HCAN1_MC12_7"); eprintf(" Message control 12 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE688) { eprintf("HCAN1_MC13_0"); eprintf(" Message control 13 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE689) { eprintf("HCAN1_MC13_1"); eprintf(" Message control 13 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE68A) { eprintf("HCAN1_MC13_2"); eprintf(" Message control 13 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE68B) { eprintf("HCAN1_MC13_3"); eprintf(" Message control 13 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE68C) { eprintf("HCAN1_MC13_4"); eprintf(" Message control 13 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE68D) { eprintf("HCAN1_MC13_5"); eprintf(" Message control 13 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE68E) { eprintf("HCAN1_MC13_6"); eprintf(" Message control 13 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE68F) { eprintf("HCAN1_MC13_7"); eprintf(" Message control 13 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE690) { eprintf("HCAN1_MC14_0"); eprintf(" Message control 14 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE691) { eprintf("HCAN1_MC14_1"); eprintf(" Message control 14 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE692) { eprintf("HCAN1_MC14_2"); eprintf(" Message control 14 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE693) { eprintf("HCAN1_MC14_3"); eprintf(" Message control 14 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE694) { eprintf("HCAN1_MC14_4"); eprintf(" Message control 14 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE695) { eprintf("HCAN1_MC14_5"); eprintf(" Message control 14 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE696) { eprintf("HCAN1_MC14_6"); eprintf(" Message control 14 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE697) { eprintf("HCAN1_MC14_7"); eprintf(" Message control 14 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE698) { eprintf("HCAN1_MC15_0"); eprintf(" Message control 15 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE699) { eprintf("HCAN1_MC15_1"); eprintf(" Message control 15 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE69A) { eprintf("HCAN1_MC15_2"); eprintf(" Message control 15 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE69B) { eprintf("HCAN1_MC15_3"); eprintf(" Message control 15 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE69C) { eprintf("HCAN1_MC15_4"); eprintf(" Message control 15 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE69D) { eprintf("HCAN1_MC15_5"); eprintf(" Message control 15 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE69E) { eprintf("HCAN1_MC15_6"); eprintf(" Message control 15 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE69F) { eprintf("HCAN1_MC15_7"); eprintf(" Message control 15 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE6B0) { eprintf("HCAN1_MD0_0"); eprintf(" Message data 0 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE6B1) { eprintf("HCAN1_MD0_1"); eprintf(" Message data 0 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE6B2) { eprintf("HCAN1_MD0_2"); eprintf(" Message data 0 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE6B3) { eprintf("HCAN1_MD0_3"); eprintf(" Message data 0 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE6B4) { eprintf("HCAN1_MD0_4"); eprintf(" Message data 0 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE6B5) { eprintf("HCAN1_MD0_5"); eprintf(" Message data 0 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE6B6) { eprintf("HCAN1_MD0_6"); eprintf(" Message data 0 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE6B7) { eprintf("HCAN1_MD0_7"); eprintf(" Message data 0 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE6B8) { eprintf("HCAN1_MD1_0"); eprintf(" Message data 1 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE6B9) { eprintf("HCAN1_MD1_1"); eprintf(" Message data 1 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE6BA) { eprintf("HCAN1_MD1_2"); eprintf(" Message data 1 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE6BB) { eprintf("HCAN1_MD1_3"); eprintf(" Message data 1 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE6BC) { eprintf("HCAN1_MD1_4"); eprintf(" Message data 1 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE6BD) { eprintf("HCAN1_MD1_5"); eprintf(" Message data 1 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE6BE) { eprintf("HCAN1_MD1_6"); eprintf(" Message data 1 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE6BF) { eprintf("HCAN1_MD1_7"); eprintf(" Message data 1 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE6C0) { eprintf("HCAN1_MD2_0"); eprintf(" Message data 2 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE6C1) { eprintf("HCAN1_MD2_1"); eprintf(" Message data 2 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE6C2) { eprintf("HCAN1_MD2_2"); eprintf(" Message data 2 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE6C3) { eprintf("HCAN1_MD2_3"); eprintf(" Message data 2 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE6C4) { eprintf("HCAN1_MD2_4"); eprintf(" Message data 2 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE6C5) { eprintf("HCAN1_MD2_5"); eprintf(" Message data 2 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE6C6) { eprintf("HCAN1_MD2_6"); eprintf(" Message data 2 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE6C7) { eprintf("HCAN1_MD2_7"); eprintf(" Message data 2 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE6C8) { eprintf("HCAN1_MD3_0"); eprintf(" Message data 3 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE6C9) { eprintf("HCAN1_MD3_1"); eprintf(" Message data 3 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE6CA) { eprintf("HCAN1_MD3_2"); eprintf(" Message data 3 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE6CB) { eprintf("HCAN1_MD3_3"); eprintf(" Message data 3 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE6CC) { eprintf("HCAN1_MD3_4"); eprintf(" Message data 3 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE6CD) { eprintf("HCAN1_MD3_5"); eprintf(" Message data 3 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE6CE) { eprintf("HCAN1_MD3_6"); eprintf(" Message data 3 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE6CF) { eprintf("HCAN1_MD3_7"); eprintf(" Message data 3 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE6D0) { eprintf("HCAN1_MD4_0"); eprintf(" Message data 4 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE6D1) { eprintf("HCAN1_MD4_1"); eprintf(" Message data 4 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE6D2) { eprintf("HCAN1_MD4_2"); eprintf(" Message data 4 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE6D3) { eprintf("HCAN1_MD4_3"); eprintf(" Message data 4 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE6D4) { eprintf("HCAN1_MD4_4"); eprintf(" Message data 4 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE6D5) { eprintf("HCAN1_MD4_5"); eprintf(" Message data 4 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE6D6) { eprintf("HCAN1_MD4_6"); eprintf(" Message data 4 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE6D7) { eprintf("HCAN1_MD4_7"); eprintf(" Message data 4 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE6D8) { eprintf("HCAN1_MD5_0"); eprintf(" Message data 5 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE6D9) { eprintf("HCAN1_MD5_1"); eprintf(" Message data 5 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE6DA) { eprintf("HCAN1_MD5_2"); eprintf(" Message data 5 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE6DB) { eprintf("HCAN1_MD5_3"); eprintf(" Message data 5 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE6DC) { eprintf("HCAN1_MD5_4"); eprintf(" Message data 5 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE6DD) { eprintf("HCAN1_MD5_5"); eprintf(" Message data 5 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE6DE) { eprintf("HCAN1_MD5_6"); eprintf(" Message data 5 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE6DF) { eprintf("HCAN1_MD5_7"); eprintf(" Message data 5 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE6E0) { eprintf("HCAN1_MD6_0"); eprintf(" Message data 6 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE6E1) { eprintf("HCAN1_MD6_1"); eprintf(" Message data 6 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE6E2) { eprintf("HCAN1_MD6_2"); eprintf(" Message data 6 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE6E3) { eprintf("HCAN1_MD6_3"); eprintf(" Message data 6 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE6E4) { eprintf("HCAN1_MD6_4"); eprintf(" Message data 6 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE6E5) { eprintf("HCAN1_MD6_5"); eprintf(" Message data 6 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE6E6) { eprintf("HCAN1_MD6_6"); eprintf(" Message data 6 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE6E7) { eprintf("HCAN1_MD6_7"); eprintf(" Message data 6 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE6E8) { eprintf("HCAN1_MD7_0"); eprintf(" Message data 7 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE6E9) { eprintf("HCAN1_MD7_1"); eprintf(" Message data 7 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE6EA) { eprintf("HCAN1_MD7_2"); eprintf(" Message data 7 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE6EB) { eprintf("HCAN1_MD7_3"); eprintf(" Message data 7 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE6EC) { eprintf("HCAN1_MD7_4"); eprintf(" Message data 7 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE6ED) { eprintf("HCAN1_MD7_5"); eprintf(" Message data 7 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE6EE) { eprintf("HCAN1_MD7_6"); eprintf(" Message data 7 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE6EF) { eprintf("HCAN1_MD7_7"); eprintf(" Message data 7 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE6F0) { eprintf("HCAN1_MD8_0"); eprintf(" Message data 8 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE6F1) { eprintf("HCAN1_MD8_1"); eprintf(" Message data 8 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE6F2) { eprintf("HCAN1_MD8_2"); eprintf(" Message data 8 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE6F3) { eprintf("HCAN1_MD8_3"); eprintf(" Message data 8 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE6F4) { eprintf("HCAN1_MD8_4"); eprintf(" Message data 8 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE6F5) { eprintf("HCAN1_MD8_5"); eprintf(" Message data 8 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE6F6) { eprintf("HCAN1_MD8_6"); eprintf(" Message data 8 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE6F7) { eprintf("HCAN1_MD8_7"); eprintf(" Message data 8 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE6F8) { eprintf("HCAN1_MD9_0"); eprintf(" Message data 9 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE6F9) { eprintf("HCAN1_MD9_1"); eprintf(" Message data 9 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE6FA) { eprintf("HCAN1_MD9_2"); eprintf(" Message data 9 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE6FB) { eprintf("HCAN1_MD9_3"); eprintf(" Message data 9 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE6FC) { eprintf("HCAN1_MD9_4"); eprintf(" Message data 9 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE6FD) { eprintf("HCAN1_MD9_5"); eprintf(" Message data 9 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE6FE) { eprintf("HCAN1_MD9_6"); eprintf(" Message data 9 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE6FF) { eprintf("HCAN1_MD9_7"); eprintf(" Message data 9 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE700) { eprintf("HCAN1_MD10_0"); eprintf(" Message data 10 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE701) { eprintf("HCAN1_MD10_1"); eprintf(" Message data 10 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE702) { eprintf("HCAN1_MD10_2"); eprintf(" Message data 10 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE703) { eprintf("HCAN1_MD10_3"); eprintf(" Message data 10 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE704) { eprintf("HCAN1_MD10_4"); eprintf(" Message data 10 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE705) { eprintf("HCAN1_MD10_5"); eprintf(" Message data 10 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE706) { eprintf("HCAN1_MD10_6"); eprintf(" Message data 10 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE707) { eprintf("HCAN1_MD10_7"); eprintf(" Message data 10 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE708) { eprintf("HCAN1_MD11_0"); eprintf(" Message data 11 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE709) { eprintf("HCAN1_MD11_1"); eprintf(" Message data 11 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE70A) { eprintf("HCAN1_MD11_2"); eprintf(" Message data 11 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE70B) { eprintf("HCAN1_MD11_3"); eprintf(" Message data 11 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE70C) { eprintf("HCAN1_MD11_4"); eprintf(" Message data 11 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE70D) { eprintf("HCAN1_MD11_5"); eprintf(" Message data 11 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE70E) { eprintf("HCAN1_MD11_6"); eprintf(" Message data 11 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE70F) { eprintf("HCAN1_MD11_7"); eprintf(" Message data 11 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE710) { eprintf("HCAN1_MD12_0"); eprintf(" Message data 12 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE711) { eprintf("HCAN1_MD12_1"); eprintf(" Message data 12 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE712) { eprintf("HCAN1_MD12_2"); eprintf(" Message data 12 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE713) { eprintf("HCAN1_MD12_3"); eprintf(" Message data 12 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE714) { eprintf("HCAN1_MD12_4"); eprintf(" Message data 12 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE715) { eprintf("HCAN1_MD12_5"); eprintf(" Message data 12 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE716) { eprintf("HCAN1_MD12_6"); eprintf(" Message data 12 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE717) { eprintf("HCAN1_MD12_7"); eprintf(" Message data 12 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE718) { eprintf("HCAN1_MD13_0"); eprintf(" Message data 13 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE719) { eprintf("HCAN1_MD13_1"); eprintf(" Message data 13 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE71A) { eprintf("HCAN1_MD13_2"); eprintf(" Message data 13 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE71B) { eprintf("HCAN1_MD13_3"); eprintf(" Message data 13 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE71C) { eprintf("HCAN1_MD13_4"); eprintf(" Message data 13 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE71D) { eprintf("HCAN1_MD13_5"); eprintf(" Message data 13 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE71E) { eprintf("HCAN1_MD13_6"); eprintf(" Message data 13 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE71F) { eprintf("HCAN1_MD13_7"); eprintf(" Message data 13 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE720) { eprintf("HCAN1_MD14_0"); eprintf(" Message data 14 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE721) { eprintf("HCAN1_MD14_1"); eprintf(" Message data 14 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE722) { eprintf("HCAN1_MD14_2"); eprintf(" Message data 14 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE723) { eprintf("HCAN1_MD14_3"); eprintf(" Message data 14 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE724) { eprintf("HCAN1_MD14_4"); eprintf(" Message data 14 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE725) { eprintf("HCAN1_MD14_5"); eprintf(" Message data 14 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE726) { eprintf("HCAN1_MD14_6"); eprintf(" Message data 14 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE727) { eprintf("HCAN1_MD14_7"); eprintf(" Message data 14 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE728) { eprintf("HCAN1_MD15_0"); eprintf(" Message data 15 0(0x%x)\n",addr);
	} else if(addr==0xFFFFE729) { eprintf("HCAN1_MD15_1"); eprintf(" Message data 15 1(0x%x)\n",addr);
	} else if(addr==0xFFFFE72A) { eprintf("HCAN1_MD15_2"); eprintf(" Message data 15 2(0x%x)\n",addr);
	} else if(addr==0xFFFFE72B) { eprintf("HCAN1_MD15_3"); eprintf(" Message data 15 3(0x%x)\n",addr);
	} else if(addr==0xFFFFE72C) { eprintf("HCAN1_MD15_4"); eprintf(" Message data 15 4(0x%x)\n",addr);
	} else if(addr==0xFFFFE72D) { eprintf("HCAN1_MD15_5"); eprintf(" Message data 15 5(0x%x)\n",addr);
	} else if(addr==0xFFFFE72E) { eprintf("HCAN1_MD15_6"); eprintf(" Message data 15 6(0x%x)\n",addr);
	} else if(addr==0xFFFFE72F) { eprintf("HCAN1_MD15_7"); eprintf(" Message data 15 7(0x%x)\n",addr);
	} else if(addr==0xFFFFE800) { eprintf("FLASH_FCCS"); eprintf(" Flash code control status register(0x%x)\n",addr);
	} else if(addr==0xFFFFE801) { eprintf("FLASH_FPCS"); eprintf(" Flash program code select register(0x%x)\n",addr);
	} else if(addr==0xFFFFE802) { eprintf("FLASH_FECS"); eprintf(" Flash erase code select register(0x%x)\n",addr);
	} else if(addr==0xFFFFE804) { eprintf("FLASH_FKEY"); eprintf(" Flash key code register(0x%x)\n",addr);
	} else if(addr==0xFFFFE805) { eprintf("FLASH_FMATS"); eprintf(" Flash MAT select register(0x%x)\n",addr);
	} else if(addr==0xFFFFE806) { eprintf("FLASH_FTDAR"); eprintf(" Flash transfer destination address register(0x%x)\n",addr);
	} else if(addr==0xFFFFEC00) { eprintf("UBS_UBARH"); eprintf(" User break address register H(0x%x)\n",addr);
	} else if(addr==0xFFFFEC02) { eprintf("UBS_UBARL"); eprintf(" User break address register L(0x%x)\n",addr);
	} else if(addr==0xFFFFEC04) { eprintf("UBS_UBAMRH"); eprintf(" User break address mask register H(0x%x)\n",addr);
	} else if(addr==0xFFFFEC06) { eprintf("UBS_UBAMRL"); eprintf(" User break address mask register L(0x%x)\n",addr);
	} else if(addr==0xFFFFEC08) { eprintf("UBS_UBBR"); eprintf(" User break bus cycle register(0x%x)\n",addr);
	} else if(addr==0xFFFFEC0A) { eprintf("UBS_UBCR"); eprintf(" User break control register(0x%x)\n",addr);
	} else if(addr==0xFFFFEC10) { eprintf("WDT_TCSR"); eprintf(" Timer control/status register(0x%x)\n",addr);
	} else if(addr==0xFFFFEC11) { eprintf("WDT_TCNT"); eprintf(" Timer counter(0x%x)\n",addr);
	} else if(addr==0xFFFFEC12) { eprintf("WDT_RSTCSR_W"); eprintf(" Reset control/status register(write)(0x%x)\n",addr);
	} else if(addr==0xFFFFEC13) { eprintf("WDT_RSTCSR_R"); eprintf(" Reset control/status register(read)(0x%x)\n",addr);
	} else if(addr==0xFFFFEC14) { eprintf("PDS_SBYCR"); eprintf(" Standby control register(0x%x)\n",addr);
	} else if(addr==0xFFFFF708) { eprintf("PDS_SYSCR"); eprintf(" System control register(0x%x)\n",addr);
	} else if(addr==0xFFFFF70A) { eprintf("PDS_MSTCR_W"); eprintf(" Module standby control register(write)(0x%x)\n",addr);
	} else if(addr==0xFFFFF70B) { eprintf("PDS_MSTCR_R"); eprintf(" Module standby control register(read)(0x%x)\n",addr);
	} else if(addr==0xFFFFEC20) { eprintf("BSC_BCR1"); eprintf(" Bus control register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFEC22) { eprintf("BSC_BCR2"); eprintf(" Bus control register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFEC24) { eprintf("BSC_WCR"); eprintf(" Wait state control register(0x%x)\n",addr);
	} else if(addr==0xFFFFEC26) { eprintf("BSC_RAMER"); eprintf(" RAM emulation register(0x%x)\n",addr);
	} else if(addr==0xFFFFECC0)  { eprintf("DMAC_SAR0"); eprintf(" DMA source address register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFECC4)  { eprintf("DMAC_DAR0"); eprintf(" DMA destination address register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFECC8)  { eprintf("DMAC_DMATCR0"); eprintf(" DMA transfer count register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFECCC)  { eprintf("DMAC_CHCR0"); eprintf(" DMA channel control register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFECD0)  { eprintf("DMAC_SAR1"); eprintf(" DMA source address register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFECD4)  { eprintf("DMAC_DAR1"); eprintf(" DMA destination address register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFECD8)  { eprintf("DMAC_DMATCR1"); eprintf(" DMA transfer count register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFECDC)  { eprintf("DMAC_CHCR1"); eprintf(" DMA channel control register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFECE0)  { eprintf("DMAC_SAR2"); eprintf(" DMA source address register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFECE4)  { eprintf("DMAC_DAR2"); eprintf(" DMA destination address register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFECE8)  { eprintf("DMAC_DMATCR2"); eprintf(" DMA transfer count register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFECEC)  { eprintf("DMAC_CHCR2"); eprintf(" DMA channel control register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFECF0)  { eprintf("DMAC_SAR3"); eprintf(" DMA source address register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFECF4)  { eprintf("DMAC_DAR3"); eprintf(" DMA destination address register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFECF8)  { eprintf("DMAC_DMATCR3"); eprintf(" DMA transfer count register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFECFC)  { eprintf("DMAC_CHCR3"); eprintf(" DMA channel control register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFECB0) { eprintf("DMAC_DMAOR"); eprintf(" DMA operation register(0x%x)\n",addr);
	} else if(addr==0xFFFFED00) { eprintf("INTC_IPRA"); eprintf(" Interrupt priority register A(0x%x)\n",addr);
	} else if(addr==0xFFFFED02) { eprintf("INTC_IPRB"); eprintf(" Interrupt priority register B(0x%x)\n",addr);
	} else if(addr==0xFFFFED04) { eprintf("INTC_IPRC"); eprintf(" Interrupt priority register C(0x%x)\n",addr);
	} else if(addr==0xFFFFED06) { eprintf("INTC_IPRD"); eprintf(" Interrupt priority register D(0x%x)\n",addr);
	} else if(addr==0xFFFFED08) { eprintf("INTC_IPRE"); eprintf(" Interrupt priority register E(0x%x)\n",addr);
	} else if(addr==0xFFFFED0A) { eprintf("INTC_IPRF"); eprintf(" Interrupt priority register F(0x%x)\n",addr);
	} else if(addr==0xFFFFED0C) { eprintf("INTC_IPRG"); eprintf(" Interrupt priority register G(0x%x)\n",addr);
	} else if(addr==0xFFFFED0E) { eprintf("INTC_IPRH"); eprintf(" Interrupt priority register H(0x%x)\n",addr);
	} else if(addr==0xFFFFED10) { eprintf("INTC_IPRI"); eprintf(" Interrupt priority register I(0x%x)\n",addr);
	} else if(addr==0xFFFFED12) { eprintf("INTC_IPRJ"); eprintf(" Interrupt priority register J(0x%x)\n",addr);
	} else if(addr==0xFFFFED14) { eprintf("INTC_IPRK"); eprintf(" Interrupt priority register K(0x%x)\n",addr);
	} else if(addr==0xFFFFED16) { eprintf("INTC_IPRL"); eprintf(" Interrupt priority register L(0x%x)\n",addr);
	} else if(addr==0xFFFFED18) { eprintf("INTC_ICR"); eprintf(" Interrupt control register(0x%x)\n",addr);
	} else if(addr==0xFFFFED1A) { eprintf("INTC_ISR"); eprintf(" IRQ status register(0x%x)\n",addr);
	} else if(addr==0xFFFFF000) { eprintf("SCI_SMR0"); eprintf(" Serial mode register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF001) { eprintf("SCI_BRR0"); eprintf(" Bit rate register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF002) { eprintf("SCI_SCR0"); eprintf(" Serial control register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF003) { eprintf("SCI_TDR0"); eprintf(" Transmit data register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF004) { eprintf("SCI_SSR0"); eprintf(" Serial status register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF005) { eprintf("SCI_RDR0"); eprintf(" Receive data register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF006) { eprintf("SCI_SDCR0"); eprintf(" Serial direction control register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF008) { eprintf("SCI_SMR1"); eprintf(" Serial mode register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF009) { eprintf("SCI_BRR1"); eprintf(" Bit rate register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF00A) { eprintf("SCI_SCR1"); eprintf(" Serial control register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF00B) { eprintf("SCI_TDR1"); eprintf(" Transmit data register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF00C) { eprintf("SCI_SSR1"); eprintf(" Serial status register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF00D) { eprintf("SCI_RDR1"); eprintf(" Receive data register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF00E) { eprintf("SCI_SDCR1"); eprintf(" Serial direction control register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF010) { eprintf("SCI_SMR2"); eprintf(" Serial mode register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF011) { eprintf("SCI_BRR2"); eprintf(" Bit rate register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF012) { eprintf("SCI_SCR2"); eprintf(" Serial control register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF013) { eprintf("SCI_TDR2"); eprintf(" Transmit data register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF014) { eprintf("SCI_SSR2"); eprintf(" Serial status register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF015) { eprintf("SCI_RDR2"); eprintf(" Receive data register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF016) { eprintf("SCI_SDCR2"); eprintf(" Serial direction control register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF018) { eprintf("SCI_SMR3"); eprintf(" Serial mode register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF019) { eprintf("SCI_BRR3"); eprintf(" Bit rate register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF01A) { eprintf("SCI_SCR3"); eprintf(" Serial control register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF01B) { eprintf("SCI_TDR3"); eprintf(" Transmit data register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF01C) { eprintf("SCI_SSR3"); eprintf(" Serial status register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF01D) { eprintf("SCI_RDR3"); eprintf(" Receive data register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF01E) { eprintf("SCI_SDCR3"); eprintf(" Serial direction control register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF020) { eprintf("SCI_SMR4"); eprintf(" Serial mode register 4(0x%x)\n",addr);
	} else if(addr==0xFFFFF021) { eprintf("SCI_BRR4"); eprintf(" Bit rate register 4(0x%x)\n",addr);
	} else if(addr==0xFFFFF022) { eprintf("SCI_SCR4"); eprintf(" Serial control register 4(0x%x)\n",addr);
	} else if(addr==0xFFFFF023) { eprintf("SCI_TDR4"); eprintf(" Transmit data register 4(0x%x)\n",addr);
	} else if(addr==0xFFFFF024) { eprintf("SCI_SSR4"); eprintf(" Serial status register 4(0x%x)\n",addr);
	} else if(addr==0xFFFFF025) { eprintf("SCI_RDR4"); eprintf(" Receive data register 4(0x%x)\n",addr);
	} else if(addr==0xFFFFF026) { eprintf("SCI_SDCR4"); eprintf(" Serial direction control register 4(0x%x)\n",addr);
	} else if(addr==0xFFFFF401) { eprintf("ATUII_TSTR1"); eprintf(" Timer start register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF400) { eprintf("ATUII_TSTR2"); eprintf(" Timer start register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF402) { eprintf("ATUII_TSTR3"); eprintf(" Timer start register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF404) { eprintf("ATUII_PSCR1"); eprintf(" Prescaler register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF406) { eprintf("ATUII_PSCR2"); eprintf(" Prescaler register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF408) { eprintf("ATUII_PSCR3"); eprintf(" Prescaler register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF40A) { eprintf("ATUII_PSCR4"); eprintf(" Prescaler register 4(0x%x)\n",addr);
	} else if(addr==0xFFFFF430) { eprintf("ATUII_TCNT0H"); eprintf(" Free-running counter 0H(0x%x)\n",addr);
	} else if(addr==0xFFFFF432) { eprintf("ATUII_TCNT0L"); eprintf(" Free-running counter 0L(0x%x)\n",addr);
	} else if(addr==0xFFFFF434) { eprintf("ATUII_ICR0AH"); eprintf(" Input capture register 0AH(0x%x)\n",addr);
	} else if(addr==0xFFFFF436) { eprintf("ATUII_ICR0AL"); eprintf(" Input capture register 0AL(0x%x)\n",addr);
	} else if(addr==0xFFFFF438) { eprintf("ATUII_ICR0BH"); eprintf(" Input capture register 0BH(0x%x)\n",addr);
	} else if(addr==0xFFFFF43A) { eprintf("ATUII_ICR0BL"); eprintf(" Input capture register 0BL(0x%x)\n",addr);
	} else if(addr==0xFFFFF43C) { eprintf("ATUII_ICR0CH"); eprintf(" Input capture register 0CH(0x%x)\n",addr);
	} else if(addr==0xFFFFF43E) { eprintf("ATUII_ICR0CL"); eprintf(" Input capture register 0CL(0x%x)\n",addr);
	} else if(addr==0xFFFFF420) { eprintf("ATUII_ICR0DH"); eprintf(" Input capture register 0DH(0x%x)\n",addr);
	} else if(addr==0xFFFFF422) { eprintf("ATUII_ICR0DL"); eprintf(" Input capture register 0DL(0x%x)\n",addr);
	} else if(addr==0xFFFFF424) { eprintf("ATUII_ITVRR1"); eprintf(" Timer interval interrupt request register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF426) { eprintf("ATUII_ITVRR2A"); eprintf(" Timer interval interrupt request register 2A(0x%x)\n",addr);
	} else if(addr==0xFFFFF428) { eprintf("ATUII_ITVRR2B"); eprintf(" Timer interval interrupt request register 2B(0x%x)\n",addr);
	} else if(addr==0xFFFFF42A) { eprintf("ATUII_TIOR0"); eprintf(" Timer I/O control register(0x%x)\n",addr);
	} else if(addr==0xFFFFF42C) { eprintf("ATUII_TSR0"); eprintf(" Timer status register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF42E) { eprintf("ATUII_TIER0"); eprintf(" Timer interrupt enable register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF440) { eprintf("ATUII_TCNT1A"); eprintf(" Free-running counter 1A(0x%x)\n",addr);
	} else if(addr==0xFFFFF442) { eprintf("ATUII_TCNT1B"); eprintf(" Free-running counter 1B(0x%x)\n",addr);
	} else if(addr==0xFFFFF444) { eprintf("ATUII_GR1A"); eprintf(" General register 1A(0x%x)\n",addr);
	} else if(addr==0xFFFFF446) { eprintf("ATUII_GR1B"); eprintf(" General register 1B(0x%x)\n",addr);
	} else if(addr==0xFFFFF448) { eprintf("ATUII_GR1C"); eprintf(" General register 1C(0x%x)\n",addr);
	} else if(addr==0xFFFFF44A) { eprintf("ATUII_GR1D"); eprintf(" General register 1D(0x%x)\n",addr);
	} else if(addr==0xFFFFF44C) { eprintf("ATUII_GR1E"); eprintf(" General register 1E(0x%x)\n",addr);
	} else if(addr==0xFFFFF44E) { eprintf("ATUII_GR1F"); eprintf(" General register 1F(0x%x)\n",addr);
	} else if(addr==0xFFFFF450) { eprintf("ATUII_GR1G"); eprintf(" General register 1G(0x%x)\n",addr);
	} else if(addr==0xFFFFF452) { eprintf("ATUII_GR1H"); eprintf(" General register 1H(0x%x)\n",addr);
	} else if(addr==0xFFFFF454) { eprintf("ATUII_OCR1"); eprintf(" Output compare register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF456) { eprintf("ATUII_OSBR1"); eprintf(" Offset base register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF459) { eprintf("ATUII_TIOR1A"); eprintf(" Timer I/O control register 1A(0x%x)\n",addr);
	} else if(addr==0xFFFFF458) { eprintf("ATUII_TIOR1B"); eprintf(" Timer I/O control register 1B(0x%x)\n",addr);
	} else if(addr==0xFFFFF45B) { eprintf("ATUII_TIOR1C"); eprintf(" Timer I/O control register 1C(0x%x)\n",addr);
	} else if(addr==0xFFFFF45A) { eprintf("ATUII_TIOR1D"); eprintf(" Timer I/O control register 1D(0x%x)\n",addr);
	} else if(addr==0xFFFFF45D) { eprintf("ATUII_TCR1A"); eprintf(" Timer control register 1A(0x%x)\n",addr);
	} else if(addr==0xFFFFF45C) { eprintf("ATUII_TCR1B"); eprintf(" Timer control register 1B(0x%x)\n",addr);
	} else if(addr==0xFFFFF45E) { eprintf("ATUII_TSR1A"); eprintf(" Timer status register 1A(0x%x)\n",addr);
	} else if(addr==0xFFFFF460) { eprintf("ATUII_TSR1B"); eprintf(" Timer status register1B(0x%x)\n",addr);
	} else if(addr==0xFFFFF462) { eprintf("ATUII_TIER1A"); eprintf(" Timer interrupt enable register 1A(0x%x)\n",addr);
	} else if(addr==0xFFFFF464) { eprintf("ATUII_TIER1B"); eprintf(" Timer interrupt enable register 1B(0x%x)\n",addr);
	} else if(addr==0xFFFFF466) { eprintf("ATUII_TRGMDR"); eprintf(" Trigger mode register(0x%x)\n",addr);
	} else if(addr==0xFFFFF600) { eprintf("ATUII_TCNT2A"); eprintf(" Free-running counter 2A(0x%x)\n",addr);
	} else if(addr==0xFFFFF602) { eprintf("ATUII_TCNT2B"); eprintf(" Free-running counter 2B(0x%x)\n",addr);
	} else if(addr==0xFFFFF604) { eprintf("ATUII_GR2A"); eprintf(" General register 2A(0x%x)\n",addr);
	} else if(addr==0xFFFFF606) { eprintf("ATUII_GR2B"); eprintf(" General register 2B(0x%x)\n",addr);
	} else if(addr==0xFFFFF608) { eprintf("ATUII_GR2C"); eprintf(" General register 2C(0x%x)\n",addr);
	} else if(addr==0xFFFFF60A) { eprintf("ATUII_GR2D"); eprintf(" General register 2D(0x%x)\n",addr);
	} else if(addr==0xFFFFF60C) { eprintf("ATUII_GR2E"); eprintf(" General register 2E(0x%x)\n",addr);
	} else if(addr==0xFFFFF60E) { eprintf("ATUII_GR2F"); eprintf(" General register 2F(0x%x)\n",addr);
	} else if(addr==0xFFFFF610) { eprintf("ATUII_GR2G"); eprintf(" General register 2G(0x%x)\n",addr);
	} else if(addr==0xFFFFF612) { eprintf("ATUII_GR2H"); eprintf(" General register 2H(0x%x)\n",addr);
	} else if(addr==0xFFFFF614) { eprintf("ATUII_OCR2A"); eprintf(" Output compare register 2A(0x%x)\n",addr);
	} else if(addr==0xFFFFF616) { eprintf("ATUII_OCR2B"); eprintf(" Output compare register 2B(0x%x)\n",addr);
	} else if(addr==0xFFFFF618) { eprintf("ATUII_OCR2C"); eprintf(" Output compare register 2C(0x%x)\n",addr);
	} else if(addr==0xFFFFF61A) { eprintf("ATUII_OCR2D"); eprintf(" Output compare register 2D(0x%x)\n",addr);
	} else if(addr==0xFFFFF61C) { eprintf("ATUII_OCR2E"); eprintf(" Output compare register 2E(0x%x)\n",addr);
	} else if(addr==0xFFFFF61E) { eprintf("ATUII_OCR2F"); eprintf(" Output compare register 2F(0x%x)\n",addr);
	} else if(addr==0xFFFFF620) { eprintf("ATUII_OCR2G"); eprintf(" Output compare register 2G(0x%x)\n",addr);
	} else if(addr==0xFFFFF622) { eprintf("ATUII_OCR2H"); eprintf(" Output compare register 2H(0x%x)\n",addr);
	} else if(addr==0xFFFFF624) { eprintf("ATUII_OSBR2"); eprintf(" Offset base register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF627) { eprintf("ATUII_TIOR2A"); eprintf(" Timer I/O control register 2A(0x%x)\n",addr);
	} else if(addr==0xFFFFF626) { eprintf("ATUII_TIOR2B"); eprintf(" Timer I/O control register 2B(0x%x)\n",addr);
	} else if(addr==0xFFFFF629) { eprintf("ATUII_TIOR2C"); eprintf(" Timer I/O control register 2C(0x%x)\n",addr);
	} else if(addr==0xFFFFF628) { eprintf("ATUII_TIOR2D"); eprintf(" Timer I/O control register 2D(0x%x)\n",addr);
	} else if(addr==0xFFFFF62B) { eprintf("ATUII_TCR2A"); eprintf(" Timer control register 2A(0x%x)\n",addr);
	} else if(addr==0xFFFFF62A) { eprintf("ATUII_TCR2B"); eprintf(" Timer control register 2B(0x%x)\n",addr);
	} else if(addr==0xFFFFF62C) { eprintf("ATUII_TSR2A"); eprintf(" Timer status register 2A(0x%x)\n",addr);
	} else if(addr==0xFFFFF62E) { eprintf("ATUII_TSR2B"); eprintf(" Timer status register 2B(0x%x)\n",addr);
	} else if(addr==0xFFFFF630) { eprintf("ATUII_TIER2A"); eprintf(" Timer interrupt enable register 2A(0x%x)\n",addr);
	} else if(addr==0xFFFFF632) { eprintf("ATUII_TIER2B"); eprintf(" Timer interrupt enable register 2B(0x%x)\n",addr);
	} else if(addr==0xFFFFF480) { eprintf("ATUII_TSR3"); eprintf(" Timer status register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF482) { eprintf("ATUII_TIER3"); eprintf(" Timer interrupt enable register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF484) { eprintf("ATUII_TMDR"); eprintf(" Timer mode register(0x%x)\n",addr);
	} else if(addr==0xFFFFF4A0) { eprintf("ATUII_TCNT3"); eprintf(" Free-running counter 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF4A2) { eprintf("ATUII_GR3A"); eprintf(" General register 3A(0x%x)\n",addr);
	} else if(addr==0xFFFFF4A4) { eprintf("ATUII_GR3B"); eprintf(" General register 3B(0x%x)\n",addr);
	} else if(addr==0xFFFFF4A6) { eprintf("ATUII_GR3C"); eprintf(" General register 3C(0x%x)\n",addr);
	} else if(addr==0xFFFFF4A8) { eprintf("ATUII_GR3D"); eprintf(" General register 3D(0x%x)\n",addr);
	} else if(addr==0xFFFFF4AB) { eprintf("ATUII_TIOR3A"); eprintf(" Timer I/O control register 3A(0x%x)\n",addr);
	} else if(addr==0xFFFFF4AA) { eprintf("ATUII_TIOR3B"); eprintf(" Timer I/O control register 3B(0x%x)\n",addr);
	} else if(addr==0xFFFFF4AC) { eprintf("ATUII_TCR3"); eprintf(" Timer control register 3(0x%x)\n",addr);
	} else if(addr==0xFFFFF4C0) { eprintf("ATUII_TCNT4"); eprintf(" Free-running counter 4(0x%x)\n",addr);
	} else if(addr==0xFFFFF4C2) { eprintf("ATUII_GR4A"); eprintf(" General register 4A(0x%x)\n",addr);
	} else if(addr==0xFFFFF4C4) { eprintf("ATUII_GR4B"); eprintf(" General register 4B(0x%x)\n",addr);
	} else if(addr==0xFFFFF4C6) { eprintf("ATUII_GR4C"); eprintf(" General register 4C(0x%x)\n",addr);
	} else if(addr==0xFFFFF4C8) { eprintf("ATUII_GR4D"); eprintf(" General register 4D(0x%x)\n",addr);
	} else if(addr==0xFFFFF4CB) { eprintf("ATUII_TIOR4A"); eprintf(" Timer I/O control register 4A(0x%x)\n",addr);
	} else if(addr==0xFFFFF4CA) { eprintf("ATUII_TIOR4B"); eprintf(" Timer I/O control register 4B(0x%x)\n",addr);
	} else if(addr==0xFFFFF4CC) { eprintf("ATUII_TCR4"); eprintf(" Timer control register 4(0x%x)\n",addr);
	} else if(addr==0xFFFFF4E0) { eprintf("ATUII_TCNT5"); eprintf(" Free-running counter 5(0x%x)\n",addr);
	} else if(addr==0xFFFFF4E2) { eprintf("ATUII_GR5A"); eprintf(" General register 5A(0x%x)\n",addr);
	} else if(addr==0xFFFFF4E4) { eprintf("ATUII_GR5B"); eprintf(" General register 5B(0x%x)\n",addr);
	} else if(addr==0xFFFFF4E6) { eprintf("ATUII_GR5C"); eprintf(" General register 5C(0x%x)\n",addr);
	} else if(addr==0xFFFFF4E8) { eprintf("ATUII_GR5D"); eprintf(" General register 5D(0x%x)\n",addr);
	} else if(addr==0xFFFFF4EB) { eprintf("ATUII_TIOR5A"); eprintf(" Timer I/O control register 5A(0x%x)\n",addr);
	} else if(addr==0xFFFFF4EA) { eprintf("ATUII_TIOR5B"); eprintf(" Timer I/O control register 5B(0x%x)\n",addr);
	} else if(addr==0xFFFFF4EC) { eprintf("ATUII_TCR5"); eprintf(" Timer control register 5(0x%x)\n",addr);
	} else if(addr==0xFFFFF500) { eprintf("ATUII_TCNT6A"); eprintf(" Free-running counter 6A(0x%x)\n",addr);
	} else if(addr==0xFFFFF502) { eprintf("ATUII_TCNT6B"); eprintf(" Free-running counter 6B(0x%x)\n",addr);
	} else if(addr==0xFFFFF504) { eprintf("ATUII_TCNT6C"); eprintf(" Free-running counter 6C(0x%x)\n",addr);
	} else if(addr==0xFFFFF506) { eprintf("ATUII_TCNT6D"); eprintf(" Free-running counter 6D(0x%x)\n",addr);
	} else if(addr==0xFFFFF508) { eprintf("ATUII_CYLR6A"); eprintf(" Cycle register 6A(0x%x)\n",addr);
	} else if(addr==0xFFFFF50A) { eprintf("ATUII_CYLR6B"); eprintf(" Cycle register 6B(0x%x)\n",addr);
	} else if(addr==0xFFFFF50C) { eprintf("ATUII_CYLR6C"); eprintf(" Cycle register 6C(0x%x)\n",addr);
	} else if(addr==0xFFFFF50E) { eprintf("ATUII_CYLR6D"); eprintf(" Cycle register 6D(0x%x)\n",addr);
	} else if(addr==0xFFFFF510) { eprintf("ATUII_BFR6A"); eprintf(" Buffer register 6A(0x%x)\n",addr);
	} else if(addr==0xFFFFF512) { eprintf("ATUII_BFR6B"); eprintf(" Buffer register 6B(0x%x)\n",addr);
	} else if(addr==0xFFFFF514) { eprintf("ATUII_BFR6C"); eprintf(" Buffer register 6C(0x%x)\n",addr);
	} else if(addr==0xFFFFF516) { eprintf("ATUII_BFR6D"); eprintf(" Buffer register 6D(0x%x)\n",addr);
	} else if(addr==0xFFFFF518) { eprintf("ATUII_DTR6A"); eprintf(" Duty register 6A(0x%x)\n",addr);
	} else if(addr==0xFFFFF51A) { eprintf("ATUII_DTR6B"); eprintf(" Duty register 6B(0x%x)\n",addr);
	} else if(addr==0xFFFFF51C) { eprintf("ATUII_DTR6C"); eprintf(" Duty register 6C(0x%x)\n",addr);
	} else if(addr==0xFFFFF51E) { eprintf("ATUII_DTR6D"); eprintf(" Duty register 6D(0x%x)\n",addr);
	} else if(addr==0xFFFFF521) { eprintf("ATUII_TCR6A"); eprintf(" Timer control register 6A(0x%x)\n",addr);
	} else if(addr==0xFFFFF520) { eprintf("ATUII_TCR6B"); eprintf(" Timer control register 6B(0x%x)\n",addr);
	} else if(addr==0xFFFFF522) { eprintf("ATUII_TSR6"); eprintf(" Timer status register 6(0x%x)\n",addr);
	} else if(addr==0xFFFFF524) { eprintf("ATUII_TIER6"); eprintf(" Timer interrupt enable register 6(0x%x)\n",addr);
	} else if(addr==0xFFFFF526) { eprintf("ATUII_PMDR"); eprintf(" PWM mode register(0x%x)\n",addr);
	} else if(addr==0xFFFFF580) { eprintf("ATUII_TCNT7A"); eprintf(" Free-running counter 7A(0x%x)\n",addr);
	} else if(addr==0xFFFFF582) { eprintf("ATUII_TCNT7B"); eprintf(" Free-running counter 7B(0x%x)\n",addr);
	} else if(addr==0xFFFFF584) { eprintf("ATUII_TCNT7C"); eprintf(" Free-running counter 7C(0x%x)\n",addr);
	} else if(addr==0xFFFFF586) { eprintf("ATUII_TCNT7D"); eprintf(" Free-running counter 7D(0x%x)\n",addr);
	} else if(addr==0xFFFFF588) { eprintf("ATUII_CYLR7A"); eprintf(" Cycle register 7A(0x%x)\n",addr);
	} else if(addr==0xFFFFF58A) { eprintf("ATUII_CYLR7B"); eprintf(" Cycle register 7B(0x%x)\n",addr);
	} else if(addr==0xFFFFF58C) { eprintf("ATUII_CYLR7C"); eprintf(" Cycle register 7C(0x%x)\n",addr);
	} else if(addr==0xFFFFF58E) { eprintf("ATUII_CYLR7D"); eprintf(" Cycle register 7D(0x%x)\n",addr);
	} else if(addr==0xFFFFF590) { eprintf("ATUII_BFR7A"); eprintf(" Buffer register 7A(0x%x)\n",addr);
	} else if(addr==0xFFFFF592) { eprintf("ATUII_BFR7B"); eprintf(" Buffer register 7B(0x%x)\n",addr);
	} else if(addr==0xFFFFF594) { eprintf("ATUII_BFR7C"); eprintf(" Buffer register 7C(0x%x)\n",addr);
	} else if(addr==0xFFFFF596) { eprintf("ATUII_BFR7D"); eprintf(" Buffer register 7D(0x%x)\n",addr);
	} else if(addr==0xFFFFF598) { eprintf("ATUII_DTR7A"); eprintf(" Duty register 7A(0x%x)\n",addr);
	} else if(addr==0xFFFFF59A) { eprintf("ATUII_DTR7B"); eprintf(" Duty register 7B(0x%x)\n",addr);
	} else if(addr==0xFFFFF59C) { eprintf("ATUII_DTR7C"); eprintf(" Duty register 7C(0x%x)\n",addr);
	} else if(addr==0xFFFFF59E) { eprintf("ATUII_DTR7D"); eprintf(" Duty register 7D(0x%x)\n",addr);
	} else if(addr==0xFFFFF5A1) { eprintf("ATUII_TCR7A"); eprintf(" Timer control register 7A(0x%x)\n",addr);
	} else if(addr==0xFFFFF5A0) { eprintf("ATUII_TCR7B"); eprintf(" Timer control register 7B(0x%x)\n",addr);
	} else if(addr==0xFFFFF5A2) { eprintf("ATUII_TSR7"); eprintf(" Timer status register 7(0x%x)\n",addr);
	} else if(addr==0xFFFFF5A4) { eprintf("ATUII_TIER7"); eprintf(" Timer interrupt enable register 7(0x%x)\n",addr);
	} else if(addr==0xFFFFF640) { eprintf("ATUII_DCNT8A"); eprintf(" Down-counter 8A(0x%x)\n",addr);
	} else if(addr==0xFFFFF642) { eprintf("ATUII_DCNT8B"); eprintf(" Down-counter 8B(0x%x)\n",addr);
	} else if(addr==0xFFFFF644) { eprintf("ATUII_DCNT8C"); eprintf(" Down-counter 8C(0x%x)\n",addr);
	} else if(addr==0xFFFFF646) { eprintf("ATUII_DCNT8D"); eprintf(" Down-counter 8D(0x%x)\n",addr);
	} else if(addr==0xFFFFF648) { eprintf("ATUII_DCNT8E"); eprintf(" Down-counter 8E(0x%x)\n",addr);
	} else if(addr==0xFFFFF64A) { eprintf("ATUII_DCNT8F"); eprintf(" Down-counter 8F(0x%x)\n",addr);
	} else if(addr==0xFFFFF64C) { eprintf("ATUII_DCNT8G"); eprintf(" Down-counter 8G(0x%x)\n",addr);
	} else if(addr==0xFFFFF64E) { eprintf("ATUII_DCNT8H"); eprintf(" Down-counter 8H(0x%x)\n",addr);
	} else if(addr==0xFFFFF650) { eprintf("ATUII_DCNT8I"); eprintf(" Down-counter 8I(0x%x)\n",addr);
	} else if(addr==0xFFFFF652) { eprintf("ATUII_DCNT8J"); eprintf(" Down-counter 8J(0x%x)\n",addr);
	} else if(addr==0xFFFFF654) { eprintf("ATUII_DCNT8K"); eprintf(" Down-counter 8K(0x%x)\n",addr);
	} else if(addr==0xFFFFF656) { eprintf("ATUII_DCNT8L"); eprintf(" Down-counter 8L(0x%x)\n",addr);
	} else if(addr==0xFFFFF658) { eprintf("ATUII_DCNT8M"); eprintf(" Down-counter 8M(0x%x)\n",addr);
	} else if(addr==0xFFFFF65A) { eprintf("ATUII_DCNT8N"); eprintf(" Down-counter 8N(0x%x)\n",addr);
	} else if(addr==0xFFFFF65C) { eprintf("ATUII_DCNT8O"); eprintf(" Down-counter 8O(0x%x)\n",addr);
	} else if(addr==0xFFFFF65E) { eprintf("ATUII_DCNT8P"); eprintf(" Down-counter 8P(0x%x)\n",addr);
	} else if(addr==0xFFFFF660) { eprintf("ATUII_RLDR8"); eprintf(" Reload register 8(0x%x)\n",addr);
	} else if(addr==0xFFFFF662) { eprintf("ATUII_TCNR"); eprintf(" Timer connection register(0x%x)\n",addr);
	} else if(addr==0xFFFFF664) { eprintf("ATUII_OTR"); eprintf(" One-shot pulse terminate register(0x%x)\n",addr);
	} else if(addr==0xFFFFF666) { eprintf("ATUII_DSTR"); eprintf(" Down-count start register(0x%x)\n",addr);
	} else if(addr==0xFFFFF668) { eprintf("ATUII_TCR8"); eprintf(" Timer control register 8(0x%x)\n",addr);
	} else if(addr==0xFFFFF66A) { eprintf("ATUII_TSR8"); eprintf(" Timer status register 8(0x%x)\n",addr);
	} else if(addr==0xFFFFF66C) { eprintf("ATUII_TIER8"); eprintf(" Timer interrupt enable register 8(0x%x)\n",addr);
	} else if(addr==0xFFFFF66E) { eprintf("ATUII_RLDENR"); eprintf(" Reload enable register(0x%x)\n",addr);
	} else if(addr==0xFFFFF680) { eprintf("ATUII_ECNT9A"); eprintf(" Event counter 9A(0x%x)\n",addr);
	} else if(addr==0xFFFFF682) { eprintf("ATUII_ECNT9B"); eprintf(" Event counter 9B(0x%x)\n",addr);
	} else if(addr==0xFFFFF684) { eprintf("ATUII_ECNT9C"); eprintf(" Event counter 9C(0x%x)\n",addr);
	} else if(addr==0xFFFFF686) { eprintf("ATUII_ECNT9D"); eprintf(" Event counter 9D(0x%x)\n",addr);
	} else if(addr==0xFFFFF688) { eprintf("ATUII_ECNT9E"); eprintf(" Event counter 9E(0x%x)\n",addr);
	} else if(addr==0xFFFFF68A) { eprintf("ATUII_ECNT9F"); eprintf(" Event counter 9F(0x%x)\n",addr);
	} else if(addr==0xFFFFF68C) { eprintf("ATUII_GR9A"); eprintf(" General register 9A(0x%x)\n",addr);
	} else if(addr==0xFFFFF68E) { eprintf("ATUII_GR9B"); eprintf(" General register 9B(0x%x)\n",addr);
	} else if(addr==0xFFFFF690) { eprintf("ATUII_GR9C"); eprintf(" General register 9C(0x%x)\n",addr);
	} else if(addr==0xFFFFF692) { eprintf("ATUII_GR9D"); eprintf(" General register 9D(0x%x)\n",addr);
	} else if(addr==0xFFFFF694) { eprintf("ATUII_GR9E"); eprintf(" General register 9E(0x%x)\n",addr);
	} else if(addr==0xFFFFF696) { eprintf("ATUII_GR9F"); eprintf(" General register 9F(0x%x)\n",addr);
	} else if(addr==0xFFFFF698) { eprintf("ATUII_TCR9A"); eprintf(" Timer control register 9A(0x%x)\n",addr);
	} else if(addr==0xFFFFF69A) { eprintf("ATUII_TCR9B"); eprintf(" Timer control register 9B(0x%x)\n",addr);
	} else if(addr==0xFFFFF69C) { eprintf("ATUII_TCR9C"); eprintf(" Timer control register 9C(0x%x)\n",addr);
	} else if(addr==0xFFFFF69E) { eprintf("ATUII_TSR9"); eprintf(" Timer status register 9(0x%x)\n",addr);
	} else if(addr==0xFFFFF6A0) { eprintf("ATUII_TIER9"); eprintf(" Timer interrupt enable register 9(0x%x)\n",addr);
	} else if(addr==0xFFFFF6C0) { eprintf("ATUII_TCNT10AH"); eprintf(" Free-running counter 10AH(0x%x)\n",addr);
	} else if(addr==0xFFFFF6C2) { eprintf("ATUII_TCNT10AL"); eprintf(" Free-running counter 10AL(0x%x)\n",addr);
	} else if(addr==0xFFFFF6C4) { eprintf("ATUII_TCNT10B"); eprintf(" Event counter 10B(0x%x)\n",addr);
	} else if(addr==0xFFFFF6C6) { eprintf("ATUII_TCNT10C"); eprintf(" Reload counter 10C(0x%x)\n",addr);
	} else if(addr==0xFFFFF6C8) { eprintf("ATUII_TCNT10D"); eprintf(" Correction counter 10D(0x%x)\n",addr);
	} else if(addr==0xFFFFF6CA) { eprintf("ATUII_TCNT10E"); eprintf(" Correction angle counter 10E(0x%x)\n",addr);
	} else if(addr==0xFFFFF6CC) { eprintf("ATUII_TCNT10F"); eprintf(" Correction angle counter 10F(0x%x)\n",addr);
	} else if(addr==0xFFFFF6CE) { eprintf("ATUII_TCNT10G"); eprintf(" Free-running counter 10G(0x%x)\n",addr);
	} else if(addr==0xFFFFF6D0) { eprintf("ATUII_ICR10AH"); eprintf(" Input capture register 10AH(0x%x)\n",addr);
	} else if(addr==0xFFFFF6D2) { eprintf("ATUII_ICR10AL"); eprintf(" Input capture register 10AL(0x%x)\n",addr);
	} else if(addr==0xFFFFF6D4) { eprintf("ATUII_OCR10AH"); eprintf(" Output compare register 10AH(0x%x)\n",addr);
	} else if(addr==0xFFFFF6D6) { eprintf("ATUII_OCR10AL"); eprintf(" Output compare register 10AL(0x%x)\n",addr);
	} else if(addr==0xFFFFF6D8) { eprintf("ATUII_OCR10B"); eprintf(" Output compare register 10B(0x%x)\n",addr);
	} else if(addr==0xFFFFF6DA) { eprintf("ATUII_RLD10C"); eprintf(" Reload register 10C(0x%x)\n",addr);
	} else if(addr==0xFFFFF6DC) { eprintf("ATUII_GR10G"); eprintf(" General register 10G(0x%x)\n",addr);
	} else if(addr==0xFFFFF6DE) { eprintf("ATUII_TCNT10H"); eprintf(" Noise canceler counter 10H(0x%x)\n",addr);
	} else if(addr==0xFFFFF6E0) { eprintf("ATUII_NCR10"); eprintf(" Noise canceler register 10(0x%x)\n",addr);
	} else if(addr==0xFFFFF6E2) { eprintf("ATUII_TIOR10"); eprintf(" Timer I/O control register 10(0x%x)\n",addr);
	} else if(addr==0xFFFFF6E4) { eprintf("ATUII_TCR10"); eprintf(" Timer control register 10(0x%x)\n",addr);
	} else if(addr==0xFFFFF6E6) { eprintf("ATUII_TCCLR10"); eprintf(" Correction counter clear register 10(0x%x)\n",addr);
	} else if(addr==0xFFFFF6E8) { eprintf("ATUII_TSR10"); eprintf(" Timer status register 10(0x%x)\n",addr);
	} else if(addr==0xFFFFF6EA) { eprintf("ATUII_TIER10"); eprintf(" Timer interrupt enable register 10(0x%x)\n",addr);
	} else if(addr==0xFFFFF5C0) { eprintf("ATUII_TCNT11"); eprintf(" Free-running counter 11(0x%x)\n",addr);
	} else if(addr==0xFFFFF5C2) { eprintf("ATUII_GR11A"); eprintf(" General register 11A(0x%x)\n",addr);
	} else if(addr==0xFFFFF5C4) { eprintf("ATUII_GR11B"); eprintf(" General register 11B(0x%x)\n",addr);
	} else if(addr==0xFFFFF5C6) { eprintf("ATUII_TIOR11"); eprintf(" Timer I/O control register 11(0x%x)\n",addr);
	} else if(addr==0xFFFFF5C8) { eprintf("ATUII_TCR11"); eprintf(" Timer control register 11(0x%x)\n",addr);
	} else if(addr==0xFFFFF5CA) { eprintf("ATUII_TSR11"); eprintf(" Timer status register 11(0x%x)\n",addr);
	} else if(addr==0xFFFFF5CC) { eprintf("ATUII_TIER11"); eprintf(" Timer interrupt enable register 11(0x%x)\n",addr);
	} else if(addr==0xFFFFF700) { eprintf("APC_POPCR"); eprintf(" Pulse output port control register(0x%x)\n",addr);
	} else if(addr==0xFFFFF710) { eprintf("CMT_CMSTR"); eprintf(" Compare match timer start register(0x%x)\n",addr);
	} else if(addr==0xFFFFF712) { eprintf("CMT_CMCSR0"); eprintf(" Compare match timer control/status register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF714) { eprintf("CMT_CMCNT0"); eprintf(" Compare match timer counter 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF716) { eprintf("CMT_CMCOR0"); eprintf(" Compare match timer constant register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF718) { eprintf("CMT_CMCSR1"); eprintf(" Compare match timer control/status register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF71A) { eprintf("CMT_CMCNT1"); eprintf(" Compare match timer counter 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF71C) { eprintf("CMT_CMCOR1"); eprintf(" Compare match timer constant register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF720) { eprintf("PFC_PAIOR"); eprintf(" Port A IO register(0x%x)\n",addr);
	} else if(addr==0xFFFFF722) { eprintf("PFC_PACRH"); eprintf(" Port A control register H(0x%x)\n",addr);
	} else if(addr==0xFFFFF724) { eprintf("PFC_PACRL"); eprintf(" Port A control register L(0x%x)\n",addr);
	} else if(addr==0xFFFFF730) { eprintf("PFC_PBIOR"); eprintf(" Port B IO register(0x%x)\n",addr);
	} else if(addr==0xFFFFF732) { eprintf("PFC_PBCRH"); eprintf(" Port B control register H(0x%x)\n",addr);
	} else if(addr==0xFFFFF734) { eprintf("PFC_PBCRL"); eprintf(" Port B control register L(0x%x)\n",addr);
	} else if(addr==0xFFFFF736) { eprintf("PFC_PBIR"); eprintf(" Port B invert register(0x%x)\n",addr);
	} else if(addr==0xFFFFF73A) { eprintf("PFC_PCIOR"); eprintf(" Port C IO register(0x%x)\n",addr);
	} else if(addr==0xFFFFF73C) { eprintf("PFC_PCCR"); eprintf(" Port C control register(0x%x)\n",addr);
	} else if(addr==0xFFFFF740) { eprintf("PFC_PDIOR"); eprintf(" Port D IO register(0x%x)\n",addr);
	} else if(addr==0xFFFFF742) { eprintf("PFC_PDCRH"); eprintf(" Port D control register H(0x%x)\n",addr);
	} else if(addr==0xFFFFF744) { eprintf("PFC_PDCRL"); eprintf(" Port D control register L(0x%x)\n",addr);
	} else if(addr==0xFFFFF750) { eprintf("PFC_PEIOR"); eprintf(" Port E IO register(0x%x)\n",addr);
	} else if(addr==0xFFFFF752) { eprintf("PFC_PECR"); eprintf(" Port E control register(0x%x)\n",addr);
	} else if(addr==0xFFFFF748) { eprintf("PFC_PFIOR"); eprintf(" Port F IO register(0x%x)\n",addr);
	} else if(addr==0xFFFFF74A) { eprintf("PFC_PFCRH"); eprintf(" Port F control register H(0x%x)\n",addr);
	} else if(addr==0xFFFFF74C) { eprintf("PFC_PFCRL"); eprintf(" Port F control register L(0x%x)\n",addr);
	} else if(addr==0xFFFFF760) { eprintf("PFC_PGIOR"); eprintf(" Port G IO register(0x%x)\n",addr);
	} else if(addr==0xFFFFF762) { eprintf("PFC_PGCR"); eprintf(" Port G control register(0x%x)\n",addr);
	} else if(addr==0xFFFFF728) { eprintf("PFC_PHIOR"); eprintf(" Port H IO register(0x%x)\n",addr);
	} else if(addr==0xFFFFF72A) { eprintf("PFC_PHCR"); eprintf(" Port H control register(0x%x)\n",addr);
	} else if(addr==0xFFFFF766) { eprintf("PFC_PJIOR"); eprintf(" Port J IO register(0x%x)\n",addr);
	} else if(addr==0xFFFFF768) { eprintf("PFC_PJCRH"); eprintf(" Port J control register H(0x%x)\n",addr);
	} else if(addr==0xFFFFF76A) { eprintf("PFC_PJCRL"); eprintf(" Port J control register L(0x%x)\n",addr);
	} else if(addr==0xFFFFF770) { eprintf("PFC_PKIOR"); eprintf(" Port K IO register(0x%x)\n",addr);
	} else if(addr==0xFFFFF772) { eprintf("PFC_PKCRH"); eprintf(" Port K control register H(0x%x)\n",addr);
	} else if(addr==0xFFFFF774) { eprintf("PFC_PKCRL"); eprintf(" Port K control register L(0x%x)\n",addr);
	} else if(addr==0xFFFFF776) { eprintf("PFC_PKIR"); eprintf(" Port K invert register(0x%x)\n",addr);
	} else if(addr==0xFFFFF756) { eprintf("PFC_PLIOR"); eprintf(" Port L IO register(0x%x)\n",addr);
	} else if(addr==0xFFFFF758) { eprintf("PFC_PLCRH"); eprintf(" Port L control register H(0x%x)\n",addr);
	} else if(addr==0xFFFFF75A) { eprintf("PFC_PLCRL"); eprintf(" Port L control register L(0x%x)\n",addr);
	} else if(addr==0xFFFFF75C) { eprintf("PFC_PLIR"); eprintf(" Port L invert register(0x%x)\n",addr);
	} else if(addr==0xFFFFF7C0) { eprintf("HUDI_SDIR"); eprintf(" Instruction register(0x%x)\n",addr);
	} else if(addr==0xFFFFF7C2) { eprintf("HUDI_SDSR"); eprintf(" Status register(0x%x)\n",addr);
	} else if(addr==0xFFFFF7C4) { eprintf("HUDI_SDDRH"); eprintf(" Data register H(0x%x)\n",addr);
	} else if(addr==0xFFFFF7C6) { eprintf("HUDI_SDDRL"); eprintf(" Data register L(0x%x)\n",addr);
	} else if(addr==0xFFFFF800) { eprintf("AD_ADDR0"); eprintf(" A/D data register 0 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF802) { eprintf("AD_ADDR1"); eprintf(" A/D data register 1 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF804) { eprintf("AD_ADDR2"); eprintf(" A/D data register 2 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF806) { eprintf("AD_ADDR3"); eprintf(" A/D data register 3 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF808) { eprintf("AD_ADDR4"); eprintf(" A/D data register 4 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF80A) { eprintf("AD_ADDR5"); eprintf(" A/D data register 5 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF80C) { eprintf("AD_ADDR6"); eprintf(" A/D data register 6 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF80E) { eprintf("AD_ADDR7"); eprintf(" A/D data register 7 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF810) { eprintf("AD_ADDR8"); eprintf(" A/D data register 8 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF812) { eprintf("AD_ADDR9"); eprintf(" A/D data register 9 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF814) { eprintf("AD_ADDR10"); eprintf(" A/D data register 10 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF816) { eprintf("AD_ADDR11"); eprintf(" A/D data register 11 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF820) { eprintf("AD_ADDR12"); eprintf(" A/D data register 12 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF822) { eprintf("AD_ADDR13"); eprintf(" A/D data register 13 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF824) { eprintf("AD_ADDR14"); eprintf(" A/D data register 14 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF826) { eprintf("AD_ADDR15"); eprintf(" A/D data register 15 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF828) { eprintf("AD_ADDR16"); eprintf(" A/D data register 16 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF82A) { eprintf("AD_ADDR17"); eprintf(" A/D data register 17 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF82C) { eprintf("AD_ADDR18"); eprintf(" A/D data register 18 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF82E) { eprintf("AD_ADDR19"); eprintf(" A/D data register 19 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF830) { eprintf("AD_ADDR20"); eprintf(" A/D data register 20 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF832) { eprintf("AD_ADDR21"); eprintf(" A/D data register 21 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF834) { eprintf("AD_ADDR22"); eprintf(" A/D data register 22 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF836) { eprintf("AD_ADDR23"); eprintf(" A/D data register 23 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF840) { eprintf("AD_ADDR24"); eprintf(" A/D data register 24 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF842) { eprintf("AD_ADDR25"); eprintf(" A/D data register 25 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF844) { eprintf("AD_ADDR26"); eprintf(" A/D data register 26 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF846) { eprintf("AD_ADDR27"); eprintf(" A/D data register 27 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF848) { eprintf("AD_ADDR28"); eprintf(" A/D data register 28 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF84A) { eprintf("AD_ADDR29"); eprintf(" A/D data register 29 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF84C) { eprintf("AD_ADDR30"); eprintf(" A/D data register 30 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF84E) { eprintf("AD_ADDR31"); eprintf(" A/D data register 31 (H/L)(0x%x)\n",addr);
	} else if(addr==0xFFFFF818) { eprintf("AD_ADCSR0"); eprintf(" A/D control/status register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF819) { eprintf("AD_ADCR0"); eprintf(" A/D control register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF76E) { eprintf("AD_ADTRGR0"); eprintf(" A/D trigger register 0(0x%x)\n",addr);
	} else if(addr==0xFFFFF838) { eprintf("AD_ADCSR1"); eprintf(" A/D control/status register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF839) { eprintf("AD_ADCR1"); eprintf(" A/D control register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF72E) { eprintf("AD_ADTRGR1"); eprintf(" A/D trigger register 1(0x%x)\n",addr);
	} else if(addr==0xFFFFF858) { eprintf("AD_ADCSR2"); eprintf(" A/D control/status register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF859) { eprintf("AD_ADCR2"); eprintf(" A/D control register 2(0x%x)\n",addr);
	} else if(addr==0xFFFFF72F) { eprintf("AD_ADTRGR2"); eprintf(" A/D trigger register 2(0x%x)\n",addr);};

}

/* internal helper functions */
static void err(RAnalEsil *esil, const char *msg) {
	if (esil->verbose) {
		eprintf ("0x%08" PFMT64x " %s\n", esil->address, msg);
	}
}
#define ERR(x) err(esil,x)

/* Returns the number that has bits + 1 least significant bits set. */
static inline ut64 genmask(int bits) {
	ut64 m = UT64_MAX;
	if (bits < 64) {
		m = (ut64)(((ut64)(2) << bits) - 1);
		if (!m) m = UT64_MAX;
	}
	return m;
}

static bool isnum(RAnalEsil *esil, const char *str, ut64 *num) {
	if (!esil || !str) {
		return false;
	}
	if (IS_DIGIT (*str)) {
		if (num) {
			*num = r_num_get (NULL, str);
		}
		return true;
	}
	if (num) {
		*num = 0;
	}
	return false;
}

static bool ispackedreg(RAnalEsil *esil, const char *str) {
	RRegItem *ri = r_reg_get (esil->anal->reg, str, -1);
	return ri? ri->packed_size > 0: false;
}

static bool isregornum(RAnalEsil *esil, const char *str, ut64 *num) {
	if (!r_anal_esil_reg_read (esil, str, num, NULL)) {
		if (!isnum (esil, str, num)) {
			return false;
		}
	}
	return true;
}

/* pop Register or Number */
static bool popRN(RAnalEsil *esil, ut64 *n) {
	char *str = r_anal_esil_pop (esil);
	if (str) {
		bool ret = isregornum (esil, str, n);
		free (str);
		return ret;
	}
	return false;
}

/* R_ANAL_ESIL API */

R_API RAnalEsil *r_anal_esil_new(int stacksize, int iotrap, unsigned int addrsize) {
	RAnalEsil *esil = R_NEW0 (RAnalEsil);
	if (!esil) {
		return NULL;
	}
	if (stacksize < 3) {
		free (esil);
		return NULL;
	}
	if (!(esil->stack = calloc (sizeof (char *), stacksize))) {
		free (esil);
		return NULL;
	}
	esil->verbose = false;
	esil->stacksize = stacksize;
	esil->parse_goto_count = R_ANAL_ESIL_GOTO_LIMIT;
	esil->ops = sdb_new0 ();
	esil->iotrap = iotrap;
	esil->interrupts = sdb_new0 ();
	esil->sessions = r_list_newf (r_anal_esil_session_free);
	esil->addrmask = genmask (addrsize - 1);
	return esil;
}

R_API int r_anal_esil_set_op(RAnalEsil *esil, const char *op, RAnalEsilOp code) {
	char t[128];
	if (!code || !op || !strlen (op) || !esil || !esil->ops) {
		return false;
	}
	char *h = sdb_itoa (sdb_hash (op), t, 16);
	sdb_num_set (esil->ops, h, (ut64)(size_t)code, 0);
	if (!sdb_num_exists (esil->ops, h)) {
		eprintf ("can't set esil-op %s\n", op);
		return false;
	}
	return true;
}

R_API int r_anal_esil_set_interrupt(RAnalEsil *esil, int interrupt, RAnalEsilInterruptCB interruptcb) {
	char t[128];
	char *i;
	if (!esil || !esil->interrupts) {
		return false;
	}
	i = sdb_itoa ((ut64)interrupt, t, 16);
	sdb_num_set (esil->interrupts, i, (ut64)(size_t)interruptcb, 0);
	if (!sdb_num_exists (esil->interrupts, i)) {
		eprintf ("can't set interrupt-handler for interrupt %d\n", interrupt);
		return false;
	}
	return true;
}

R_API int r_anal_esil_fire_trap(RAnalEsil *esil, int trap_type, int trap_code) {
	if (!esil) {
		return false;
	}
	if (esil->cmd) {
		if (esil->cmd (esil, esil->cmd_trap, trap_type, trap_code)) {
			return true;
		}
	}
	if (esil->anal) {
		RAnalPlugin *ap = esil->anal->cur;
		if (ap && ap->esil_trap) {
			if (ap->esil_trap (esil, trap_type, trap_code)) {
				return true;
			}
		}
	}
#if 0
	RAnalEsilTrapCB icb;
	icb = (RAnalEsilTrapCB)sdb_ptr_get (esil->traps, i, 0);
	return icb (esil, trap_type, trap_code);
#endif
	return false;
}

R_API int r_anal_esil_fire_interrupt(RAnalEsil *esil, int interrupt) {
	char t[128];
	char *i;
	RAnalEsilInterruptCB icb;
	if (!esil) {
		return false;
	}
	if (esil->cmd && esil->cmd (esil, esil->cmd_intr, interrupt, 0)) {
		return true;
	}
	if (esil->anal) {
		RAnalPlugin *ap = esil->anal->cur;
		if (ap && ap->esil_intr) {
			if (ap->esil_intr (esil, interrupt))
				return true;
		}
	}
	if (!esil->interrupts)
		return false;
	i = sdb_itoa ((ut64)interrupt, t, 16);
	if (!sdb_num_exists (esil->interrupts, i)) {
		//eprintf ("0x%08"PFMT64x" Invalid interrupt/syscall 0x%08x\n", esil->address, interrupt);
		return false;
	}
	icb = (RAnalEsilInterruptCB)sdb_ptr_get (esil->interrupts, i, 0);
	if (icb) return icb (esil, interrupt);
	return false;
}

R_API bool r_anal_esil_set_pc(RAnalEsil *esil, ut64 addr) {
	if (esil) {
		esil->address = addr;
		return true;
	}
	return false;
}

R_API void r_anal_esil_free(RAnalEsil *esil) {
	if (!esil) {
		return;
	}
	if (esil->anal && esil == esil->anal->esil) {
		esil->anal->esil = NULL;
	}
	sdb_free (esil->ops);
	esil->ops = NULL;
	sdb_free (esil->interrupts);
	esil->interrupts = NULL;
	sdb_free (esil->stats);
	esil->stats = NULL;
	sdb_free (esil->db_trace);
	esil->db_trace = NULL;
	r_anal_esil_stack_free (esil);
	free (esil->stack);
	if (esil->anal && esil->anal->cur && esil->anal->cur->esil_fini) {
		esil->anal->cur->esil_fini (esil);
	}
	r_list_free (esil->sessions);
	free (esil->cmd_intr);
	free (esil->cmd_trap);
	free (esil->cmd_mdev);
	free (esil->cmd_todo);
	free (esil->cmd_ioer);
	free (esil);
}

static ut8 esil_internal_sizeof_reg(RAnalEsil *esil, const char *r) {
	if (!esil || !esil->anal || !esil->anal->reg || !r) {
		return 0;
	}
	RRegItem *ri = r_reg_get (esil->anal->reg, r, -1);
	return ri? ri->size: 0;
}

static bool alignCheck(RAnalEsil *esil, ut64 addr) {
	int dataAlign = r_anal_archinfo (esil->anal, R_ANAL_ARCHINFO_DATA_ALIGN);
	if (dataAlign > 0 && addr % dataAlign) {
		return false;
	}
	return true;
}

static int internal_esil_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	if (!esil || !esil->anal || !esil->anal->iob.io) {
		return 0;
	}
	addr &= esil->addrmask;
	if (!alignCheck (esil, addr)) {
		esil->trap = R_ANAL_TRAP_READ_ERR;
		esil->trap_code = addr;
		return false;
	}
	if (esil->cmd_mdev && esil->mdev_range) {
		if (r_str_range_in (esil->mdev_range, addr)) {
			if (esil->cmd (esil, esil->cmd_mdev, addr, 0)) {
				return true;
			}
		}
	}
	//TODO: Check if error return from read_at.(on previous version of r2 this call always return len)
	(void)esil->anal->iob.read_at (esil->anal->iob.io, addr, buf, len);
	// check if request addres is mapped , if dont fire trap and esil ioer callback
	// now with siol, read_at return true/false cant be used to check error vs len
	if (!esil->anal->iob.is_valid_offset (esil->anal->iob.io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_READ_ERR;
			esil->trap_code = addr;
		}
		if (esil->cmd && esil->cmd_ioer && *esil->cmd_ioer) {
			esil->cmd (esil, esil->cmd_ioer, esil->address, 0);
		}
	}
	return len;
}

static int internal_esil_mem_read_no_null(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	if (!esil || !esil->anal || !esil->anal->iob.io || !addr) {
		return 0;
	}
	addr &= esil->addrmask;
	if (!alignCheck (esil, addr)) {
		esil->trap = R_ANAL_TRAP_READ_ERR;
		esil->trap_code = addr;
		return false;
	}
	//TODO: Check if error return from read_at.(on previous version of r2 this call always return len)
	(void)esil->anal->iob.read_at (esil->anal->iob.io, addr, buf, len);
	// check if request addres is mapped , if dont fire trap and esil ioer callback
	// now with siol, read_at return true/false cant be used to check error vs len
	if (!esil->anal->iob.is_valid_offset (esil->anal->iob.io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_READ_ERR;
			esil->trap_code = addr;
		}
	}
	return len;
}

R_API int r_anal_esil_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	int i, ret = 0;
	if (!buf || !esil) {
		return 0;
	}
	addr &= esil->addrmask;
	if (esil->cb.hook_mem_read) {
		ret = esil->cb.hook_mem_read (esil, addr, buf, len);
	}
	if (!alignCheck (esil, addr)) {
		esil->trap = R_ANAL_TRAP_READ_ERR;
		esil->trap_code = addr;
		return false;
	}
	if (!ret && esil->cb.mem_read) {
		ret = esil->cb.mem_read (esil, addr, buf, len);
		if (ret != len) {
			if (esil->iotrap) {
				esil->trap = R_ANAL_TRAP_READ_ERR;
				esil->trap_code = addr;
			}
		}
	}
	IFDBG {
		/*eprintf ("0x%08" PFMT64x " R> ", addr);
		for (i = 0; i < len; i++) {
			eprintf ("%02x", buf[i]);
		}
		eprintf ("\n");*/
		eprintf ("read %d bytes from 0x%x addr\n",len,addr);
		check_for_register(addr);
	}
	return ret;
}

static int internal_esil_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int ret = 0;
	if (!esil || !esil->anal || !esil->anal->iob.io || esil->nowrite) {
		return 0;
	}
	addr &= esil->addrmask;
	if (!alignCheck (esil, addr)) {
		esil->trap = R_ANAL_TRAP_READ_ERR;
		esil->trap_code = addr;
		return false;
	}
	if (esil->cmd_mdev && esil->mdev_range) {
		if (r_str_range_in (esil->mdev_range, addr)) {
			if (esil->cmd (esil, esil->cmd_mdev, addr, 1)) {
				return true;
			}
		}
	}
	if (esil->anal->iob.write_at (esil->anal->iob.io, addr, buf, len)) {
		ret = len;
	}
	// check if request addres is mapped , if dont fire trap and esil ioer callback
	// now with siol, write_at return true/false cant be used to check error vs len
	if (!esil->anal->iob.is_valid_offset (esil->anal->iob.io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_WRITE_ERR;
			esil->trap_code = addr;
		}
		if (esil->cmd && esil->cmd_ioer && *esil->cmd_ioer) {
			esil->cmd (esil, esil->cmd_ioer, esil->address, 0);
		}
	}
	return ret;
}

static int internal_esil_mem_write_no_null(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int ret = 0;
	if (!esil || !esil->anal || !esil->anal->iob.io || !addr) {
		return 0;
	}
	if (esil->nowrite) {
		return 0;
	}
	addr &= esil->addrmask;
	if (esil->anal->iob.write_at (esil->anal->iob.io, addr, buf, len)) {
		ret = len;
	}
	// check if request addres is mapped , if dont fire trap and esil ioer callback
	// now with siol, write_at return true/false cant be used to check error vs len
	if (!esil->anal->iob.is_valid_offset (esil->anal->iob.io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_WRITE_ERR;
			esil->trap_code = addr;
		}
	}
	return ret;
}

R_API int r_anal_esil_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int i, ret = 0;
	if (!buf || !esil) {
		return 0;
	}
	addr &= esil->addrmask;
	IFDBG {
		eprintf ("0x");
		for (i = 0; i < len; i++) {
			eprintf ("%02x", buf[i]);
		}
		eprintf (" => 0x%08x (%d bytes)\n", addr,len);
		check_for_register(addr);
	}
	if (esil->cb.hook_mem_write) {
		ret = esil->cb.hook_mem_write (esil, addr, buf, len);
	}
	if (!ret && esil->cb.mem_write) {
		ret = esil->cb.mem_write (esil, addr, buf, len);
	}
	return ret;
}

static int internal_esil_reg_read(RAnalEsil *esil, const char *regname, ut64 *num, int *size) {
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	if (reg) {
		if (size) *size = reg->size;
		if (num) *num = r_reg_get_value (esil->anal->reg, reg);
		return true;
	}
	return false;
}

static int internal_esil_reg_write(RAnalEsil *esil, const char *regname, ut64 num) {
	if (esil && esil->anal) {
		RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
		if (reg) {
			r_reg_set_value (esil->anal->reg, reg, num);
			return true;
		}
	}
	return false;
}
static int internal_esil_reg_write_no_null (RAnalEsil *esil, const char *regname, ut64 num) {
	if (!esil || !esil->anal->reg) {
		return false;
	}
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	const char *pc = r_reg_get_name (esil->anal->reg, R_REG_NAME_PC);
	const char *sp = r_reg_get_name (esil->anal->reg, R_REG_NAME_SP);
	const char *bp = r_reg_get_name (esil->anal->reg, R_REG_NAME_BP);
	//trick to protect strcmp from segfaulting with out making the condition complex
	if (!pc) {
		pc = "pc";
	}
	if (!sp) {
		sp = "sp";
	}
	if (!bp) {
		bp = "bp";
	}
	if (reg && reg->name && ((strcmp (reg->name , pc) && strcmp (reg->name, sp) && strcmp(reg->name, bp)) || num)) { //I trust k-maps
		r_reg_set_value (esil->anal->reg, reg, num);
		return true;
	}
	return false;
}

static int esil_internal_borrow_check(RAnalEsil *esil, ut8 bit) {
	bit = ((bit & 0x3f) + 0x3f) & 0x3f;
	return ((esil->old & genmask (bit)) < (esil->cur & genmask (bit)));
}

static int esil_internal_carry_check(RAnalEsil *esil, ut8 bit) {
	ut64 mask = genmask (bit);
	return (esil->cur & mask) < (esil->old & mask);
}

static int esil_internal_parity_check(RAnalEsil *esil) {
	// Set if the number of set bits in the least significant _byte_ is a multiple of 2.
	//   - Taken from: https://graphics.stanford.edu/~seander/bithacks.html#ParityWith64Bits
	ut64 c1 = 0x0101010101010101ULL;
	ut64 c2 = 0x8040201008040201ULL;
	ut64 c3 = 0x1FF;
	// Take only the least significant byte.
	ut64 lsb = esil->cur & 0xff;
	return !((((lsb * c1) & c2) % c3) & 1);
}

static bool esil_internal_sign_check(RAnalEsil *esil) {
	if (!esil || !esil->lastsz) {
		return false;
	}
	return ((esil->cur >> (esil->lastsz - 1)) & 1);
}

static bool esil_internal_overflow_check(RAnalEsil *esil) {
	if (!esil || (esil->lastsz < 2)) {
		return false;
	}
	// According to wikipedia this should work
	return (esil_internal_carry_check (esil, esil->lastsz - 1) ^ esil_internal_carry_check (esil, esil->lastsz - 2));
}

R_API int r_anal_esil_pushnum(RAnalEsil *esil, ut64 num) {
	char str[64];
	snprintf (str, sizeof (str) - 1, "0x%" PFMT64x, num);
	return r_anal_esil_push (esil, str);
}

R_API bool r_anal_esil_push(RAnalEsil *esil, const char *str) {
	if (!str || !esil || !*str || esil->stackptr > (esil->stacksize - 1)) {
		return false;
	}
	esil->stack[esil->stackptr++] = strdup (str);
	return true;
}

R_API char *r_anal_esil_pop(RAnalEsil *esil) {
	if (!esil || esil->stackptr < 1) {
		return NULL;
	}
	return esil->stack[--esil->stackptr];
}

R_API int r_anal_esil_get_parm_type(RAnalEsil *esil, const char *str) {
	int len, i;

	if (!str || !(len = strlen (str))) {
		return R_ANAL_ESIL_PARM_INVALID;
	}
	if (str[0] == ESIL_INTERNAL_PREFIX && str[1]) {
		return R_ANAL_ESIL_PARM_INTERNAL;
	}
	if (!strncmp (str, "0x", 2)) {
		return R_ANAL_ESIL_PARM_NUM;
	}
	if (!((IS_DIGIT(str[0])) || str[0] == '-')) {
		goto not_a_number;
	}
	for (i = 1; i < len; i++) {
		if (!(IS_DIGIT(str[i]))) {
			goto not_a_number;
		}
	}
	return R_ANAL_ESIL_PARM_NUM;
not_a_number:
	if (r_reg_get (esil->anal->reg, str, -1))
		return R_ANAL_ESIL_PARM_REG;
	return R_ANAL_ESIL_PARM_INVALID;
}

static int esil_internal_read(RAnalEsil *esil, const char *str, ut64 *num) {
	ut8 bit;
	if (!esil || !str || !*str) {
		return false;
	}
	if (esil->cb.hook_flag_read) {
		if (esil->cb.hook_flag_read (esil, str + 1, num)) {
			return true;
		}
	}
	switch (str[1]) {
	case '$':
		*num = esil->address;
		break;
	case 'z': //zero-flag
		{
			ut64 m = genmask (esil->lastsz - 1);
			*num = (((ut64) esil->cur & m) == 0);
		}
		break;
	case 'b': //borrow
		bit = (ut8) r_num_get (NULL, &str[2]);
		*num = esil_internal_borrow_check (esil, bit);
		break;
	case 'c': //carry
		bit = (ut8) r_num_get (NULL, &str[2]);
		*num = esil_internal_carry_check (esil, bit);
		break;
	case 'o': //overflow
		*num = esil_internal_overflow_check (esil);
		break;
	case 'p': //parity
		*num = esil_internal_parity_check (esil);
		break;
	case 'r': //regsize in 8-bit-bytes
		*num = esil->anal->bits / 8;
		break;
	case 's': //sign
		*num = esil_internal_sign_check (esil);
		break;
	case 'd': //delay slot state
		switch (str[2]) {
		case 's':
			*num = esil->delay;
			break;
		default:
			return false;
		}
		break;
	case 'j': // jump target
		switch (str[2]) {
		case 't': // "$jt"
			*num = esil->jump_target;
			break;
		case 's': // "$js"
			*num = esil->jump_target_set;
			break;
		default:
			return false;
		}
		break;
	default:
		{
			// Handle the case of "internal set", i.e. set a register without
			// having side effects. The value to be set must be in decimal and
			// prefixed by "$". Example:
			//  - Set of to 0. ("$0,of,=")
			//  - Set rax to 100 without side-effects. ("$100,rax,=")
			char *endptr = NULL;
			ut64 imm = strtoull (str + 1, &endptr, 10);
			if (endptr == str + 1) {
				return false;
			}
			*num = imm;
		}
	}
	return true;
}

static int esil_internal_write(RAnalEsil *esil, const char *str, ut64 num) {
	if (!str || !*str || !esil) {
		return false;
	}
	switch (str[1]) {
	case 'd': //delay slot state
		switch (str[2]) {
		case 's':
			esil->delay = num;
			break;
		default:
			return false;
		}
		break;
	case 'j': // jump target
		switch (str[2]) {
		case 't':
			esil->jump_target = num;
			esil->jump_target_set = 1;
			break;
		case 's':
			esil->jump_target_set = num;
			break;
		default:
			return false;
		}
	default:
		return false;
	}
	return true;
}

R_API int r_anal_esil_get_parm_size(RAnalEsil *esil, const char *str, ut64 *num, int *size) {
	if (!str || !*str) {
		return false;
	}
	int parm_type = r_anal_esil_get_parm_type (esil, str);
	if (!num || !esil) {
		return false;
	}
	switch (parm_type) {
	case R_ANAL_ESIL_PARM_INTERNAL:
		// *num = esil_internal_read (esil, str, num);
		if (size) *size = esil->anal->bits;
		return esil_internal_read (esil, str, num);
	case R_ANAL_ESIL_PARM_NUM:
		*num = r_num_get (NULL, str);
		if (size) *size = esil->anal->bits;
		return true;
	case R_ANAL_ESIL_PARM_REG:
		if (!r_anal_esil_reg_read (esil, str, num, size)) {
			break;
		}
		return true;
	default:
		IFDBG eprintf ("Invalid arg (%s)\n", str);
		esil->parse_stop = 1;
		break;
	}
	return false;
}

R_API int r_anal_esil_get_parm(RAnalEsil *esil, const char *str, ut64 *num) {
	return r_anal_esil_get_parm_size (esil, str, num, NULL);
}

R_API int r_anal_esil_reg_write(RAnalEsil *esil, const char *dst, ut64 num) {
	int ret = 0;
	IFDBG { eprintf ("%s=0x%" PFMT64x "\n", dst, num); }
	if (esil && esil->cb.hook_reg_write) {
		ret = esil->cb.hook_reg_write (esil, dst, &num);
	}
	if (!ret && esil && dst[0] == ESIL_INTERNAL_PREFIX && dst[1]) {
		ret = esil_internal_write (esil, dst, num);
	}
	if (!ret && esil && esil->cb.reg_write) {
		ret = esil->cb.reg_write (esil, dst, num);
	}
	return ret;
}

R_API int r_anal_esil_reg_read_nocallback(RAnalEsil *esil, const char *regname, ut64 *num, int *size) {
	int ret;
	void *old_hook_reg_read = (void *) esil->cb.hook_reg_read;
	esil->cb.hook_reg_read = NULL;
	ret = r_anal_esil_reg_read (esil, regname, num, size);
	esil->cb.hook_reg_read = old_hook_reg_read;
	return ret;
}

R_API int r_anal_esil_reg_read(RAnalEsil *esil, const char *regname, ut64 *num, int *size) {
	bool ret = false;
	ut64 localnum; // XXX why is this necessary?
	if (!esil || !regname) {
		return false;
	}
	if (regname[0] == ESIL_INTERNAL_PREFIX && regname[1]) {
		if (size) {
			*size = esil->anal->bits;
		}
		return esil_internal_read (esil, regname, num);
	}
	if (!num) num = &localnum;
	*num = 0LL;
	if (size) {
		*size = esil->anal->bits;
	}
	if (esil->cb.hook_reg_read) {
		ret = esil->cb.hook_reg_read (esil, regname, num, size);
	}
	if (!ret && esil->cb.reg_read) {
		ret = esil->cb.reg_read (esil, regname, num, size);
	}
	return ret;
}

static int esil_eq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (ispackedreg (esil, dst)) {
		char *src2 = r_anal_esil_pop (esil);
		char *newreg = r_str_newf ("%sl", dst);
		if (r_anal_esil_get_parm (esil, src2, &num2)) {
			ret = r_anal_esil_reg_write (esil, newreg, num2);
		}
		free (newreg);
	}

	if (src && dst && r_anal_esil_reg_read_nocallback (esil, dst, &num, NULL)) {
		if (r_anal_esil_get_parm (esil, src, &num2)) {
			ret = r_anal_esil_reg_write (esil, dst, num2);
			if (ret && r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) { //necessary for some flag-things
				esil->cur = num2;
				esil->old = num;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
		} else {
			ERR ("esil_eq: invalid src");
		}
	} else {
		ERR ("esil_eq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_neg(RAnalEsil *esil) {
	int ret = 0;
	ut64 num;
	char *src = r_anal_esil_pop (esil);
	if (src) {
		if (r_anal_esil_get_parm (esil, src, &num)) {
			r_anal_esil_pushnum (esil, !num);
			ret = 1;
		} else {
			if (isregornum (esil, src, &num)) {
				ret = 1;
				r_anal_esil_pushnum (esil, !num);
			} else {
				eprintf ("0x%08"PFMT64x" esil_neg: unknown reg %s\n", esil->address, src);
			}
		}
	} else {
		ERR ("esil_neg: empty stack");
	}
	free (src);
	return ret;
}

static int esil_negeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_reg_read (esil, src, &num, NULL)) {
		num = !num;
		r_anal_esil_reg_write (esil, src, num);
		ret = 1;
	} else {
		ERR ("esil_negeq: empty stack");
	}
	free (src);
	//r_anal_esil_pushnum (esil, ret);
	return ret;
}

static int esil_nop(RAnalEsil *esil) {
	return 0;
}

static int esil_andeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = num;
				esil->cur = num & num2;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, num & num2);
			ret = 1;
		} else {
			ERR ("esil_andeq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_oreq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = num;
				esil->cur = num | num2;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, num | num2);
			ret = 1;
		} else {
			ERR ("esil_ordeq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_xoreq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = num;
				esil->cur = num ^ num2;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, num ^ num2);
			ret = 1;
		} else {
			ERR ("esil_xoreq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

#if 0
static int esil_interrupt_linux_i386(RAnalEsil *esil) { 		//move this into a plugin
	ut32 sn, ret = 0;
	char *usn = r_anal_esil_pop (esil);
	if (usn) {
		sn = (ut32) r_num_get (NULL, usn);
	} else sn = 0x80;

	if (sn == 3) {
		// trap
		esil->trap = R_ANAL_TRAP_BREAKPOINT;
		esil->trap_code = 3;
		return -1;
	}

	if (sn != 0x80) {
		eprintf ("Interrupt 0x%x not handled.", sn);
		esil->trap = R_ANAL_TRAP_UNHANDLED;
		esil->trap_code = sn;
		return -1;
	}
#undef r
#define r(x) r_reg_getv (esil->anal->reg, "##x##")
#undef rs
#define rs(x, y) r_reg_setv (esil->anal->reg, "##x##", y)
	switch (r(eax)) {
	case 1:
		printf ("exit(%d)\n", (int)r(ebx));
		rs(eax, -1);
		// never return. stop execution somehow, throw an exception
		break;
	case 3:
		ret = r(edx);
		printf ("ret:%d = read(fd:%"PFMT64d", ptr:0x%08"PFMT64x", len:%"PFMT64d")\n",
			(int)ret, r(ebx), r(ecx), r(edx));
		rs(eax, ret);
		break;
	case 4:
		ret = r(edx);
		printf ("ret:%d = write(fd:%"PFMT64d", ptr:0x%08"PFMT64x", len:%"PFMT64d")\n",
			(int)ret, r(ebx), r(ecx), r(edx));
		rs(eax, ret);
		break;
	case 5:
		ret = -1;
		printf ("fd:%d = open(file:0x%08"PFMT64x", mode:%"PFMT64d", perm:%"PFMT64d")\n",
			(int)ret, r(ebx), r(ecx), r(edx));
		rs(eax, ret);
		break;
	}
#undef r
#undef rs
	return 0;
}
#endif

static int esil_trap(RAnalEsil *esil) {
	ut64 s, d;
	if (popRN (esil, &s) && popRN (esil, &d)) {
		esil->trap = s;
		esil->trap_code = d;
		return r_anal_esil_fire_trap (esil, (int)s, (int)d);
	}
	ERR ("esil_trap: missing parameters in stack");
	return false;
}

static int esil_bits(RAnalEsil *esil) {
	ut64 s;
	if (popRN (esil, &s)) {
		if (esil->anal && esil->anal->coreb.setab) {
			esil->anal->coreb.setab (esil->anal->coreb.core, NULL, s);
		}
		return true;
	}
	ERR ("esil_bits: missing parameters in stack");
	return false;
}

static int esil_interrupt(RAnalEsil *esil) {
	ut64 interrupt;
	if (popRN (esil, &interrupt)) {
		return r_anal_esil_fire_interrupt (esil, (int)interrupt);
	}
	return false;
}

// Pushes result onto stack. Pushes op1 == op2 onto stack, not the difference.
// This function also sets internal vars which is used in flag calculations.
static int esil_cmp(RAnalEsil *esil) {
	ut64 num, num2;
	int ret = 0;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = 1;
			if (r_reg_get (esil->anal->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			} else if (r_reg_get (esil->anal->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			r_anal_esil_pushnum (esil, num == num2);
		}
	}
	free (dst);
	free (src);
	return ret;
}

#if 0
x86 documentation:
CF - carry flag -- Set on high-order bit carry or borrow; cleared otherwise
	num>>63
PF - parity flag
	(num&0xff)
    Set if low-order eight bits of result contain an even number of "1" bits; cleared otherwise
ZF - zero flags
    Set if result is zero; cleared otherwise
	zf = num?0:1;
SF - sign flag
    Set equal to high-order bit of result (0 if positive 1 if negative)
	sf = ((st64)num)<0)?1:0;
OF - overflow flag
	if (a>0&&b>0 && (a+b)<0)
    Set if result is too large a positive number or too small a negative number (excluding sign bit) to fit in destination operand; cleared otherwise

JBE: CF = 1 || ZF = 1

#endif

/*
 * Expects a string in the stack. Each char of the string represents a CPU flag.
 * Those relations are associated by the CPU itself and are used to move values
 * from the internal ESIL into the RReg instance.
 *
 * For example:
 *   zco,?=     # update zf, cf and of
 *
 * If we want to update the esil value of a specific flag we use the =? command
 *
 *    zf,z,=?    # esil[zf] = r_reg[zf]
 *
 * Defining new cpu flags
 */
#if 0
static int esil_ifset(RAnalEsil *esil) {
	char *s, *src = r_anal_esil_pop (esil);
	for (s=src; *s; s++) {
		switch (*s) {
		case 'z':
			r_anal_esil_reg_write (esil, "zf", R_BIT_CHK(&esil->flags, FLG(ZERO)));
			break;
		case 'c':
			r_anal_esil_reg_write (esil, "cf", R_BIT_CHK(&esil->flags, FLG(CARRY)));
			break;
		case 'o':
			r_anal_esil_reg_write (esil, "of", R_BIT_CHK(&esil->flags, FLG(OVERFLOW)));
			break;
		case 'p':
			r_anal_esil_reg_write (esil, "pf", R_BIT_CHK(&esil->flags, FLG(PARITY)));
			break;
		}
	}
	free (src);
	return 0;
}
#endif

static int esil_if(RAnalEsil *esil) {
	ut64 num = 0LL;
	char *src = r_anal_esil_pop (esil);
	if (src) {
		// TODO: check return value
		(void)r_anal_esil_get_parm (esil, src, &num);
		// condition not matching, skipping until }
		if (!num) {
			esil->skip = true;
		}
		free (src);
		return true;
	}
	return false;
}

static int esil_lsl(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (num2 > sizeof (ut64) * 8) {
				ERR ("esil_lsl: shift is too big");
			} else {
				if (num2 > 63) {
					r_anal_esil_pushnum (esil, 0);
				} else {
					r_anal_esil_pushnum (esil, num << num2);
				}
				ret = 1;
			}
		} else {
			ERR ("esil_lsl: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_lsleq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (num2 > sizeof (ut64) * 8) {
				ERR ("esil_lsleq: shift is too big");
			} else {
				esil->old = num;
				if (num2 > 63) {
					num = 0;
				} else {
					num <<= num2;
				}
				esil->cur = num;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
				r_anal_esil_reg_write (esil, dst, num);
				ret = 1;
			}
		} else {
			ERR ("esil_lsleq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_lsr(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			ut64 res = num >> R_MIN(num2, 63);
			r_anal_esil_pushnum (esil, res);
			ret = 1;
		} else {
			ERR ("esil_lsr: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_lsreq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			num >>= num2;
			esil->cur = num;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			r_anal_esil_reg_write (esil, dst, num);
			ret = 1;
		} else {
			ERR ("esil_lsreq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_asreq(RAnalEsil *esil) {
	int regsize, ret = 0;
	ut64 op_num, param_num;
	char *op = r_anal_esil_pop (esil);
	char *param = r_anal_esil_pop (esil);
	if (op && r_anal_esil_get_parm_size (esil, op, &op_num, &regsize)) {
		if (param && r_anal_esil_get_parm (esil, param, &param_num)) {
			ut64 mask = (regsize - 1);
			param_num &= mask;
			bool isNegative;
			if (regsize == 32) {
				isNegative = ((st32)op_num)<0;
				st32 snum = op_num;
				op_num = snum;
			} else {
				isNegative = ((st64)op_num)<0;
			}
			if (isNegative) {
				if (regsize == 32) {
					op_num = -(st64)op_num;
					if (op_num >> param_num) {
						op_num >>= param_num;
						op_num = -(st64)op_num;
					} else {
						op_num = -1;
					}
				} else {
					ut64 mask = (regsize - 1);
					param_num &= mask;
					ut64 left_bits = 0;
					if (op_num & (1 << (regsize - 1))) {
						left_bits = (1 << param_num) - 1;
						left_bits <<= regsize - param_num;
					}
					op_num = left_bits | (op_num >> param_num);
				}
			} else {
				op_num >>= param_num;
			}
			ut64 res = op_num;
			esil->cur = res;
			esil->lastsz = esil_internal_sizeof_reg (esil, op);
			r_anal_esil_reg_write (esil, op, res);
			// r_anal_esil_pushnum (esil, res);
			ret = 1;
		} else {
			ERR ("esil_asr: empty stack");
		}
	}
	free (param);
	free (op);
	return ret;
}

static int esil_asr(RAnalEsil *esil) {
	int regsize, ret = 0;
	ut64 op_num, param_num;
	char *op    = r_anal_esil_pop (esil);
	char *param = r_anal_esil_pop (esil);
	if (op && r_anal_esil_get_parm_size (esil, op, &op_num, &regsize)) {
		if (param && r_anal_esil_get_parm (esil, param, &param_num)) {
			bool isNegative;
			if (regsize == 32) {
				isNegative = ((st32)op_num)<0;
				st32 snum = op_num;
				op_num = snum;
			} else {
				isNegative = ((st64)op_num)<0;
			}
			if (isNegative) {
				ut64 mask = (regsize - 1);
				param_num &= mask;
				ut64 left_bits = 0;
				if (op_num & (1UL << (regsize - 1))) {
					left_bits = (1UL << param_num) - 1;
					left_bits <<= regsize - param_num;
				}
				op_num = left_bits | (op_num >> param_num);
			} else {
				op_num >>= param_num;
			}
			ut64 res = op_num;
			r_anal_esil_pushnum (esil, res);
			ret = 1;
		} else {
			ERR ("esil_asr: empty stack");
		}
	}
	free (param);
	free (op);
	return ret;
}

static int esil_ror(RAnalEsil *esil) {
	int regsize, ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm_size (esil, dst, &num, &regsize)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			ut64 mask = (regsize - 1);
			num2 &= mask;
			ut64 res = (num >> num2) | (num << ((-(st64)num2) & mask));
			r_anal_esil_pushnum (esil, res);
			ret = 1;
		} else {
			ERR ("esil_ror: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_rol(RAnalEsil *esil) {
	int regsize, ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm_size (esil, dst, &num, &regsize)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			ut64 mask = (regsize - 1);
			num2 &= mask;
			ut64 res = (num << num2) | (num >> ((-(st64)num2) & mask));
			r_anal_esil_pushnum (esil, res);
			ret = 1;
		} else {
			ERR ("esil_rol: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_and(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			num &= num2;
			r_anal_esil_pushnum (esil, num);
			ret = 1;
		} else {
			ERR ("esil_and: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_xor(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			num ^= num2;
			r_anal_esil_pushnum (esil, num);
			ret = 1;
		} else {
			ERR ("esil_xor: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_or(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			num |= num2;
			r_anal_esil_pushnum (esil, num);
			ret = 1;
		} else {
			ERR ("esil_xor: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

R_API const char *r_anal_esil_trapstr(int type) {
	switch (type) {
	case R_ANAL_TRAP_READ_ERR:
		return "read-err";
	case R_ANAL_TRAP_WRITE_ERR:
		return "write-err";
	case R_ANAL_TRAP_BREAKPOINT:
		return "breakpoint";
	case R_ANAL_TRAP_UNHANDLED:
		return "unhandled";
	case R_ANAL_TRAP_DIVBYZERO:
		return "divbyzero";
	default:
		return "unknown";
	}
}

R_API int r_anal_esil_dumpstack(RAnalEsil *esil) {
	int i;
	if (!esil) {
		return 0;
	}
	if (esil->trap) {
		eprintf ("ESIL TRAP type %d code 0x%08x %s\n",
			esil->trap, esil->trap_code,
			r_anal_esil_trapstr (esil->trap));
	}
	if (esil->stackptr < 1) {
		return 0;
	}
	for (i = esil->stackptr - 1; i >= 0; i--) {
		esil->anal->cb_printf ("%s\n", esil->stack[i]);
	}
	return 1;
}

static int esil_break(RAnalEsil *esil) {
	esil->parse_stop = 1;
	return 1;
}

static int esil_clear(RAnalEsil *esil) {
	char *r;
	while ((r = r_anal_esil_pop (esil)))
		free (r);
	return 1;
}

static int esil_todo(RAnalEsil *esil) {
	esil->parse_stop = 2;
	return 1;
}

static int esil_goto(RAnalEsil *esil) {
	ut64 num = 0;
	char *src = r_anal_esil_pop (esil);
	if (src && *src && r_anal_esil_get_parm (esil, src, &num)) {
		esil->parse_goto = num;
	}
	free (src);
	return 1;
}

static int esil_repeat(RAnalEsil *esil) {
	char *dst = r_anal_esil_pop (esil); // destaintion of the goto
	char *src = r_anal_esil_pop (esil); // value of the counter
	ut64 n, num = 0;
	if (r_anal_esil_get_parm (esil, src, &n) && r_anal_esil_get_parm (esil, dst, &num)) {
		if (n > 1) {
			esil->parse_goto = num;
			r_anal_esil_pushnum (esil, n - 1);
		}
	}
	free (dst);
	free (src);
	return 1;
}

static int esil_pop(RAnalEsil *esil) {
	char *dst = r_anal_esil_pop (esil);
	free (dst);
	return 1;
}

static int esil_mod(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
			if (s == 0) {
				if (esil->verbose > 0) {
					eprintf ("0x%08"PFMT64x" esil_mod: Division by zero!\n", esil->address);
				}
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				r_anal_esil_pushnum (esil, d % s);
			}
			ret = 1;
		}
	} else {
		ERR ("esil_mod: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_modeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (s) {
				if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
					esil->old = d;
					esil->cur = d % s;
					esil->lastsz = esil_internal_sizeof_reg (esil, dst);
				}
				r_anal_esil_reg_write (esil, dst, d % s);
			} else {
				ERR ("esil_modeq: Division by zero!");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			}
			ret = 1;
		} else {
			ERR ("esil_modeq: empty stack");
		}
	} else {
		ERR ("esil_modeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_div(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
			if (s == 0) {
				ERR ("esil_div: Division by zero!");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				r_anal_esil_pushnum (esil, d / s);
			}
			ret = 1;
		}
	} else {
		ERR ("esil_div: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_diveq(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (s) {
				if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
					esil->old = d;
					esil->cur = d / s;
					esil->lastsz = esil_internal_sizeof_reg (esil, dst);
				}
				r_anal_esil_reg_write (esil, dst, d / s);
			} else {
				// eprintf ("0x%08"PFMT64x" esil_diveq: Division by zero!\n", esil->address);
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			}
			ret = 1;
		} else {
			ERR ("esil_diveq: empty stack");
		}
	} else {
		ERR ("esil_diveq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_mul(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
			r_anal_esil_pushnum (esil, d * s);
			ret = 1;
		} else {
			ERR ("esil_mul: empty stack");
		}
	} else {
		ERR ("esil_mul: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_muleq(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = d;
				esil->cur = d * s;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, s * d);
			ret = true;
		} else {
			ERR ("esil_muleq: empty stack");
		}
	} else {
		ERR ("esil_muleq: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_add(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
			r_anal_esil_pushnum (esil, s + d);
			ret = true;
		}
	} else {
		ERR ("esil_add: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_addeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = d;
				esil->cur = d + s;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, s + d);
			ret = true;
		}
	} else {
		ERR ("esil_addeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_inc(RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		s++;
		r_anal_esil_pushnum (esil, s);
		ret = true;
	} else {
		ERR ("esil_inc: invalid parameters");
	}
	free (src);
	return ret;
}

static int esil_inceq(RAnalEsil *esil) {
	int ret = 0;
	ut64 sd;
	char *src_dst = r_anal_esil_pop (esil);
	if (src_dst && (r_anal_esil_get_parm_type (esil, src_dst) == R_ANAL_ESIL_PARM_REG) && r_anal_esil_get_parm (esil, src_dst, &sd)) {
		// inc rax
		esil->old = sd++;
		esil->cur = sd;
		r_anal_esil_reg_write (esil, src_dst, sd);
		esil->lastsz = esil_internal_sizeof_reg (esil, src_dst);
		ret = true;
	} else {
		ERR ("esil_inceq: invalid parameters");
	}
	free (src_dst);
	return ret;
}

static int esil_sub(RAnalEsil *esil) {
	ut64 s = 0, d = 0;
	char * dst = r_anal_esil_pop (esil);
	if (!dst) {
		goto dst_broken;
	}
	if (r_anal_esil_reg_read (esil, dst, &d, NULL)) {
		esil->lastsz = esil_internal_sizeof_reg (esil, dst);
	} else {
		if (!isnum (esil, dst, &d)) {
			free (dst);
			goto dst_broken;
		}
		esil->lastsz = 64;
	}
	free (dst);

	if (!popRN (esil, &s)) {
		ERR ("esil_sub: src is broken");
		return false;
	}
	esil->old = d;
	esil->cur = d - s;
	r_anal_esil_pushnum (esil, esil->cur);
	return true;

dst_broken:
	ERR ("esil_sub: dst is broken");
	return false;
}

static int esil_subeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = d;
				esil->cur = d - s;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, d - s);
			ret = true;
		}
	} else {
		ERR ("esil_subeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_dec(RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		s--;
		r_anal_esil_pushnum (esil, s);
		ret = true;
	} else {
		ERR ("esil_dec: invalid parameters");
	}
	free (src);
	return ret;
}

static int esil_deceq(RAnalEsil *esil) {
	int ret = 0;
	ut64 sd;
	char *src_dst = r_anal_esil_pop (esil);
	if (src_dst && (r_anal_esil_get_parm_type (esil, src_dst) == R_ANAL_ESIL_PARM_REG) && r_anal_esil_get_parm (esil, src_dst, &sd)) {
		esil->old = sd;
		sd--;
		esil->cur = sd;
		r_anal_esil_reg_write (esil, src_dst, sd);
		esil->lastsz = esil_internal_sizeof_reg (esil, src_dst);
		ret = true;
	} else {
		ERR ("esil_deceq: invalid parameters");
	}
	free (src_dst);
	return ret;
}

/* POKE */
static int esil_poke_n(RAnalEsil *esil, int bits) {
	ut64 bitmask = genmask (bits - 1);
	ut64 num, num2, addr;
	ut8 b[8] = {0};
	ut64 n;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	int bytes = R_MIN (sizeof (b), bits / 8), ret = 0;
	if (bits % 8) {
		free (src);
		free (dst);
		return 0;
	}
	//eprintf ("GONA POKE %d src:%s dst:%s\n", bits, src, dst);
	if (src && r_anal_esil_get_parm (esil, src, &num)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &addr)) {
			if (bits == 128) {
				char *src2 = r_anal_esil_pop (esil);
				if (src2 && r_anal_esil_get_parm (esil, src2, &num2)) {
					r_write_ble (b, num, esil->anal->big_endian, 64);
					ret = r_anal_esil_mem_write (esil, addr, b, bytes);
					r_write_ble (b, num2, esil->anal->big_endian, 64);
					ret = r_anal_esil_mem_write (esil, addr + 8, b, bytes);
					return ret;
				}
				return -1;
			}
			int type = r_anal_esil_get_parm_type (esil, src);
			if (type != R_ANAL_ESIL_PARM_INTERNAL) {
				// this is a internal peek performed before a poke
				// we disable hooks to avoid run hooks on internal peeks
				void * oldhook = (void*)esil->cb.hook_mem_read;
				esil->cb.hook_mem_read = NULL;
				r_anal_esil_mem_read (esil, addr, b, bytes);
				esil->cb.hook_mem_read = oldhook;
				n = r_read_ble64 (b, esil->anal->big_endian);
				esil->old = n;
				esil->cur = num;
				esil->lastsz = bits;
				num = num & bitmask;
			}
			r_write_ble (b, num, esil->anal->big_endian, bits);
			ret = r_anal_esil_mem_write (esil, addr, b, bytes);
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_poke1(RAnalEsil *esil) {
	return esil_poke_n (esil, 8);
}

static int esil_poke2(RAnalEsil *esil) {
	return esil_poke_n (esil, 16);
}

static int esil_poke3(RAnalEsil *esil) {
	return esil_poke_n (esil, 24);
}

static int esil_poke4(RAnalEsil *esil) {
	return esil_poke_n (esil, 32);
}

static int esil_poke8(RAnalEsil *esil) {
	return esil_poke_n (esil, 64);
}

static int esil_poke16(RAnalEsil *esil) {
	return esil_poke_n (esil, 128);
}

static int esil_poke(RAnalEsil *esil) {
	return esil_poke_n (esil, esil->anal->bits);
}

static int esil_poke_some(RAnalEsil *esil) {
	int i, ret = 0;
	int regsize;
	ut64 ptr, regs = 0, tmp;
	char *count, *dst = r_anal_esil_pop (esil);
#define BYTES_SIZE 64
	if (dst && r_anal_esil_get_parm_size (esil, dst, &tmp, &regsize)) {
		// reg
		isregornum (esil, dst, &ptr);
		count = r_anal_esil_pop (esil);
		if (count) {
			isregornum (esil, count, &regs);
			if (regs > 0) {
				ut8 b[BYTES_SIZE];
				ut64 num64;
				for (i = 0; i < regs; i++) {
					char *foo = r_anal_esil_pop (esil);
					if (!foo) {
						// avoid looping out of stack
						free (dst);
						free (count);
						return 1;
					}
					isregornum (esil, foo, &num64);
					/* TODO: implement peek here */
					// read from $dst
					r_write_ble (b, num64, esil->anal->big_endian, regsize);
					ret = r_anal_esil_mem_write (esil, ptr, b, BYTES_SIZE);
					if (ret != BYTES_SIZE) {
						//eprintf ("Cannot write at 0x%08" PFMT64x "\n", ptr);
						esil->trap = 1;
					}
					ptr += BYTES_SIZE;
					free (foo);
				}
			}
			free (dst);
			free (count);
			return 1;
		}
		free (dst);
	}
	return 0;
}

/* PEEK */

static int esil_peek_n(RAnalEsil *esil, int bits) {
	if (bits & 7) {
		return 0;
	}
	char res[32];
	ut64 addr;
	int ret = 0, bytes = bits / 8;
	char *dst = r_anal_esil_pop (esil);
	//eprintf ("GONA PEEK %d dst:%s\n", bits, dst);
	if (dst && isregornum (esil, dst, &addr)) {
		if (bits == 128) {
			ut8 a[sizeof(ut64) * 2] = {0};
			ret = r_anal_esil_mem_read (esil, addr, a, bytes);
			ut64 b = r_read_ble64 (&a, 0); //esil->anal->big_endian);
			ut64 c = r_read_ble64 (&a[8], 0); //esil->anal->big_endian);
			snprintf (res, sizeof (res), "0x%" PFMT64x, b);
			r_anal_esil_push (esil, res);
			snprintf (res, sizeof (res), "0x%" PFMT64x, c);
			r_anal_esil_push (esil, res);
			free (dst);
			return ret;
		}
		ut64 bitmask = genmask (bits - 1);
		ut8 a[sizeof(ut64)] = {0};
		ret = r_anal_esil_mem_read (esil, addr, a, bytes);
		ut64 b = r_read_ble64 (a, 0); //esil->anal->big_endian);
		if (esil->anal->big_endian) {
			r_mem_swapendian ((ut8*)&b, (const ut8*)&b, bytes);
		}
		snprintf (res, sizeof (res), "0x%" PFMT64x, b & bitmask);
		r_anal_esil_push (esil, res);
		esil->lastsz = bits;
	}
	free (dst);
	return ret;
}

static int esil_peek1(RAnalEsil *esil) {
	return esil_peek_n (esil, 8);
}

static int esil_peek2(RAnalEsil *esil) {
	return esil_peek_n (esil, 16);
}

static int esil_peek3(RAnalEsil *esil) {
	return esil_peek_n (esil, 24);
}

static int esil_peek4(RAnalEsil *esil) {
	return esil_peek_n (esil, 32);
}

static int esil_peek8(RAnalEsil *esil) {
	return esil_peek_n (esil, 64);
}

static int esil_peek16(RAnalEsil *esil) {
	// packed only
	return esil_peek_n (esil, 128);
}

static int esil_peek(RAnalEsil *esil) {
	return esil_peek_n (esil, esil->anal->bits);
};

static int esil_peek_some(RAnalEsil *esil) {
	int i, ret = 0;
	ut64 ptr, regs;
	// pop ptr
	char *count, *dst = r_anal_esil_pop (esil);
	if (dst) {
		// reg
		isregornum (esil, dst, &ptr);
		count = r_anal_esil_pop (esil);
		if (count) {
			isregornum (esil, count, &regs);
			if (regs > 0) {
				ut32 num32;
				ut8 a[sizeof (ut32)];
				for (i = 0; i < regs; i++) {
					char *foo = r_anal_esil_pop (esil);
					if (!foo) {
						ERR ("Cannot pop in peek");
						return 0;
					}
					ret = r_anal_esil_mem_read (esil, ptr, a, 4);
					if (ret == sizeof (ut32)) {
						num32 = r_read_ble32 (a, esil->anal->big_endian);
						r_anal_esil_reg_write (esil, foo, num32);
					} else {
						if (esil->verbose) {
							eprintf ("Cannot peek from 0x%08" PFMT64x "\n", ptr);
						}
					}
					ptr += sizeof (ut32);
					free (foo);
				}
			}
			free (dst);
			free (count);
			return 1;
		}
		free (dst);
	}
	return 0;
}

/* OREQ */

static int esil_mem_oreq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);  //save the dst-addr
	char *src0 = r_anal_esil_pop (esil); //get the src
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) { 	//get the src
		r_anal_esil_push (esil, dst);			//push the dst-addr
		ret = (!!esil_peek_n (esil, bits));		//read
		src1 = r_anal_esil_pop (esil);			//get the old dst-value
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) { //get the old dst-value
			d |= s;					//calculate the new dst-value
			r_anal_esil_pushnum (esil, d);		//push the new dst-value
			r_anal_esil_push (esil, dst);		//push the dst-addr
			ret &= (!!esil_poke_n (esil, bits));	//write
		} else ret = 0;
	}
	if (!ret) {
		ERR ("esil_mem_oreq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_oreq1(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 8);
}
static int esil_mem_oreq2(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 16);
}
static int esil_mem_oreq4(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 32);
}
static int esil_mem_oreq8(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 64);
}
static int esil_mem_oreq(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, esil->anal->bits);
}

/* XOREQ */

static int esil_mem_xoreq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d ^= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret) {
		ERR ("esil_mem_xoreq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_xoreq1(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 8);
}
static int esil_mem_xoreq2(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 16);
}
static int esil_mem_xoreq4(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 32);
}
static int esil_mem_xoreq8(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 64);
}
static int esil_mem_xoreq(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, esil->anal->bits);
}

/* ANDEQ */

static int esil_mem_andeq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d &= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret) {
		ERR ("esil_mem_andeq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_andeq1(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 8);
}
static int esil_mem_andeq2(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 16);
}
static int esil_mem_andeq4(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 32);
}
static int esil_mem_andeq8(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 64);
}
static int esil_mem_andeq(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, esil->anal->bits);
}

/* ADDEQ */

static int esil_mem_addeq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d += s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret)
		ERR ("esil_mem_addeq_n: invalid parameters");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_addeq1(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 8);
}
static int esil_mem_addeq2(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 16);
}
static int esil_mem_addeq4(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 32);
}
static int esil_mem_addeq8(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 64);
}
static int esil_mem_addeq(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, esil->anal->bits);
}

/* SUBEQ */

static int esil_mem_subeq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d -= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret)
		ERR ("esil_mem_subeq_n: invalid parameters");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_subeq1(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 8);
}
static int esil_mem_subeq2(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 16);
}
static int esil_mem_subeq4(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 32);
}
static int esil_mem_subeq8(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 64);
}
static int esil_mem_subeq(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, esil->anal->bits);
}

/* MODEQ */

static int esil_mem_modeq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		if (s == 0) {
			ERR ("esil_mem_modeq4: Division by zero!");
			esil->trap = R_ANAL_TRAP_DIVBYZERO;
			esil->trap_code = 0;
		} else {
			r_anal_esil_push (esil, dst);
			ret = (!!esil_peek_n (esil, bits));
			src1 = r_anal_esil_pop (esil);
			if (src1 && r_anal_esil_get_parm (esil, src1, &d) && s >= 1) {
				r_anal_esil_pushnum (esil, d % s);
				d = d % s;
				r_anal_esil_pushnum (esil, d);
				r_anal_esil_push (esil, dst);
				ret &= (!!esil_poke_n (esil, bits));
			} else {
				ret = 0;
			}
		}
	}
	if (!ret) {
		ERR ("esil_mem_modeq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_modeq1(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 8);
}
static int esil_mem_modeq2(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 16);
}
static int esil_mem_modeq4(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 32);
}
static int esil_mem_modeq8(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 64);
}
static int esil_mem_modeq(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, esil->anal->bits);
}

/* DIVEQ */

static int esil_mem_diveq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		if (s == 0) {
			ERR ("esil_mem_diveq8: Division by zero!");
			esil->trap = R_ANAL_TRAP_DIVBYZERO;
			esil->trap_code = 0;
		} else {
			r_anal_esil_push (esil, dst);
			ret = (!!esil_peek_n (esil, bits));
			src1 = r_anal_esil_pop (esil);
			if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
				d = d / s;
				r_anal_esil_pushnum (esil, d);
				r_anal_esil_push (esil, dst);
				ret &= (!!esil_poke_n (esil, bits));
			} else ret = 0;
		}
	}
	if (!ret)
		ERR ("esil_mem_diveq_n: invalid parameters");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_diveq1(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 8);
}
static int esil_mem_diveq2(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 16);
}
static int esil_mem_diveq4(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 32);
}
static int esil_mem_diveq8(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 64);
}
static int esil_mem_diveq(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, esil->anal->bits);
}

/* MULEQ */

static int esil_mem_muleq_n(RAnalEsil *esil, int bits, ut64 bitmask) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d *= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret)
		ERR ("esil_mem_muleq_n: invalid parameters");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_muleq1(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 8, UT8_MAX);
}
static int esil_mem_muleq2(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 16, UT16_MAX);
}
static int esil_mem_muleq4(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 32, UT32_MAX);
}
static int esil_mem_muleq8(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 64, UT64_MAX);
}

static int esil_mem_muleq(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_mem_muleq8 (esil);
	case 32: return esil_mem_muleq4 (esil);
	case 16: return esil_mem_muleq2 (esil);
	case 8: return esil_mem_muleq1 (esil);
	}
	return 0;
}

/* INCEQ */

static int esil_mem_inceq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		r_anal_esil_push (esil, off);
		ret = (!!esil_peek_n (esil, bits));
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s++;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret)
		ERR ("esil_mem_inceq_n: invalid parameters");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_inceq1(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 8);
}
static int esil_mem_inceq2(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 16);
}
static int esil_mem_inceq4(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 32);
}
static int esil_mem_inceq8(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 64);
}
static int esil_mem_inceq(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, esil->anal->bits);
}

/* DECEQ */

static int esil_mem_deceq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		r_anal_esil_push (esil, off);
		ret = (!!esil_peek_n (esil, bits));
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s--;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret)
		ERR ("esil_mem_deceq_n: invalid parameters");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_deceq1(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 8);
}
static int esil_mem_deceq2(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 16);
}
static int esil_mem_deceq4(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 32);
}
static int esil_mem_deceq8(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 64);
}
static int esil_mem_deceq(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, esil->anal->bits);
}

/* LSLEQ */

static int esil_mem_lsleq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		if (s > sizeof (ut64) * 8) {
			ERR ("esil_mem_lsleq_n: shift is too big");
		} else {
			r_anal_esil_push (esil, dst);
			ret = (!!esil_peek_n (esil, bits));
			src1 = r_anal_esil_pop (esil);
			if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
				if (s > 63) {
					d = 0;
				} else {
					d <<= s;
				}
				r_anal_esil_pushnum (esil, d);
				r_anal_esil_push (esil, dst);
				ret &= (!!esil_poke_n (esil, bits));
			} else {
				ret = 0;
			}
		}
	}
	if (!ret) {
		ERR ("esil_mem_lsleq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_lsleq1(RAnalEsil *esil) {
	return esil_mem_lsleq_n (esil, 8);
}
static int esil_mem_lsleq2(RAnalEsil *esil) {
	return esil_mem_lsleq_n (esil, 16);
}
static int esil_mem_lsleq4(RAnalEsil *esil) {
	return esil_mem_lsleq_n (esil, 32);
}
static int esil_mem_lsleq8(RAnalEsil *esil) {
	return esil_mem_lsleq_n (esil, 64);
}
static int esil_mem_lsleq(RAnalEsil *esil) {
	return esil_mem_lsleq_n (esil, esil->anal->bits);
}

/* LSREQ */

static int esil_mem_lsreq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d >>= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret)
		ERR ("esil_mem_lsreq_n: invalid parameters");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_lsreq1(RAnalEsil *esil) {
	return esil_mem_lsreq_n (esil, 8);
}
static int esil_mem_lsreq2(RAnalEsil *esil) {
	return esil_mem_lsreq_n (esil, 16);
}
static int esil_mem_lsreq4(RAnalEsil *esil) {
	return esil_mem_lsreq_n (esil, 32);
}
static int esil_mem_lsreq8(RAnalEsil *esil) {
	return esil_mem_lsreq_n (esil, 64);
}
static int esil_mem_lsreq(RAnalEsil *esil) {
	return esil_mem_lsreq_n (esil, esil->anal->bits);
}

/* get value of register or memory reference and push the value */
static int esil_num(RAnalEsil *esil) {
	char *dup_me;
	ut64 dup;
	if (!esil)
		return false;
	if (!(dup_me = r_anal_esil_pop (esil)))
		return false;
	if (!r_anal_esil_get_parm (esil, dup_me, &dup)) {
		free (dup_me);
		return false;
	}
	free (dup_me);
	return r_anal_esil_pushnum (esil, dup);
}

/* duplicate the last element in the stack */
static int esil_dup(RAnalEsil *esil) {
	if (!esil || !esil->stack || esil->stackptr < 1 || esil->stackptr > (esil->stacksize - 1))
		return false;
	return r_anal_esil_push (esil, esil->stack[esil->stackptr-1]);
}

static int esil_swap(RAnalEsil *esil) {
	char *tmp;
	if (!esil || !esil->stack || esil->stackptr < 2)
		return false;
	if (!esil->stack[esil->stackptr-1] || !esil->stack[esil->stackptr-2])
		return false;
	tmp = esil->stack[esil->stackptr-1];
	esil->stack[esil->stackptr-1] = esil->stack[esil->stackptr-2];
	esil->stack[esil->stackptr-2] = tmp;
	return true;
}

static int __esil_generic_pick(RAnalEsil *esil, int rev) {
	char *idx = r_anal_esil_pop (esil);
	ut64 i;
	int ret = false;
	if (!idx || !r_anal_esil_get_parm (esil, idx, &i)) {
		ERR ("esil_pick: invalid index number");
		goto end;
	}
	if (!esil || !esil->stack) {
		ERR ("esil_pick: stack not initialized");
		goto end;
	}
	if (rev) {
		i = esil->stackptr + (((st64) i) * -1);
	}
	if (esil->stackptr < i) {
		ERR ("esil_pick: index out of stack bounds");
		goto end;
	}
	if (!esil->stack[esil->stackptr-i]) {
		ERR ("esil_pick: undefined element");
		goto end;
	}
	if (!r_anal_esil_push (esil, esil->stack[esil->stackptr-i])) {
		ERR ("ESIL stack is full");
		esil->trap = 1;
		esil->trap_code = 1;
		goto end;
	}
	ret = true;
end:
	free (idx);
	return ret;
}

static int esil_pick(RAnalEsil *esil) {
	return __esil_generic_pick (esil, 0);
}

static int esil_rpick(RAnalEsil *esil) {
	return __esil_generic_pick (esil, 1);
}

// NOTE on following comparison functions:
// The push to top of the stack is based on a
// signed compare (as this causes least surprise to the users).
// If an unsigned comparison is necessary, one must not use the
// result pushed onto the top of the stack, but rather test the flags which
// are set as a result of the compare.

static int signed_compare_gt(ut64 a, ut64 b, ut64 size) {
	int result;
	switch (size) {
	case 1:  result = (a & 1) > (b & 1);
		break;
	case 8:  result = (st8) a > (st8) b;
		break;
	case 16: result = (st16) a > (st16) b;
		break;
	case 32: result = (st32) a > (st32) b;
		break;
	case 64:
	default: result = (st64) a > (st64) b;
		break;
	}
	return result;
}

static int esil_smaller(RAnalEsil *esil) { // 'dst < src' => 'src,dst,<'
	ut64 num, num2;
	int ret = 0;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = 1;
			if (r_reg_get (esil->anal->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			} else if (r_reg_get (esil->anal->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			r_anal_esil_pushnum (esil, (num != num2) &
			                           !signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_bigger(RAnalEsil *esil) { // 'dst > src' => 'src,dst,>'
	ut64 num, num2;
	int ret = 0;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = 1;
			if (r_reg_get (esil->anal->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			} else if (r_reg_get (esil->anal->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			r_anal_esil_pushnum (esil, signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_smaller_equal(RAnalEsil *esil) { // 'dst <= src' => 'src,dst,<='
	ut64 num, num2;
	int ret = 0;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = 1;
			if (r_reg_get (esil->anal->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			} else if (r_reg_get (esil->anal->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			r_anal_esil_pushnum (esil, !signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_bigger_equal(RAnalEsil *esil) { // 'dst >= src' => 'src,dst,>='
	ut64 num, num2;
	int ret = 0;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = 1;
			if (r_reg_get (esil->anal->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			} else if (r_reg_get (esil->anal->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			r_anal_esil_pushnum (esil, (num == num2) |
			                           signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static int iscommand(RAnalEsil *esil, const char *word, RAnalEsilOp *op) {
	char t[128];
	char *h;
	h = sdb_itoa (sdb_hash (word), t, 16);
	if (sdb_num_exists (esil->ops, h)) {
		*op = (RAnalEsilOp)(size_t)sdb_num_get (esil->ops, h, 0);
		return true;
	}
	return false;
}

static int runword(RAnalEsil *esil, const char *word) {
	RAnalEsilOp op = NULL;
	if (!word) {
		return 0;
	}
	esil->parse_goto_count--;
	if (esil->parse_goto_count < 1) {
		ERR ("ESIL infinite loop detected\n");
		esil->trap = 1;       // INTERNAL ERROR
		esil->parse_stop = 1; // INTERNAL ERROR
		return 0;
	}

	// Don't push anything onto stack when processing if statements
	if (!strcmp (word, "?{") && esil->Reil) {
		esil->Reil->skip = esil->Reil->skip? 0: 1;
		if (esil->Reil->skip) {
			esil->Reil->cmd_count = 0;
			memset (esil->Reil->if_buf, 0, sizeof (esil->Reil->if_buf));
		}
	}

	if (esil->Reil && esil->Reil->skip) {
		int tmp_len = strlen (esil->Reil->if_buf);
		strncat (esil->Reil->if_buf, word, sizeof (esil->Reil->if_buf) - tmp_len - 2);
		strncat (esil->Reil->if_buf, ",", 1);
		if (!strcmp (word, "}")) {
			r_anal_esil_pushnum (esil, esil->Reil->addr + esil->Reil->cmd_count + 1);
			r_anal_esil_parse (esil, esil->Reil->if_buf);
			return 1;
		}
		if (iscommand (esil, word, &op)) esil->Reil->cmd_count++;
		return 1;
	}

	//eprintf ("WORD (%d) (%s)\n", esil->skip, word);
	if (!strcmp (word, "}{")) {
		esil->skip = esil->skip? 0: 1;
		return 1;
	} else if (!strcmp (word, "}")) {
		esil->skip = 0;
		return 1;
	}
	if (esil->skip) {
		return 1;
	}

	if (iscommand (esil, word, &op)) {
		// run action
		if (op) {
			if (esil->cb.hook_command) {
				if (esil->cb.hook_command (esil, word)) {
					return 1; // XXX cannot return != 1
				}
			}
			return op (esil);
		}
	}
	if (!*word || *word == ',') {
		// skip empty words
		return 1;
	}

	// push value
	if (!r_anal_esil_push (esil, word)) {
		ERR ("ESIL stack is full");
		esil->trap = 1;
		esil->trap_code = 1;
	}
	return 1;
}

static const char *gotoWord(const char *str, int n) {
	const char *ostr = str;
	int count = 0;
	while (*str) {
		if (count == n)
			return ostr;
		str++;
		if (*str == ',') {
			ostr = str + 1;
			count++;
		}
	}
	return NULL;
}

/** evaluate an esil word and return the action to perform
 * TODO: Use `enum` here
 * 0: continue running the
 * 1: stop execution
 * 2: continue in loop
 * 3: normal continuation
 */
static int evalWord(RAnalEsil *esil, const char *ostr, const char **str) {
	if (!esil || !str || !*str) {
		return 0;
	}
	if ((*str)[0] && (*str)[1] == ',') {
		return 2;
	}
	if (esil->repeat) {
		return 0;
	}
	if (esil->parse_goto != -1) {
		// TODO: detect infinite loop??? how??
		*str = gotoWord (ostr, esil->parse_goto);
		if (*str) {
			esil->parse_goto = -1;
			return 2;
		}
		if (esil->verbose) {
			eprintf ("Cannot find word %d\n", esil->parse_goto);
		}
		return 1;
	}
	if (esil->parse_stop) {
		if (esil->parse_stop == 2) {
			eprintf ("ESIL TODO: %s\n", *str + 1);
		}
		return 1;
	}
	return 3;
}

R_API int r_anal_esil_parse(RAnalEsil *esil, const char *str) {
	int wordi = 0;
	int dorunword;
	char word[64];
	const char *ostr = str;
	if (!esil || !str || !*str) {
		return 0;
	}
	esil->trap = 0;
	if (esil->cmd && esil->cmd_todo) {
		if (!strncmp (str, "TODO", 4)) {
			esil->cmd (esil, esil->cmd_todo, esil->address, 0);
		}
	}
loop:
	esil->repeat = 0;
	esil->skip = 0;
	esil->parse_goto = -1;
	esil->parse_stop = 0;
	if (esil->anal) {
		esil->parse_goto_count = esil->anal->esil_goto_limit;
	} else {
		esil->parse_goto_count = R_ANAL_ESIL_GOTO_LIMIT;
	}
	str = ostr;
repeat:
	wordi = 0;
	while (*str) {
		if (wordi > 62) {
			ERR ("Invalid esil string");
			return -1;
		}
		dorunword = 0;
		if (*str == ';') {
			word[wordi] = 0;
			dorunword = 1;
		}
		if (*str == ',') {
			word[wordi] = 0;
			dorunword = 2;
		}

		if (dorunword) {
			if (*word) {
				if (!runword (esil, word)) {
					return 0;
				}
				word[wordi] = ',';
				wordi = 0;
				switch (evalWord (esil, ostr, &str)) {
					case 0: goto loop;
					case 1: return 0;
					case 2: continue;
				}
				if (dorunword == 1) {
					return 0;
				}
			}
			str++;
		}
		word[wordi++] = *str;
		//is *str is '\0' in the next iteration the condition will be true
		//reading beyond the boundaries
		if (*str) str++;
	}
	word[wordi] = 0;
	if (*word) {
		if (!runword (esil, word)) {
			return 0;
		}
		switch (evalWord (esil, ostr, &str)) {
		case 0: goto loop;
		case 1: return 0;
		case 2: goto repeat;
		}
	}
	return 1;
}

R_API int r_anal_esil_runword(RAnalEsil *esil, const char *word) {
	const char *str = NULL;
	runword (esil, word);
	if (*word) {
		if (!runword (esil, word)) {
			return 0;
		}
		int ew = evalWord (esil, word, &str);
		eprintf ("ew %d\n", ew);
		eprintf ("--> %s\n", r_str_get (str));
	}
	return 1;
}

//frees all elements from the stack, not the stack itself
//rename to stack_empty() ?
R_API void r_anal_esil_stack_free(RAnalEsil *esil) {
	int i;
	if (esil) {
		for (i = 0; i < esil->stackptr; i++) {
			R_FREE (esil->stack[i]);
		}
		esil->stackptr = 0;
	}
}

R_API int r_anal_esil_condition(RAnalEsil *esil, const char *str) {
	char *popped;
	int ret;
	if (!esil) {
		return false;
	}
	while (*str == ' ') str++; // use proper string chop?
	(void) r_anal_esil_parse (esil, str);
	popped = r_anal_esil_pop (esil);
	if (popped) {
		ut64 num;
		if (isregornum (esil, popped, &num)) {
			ret = !!num;
		} else {
			ret = 0;
		}
		free (popped);
	} else {
		ERR ("ESIL stack is empty");
		return -1;
	}
	return ret;
}

static void r_anal_esil_setup_ops(RAnalEsil *esil) {
#define OP(x, y) r_anal_esil_set_op (esil, x, y)
	OP ("$", esil_interrupt);
	OP ("==", esil_cmp);
	OP ("<", esil_smaller);
	OP (">", esil_bigger);
	OP ("<=", esil_smaller_equal);
	OP (">=", esil_bigger_equal);
	OP ("?{", esil_if);
	OP ("<<", esil_lsl);
	OP ("<<=", esil_lsleq);
	OP (">>", esil_lsr);
	OP (">>=", esil_lsreq);
	OP (">>>>", esil_asr);
	OP (">>>>=", esil_asreq);
	OP (">>>", esil_ror);
	OP ("<<<", esil_rol);
	OP ("&", esil_and);
	OP ("&=", esil_andeq);
	OP ("}", esil_nop); // just to avoid push
	OP ("|", esil_or);
	OP ("|=", esil_oreq);
	OP ("!", esil_neg);
	OP ("!=", esil_negeq);
	OP ("=", esil_eq);
	OP ("*", esil_mul);
	OP ("*=", esil_muleq);
	OP ("^", esil_xor);
	OP ("^=", esil_xoreq);
	OP ("+", esil_add);
	OP ("+=", esil_addeq);
	OP ("++", esil_inc);
	OP ("++=", esil_inceq);
	OP ("-", esil_sub);
	OP ("-=", esil_subeq);
	OP ("--", esil_dec);
	OP ("--=", esil_deceq);
	OP ("/", esil_div);
	OP ("/=", esil_diveq);
	OP ("%", esil_mod);
	OP ("%=", esil_modeq);
	OP ("=[]", esil_poke);
	OP ("=[1]", esil_poke1);
	OP ("=[2]", esil_poke2);
	OP ("=[3]", esil_poke3);
	OP ("=[4]", esil_poke4);
	OP ("=[8]", esil_poke8);
	OP ("=[16]", esil_poke16);
	OP ("|=[]", esil_mem_oreq);
	OP ("|=[1]", esil_mem_oreq1);
	OP ("|=[2]", esil_mem_oreq2);
	OP ("|=[4]", esil_mem_oreq4);
	OP ("|=[8]", esil_mem_oreq8);
	OP ("^=[]", esil_mem_xoreq);
	OP ("^=[1]", esil_mem_xoreq1);
	OP ("^=[2]", esil_mem_xoreq2);
	OP ("^=[4]", esil_mem_xoreq4);
	OP ("^=[8]", esil_mem_xoreq8);
	OP ("&=[]", esil_mem_andeq);
	OP ("&=[1]", esil_mem_andeq1);
	OP ("&=[2]", esil_mem_andeq2);
	OP ("&=[4]", esil_mem_andeq4);
	OP ("&=[8]", esil_mem_andeq8);
	OP ("+=[]", esil_mem_addeq);
	OP ("+=[1]", esil_mem_addeq1);
	OP ("+=[2]", esil_mem_addeq2);
	OP ("+=[4]", esil_mem_addeq4);
	OP ("+=[8]", esil_mem_addeq8);
	OP ("-=[]", esil_mem_subeq);
	OP ("-=[1]", esil_mem_subeq1);
	OP ("-=[2]", esil_mem_subeq2);
	OP ("-=[4]", esil_mem_subeq4);
	OP ("-=[8]", esil_mem_subeq8);
	OP ("%=[]", esil_mem_modeq);
	OP ("%=[1]", esil_mem_modeq1);
	OP ("%=[2]", esil_mem_modeq2);
	OP ("%=[4]", esil_mem_modeq4);
	OP ("%=[8]", esil_mem_modeq8);
	OP ("/=[]", esil_mem_diveq);
	OP ("/=[1]", esil_mem_diveq1);
	OP ("/=[2]", esil_mem_diveq2);
	OP ("/=[4]", esil_mem_diveq4);
	OP ("/=[8]", esil_mem_diveq8);
	OP ("*=[]", esil_mem_muleq);
	OP ("*=[1]", esil_mem_muleq1);
	OP ("*=[2]", esil_mem_muleq2);
	OP ("*=[4]", esil_mem_muleq4);
	OP ("*=[8]", esil_mem_muleq8);
	OP ("++=[]", esil_mem_inceq);
	OP ("++=[1]", esil_mem_inceq1);
	OP ("++=[2]", esil_mem_inceq2);
	OP ("++=[4]", esil_mem_inceq4);
	OP ("++=[8]", esil_mem_inceq8);
	OP ("--=[]", esil_mem_deceq);
	OP ("--=[1]", esil_mem_deceq1);
	OP ("--=[2]", esil_mem_deceq2);
	OP ("--=[4]", esil_mem_deceq4);
	OP ("--=[8]", esil_mem_deceq8);
        OP ("<<=[]", esil_mem_lsleq);
	OP ("<<=[1]", esil_mem_lsleq1);
	OP ("<<=[2]", esil_mem_lsleq2);
	OP ("<<=[4]", esil_mem_lsleq4);
	OP ("<<=[8]", esil_mem_lsleq8);
	OP (">>=[]", esil_mem_lsreq);
	OP (">>=[1]", esil_mem_lsreq1);
	OP (">>=[2]", esil_mem_lsreq2);
	OP (">>=[4]", esil_mem_lsreq4);
	OP (">>=[8]", esil_mem_lsreq8);
	OP ("[]", esil_peek);
	OP ("[*]", esil_peek_some);
	OP ("=[*]", esil_poke_some);
	OP ("[1]", esil_peek1);
	OP ("[2]", esil_peek2);
	OP ("[3]", esil_peek3);
	OP ("[4]", esil_peek4);
	OP ("[8]", esil_peek8);
	OP ("[16]", esil_peek16);
	OP ("STACK", r_anal_esil_dumpstack);
	OP ("REPEAT", esil_repeat);
	OP ("POP", esil_pop);
	OP ("TODO", esil_todo);
	OP ("GOTO", esil_goto);
	OP ("BREAK", esil_break);
	OP ("CLEAR", esil_clear);
	OP ("DUP", esil_dup);
	OP ("NUM", esil_num);
	OP ("PICK", esil_pick);
	OP ("RPICK", esil_rpick);
	OP ("SWAP", esil_swap);
	OP ("TRAP", esil_trap);
	OP ("BITS", esil_bits);
}

/* register callbacks using this anal module. */
R_API int r_anal_esil_setup(RAnalEsil *esil, RAnal *anal, int romem, int stats, int nonull) {
	if (!esil) return false;
	//esil->debug = 0;
	esil->anal = anal;
	esil->parse_goto_count = anal->esil_goto_limit;
	esil->trap = 0;
	esil->trap_code = 0;
	//esil->user = NULL;
	esil->cb.reg_read = internal_esil_reg_read;
	esil->cb.mem_read = internal_esil_mem_read;

	if (nonull) {
		// never writes zero to PC, BP, SP, why? because writing
		// zeros to these registers is equivalent to acessing NULL
		// pointer somehow
		esil->cb.reg_write = internal_esil_reg_write_no_null;
		esil->cb.mem_read = internal_esil_mem_read_no_null;
		esil->cb.mem_write = internal_esil_mem_write_no_null;

	} else {
		esil->cb.reg_write = internal_esil_reg_write;
		esil->cb.mem_read = internal_esil_mem_read;
		esil->cb.mem_write = internal_esil_mem_write;
	}
	r_anal_esil_mem_ro (esil, romem);
	r_anal_esil_stats (esil, stats);
	r_anal_esil_setup_ops (esil);

	if (anal->cur && anal->cur->esil_init && anal->cur->esil_fini) {
		return anal->cur->esil_init (esil);
	}
	return true;
}
