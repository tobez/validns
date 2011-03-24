#include "common.h"
#include "rr.h"

static struct binary_data new_set(void)
{
	struct binary_data set;
	set.length = 256*(1+1+32);
	set.data = getmem_temp(set.length);
	bzero(set.data, set.length);
	return set;
}

static void add_bit_to_set(struct binary_data *set, int bit)
{
	int map;
	int map_base;
	int byte;

	if (bit < 0 || bit > 65535)
		croakx("bitmap index out of range");
	map = bit / 256;
	map_base = map*(1+1+32);
	set->data[map_base] = map;
	bit = bit & 0xff;
	byte = bit / 8;
	if (set->data[map_base + 1] <= byte)
		set->data[map_base + 1] = byte+1;
	set->data[map_base + 2 + byte] |= 0x80 >> (bit & 0x07);
}

static struct binary_data compressed_set(struct binary_data *set)
{
	int len = 0;
	int map;
	int map_base;
	struct binary_data r;

	for (map = 0; map <= 255; map++) {
		map_base = map*(1+1+32);
		if (set->data[map_base+1]) {
			len += 2 + set->data[map_base+1];
		}
	}
	r.length = len;
	r.data = getmem_temp(r.length);
	len = 0;
	for (map = 0; map <= 255; map++) {
		map_base = map*(1+1+32);
		if (set->data[map_base+1]) {
			memcpy(r.data[len], &set->data[map_base], 2 + set->data[map_base+1]);
			len += 2 + set->data[map_base+1];
		}
	}
	return r;
}

