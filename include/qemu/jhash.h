/*
 * COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 * (a.k.a. Fault Tolerance or Continuous Replication)
 *
 * Copyright (c) 2015 HUAWEI TECHNOLOGIES CO., LTD.
 * Copyright (c) 2015 FUJITSU LIMITED
 * Copyright (c) 2015 Intel Corporation
 *
 * Author: Zhang Chen <zhangchen.fnst@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#ifndef QEMU_JHASH_H__
#define QEMU_JHASH_H__

/*
 * hashtable relation copy from linux kernel jhash
 */
static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
    return (word << shift) | (word >> (32 - shift));
}

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)                \
{                                           \
    a -= c;  a ^= rol32(c, 4);  c += b;     \
    b -= a;  b ^= rol32(a, 6);  a += c;     \
    c -= b;  c ^= rol32(b, 8);  b += a;     \
    a -= c;  a ^= rol32(c, 16); c += b;     \
    b -= a;  b ^= rol32(a, 19); a += c;     \
    c -= b;  c ^= rol32(b, 4);  b += a;     \
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)  \
{                               \
    c ^= b; c -= rol32(b, 14);  \
    a ^= c; a -= rol32(c, 11);  \
    b ^= a; b -= rol32(a, 25);  \
    c ^= b; c -= rol32(b, 16);  \
    a ^= c; a -= rol32(c, 4);   \
    b ^= a; b -= rol32(a, 14);  \
    c ^= b; c -= rol32(b, 24);  \
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL           0xdeadbeef

#endif /* QEMU_JHASH_H__ */
