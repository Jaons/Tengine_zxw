/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __HASH_H__
#define __HASH_H__

/* hash init info structure */
typedef struct ngx_usr_hash_init_t_ {
    ngx_pool_t      *pool;
    uint32_t        size;
}ngx_usr_hash_init_t;

/* hash bucket structure */
typedef struct ngx_usr_hash_bucket_t_ {
    void *data;
    uint16_t size;
    struct ngx_usr_hash_bucket_t_ *next;
} ngx_usr_hash_bucket_t;

/* hash table structure */
typedef struct ngx_usr_hash_t_ {
    ngx_usr_hash_bucket_t **array;
    uint32_t array_size;
#ifdef UNITTESTS
    uint32_t count;
#endif
    uint32_t (*Hash)(struct ngx_usr_hash_t_ *, void *, uint16_t);
    char (*Compare)(void *, uint16_t, void *, uint16_t);
} ngx_usr_hash_t;

#define HASH_NO_SIZE 0

/* prototypes */
//ngx_usr_hash_t* ngx_usr_hash_init(ngx_usr_hash_init_t *uhinit, uint32_t (*Hash)(struct ngx_usr_hash_t *, void *, uint16_t), char (*Compare)(void *, uint16_t, void *, uint16_t), void (*Free)(void *));
ngx_usr_hash_t* ngx_usr_hash_init(ngx_usr_hash_init_t *uhinit, uint32_t (*Hash)(struct ngx_usr_hash_t *, void *, uint16_t), char (*Compare)(void *, uint16_t, void *, uint16_t));
void ngx_usr_hash_free(ngx_usr_hash_t *);
//void ngx_usr_hash_print(ngx_usr_hash_t *);
int ngx_usr_hash_add(ngx_usr_hash_init_t *uhinit, ngx_usr_hash_t *, void *, uint16_t);
int ngx_usr_hash_remove(ngx_usr_hash_t *, void *, uint16_t);
void *ngx_usr_hash_lookup(ngx_usr_hash_t *, void *, uint16_t);
uint32_t ngx_usr_hash_generichash(ngx_usr_hash_t *, void *, uint16_t);
char ngx_usr_hash_defaultcompare(void *, uint16_t, void *, uint16_t);

#endif /* __HASH_H__ */

