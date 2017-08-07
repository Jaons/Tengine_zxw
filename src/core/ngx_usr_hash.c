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
 *
 * Chained hash table implementation
 *
 * The 'Free' pointer can be used to have the API free your
 * hashed data. If it's NULL it's the callers responsebility
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <util-hash.h>

ngx_usr_hash_t* ngx_usr_hash_init(ngx_usr_hash_init_t *uhinit, uint32_t (*Hash)(struct ngx_usr_hash_t *, void *, uint16_t), char (*Compare)(void *, uint16_t, void *, uint16_t)) {

    ngx_usr_hash_t *ht = NULL;

    if (uhinit->size == 0) {
        goto error;
    }

    if (Hash == NULL) {
        goto error;
    }

    /* setup the filter */
    //ht = (ngx_usr_hash_t*)malloc(sizeof(ngx_usr_hash_t));
    ht = (ngx_usr_hash_t*)ngx_pcalloc(uhinit->pool, sizeof(ngx_usr_hash_t));
    if ((ht == NULL))
        goto error;
    ht->array_size = uhinit->size;
    ht->Hash = Hash;

    if (Compare != NULL)
        ht->Compare = Compare;
    else
        ht->Compare = ngx_usr_hash_defaultcompare;

    /* setup the bitarray */
    ht->array = (ngx_usr_hash_bucket_t**)ngx_pcalloc(pool, ht->array_size * sizeof(ngx_usr_hash_bucket_t *));
    if (ht->array == NULL)
        goto error;

    return ht;

error:
    // 待确认是否需要在此处释放
    if (ht != NULL) {
        if (ht->array != NULL)
            free(ht->array);

        free(ht);
    }
    return NULL;
}

//void ngx_usr_hash_free(ngx_usr_hash_t *ht)
//{
//    uint32_t i = 0;
//
//    if (ht == NULL)
//        return;
//
//    /* free the buckets */
//    for (i = 0; i < ht->array_size; i++) {
//        ngx_usr_hash_bucket_t *hashbucket = ht->array[i];
//        while (hashbucket != NULL) {
//            ngx_usr_hash_bucket_t *next_hashbucket = hashbucket->next;
//            if (ht->Free != NULL)
//                ht->Free(hashbucket->data);
//            free(hashbucket);
//            hashbucket = next_hashbucket;
//        }
//    }
//
//    /* free the arrray */
//    if (ht->array != NULL)
//        free(ht->array);
//
//    free(ht);
//}

//void ngx_usr_hash_tPrint(ngx_usr_hash_t *ht)
//{
//    printf("\n----------- Hash Table Stats ------------\n");
//    printf("Buckets:               %" PRIu32 "\n", ht->array_size);
//    printf("Hash function pointer: %p\n", ht->Hash);
//    printf("-----------------------------------------\n");
//}

int ngx_usr_hash_add(ngx_usr_hash_init_t *uhinit, ngx_usr_hash_t *ht, void *data, uint16_t datalen)
{
    if (ht == NULL || data == NULL)
        return -1;

    uint32_t hash = ht->Hash(ht, data, datalen);

    ngx_usr_hash_bucket_t *hb = (ngx_usr_hash_bucket_t*)ngx_pcalloc(uhinit->pool, sizeof(ngx_usr_hash_bucket_t));
    if ((hb == NULL))
        goto error;
    hb->data = data;
    hb->size = datalen;
    hb->next = NULL;

    if (ht->array[hash] == NULL) {
        ht->array[hash] = hb;
    } else {
        hb->next = ht->array[hash];
        ht->array[hash] = hb;
    }

    return 0;

error:
    return -1;
}

int ngx_usr_hash_remove(ngx_usr_hash_t *ht, void *data, uint16_t datalen)
{
    uint32_t hash = ht->Hash(ht, data, datalen);

    if (ht->array[hash] == NULL) {
        return -1;
    }

    if (ht->array[hash]->next == NULL) {
        if (ht->Free != NULL)
            ht->Free(ht->array[hash]->data);
        free(ht->array[hash]);
        ht->array[hash] = NULL;
        return 0;
    }

    ngx_usr_hash_bucket_t *hashbucket = ht->array[hash], *prev_hashbucket = NULL;
    do {
        if (ht->Compare(hashbucket->data,hashbucket->size,data,datalen) == 1) {
            if (prev_hashbucket == NULL) {
                /* root bucket */
                ht->array[hash] = hashbucket->next;
            } else {
                /* child bucket */
                prev_hashbucket->next = hashbucket->next;
            }

            /* remove this */
            if (ht->Free != NULL)
                ht->Free(hashbucket->data);
            free(hashbucket);
            return 0;
        }

        prev_hashbucket = hashbucket;
        hashbucket = hashbucket->next;
    } while (hashbucket != NULL);

    return -1;
}

void *ngx_usr_hash_tLookup(ngx_usr_hash_t *ht, void *data, uint16_t datalen)
{
    uint32_t hash = 0;

    if (ht == NULL)
        return NULL;

    hash = ht->Hash(ht, data, datalen);

    if (ht->array[hash] == NULL)
        return NULL;

    ngx_usr_hash_bucket_t *hashbucket = ht->array[hash];
    do {
        if (ht->Compare(hashbucket->data, hashbucket->size, data, datalen) == 1)
            return hashbucket->data;

        hashbucket = hashbucket->next;
    } while (hashbucket != NULL);

    return NULL;
}

uint32_t ngx_usr_hash_tGenericHash(ngx_usr_hash_t *ht, void *data, uint16_t datalen)
{
     uint8_t *d = (uint8_t *)data;
     uint32_t i;
     uint32_t hash = 0;

     for (i = 0; i < datalen; i++) {
         if (i == 0)      hash += (((uint32_t)*d++));
         else if (i == 1) hash += (((uint32_t)*d++) * datalen);
         else             hash *= (((uint32_t)*d++) * i) + datalen + i;
     }

     hash *= datalen;
     hash %= ht->array_size;
     return hash;
}

char ngx_usr_hash_tDefaultCompare(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    if (len1 != len2)
        return 0;

    if (memcmp(data1,data2,len1) != 0)
        return 0;

    return 1;
}
