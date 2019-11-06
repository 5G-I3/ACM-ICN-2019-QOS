/*
 * Copyright (C) 2019 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include <stdio.h>

#include "tlsf-malloc.h"
#include "msg.h"
#include "shell.h"
#include "net/gnrc/netif.h"

#include "thread.h"
#include "xtimer.h"
#include "random.h"

#include "ccn-lite-riot.h"
#include "ccnl-pkt-builder.h"
#include "ccnl-callbacks.h"
#include "ccnl-producer.h"
#include "ccnl-qos.h"

#include "qos-config.h"

#define MAIN_QSZ (4)
static msg_t _main_q[MAIN_QSZ];

uint8_t hwaddr[GNRC_NETIF_L2ADDR_MAXLEN];
char hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];
bool i_am_root = false;

#ifndef CONSUMER_STACKSZ
#define CONSUMER_STACKSZ (THREAD_STACKSIZE_DEFAULT + THREAD_EXTRA_STACKSIZE_PRINTF)
#endif

char consumer_stack[CONSUMER_STACKSZ];

static uint32_t _tlsf_heap[TLSF_BUFFER / sizeof(uint32_t)];

static unsigned char int_buf[CCNL_MAX_PACKET_SIZE];
static unsigned char data_buf[CCNL_MAX_PACKET_SIZE];

uint64_t the_time = 0;
uint32_t num_ints = 0;
uint32_t num_datas = 0;
uint32_t num_gasints = 0;
uint32_t num_gasdatas = 0;
uint32_t num_pits_qos = 0;
uint32_t num_pits_noqos = 0;
uint32_t num_cs_qos = 0;
uint32_t num_cs_noqos = 0;

#define QOS_MAX_TC_ENTRIES (3)

#if defined (CONFIG1) || defined (CONFIG7) || defined(CONFIG14)
static const qos_traffic_class_t tcs_default[QOS_MAX_TC_ENTRIES] =
{
    { "/HK/", false, false },
    { "/HK/sensors", false, false },
    { "/HK/control", false, false },
};
#endif
#if defined(CONFIG3) || defined (CONFIG8) || defined (CONFIG9) || defined (CONFIG15) || defined (CONFIG19) || defined (CONFIG20)
static const qos_traffic_class_t tcs[QOS_MAX_TC_ENTRIES] =
{
    { "/HK/", false, false },
    { "/HK/sensors", false, false },
    { "/HK/control", true, true },
};
#endif
#if defined(CONFIG10) || defined(CONFIG11) || defined (CONFIG16) || defined(CONFIG18)
static const qos_traffic_class_t tcs[QOS_MAX_TC_ENTRIES] =
{
    { "/HK/", false, false },
    { "/HK/sensors", false, false },
    { "/HK/control", true, false },
};
#endif
#if defined(CONFIG5) || defined(CONFIG12) || defined(CONFIG13) || defined(CONFIG17)
static const qos_traffic_class_t tcs[QOS_MAX_TC_ENTRIES] =
{
    { "/HK/", false, false },
    { "/HK/sensors", false, false },
    { "/HK/control", false, true },
};
#endif
#if defined(CONFIG21) || defined(CONFIG22) || defined(CONFIG23) || defined(CONFIG24) || defined (CONFIG25) || defined (CONFIG26)
static const qos_traffic_class_t tcs[QOS_MAX_TC_ENTRIES] =
{
    { "/HK/", false, false },
    { "/HK/sensors", true, true },
    { "/HK/control", false, false },
};
#endif

static struct ccnl_face_s *_intern_face_get(char *addr_str)
{
    uint8_t relay_addr[GNRC_NETIF_L2ADDR_MAXLEN];
    memset(relay_addr, UINT8_MAX, GNRC_NETIF_L2ADDR_MAXLEN);
    size_t addr_len = gnrc_netif_addr_from_str(addr_str, relay_addr);

    if (addr_len == 0) {
        printf("Error: %s is not a valid link layer address\n", addr_str);
        return NULL;
    }

    sockunion sun;
    sun.sa.sa_family = AF_PACKET;
    memcpy(&(sun.linklayer.sll_addr), relay_addr, addr_len);
    sun.linklayer.sll_halen = addr_len;
    sun.linklayer.sll_protocol = htons(ETHERTYPE_NDN);

    return ccnl_get_face_or_create(&ccnl_relay, 0, &sun.sa, sizeof(sun.linklayer));
}

static void add_fib(char *pfx, char *addr)
{
    char *prefix_str[64];
    memset(prefix_str, 0, sizeof(prefix_str));
    memcpy(prefix_str, pfx, strlen(pfx));

    int suite = CCNL_SUITE_NDNTLV;
    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix((char *)prefix_str, suite, NULL);
    struct ccnl_face_s *fibface = _intern_face_get(addr);
    fibface->flags |= CCNL_FACE_FLAGS_STATIC;
    ccnl_fib_add_entry(&ccnl_relay, prefix, fibface);
}

static void setup_forwarding(char *my_addr) __attribute__((used));
static void setup_forwarding(char *my_addr)
{
    #include "fibs.in"

    return;
}

static int pit_strategy_qos(struct ccnl_relay_s *relay, struct ccnl_interest_s *i) __attribute__((used));
static int pit_strategy_qos(struct ccnl_relay_s *relay, struct ccnl_interest_s *i)
{
    qos_traffic_class_t *tc = i->tc;

    struct ccnl_interest_s *oldest = NULL;

    char s[CCNL_MAX_PREFIX_SIZE];

    // (Reg, Reg)
    if (!tc->expedited && !tc->reliable) {
        // Drop
    }
    // (Reg, Rel)
    else if (!tc->expedited && tc->reliable) {
        // Replace (Reg, Reg)
        struct ccnl_interest_s *cur = relay->pit;
        while (cur) {
            if (!cur->tc->expedited && !cur->tc->reliable) {
                if (!oldest || cur->last_used < oldest->last_used) {
                    oldest = cur;
                }
            }
            cur = cur->next;
        }

        if (oldest) {
            // Found a (Reg, Reg) entry to remove
            ccnl_prefix_to_str(oldest->pkt->pfx,s,CCNL_MAX_PREFIX_SIZE);
            if (strstr(s, "/HK/control") != NULL) {
                printf("eap;%lu;%s;%lu;%lu;%u;0\n", (unsigned long) xtimer_now_usec64(), &s[12], (unsigned long)num_ints, (unsigned long)num_datas, relay->pitcnt);
                printf("iadelq;%lu;%s;%u;%u;%lu;%lu;%lu;%lu\n", (unsigned long) xtimer_now_usec64(), &s[12], ccnl_relay.pitcnt, ccnl_relay.contentcnt, num_pits_qos, num_pits_noqos, num_cs_qos, num_cs_noqos);
                num_pits_qos--;
            } else {
                printf("esp;%lu;%s;%lu;%lu;%u;0\n", (unsigned long) xtimer_now_usec64(), &s[12], (unsigned long)num_ints, (unsigned long)num_datas, relay->pitcnt);
                printf("isdelq;%lu;%s;%u;%u;%lu;%lu;%lu;%lu\n", (unsigned long) xtimer_now_usec64(), &s[12], ccnl_relay.pitcnt, ccnl_relay.contentcnt, num_pits_qos, num_pits_noqos, num_cs_qos, num_cs_noqos);
                num_pits_noqos--;
            }
            ccnl_interest_remove(relay, oldest);

            return 1;
        }

        // No (Reg, Reg) entry to remove
    }
    // (Exp, _)
    else if (tc->expedited) {
        // Replace (Reg, _)
        struct ccnl_interest_s *cur = relay->pit, *oldest_unreliable = NULL, *oldest_reliable = NULL;
        while (cur) {
            if (!cur->tc->expedited) {
                if (!cur->tc->reliable) {
                    if (!oldest_unreliable || cur->last_used < oldest_unreliable->last_used) {
                        oldest_unreliable = cur;
                    }
                }
                else if (!oldest_reliable || cur->last_used < oldest_reliable->last_used) {
                    oldest_reliable = cur;
                }
            }
            cur = cur->next;
        }

        oldest = oldest_unreliable ? oldest_unreliable : oldest_reliable;

        if (oldest) {
            // Found a (Reg, _) entry to remove

            ccnl_prefix_to_str(oldest->pkt->pfx,s,CCNL_MAX_PREFIX_SIZE);
            if (strstr(s, "/HK/control") != NULL) {
                printf("eap;%lu;%s;%lu;%lu;%u;0\n", (unsigned long) xtimer_now_usec64(), &s[12], (unsigned long)num_ints, (unsigned long)num_datas, relay->pitcnt);
                printf("iadelq;%lu;%s;%u;%u;%lu;%lu;%lu;%lu\n", (unsigned long) xtimer_now_usec64(), &s[12], ccnl_relay.pitcnt, ccnl_relay.contentcnt, num_pits_qos, num_pits_noqos, num_cs_qos, num_cs_noqos);
                num_pits_qos--;
            } else {
                printf("esp;%lu;%s;%lu;%lu;%u;0\n", (unsigned long) xtimer_now_usec64(), &s[12], (unsigned long)num_ints, (unsigned long)num_datas, relay->pitcnt);
                printf("isdelq;%lu;%s;%u;%u;%lu;%lu;%lu;%lu\n", (unsigned long) xtimer_now_usec64(), &s[12], ccnl_relay.pitcnt, ccnl_relay.contentcnt, num_pits_qos, num_pits_noqos, num_cs_qos, num_cs_noqos);
                num_pits_noqos--;
            }
            ccnl_interest_remove(relay, oldest);

            return 1;
        }

        // No (Reg, _) entry to remove
    }


    ccnl_prefix_to_str(i->pkt->pfx,s,CCNL_MAX_PREFIX_SIZE);
    if (strstr(s, "/HK/control") != NULL) {
        printf("dap;%lu;%s;%lu;%lu;%u;0\n", (unsigned long) xtimer_now_usec64(), &s[12], (unsigned long)num_ints, (unsigned long)num_datas, relay->pitcnt);
    } else {
        printf("dsp;%lu;%s;%lu;%lu;%u;0\n", (unsigned long) xtimer_now_usec64(), &s[12], (unsigned long)num_ints, (unsigned long)num_datas, relay->pitcnt);
    }
    return 0;
}
static int pit_strategy_lru(struct ccnl_relay_s *relay, struct ccnl_interest_s *i) __attribute__((used));
static int pit_strategy_lru(struct ccnl_relay_s *relay, struct ccnl_interest_s *i)
{
    (void) i;
    struct ccnl_interest_s *oldest = NULL;
    struct ccnl_interest_s *cur = relay->pit;
    char s[CCNL_MAX_PREFIX_SIZE];

    while (cur) {
        if (!oldest || (cur->last_used < oldest->last_used)) {
            oldest = cur;
        }
        cur = cur->next;
    }

    if (oldest) {

        ccnl_prefix_to_str(oldest->pkt->pfx,s,CCNL_MAX_PREFIX_SIZE);
        if (strstr(s, "/HK/control") != NULL) {
            printf("eap;%lu;%s;%lu;%lu;%u;0\n", (unsigned long) xtimer_now_usec64(), &s[12], (unsigned long)num_ints, (unsigned long)num_datas, relay->pitcnt);
            num_pits_qos--;
            printf("iadelq;%lu;%s;%u;%u;%lu;%lu;%lu;%lu\n", (unsigned long) xtimer_now_usec64(), &s[12], ccnl_relay.pitcnt, ccnl_relay.contentcnt, num_pits_qos, num_pits_noqos, num_cs_qos, num_cs_noqos);
        } else {
            printf("esp;%lu;%s;%lu;%lu;%u;0\n", (unsigned long) xtimer_now_usec64(), &s[12], (unsigned long)num_ints, (unsigned long)num_datas, relay->pitcnt);
            num_pits_noqos--;
            printf("isdelq;%lu;%s;%u;%u;%lu;%lu;%lu;%lu\n", (unsigned long) xtimer_now_usec64(), &s[12], ccnl_relay.pitcnt, ccnl_relay.contentcnt, num_pits_qos, num_pits_noqos, num_cs_qos, num_cs_noqos);
        }
        ccnl_interest_remove(relay, oldest);
        return 1;
    }

    return 0;
}

static int pit_strategy_drop(struct ccnl_relay_s *relay, struct ccnl_interest_s *i) __attribute__((used));
static int pit_strategy_drop(struct ccnl_relay_s *relay, struct ccnl_interest_s *i)
{
    (void) i;
    (void) relay;

    char s[CCNL_MAX_PREFIX_SIZE];

    ccnl_prefix_to_str(i->pkt->pfx,s,CCNL_MAX_PREFIX_SIZE);

    if (strstr(s, "/HK/control") != NULL) {
        printf("dap;%lu;%s;%lu;%lu;%u;0\n", (unsigned long) xtimer_now_usec64(), &s[12], (unsigned long)num_ints, (unsigned long)num_datas, relay->pitcnt);
    } else {
        printf("dsp;%lu;%s;%lu;%lu;%u;0\n", (unsigned long) xtimer_now_usec64(), &s[12], (unsigned long)num_ints, (unsigned long)num_datas, relay->pitcnt);
    }

    return 0;
}

static uint32_t _count_fib_entries(void) {
    int num_fib_entries = 0;
    struct ccnl_forward_s *fwd;
    for (fwd = ccnl_relay.fib; fwd; fwd = fwd->next) {
        num_fib_entries++;
    }
    return num_fib_entries;
}

static void *consumer_event_loop(void *arg) __attribute((used));
static void *consumer_event_loop(void *arg)
{
    (void)arg;
    char req_uri[64];
    char s[CCNL_MAX_PREFIX_SIZE];
    struct ccnl_forward_s *fwd;
    int nodes_num = _count_fib_entries() - 1;
    uint32_t delay = 0;
    struct ccnl_prefix_s *prefix = NULL;

    printf("ss;%lu;%d\n", (unsigned long) xtimer_now_usec64(), nodes_num);

    for (unsigned i = 0; i < REQ_NUMS_VAL; i++) {
        uint32_t randfwd = random_uint32_range(0, 30);
        fwd = ccnl_relay.fib;
        while (randfwd--) {
            fwd = fwd->next;
        }
        memset(int_buf, 0, CCNL_MAX_PACKET_SIZE);
        ccnl_prefix_to_str(fwd->prefix,s,CCNL_MAX_PREFIX_SIZE);
        if (strstr(s, "/HK/sensors") == NULL) {
            continue;
        }
        delay = (uint32_t)((float)REQ_DELAY_VAL/(float)nodes_num);
        xtimer_usleep(delay);
        snprintf(req_uri, 64, "%s/%05lu", s, (unsigned long) i);
        prefix = ccnl_URItoPrefix(req_uri, CCNL_SUITE_NDNTLV, NULL);
        ccnl_send_interest(prefix, int_buf, CCNL_MAX_PACKET_SIZE, NULL, NULL);
        ccnl_prefix_free(prefix);
    }
    xtimer_sleep(10);
    printf("sd;%lu;%lu;%lu\n", (unsigned long) xtimer_now_usec64(), (unsigned long) num_ints, (unsigned long) num_datas);

    return 0;
}

static void *actuators_event_loop(void *arg) __attribute((used));
static void *actuators_event_loop(void *arg)
{
    (void)arg;
    char req_uri[64];
    struct ccnl_prefix_s *prefix = NULL;

    printf("as;%lu\n", (unsigned long) xtimer_now_usec64());

    for (unsigned i = 0; i < ACTUATOR_NUMS_VAL; i++) {
        xtimer_usleep(ACTUATOR_DELAY_VAL);
        memset(int_buf, 0, CCNL_MAX_PACKET_SIZE);
#if defined (CONFIG7) || defined (CONFIG8) || defined (CONFIG9) || defined(CONFIG10) || defined(CONFIG11) || defined(CONFIG12) || defined(CONFIG13) || defined(CONFIG14) || defined (CONFIG20) || defined (CONFIG23) || defined (CONFIG24) || defined (CONFIG25) || defined (CONFIG26)
        unsigned long group = random_uint32_range(0, 5);
        snprintf(req_uri, 64, "/%s/control/%lu/%04lu", ROOTPFX, (unsigned long) group, (unsigned long) i);
#else
        snprintf(req_uri, 64, "/%s/control/%s/%04lu", ROOTPFX, hwaddr_str, (unsigned long) i);
#endif
        prefix = ccnl_URItoPrefix(req_uri, CCNL_SUITE_NDNTLV, NULL);
        ccnl_send_interest(prefix, int_buf, CCNL_MAX_PACKET_SIZE, NULL, NULL);
        ccnl_prefix_free(prefix);
    }
    xtimer_sleep(10);
    printf("ad;%lu;%lu;%lu\n", (unsigned long) xtimer_now_usec64(), (unsigned long) num_ints, (unsigned long) num_datas);

    return 0;
}

static struct ccnl_content_s *produce_cont_and_cache(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt, int id)
{
    (void) pkt;
    (void) relay;
    char name[64];
    size_t offs = CCNL_MAX_PACKET_SIZE;

    char buffer[33];
    size_t len = sprintf(buffer, "%s", "{\"id\":\"0x12a77af232\",\"val\":3000}");
    buffer[len]='\0';

    int name_len = 0;

    name_len = sprintf(name, "/%s/sensors/%s/%05lu", ROOTPFX, hwaddr_str, (long unsigned) id);

    name[name_len]='\0';

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL);
    size_t reslen = 0;
    ccnl_ndntlv_prependContent(prefix, (unsigned char*) buffer, len, NULL, NULL, &offs, data_buf, &reslen);

    ccnl_prefix_free(prefix);

    unsigned char *olddata;
    unsigned char *data = olddata = data_buf + offs;

    uint64_t typ;

    if (ccnl_ndntlv_dehead(&data, &reslen, &typ, &len) || typ != NDN_TLV_Data) {
        puts("ERROR in producer_func");
        return 0;
    }

    struct ccnl_content_s *c = 0;
    struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &reslen);
    c = ccnl_content_new(&pk);
    return c;
}

struct ccnl_content_s *producer_func(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                                     struct ccnl_pkt_s *pkt) {
    (void) relay;
    (void) from;

    if(pkt->pfx->compcnt == 4) { /* /PREFIX/sensors/ID/<value> */
        if (!memcmp(pkt->pfx->comp[0], ROOTPFX, pkt->pfx->complen[0]) &&
            !memcmp(pkt->pfx->comp[1], "sensors", pkt->pfx->complen[1]) &&
            !memcmp(pkt->pfx->comp[2], hwaddr_str, pkt->pfx->complen[2])) {
            return produce_cont_and_cache(relay, pkt, atoi((const char *)pkt->pfx->comp[3]));
        }
    }

    return NULL;
}

static struct ccnl_content_s *actuator_produce_cont_and_cache(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt)
{
    (void) pkt;
    (void) relay;
    size_t offs = CCNL_MAX_PACKET_SIZE;

    char buffer[33];
    size_t len = sprintf(buffer, "%s", "{\"id\":\"0x12a77af232\",\"val\":\"on\"}");
    buffer[len]='\0';

    size_t reslen = 0;
    ccnl_ndntlv_prependContent(pkt->pfx, (unsigned char*) buffer, len, NULL, NULL, &offs, data_buf, &reslen);

    unsigned char *olddata;
    unsigned char *data = olddata = data_buf + offs;

    uint64_t typ;

    if (ccnl_ndntlv_dehead(&data, &reslen, &typ, &len) || typ != NDN_TLV_Data) {
        puts("ERROR in producer_func");
        return 0;
    }

    struct ccnl_content_s *c = 0;
    struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &reslen);
    c = ccnl_content_new(&pk);
    return c;
}

struct ccnl_content_s *actuator_producer_func(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                                              struct ccnl_pkt_s *pkt) {
    (void) relay;
    (void) from;

    if(pkt->pfx->compcnt == 4) { /* /PREFIX/control/hwaddr/<value> */
        if (!memcmp(pkt->pfx->comp[0], ROOTPFX, pkt->pfx->complen[0]) &&
            !memcmp(pkt->pfx->comp[1], "control", pkt->pfx->complen[1])) {
            return actuator_produce_cont_and_cache(relay, pkt);
        }
    }
    return NULL;
}

int cache_decision_solicited_always(struct ccnl_relay_s *relay, struct ccnl_content_s *c, int pit_pending) __attribute((used));
int cache_decision_solicited_always(struct ccnl_relay_s *relay, struct ccnl_content_s *c, int pit_pending)
{
    (void) c;
    (void) relay;
    (void) pit_pending;

    char s[CCNL_MAX_PREFIX_SIZE];

    if (pit_pending) {
        ccnl_prefix_to_str(c->pkt->pfx,s,CCNL_MAX_PREFIX_SIZE);

        if (strstr(s, "/HK/control") != NULL) {
            printf("cduap;%lu;%s\n", (unsigned long) xtimer_now_usec64(), &s[12]);
        } else {
            printf("cdusp;%lu;%s\n", (unsigned long) xtimer_now_usec64(), &s[12]);
        }

        return 1;
    }

    return 0;
}

int cache_decision_solicited_always_for_reliable(struct ccnl_relay_s *relay, struct ccnl_content_s *c, int pit_pending) __attribute((used));
int cache_decision_solicited_always_for_reliable(struct ccnl_relay_s *relay, struct ccnl_content_s *c, int pit_pending)
{
    (void) relay;
    char s[CCNL_MAX_PREFIX_SIZE];

    if (pit_pending || c->tclass->reliable) {
        ccnl_prefix_to_str(c->pkt->pfx,s,CCNL_MAX_PREFIX_SIZE);

        if (strstr(s, "/HK/control") != NULL) {
            printf("cdurap;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
        } else {
            printf("cdursp;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
        }
        return 1;
    }
    return 0;
}

int cache_decision_probabilistic(struct ccnl_relay_s *relay, struct ccnl_content_s *c, int pit_pending) __attribute((used));
int cache_decision_probabilistic(struct ccnl_relay_s *relay, struct ccnl_content_s *c, int pit_pending)
{
    (void) c;
    (void) relay;
    (void) pit_pending;

    char s[CCNL_MAX_PREFIX_SIZE];
    ccnl_prefix_to_str(c->pkt->pfx,s,CCNL_MAX_PREFIX_SIZE);

    if (strstr(s, hwaddr_str) != NULL) {
        return 0;
    }

    if (!pit_pending && !c->tclass->reliable) {

        if (strstr(s, "/HK/control") != NULL) {
            printf("cduap;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
        } else {
            printf("cdusp;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
        }
        return 0;
    }

    if (relay->contentcnt < relay->max_cache_entries) {
        return 1;
    }

    uint32_t p = random_uint32_range(0, 100);

    if (c->tclass->reliable) {
        if (p >= 30) {
            if (strstr(s, "/HK/control") != NULL) {
                printf("craap;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
            } else {
                printf("crasp;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
            }
            return 1;
        }

        if (strstr(s, "/HK/control") != NULL) {
            printf("cirap;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
        } else {
            printf("cirsp;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
        }
        return 0;
    }

    if (p < 30) {
        if (strstr(s, "/HK/control") != NULL) {
            printf("cuaap;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
        } else {
            printf("cuasp;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
        }
        return 1;
    }

    if (strstr(s, "/HK/control") != NULL) {
        printf("ciuap;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
    } else {
        printf("ciusp;%lu;%s;%u\n", (unsigned long) xtimer_now_usec64(), &s[12], c->tclass->reliable);
    }
    return 0;
}

int cache_remove_lru(struct ccnl_relay_s *relay, struct ccnl_content_s *c) __attribute((used));
int cache_remove_lru(struct ccnl_relay_s *relay, struct ccnl_content_s *c)
{
    (void) c;
    char s[CCNL_MAX_PREFIX_SIZE];
    char s2[CCNL_MAX_PREFIX_SIZE];
    struct ccnl_content_s *cur, *oldest = NULL;

    for (cur = relay->contents; cur; cur = cur->next) {
        if (!oldest || cur->last_used < oldest->last_used) {
            oldest = cur;
        }
    }
    if (oldest) {
        ccnl_prefix_to_str(oldest->pkt->pfx,s,CCNL_MAX_PREFIX_SIZE);
        ccnl_prefix_to_str(c->pkt->pfx,s2,CCNL_MAX_PREFIX_SIZE);

        if (strstr(s, "/HK/control") != NULL) {
            printf("cdap;%lu;%s;%s\n", (unsigned long) xtimer_now_usec64(), &s[12], &s2[12]);
        } else {
            printf("cdsp;%lu;%s;%s\n", (unsigned long) xtimer_now_usec64(), &s[12], &s2[12]);
        }
        ccnl_content_remove(relay, oldest);
        return 1;
    }
    return 0;
}
int cache_remove_lru_qos(struct ccnl_relay_s *relay, struct ccnl_content_s *c) __attribute((used));
int cache_remove_lru_qos(struct ccnl_relay_s *relay, struct ccnl_content_s *c)
{
    qos_traffic_class_t *tc = c->tclass;

    char s[CCNL_MAX_PREFIX_SIZE];
    char s2[CCNL_MAX_PREFIX_SIZE];
    struct ccnl_content_s *cur, *oldest = NULL, *oldest_reliable = NULL, *oldest_unreliable = NULL;

    for (cur = relay->contents; cur; cur = cur->next) {
        if (!cur->tclass->reliable) {
            if (!oldest_unreliable || cur->last_used < oldest_unreliable->last_used) {
                oldest_unreliable = cur;
            }
        }
        else {
            if (!oldest_reliable || cur->last_used < oldest_reliable->last_used) {
                oldest_reliable = cur;
            }
        }
    }

    if (tc->reliable) {
        oldest = oldest_unreliable ? oldest_unreliable : oldest_reliable;
    }
    else {
        oldest = oldest_unreliable;
    }

    if (oldest) {
        ccnl_prefix_to_str(oldest->pkt->pfx,s,CCNL_MAX_PREFIX_SIZE);
        ccnl_prefix_to_str(c->pkt->pfx,s2,CCNL_MAX_PREFIX_SIZE);

        if (strstr(s, "/HK/control") != NULL) {
            printf("cdap;%lu;%s;%s\n", (unsigned long) xtimer_now_usec64(), &s[12], &s2[12]);
        } else {
            printf("cdsp;%lu;%s;%s\n", (unsigned long) xtimer_now_usec64(), &s[12], &s2[12]);
        }
        ccnl_content_remove(relay, oldest);
        return 1;
    }

    return 0;
}

int cache_remove_random(struct ccnl_relay_s *relay, struct ccnl_content_s *c) __attribute((used));
int cache_remove_random(struct ccnl_relay_s *relay, struct ccnl_content_s *c)
{
    (void) c;
    char s[CCNL_MAX_PREFIX_SIZE];
    char s2[CCNL_MAX_PREFIX_SIZE];
    struct ccnl_content_s *cur = relay->contents, *rmc = relay->contents;
    uint32_t random = random_uint32_range(0, relay->contentcnt);

    for (unsigned i = 0; i < random; i++) {
        cur = cur->next;
        rmc = cur;
    }

    if (rmc) {
        ccnl_prefix_to_str(rmc->pkt->pfx,s,CCNL_MAX_PREFIX_SIZE);
        ccnl_prefix_to_str(c->pkt->pfx,s2,CCNL_MAX_PREFIX_SIZE);

        if (strstr(s, "/HK/control") != NULL) {
            printf("cdap;%lu;%s;%s\n", (unsigned long) xtimer_now_usec64(), &s[12], &s2[12]);
        } else {
            printf("cdsp;%lu;%s;%s\n", (unsigned long) xtimer_now_usec64(), &s[12], &s2[12]);
        }
        ccnl_content_remove(relay, rmc);
        return 1;
    }
    return 0;
}

int main(void)
{
    tlsf_add_global_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_q, MAIN_QSZ);

    ccnl_core_init();

    ccnl_start();

    gnrc_netif_t *ccn_netif;

    if (((ccn_netif = gnrc_netif_iter(NULL)) == NULL) ||
        (ccnl_open_netif(ccn_netif->pid, GNRC_NETTYPE_CCN) < 0)) {
        return -1;
    }

    uint16_t chan = 15;
    gnrc_netapi_set(ccn_netif->pid, NETOPT_CHANNEL, 0, &chan, sizeof(chan));

    uint16_t src_len = 8U;
    gnrc_netapi_set(ccn_netif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));
#ifdef BOARD_NATIVE
    gnrc_netapi_get(ccn_netif->pid, NETOPT_ADDRESS, 0, hwaddr, sizeof(hwaddr));
#else
    gnrc_netapi_get(ccn_netif->pid, NETOPT_ADDRESS_LONG, 0, hwaddr, sizeof(hwaddr));
#endif
    gnrc_netif_addr_to_str(hwaddr, sizeof(hwaddr), hwaddr_str);

#if defined (CONFIG1) || defined (CONFIG2) || defined (CONFIG7) || defined(CONFIG14)
    qos_traffic_class_t *cur_tc = (qos_traffic_class_t *) tcs_default;
#elif defined (CONFIG3) || defined(CONFIG4) || defined(CONFIG5) || defined(CONFIG8) || defined (CONFIG9) || defined(CONFIG10) || defined (CONFIG11) || defined(CONFIG12) || defined(CONFIG13) || defined (CONFIG15) || defined(CONFIG16) || defined(CONFIG17) || defined(CONFIG18) || defined (CONFIG19) || defined (CONFIG20) || defined (CONFIG21) || defined (CONFIG22) || defined (CONFIG23) || defined (CONFIG24) || defined (CONFIG25) || defined (CONFIG26)
    qos_traffic_class_t *cur_tc = (qos_traffic_class_t *) tcs;
#endif

    ccnl_qos_set_tcs(cur_tc, QOS_MAX_TC_ENTRIES);

#if defined (CONFIG1) || defined (CONFIG7)
    ccnl_set_pit_strategy_remove(pit_strategy_drop);
    ccnl_set_cache_strategy_cache(cache_decision_solicited_always);
    ccnl_set_cache_strategy_remove(cache_remove_lru);
#elif defined(CONFIG13)
    ccnl_set_pit_strategy_remove(pit_strategy_qos);
    ccnl_set_cache_strategy_cache(cache_decision_probabilistic);
    ccnl_set_cache_strategy_remove(cache_remove_lru_qos);
#elif defined(CONFIG14)
    ccnl_set_pit_strategy_remove(pit_strategy_drop);
    ccnl_set_cache_strategy_cache(cache_decision_probabilistic);
    ccnl_set_cache_strategy_remove(cache_remove_lru);
#elif defined (CONFIG2)
    ccnl_set_pit_strategy_remove(pit_strategy_lru);
    ccnl_set_cache_strategy_cache(cache_decision_solicited_always);
    ccnl_set_cache_strategy_remove(cache_remove_lru);
#elif defined (CONFIG3) || defined (CONFIG4) || defined (CONFIG5) || defined (CONFIG8) || defined (CONFIG11) || defined (CONFIG12) || defined (CONFIG17) || defined (CONFIG18) || defined (CONFIG21) || defined (CONFIG23)
    ccnl_set_pit_strategy_remove(pit_strategy_qos);
    ccnl_set_cache_strategy_cache(cache_decision_solicited_always_for_reliable);
    ccnl_set_cache_strategy_remove(cache_remove_lru_qos);
#elif defined (CONFIG9) || defined (CONFIG10) || defined (CONFIG16)
    ccnl_set_pit_strategy_remove(pit_strategy_qos);
    ccnl_set_cache_strategy_cache(cache_decision_probabilistic);
    ccnl_set_cache_strategy_remove(cache_remove_lru);
#elif defined (CONFIG15)
    ccnl_set_pit_strategy_remove(pit_strategy_qos);
    ccnl_set_cache_strategy_cache(cache_decision_probabilistic);
    ccnl_set_cache_strategy_remove(cache_remove_lru_qos);
#elif defined(CONFIG25)
    ccnl_set_pit_strategy_remove(pit_strategy_qos);
    ccnl_set_cache_strategy_cache(cache_decision_probabilistic);
    ccnl_set_cache_strategy_remove(cache_remove_lru);
#endif

    xtimer_sleep(30);

    printf("config;%s;%d;%d\n", hwaddr_str, ccnl_relay.max_pit_entries, ccnl_relay.max_cache_entries);
    unsigned i = 0;
    for (i = 0; i < QOS_MAX_TC_ENTRIES; i++) {
        printf("qos;%s;%u;%u\n", cur_tc[i].traffic_class, cur_tc[i].expedited, cur_tc[i].reliable);
    }

    setup_forwarding(hwaddr_str);

    if (i_am_root) {
        ccnl_relay.max_pit_entries = 50;
        ccnl_set_local_producer(actuator_producer_func);
        xtimer_sleep(5);
        memset(consumer_stack, 0, CONSUMER_STACKSZ);
        thread_create(consumer_stack, sizeof(consumer_stack),
                      CONSUMER_THREAD_PRIORITY, THREAD_CREATE_STACKTEST,
                      consumer_event_loop, NULL, "consumer");
    }
    else {
        ccnl_set_local_producer(producer_func);
        xtimer_sleep(5);
        memset(consumer_stack, 0, CONSUMER_STACKSZ);
        thread_create(consumer_stack, sizeof(consumer_stack),
                      CONSUMER_THREAD_PRIORITY, THREAD_CREATE_STACKTEST,
                      actuators_event_loop, NULL, "consumer");
    }

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
