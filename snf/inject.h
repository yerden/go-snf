#ifndef _INJECT_H_
#define _INJECT_H_

#include <stdint.h>
#include <string.h>

#ifndef USE_MOCKUP
#include <snf.h>
#endif

static inline struct compound_int
snf_inject_send_bulk(snf_inject_t inj, int timeout_ms, int flags,
                     uintptr_t *pkts, uint32_t n_pkts, const uint32_t *lengths)
{
    struct compound_int x;
    memset(&x, 0, sizeof(x));
    int i;

    for (i = 0; i < n_pkts; i++)
    {
        x.rc = snf_inject_send(inj, timeout_ms, flags, (void *)pkts[i], lengths[i]);
        if (x.rc)
        {
            break;
        }
    }

    x.i[0] = i;
    return x;
}

#endif /* _INJECT_H_ */
