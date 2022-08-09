#ifndef _INJECT_H_
#define _INJECT_H_

#include <stdint.h>

#ifndef USE_MOCKUP
#include <snf.h>
#endif

static inline int
snf_inject_send_bulk(snf_inject_t inj, int timeout_ms, int flags,
                     uintptr_t *pkts, uint32_t n_pkts, const uint32_t *lengths)
{
    int rc;

    for (size_t i = 0; i < n_pkts; i++)
    {
        rc = snf_inject_send(inj, timeout_ms, flags, (void *)pkts[i], lengths[i]);
        if (rc)
        {
            return rc;
        }
    }

    return 0;
}

#endif /* _INJECT_H_ */
