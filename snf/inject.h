#ifndef _INJECT_H_
#define _INJECT_H_

#include <stdint.h>

#ifndef USE_MOCKUP
#include <snf.h>
#endif

static inline int
snf_inject_send_bulk(snf_inject_t inj, int timeout_ms, int flags,
                     const uint8_t *pkts, uint32_t n_pkts, const uint32_t *lengths)
{
    uint32_t offset = 0;
    int rc;

    for (size_t i = 0; i < n_pkts; i++)
    {
        rc = snf_inject_send(inj, timeout_ms, flags, &pkts[offset], lengths[i]);
        if (rc)
        {
            return rc;
        }

        offset = lengths[i];
    }

    return 0;
}

#endif /* _INJECT_H_ */
