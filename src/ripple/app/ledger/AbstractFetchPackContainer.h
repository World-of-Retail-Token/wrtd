//------------------------------------------------------------------------------
/*
    This file is part of wrtd: https://github.com/World-of-Retail-Token/wrtd
    Copyright (c) 2019 Ripple Labs Inc.
    Copyright (c) 2019 WORLD OF RETAIL SERVICES LIMITED.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#ifndef RIPPLE_APP_LEDGER_ABSTRACTFETCHPACKCONTAINER_H_INCLUDED
#define RIPPLE_APP_LEDGER_ABSTRACTFETCHPACKCONTAINER_H_INCLUDED

#include <ripple/basics/base_uint.h>
#include <ripple/basics/Blob.h>
#include <boost/optional.hpp>

namespace ripple {

/** An interface facilitating retrieval of fetch packs without
    an application or ledgermaster object.
*/
class AbstractFetchPackContainer
{
public:
    virtual ~AbstractFetchPackContainer() = default;

    /** Retrieves partial ledger data of the coresponding hash from peers.`

        @param nodeHash The 256-bit hash of the data to fetch.
        @return `boost::none` if the hash isn't cached,
            otherwise, the hash associated data.
    */
    virtual boost::optional<Blob> getFetchPack(uint256 const& nodeHash) = 0;
};

} // ripple

#endif
