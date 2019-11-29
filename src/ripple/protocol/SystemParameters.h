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

#ifndef RIPPLE_PROTOCOL_SYSTEMPARAMETERS_H_INCLUDED
#define RIPPLE_PROTOCOL_SYSTEMPARAMETERS_H_INCLUDED

#include <cstdint>
#include <string>

namespace ripple {

// Various protocol and system specific constant globals.

/* The name of the system. */
static inline
std::string const&
systemName ()
{
    static std::string const name = "WRT";
    return name;
}

/** Initial 10000000000 WRTs for the genesis ledger. */

/** Configure the native currency. */
static
std::int64_t const
SYSTEM_CURRENCY_COINS = 10000000000;

/** Number of drops per 1 WRT */
static
std::int64_t const
SYSTEM_CURRENCY_PARTS = 1000000;

/** Number of drops in the genesis account. */
static
std::int64_t const
SYSTEM_CURRENCY_START = SYSTEM_CURRENCY_COINS * SYSTEM_CURRENCY_PARTS;

/* The currency code for the native currency. */
static inline
std::string const&
systemCurrencyCode ()
{
    static std::string const code = "WRT";
    return code;
}

/** The WRT ledger network's earliest allowed sequence */
static
std::uint32_t constexpr
XRP_LEDGER_EARLIEST_SEQ {1};

} // ripple

#endif
