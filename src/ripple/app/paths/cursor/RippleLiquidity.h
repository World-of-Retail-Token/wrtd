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

#ifndef RIPPLE_APP_PATHS_CURSOR_RIPPLELIQUIDITY_H_INCLUDED
#define RIPPLE_APP_PATHS_CURSOR_RIPPLELIQUIDITY_H_INCLUDED

#include <ripple/app/paths/cursor/PathCursor.h>
#include <ripple/app/paths/RippleCalc.h>
#include <ripple/app/paths/Tuning.h>
#include <ripple/ledger/View.h>
#include <ripple/protocol/Rate.h>

namespace ripple {
namespace path {

void rippleLiquidity (
    RippleCalc&,
    Rate const& qualityIn,
    Rate const& qualityOut,
    STAmount const& saPrvReq,
    STAmount const& saCurReq,
    STAmount& saPrvAct,
    STAmount& saCurAct,
    std::uint64_t& uRateMax);

Rate
quality_in (
    ReadView const& view,
    AccountID const& uToAccountID,
    AccountID const& uFromAccountID,
    Currency const& currency);

Rate
quality_out (
    ReadView const& view,
    AccountID const& uToAccountID,
    AccountID const& uFromAccountID,
    Currency const& currency);

} // path
} // ripple

#endif
