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

#include <ripple/app/misc/LoadFeeTrack.h>
#include <ripple/basics/contract.h>
#include <ripple/basics/Log.h>
#include <ripple/basics/safe_cast.h>
#include <ripple/core/Config.h>
#include <ripple/ledger/ReadView.h>
#include <ripple/protocol/jss.h>
#include <ripple/protocol/STAmount.h>

#include <cstdint>
#include <numeric>
#include <type_traits>

namespace ripple {

bool
LoadFeeTrack::raiseLocalFee ()
{
    std::lock_guard sl (lock_);

    if (++raiseCount_ < 2)
        return false;

    std::uint32_t origFee = localTxnLoadFee_;

    // make sure this fee takes effect
    if (localTxnLoadFee_ < remoteTxnLoadFee_)
        localTxnLoadFee_ = remoteTxnLoadFee_;

    // Increase slowly
    localTxnLoadFee_ += (localTxnLoadFee_ / lftFeeIncFraction);

    if (localTxnLoadFee_ > lftFeeMax)
        localTxnLoadFee_ = lftFeeMax;

    if (origFee == localTxnLoadFee_)
        return false;

    JLOG(j_.debug()) << "Local load fee raised from " <<
        origFee << " to " << localTxnLoadFee_;
    return true;
}

bool
LoadFeeTrack::lowerLocalFee ()
{
    std::lock_guard sl (lock_);
    std::uint32_t origFee = localTxnLoadFee_;
    raiseCount_ = 0;

    // Reduce slowly
    localTxnLoadFee_ -= (localTxnLoadFee_ / lftFeeDecFraction );

    if (localTxnLoadFee_ < lftNormalFee)
        localTxnLoadFee_ = lftNormalFee;

    if (origFee == localTxnLoadFee_)
        return false;

    JLOG(j_.debug()) << "Local load fee lowered from " <<
        origFee << " to " << localTxnLoadFee_;
    return true;
}

//------------------------------------------------------------------------------

template <class T1, class T2,
    class = std::enable_if_t<
        std::is_integral_v<T1> &&
        std::is_integral_v<T2>>
>
void lowestTerms(T1& a,  T2& b)
{
    if (auto const gcd = std::gcd(a, b))
    {
        a /= gcd;
        b /= gcd;
    }
}

// Scale using load as well as base rate
std::uint64_t
scaleFeeLoad(std::uint64_t fee, LoadFeeTrack const& feeTrack,
    Fees const& fees, bool bUnlimited)
{
    if (fee == 0)
        return fee;

    // Collect the fee rates
    auto [feeFactor, uRemFee] = feeTrack.getScalingFactors();

    // Let privileged users pay the normal fee until
    //   the local load exceeds four times the remote.
    if (bUnlimited && (feeFactor > uRemFee) && (feeFactor < (4 * uRemFee)))
        feeFactor = uRemFee;

    auto baseFee = fees.base;
    // Compute:
    // fee = fee * baseFee * feeFactor / (fees.units * lftNormalFee);
    // without overflow, and as accurately as possible

    // The denominator of the fraction we're trying to compute.
    // fees.units and lftNormalFee are both 32 bit,
    //  so the multiplication can't overflow.
    auto den = safe_cast<std::uint64_t>(fees.units)
        * safe_cast<std::uint64_t>(feeTrack.getLoadBase());
    // Reduce fee * baseFee * feeFactor / (fees.units * lftNormalFee)
    // to lowest terms.
    lowestTerms(fee, den);
    lowestTerms(baseFee, den);
    lowestTerms(feeFactor, den);

    // fee and baseFee are 64 bit, feeFactor is 32 bit
    // Order fee and baseFee largest first
    if (fee < baseFee)
        std::swap(fee, baseFee);
    // If baseFee * feeFactor overflows, the final result will overflow
    const auto max = std::numeric_limits<std::uint64_t>::max();
    if (baseFee > max / feeFactor)
        Throw<std::overflow_error> ("scaleFeeLoad");
    baseFee *= feeFactor;
    // Reorder fee and baseFee
    if (fee < baseFee)
        std::swap(fee, baseFee);
    // If fee * baseFee / den might overflow...
    if (fee > max / baseFee)
    {
        // Do the division first, on the larger of fee and baseFee
        fee /= den;
        if (fee > max / baseFee)
            Throw<std::overflow_error> ("scaleFeeLoad");
        fee *= baseFee;
    }
    else
    {
        // Otherwise fee * baseFee won't overflow,
        //   so do it prior to the division.
        fee *= baseFee;
        fee /= den;
    }
    return fee;
}

} // ripple
