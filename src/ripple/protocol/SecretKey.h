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

#ifndef RIPPLE_PROTOCOL_SECRETKEY_H_INCLUDED
#define RIPPLE_PROTOCOL_SECRETKEY_H_INCLUDED

#include <ripple/basics/Buffer.h>
#include <ripple/basics/Slice.h>
#include <ripple/protocol/PublicKey.h>
#include <ripple/protocol/Seed.h>
#include <ripple/protocol/tokens.h>
#include <array>
#include <string>

namespace ripple {

/** A secret key. */
class SecretKey
{
private:
    std::uint8_t buf_[32];

public:
    using const_iterator = std::uint8_t const*;

    SecretKey() = default;
    SecretKey (SecretKey const&) = default;
    SecretKey& operator= (SecretKey const&) = default;

    ~SecretKey();

    SecretKey (std::array<std::uint8_t, 32> const& data);
    SecretKey (Slice const& slice);

    std::uint8_t const*
    data() const
    {
        return buf_;
    }

    std::size_t
    size() const
    {
        return sizeof(buf_);
    }

    /** Convert the secret key to a hexadecimal string.

        @note The operator<< function is deliberately omitted
        to avoid accidental exposure of secret key material.
    */
    std::string
    to_string() const;

    const_iterator
    begin() const noexcept
    {
        return buf_;
    }

    const_iterator
    cbegin() const noexcept
    {
        return buf_;
    }

    const_iterator
    end() const noexcept
    {
        return buf_ + sizeof(buf_);
    }

    const_iterator
    cend() const noexcept
    {
        return buf_ + sizeof(buf_);
    }
};

inline
bool
operator== (SecretKey const& lhs,
    SecretKey const& rhs)
{
    return lhs.size() == rhs.size() &&
        std::memcmp(lhs.data(),
            rhs.data(), rhs.size()) == 0;
}

inline
bool
operator!= (SecretKey const& lhs,
    SecretKey const& rhs)
{
    return ! (lhs == rhs);
}

//------------------------------------------------------------------------------

/** Parse a secret key */
template <>
boost::optional<SecretKey>
parseBase58 (TokenType type, std::string const& s);


template<>
boost::optional<SecretKey>
parseHex (std::string const& str);

inline
std::string
toBase58 (TokenType type, SecretKey const& sk)
{
    return base58EncodeToken(
        type, sk.data(), sk.size());
}

inline
std::string
toWIF(SecretKey const& sk)
{
    std::vector<uint8_t> k;
    k.assign(sk.data(), sk.data() + sk.size());
    k.push_back(1);
    return base58EncodeToken(
        TokenType::AccountWif, k.data(), k.size());
}

/** Create a secret key using secure random numbers. */
SecretKey
randomSecretKey();

/** Generate a new secret key deterministically. */
SecretKey
generateSecretKey (Seed const& seed);

/** Derive the public key from a secret key. */
PublicKey
derivePublicKey (SecretKey const& sk);

/** Generate a key pair deterministically.

    This algorithm is specific to Ripple:

    For secp256k1 key pairs, the seed is converted
    to a Generator and used to compute the key pair
    corresponding to ordinal 0 for the generator.
*/
std::pair<PublicKey, SecretKey>
generateKeyPair (Seed const& seed, bool fCompat);

/** Create a key pair using secure random numbers. */
std::pair<PublicKey, SecretKey>
randomKeyPair ();

/** Generate a signature for a message digest.
*/
/** @{ */
Buffer
signDigest (PublicKey const& pk, SecretKey const& sk,
    uint256 const& digest);

inline
Buffer
signDigest (SecretKey const& sk, uint256 const& digest)
{
    return signDigest (derivePublicKey(sk), sk, digest);
}
/** @} */

/** Generate a signature for a message.
    With secp256k1 signatures, the data is first hashed with
    SHA512-Half, and the resulting digest is signed.
*/
/** @{ */
Buffer
sign (PublicKey const& pk,
    SecretKey const& sk, Slice const& message);

inline
Buffer
sign (SecretKey const& sk, Slice const& message)
{
    return sign (derivePublicKey(sk), sk, message);
}
/** @} */

} // ripple

#endif
