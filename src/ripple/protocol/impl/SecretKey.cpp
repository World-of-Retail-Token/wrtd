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

#include <ripple/basics/strHex.h>
#include <ripple/protocol/SecretKey.h>
#include <ripple/protocol/digest.h>
#include <ripple/protocol/impl/secp256k1.h>
#include <ripple/basics/contract.h>
#include <ripple/crypto/GenerateDeterministicKey.h>
#include <ripple/crypto/csprng.h>
#include <ripple/beast/crypto/secure_erase.h>
#include <ripple/beast/utility/rngfill.h>
#include <cstring>

namespace ripple {

SecretKey::~SecretKey()
{
    beast::secure_erase(buf_, sizeof(buf_));
}

SecretKey::SecretKey (std::array<std::uint8_t, 32> const& key)
{
    std::memcpy(buf_, key.data(), key.size());
}

SecretKey::SecretKey (Slice const& slice)
{
    if (slice.size() != sizeof(buf_))
        LogicError("SecretKey::SecretKey: invalid size");
    std::memcpy(buf_, slice.data(), sizeof(buf_));
}

std::string
SecretKey::to_string() const
{
    return strHex(*this);
}

//------------------------------------------------------------------------------
/** Produces a sequence of secp256k1 key pairs. */
class Generator
{
private:
    Blob gen_; // VFALCO compile time size?

public:
    explicit
    Generator (Seed const& seed)
    {
        // FIXME: Avoid copying the seed into a uint128 key only to have
        //        generateRootDeterministicPublicKey copy out of it.
        uint128 ui;
        std::memcpy(ui.data(),
            seed.data(), seed.size());
        gen_ = generateRootDeterministicPublicKey(ui);
    }

    /** Generate the nth key pair.

        The seed is required to produce the private key.
    */
    std::pair<PublicKey, SecretKey>
    operator()(Seed const& seed, std::size_t ordinal) const
    {
        // FIXME: Avoid copying the seed into a uint128 key only to have
        //        generatePrivateDeterministicKey copy out of it.
        uint128 ui;
        std::memcpy(ui.data(), seed.data(), seed.size());
        auto gsk = generatePrivateDeterministicKey(gen_, ui, ordinal);
        auto gpk = generatePublicDeterministicKey(gen_, ordinal);
        SecretKey const sk(Slice{ gsk.data(), gsk.size() });
        PublicKey const pk(Slice{ gpk.data(), gpk.size() });
        beast::secure_erase(ui.data(), ui.size());
        beast::secure_erase(gsk.data(), gsk.size());
        return {pk, sk};
    }
};

//------------------------------------------------------------------------------

Buffer
signDigest (PublicKey const& pk, SecretKey const& sk,
    uint256 const& digest)
{
    if (!isPublicKey(pk.slice()))
        LogicError("sign: secp256k1 public key required for digest signing");

    BOOST_ASSERT(sk.size() == 32);
    secp256k1_ecdsa_signature sig_imp;
    if(secp256k1_ecdsa_sign(
            secp256k1Context(),
            &sig_imp,
            reinterpret_cast<unsigned char const*>(
                digest.data()),
            reinterpret_cast<unsigned char const*>(
                sk.data()),
            secp256k1_nonce_function_rfc6979,
            nullptr) != 1)
        LogicError("sign: secp256k1_ecdsa_sign failed");

    unsigned char sig[72];
    size_t len = sizeof(sig);
    if(secp256k1_ecdsa_signature_serialize_der(
            secp256k1Context(),
            sig,
            &len,
            &sig_imp) != 1)
        LogicError("sign: secp256k1_ecdsa_signature_serialize_der failed");

    return Buffer{sig, len};
}

Buffer
sign (PublicKey const& pk,
    SecretKey const& sk, Slice const& m)
{
    if (!isPublicKey(pk.slice()))
        LogicError("sign: invalid type");
    sha512_half_hasher h;
    h(m.data(), m.size());
    auto const digest = sha512_half_hasher::result_type(h);

    secp256k1_ecdsa_signature sig_imp;
    if (secp256k1_ecdsa_sign(
            secp256k1Context(),
            &sig_imp,
            reinterpret_cast<unsigned char const*>(digest.data()),
            reinterpret_cast<unsigned char const*>(sk.data()),
            secp256k1_nonce_function_rfc6979,
            nullptr) != 1)
        LogicError("sign: secp256k1_ecdsa_sign failed");

    unsigned char sig[72];
    size_t len = sizeof(sig);
    if (secp256k1_ecdsa_signature_serialize_der(
            secp256k1Context(), sig, &len, &sig_imp) != 1)
        LogicError("sign: secp256k1_ecdsa_signature_serialize_der failed");

    return Buffer{sig, len};
}

SecretKey
randomSecretKey()
{
    std::uint8_t buf[32];
    beast::rngfill(
        buf,
        sizeof(buf),
        crypto_prng());
    SecretKey sk(Slice{ buf, sizeof(buf) });
    beast::secure_erase(buf, sizeof(buf));
    return sk;
}

// VFALCO TODO Rewrite all this without using OpenSSL
//             or calling into GenerateDetermisticKey
SecretKey
generateSecretKey (Seed const& seed)
{
    // FIXME: Avoid copying the seed into a uint128 key only to have
    //        generateRootDeterministicPrivateKey copy out of it.
    uint128 ps;
    std::memcpy(ps.data(),
        seed.data(), seed.size());
    auto const upk =
        generateRootDeterministicPrivateKey(ps);
    SecretKey sk = Slice{ upk.data(), upk.size() };
    beast::secure_erase(ps.data(), ps.size());
    return sk;
}

PublicKey
derivePublicKey (SecretKey const& sk)
{
    secp256k1_pubkey pubkey_imp;
    if(secp256k1_ec_pubkey_create(
            secp256k1Context(),
            &pubkey_imp,
            reinterpret_cast<unsigned char const*>(
                sk.data())) != 1)
        LogicError("derivePublicKey: secp256k1_ec_pubkey_create failed");

    unsigned char pubkey[33];
    std::size_t len = sizeof(pubkey);
    if(secp256k1_ec_pubkey_serialize(
            secp256k1Context(),
            pubkey,
            &len,
            &pubkey_imp,
            SECP256K1_EC_COMPRESSED) != 1)
        LogicError("derivePublicKey: secp256k1_ec_pubkey_serialize failed");

    return PublicKey{Slice{ pubkey, len }};
}

std::pair<PublicKey, SecretKey>
generateKeyPair (Seed const& seed, bool fCompat)
{
    if (!fCompat)
    {
        Generator g(seed);
        return g(seed, 0);
    }
    else
    {
        auto const sk = generateSecretKey(seed);
        return { derivePublicKey(sk), sk }; 
    }
}

std::pair<PublicKey, SecretKey>
randomKeyPair ()
{
    auto const sk = randomSecretKey();
    return { derivePublicKey(sk), sk };
}

template <>
boost::optional<SecretKey>
parseBase58 (TokenType type, std::string const& s)
{
    auto result = decodeBase58Token(s, type);
    if (result.empty())
        return boost::none;
    if (result.size() == 33 && type == TokenType::AccountWif)
        result.pop_back();
    if (result.size() != 32)
        return boost::none;
    return SecretKey(makeSlice(result));
}


template<>
boost::optional<SecretKey>
parseHex (std::string const& str)
{
    uint256 secret;
    if (secret.SetHexExact (str))
        return SecretKey(Slice(secret.data(), secret.size()));
    return boost::none;
}

} // ripple

