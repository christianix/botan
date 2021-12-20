/*
* TLS Extensions
* (C) 2011,2012,2015,2016 Jack Lloyd
*     2016 Juraj Somorovsky
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_callbacks.h>
#include <botan/rng.h>

#if defined(BOTAN_HAS_CURVE_25519)
#include <botan/curve25519.h>
#endif

#include <botan/dh.h>
#include <botan/ecdh.h>

namespace Botan {

namespace TLS {

#if defined(BOTAN_HAS_TLS_13)

namespace {

constexpr bool is_x25519(const Group_Params group)
{
   return group == Group_Params::X25519;
}

constexpr bool is_ecdh(const Group_Params group)
{
   return
      group == Group_Params::SECP256R1      ||
      group == Group_Params::SECP384R1      ||
      group == Group_Params::SECP521R1      ||
      group == Group_Params::BRAINPOOL256R1 ||
      group == Group_Params::BRAINPOOL384R1 ||
      group == Group_Params::BRAINPOOL512R1;
}

constexpr bool is_dh(const Group_Params group)
{
   return
      group == Group_Params::FFDHE_2048 ||
      group == Group_Params::FFDHE_3072 ||
      group == Group_Params::FFDHE_4096 ||
      group == Group_Params::FFDHE_6144 ||
      group == Group_Params::FFDHE_8192;
}

class Key_Share_Entry
   {
   public:
      Key_Share_Entry(TLS_Data_Reader &reader)
      {
         // TODO check that the group actually exists before casting...
         m_group = static_cast<Named_Group>(reader.get_uint16_t());
         const auto key_exchange_length = reader.get_uint16_t();
         m_key_exchange = reader.get_fixed<uint8_t>(key_exchange_length);
      }

      Key_Share_Entry(Named_Group group, std::vector<uint8_t> key_exchange)
         : m_group(group)
         , m_key_exchange(std::move(key_exchange))
      {
         if (m_key_exchange.empty()) {
            throw Decoding_Error("Size of key_exchange in KeyShareEntry must be at least 1 byte.");
         }
      }

      Key_Share_Entry(Named_Group group, std::unique_ptr<Private_Key> private_key)
         : m_group(group)
         , m_key_exchange(private_key->public_key_bits())
         , m_private_key(std::move(private_key)) {}

      bool empty() const { return (m_group == Group_Params::NONE) && m_key_exchange.empty(); }

      std::vector<uint8_t> serialize() const{
         std::vector<uint8_t> result;

         const uint16_t named_curve_id = static_cast<uint16_t>(m_group);
         result.push_back(get_byte<0>(named_curve_id));
         result.push_back(get_byte<1>(named_curve_id));
         append_tls_length_value(result, m_key_exchange, 2);

         return result;
      }

   private:
      Named_Group                  m_group;
      std::vector<uint8_t>         m_key_exchange;
      std::unique_ptr<Private_Key> m_private_key;
   };

class Key_Share_ClientHello final : public Key_Share_Content
   {
   public:
      explicit Key_Share_ClientHello(TLS_Data_Reader& reader, uint16_t /* extension_size */)
      {
         const auto client_key_share_length = reader.get_uint16_t();
         const auto read_bytes_so_far_begin = reader.read_so_far();

         while (reader.has_remaining() and ((reader.read_so_far() - read_bytes_so_far_begin) < client_key_share_length))
            {
            const auto group = reader.get_uint16_t();
            const auto key_exchange_length = reader.get_uint16_t();

            if (key_exchange_length > reader.remaining_bytes())
               {
               throw Decoding_Error("Not enough bytes in the buffer to decode KeyShare (ClientHello) extension");
               }

            std::vector<uint8_t> client_share;
            client_share.reserve(key_exchange_length);

            for (auto i = 0u; i < key_exchange_length; ++i)
               {
               client_share.push_back(reader.get_byte());
               }

            m_client_shares.emplace_back(static_cast<Named_Group>(group), client_share);
            }

         if ((reader.read_so_far() - read_bytes_so_far_begin) != client_key_share_length)
            {
            throw Decoding_Error("Read bytes are not equal client KeyShare length");
            }
      }

      ~Key_Share_ClientHello() override = default;

      static std::unique_ptr<Key_Share_ClientHello> 
      prepare_share_offers(const Policy &policy, Callbacks& cb, RandomNumberGenerator &rng)
      {
         const auto supported = policy.key_exchange_groups();
         const auto offers    = policy.key_exchange_groups_to_offer();

         std::vector<Key_Share_Entry> kse;

         // RFC 8446 P. 48
         //
         //   This vector MAY be empty if the client is requesting a
         //   HelloRetryRequest.  Each KeyShareEntry value MUST correspond to a
         //   group offered in the "supported_groups" extension and MUST appear in
         //   the same order.  However, the values MAY be a non-contiguous subset
         //   of the "supported_groups" extension and MAY omit the most preferred
         //   groups.
         //
         // ... hence, we're going through the supported groups and find those that
         //     should be used to offer a key exchange. This will satisfy above spec.
         //
         // ... TODO: improve efficiency
         for (const auto group : supported)
         {
            if (std::find(offers.begin(), offers.end(), group) == offers.end()) {
               continue;
            }

            if (is_x25519(group)) {
               kse.emplace_back(group, std::make_unique<X25519_PrivateKey>(rng));
            } else if (is_ecdh(group)) {
               const EC_Group ec_group(cb.tls_decode_group_param(group));
               auto private_key = std::make_unique<ECDH_PrivateKey>(rng, ec_group);

               // RFC 8446 Ch. 4.2.8.2
               //
               //   Note: Versions of TLS prior to 1.3 permitted point format
               //   negotiation; TLS 1.3 removes this feature in favor of a single point
               //   format for each curve.
               //
               // Hence, we neither need to take Policy::use_ecc_point_compression() nor
               // ClientHello::prefers_compressed_ec_points() into account here.
               private_key->set_point_encoding(PointGFp::UNCOMPRESSED);
               kse.emplace_back(group, std::move(private_key));
            } else if (is_dh(group)) {
               // RFC 8446 Ch. 4.2.8.1
               //
               //   The opaque value contains the Diffie-Hellman
               //   public value (Y = g^X mod p) for the specified group (see [RFC7919]
               //   for group definitions) encoded as a big-endian integer and padded to
               //   the left with zeros to the size of p in bytes.
               //
               // TODO: the encoding for DH is currently based on the DER_Encoder (see dl_algo.cpp)
               //       and this is likely not conforming to RFC 8446!
               const DL_Group dl_group(cb.tls_decode_group_param(group));
               kse.emplace_back(group, std::make_unique<DH_PrivateKey>(rng, dl_group));
            } else {
               throw Decoding_Error("cannot create a key offering without a group definition");
            }
         }

         return std::unique_ptr<Key_Share_ClientHello>(new Key_Share_ClientHello(std::move(kse)));
      }

      std::vector<uint8_t> serialize() const override
      {
         std::vector<uint8_t> shares;
         for (const auto &share : m_client_shares)
         {
            const auto serialized_share = share.serialize();
            shares.insert(shares.end(), serialized_share.cbegin(), serialized_share.cend());
         }

         std::vector<uint8_t> result;
         append_tls_length_value(result, shares, 2);
         return result;
      }

      bool empty() const override
      {
         return m_client_shares.empty() || std::all_of(m_client_shares.cbegin(), m_client_shares.cend(),
            [](const Key_Share_Entry& key_share_entry) { return key_share_entry.empty(); });
      }

   protected:
      explicit Key_Share_ClientHello(std::vector<Key_Share_Entry> client_shares)
         : m_client_shares(std::move(client_shares)) {}

   private:
      std::vector<Key_Share_Entry> m_client_shares;
   };

class Key_Share_ServerHello final : public Key_Share_Content
   {
   public:
      explicit Key_Share_ServerHello(TLS_Data_Reader& reader,
                                     uint16_t extension_size);

      explicit Key_Share_ServerHello(const Key_Share_Entry& server_share);

      ~Key_Share_ServerHello() override;

      std::vector<uint8_t> serialize() const override;

      bool empty() const override;

   private:
      Key_Share_Entry m_server_share;
   };

class Key_Share_HelloRetryRequest final : public Key_Share_Content
   {
   public:
      explicit Key_Share_HelloRetryRequest(TLS_Data_Reader& reader,
                                           uint16_t extension_size);

      explicit Key_Share_HelloRetryRequest(Named_Group selected_group);

      ~Key_Share_HelloRetryRequest() override;

      std::vector<uint8_t> serialize() const override;

      bool empty() const override;

   private:
      Named_Group m_selected_group;
   };


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 



Key_Share_HelloRetryRequest::Key_Share_HelloRetryRequest(TLS_Data_Reader& reader,
                                                         uint16_t extension_size)
   {
   constexpr auto sizeof_uint16_t = sizeof(uint16_t);

   if (extension_size != sizeof_uint16_t)
      {
      throw Decoding_Error("Size of KeyShare extension in HelloRetryRequest must be " +
         std::to_string(sizeof_uint16_t) + " bytes");
      }

   m_selected_group = static_cast<Named_Group>(reader.get_uint16_t());
   }

Key_Share_HelloRetryRequest::Key_Share_HelloRetryRequest(Named_Group selected_group) :
   m_selected_group(selected_group)
   {
   }

Key_Share_HelloRetryRequest::~Key_Share_HelloRetryRequest() = default;

std::vector<uint8_t> Key_Share_HelloRetryRequest::serialize() const
   {
   return { get_byte<0>(static_cast<uint16_t>(m_selected_group)),
            get_byte<1>(static_cast<uint16_t>(m_selected_group)) };
   }


bool Key_Share_HelloRetryRequest::empty() const
   {
   return m_selected_group == Group_Params::NONE;
   }

Key_Share_ServerHello::Key_Share_ServerHello(TLS_Data_Reader& reader,
                                             uint16_t /*extension_size*/)
   : m_server_share(reader) {}

Key_Share_ServerHello::~Key_Share_ServerHello() = default;

std::vector<uint8_t> Key_Share_ServerHello::serialize() const
   {
   std::vector<uint8_t> buf;

   const auto server_share_serialized = m_server_share.serialize();
   buf.insert(buf.end(), server_share_serialized.cbegin(), server_share_serialized.cend());

   return buf;
   }

bool Key_Share_ServerHello::empty() const
   {
   return m_server_share.empty();
   }

}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 


Key_Share::Key_Share(TLS_Data_Reader& reader,
                     uint16_t extension_size,
                     Connection_Side from)
   {
   if (from == Connection_Side::CLIENT)
      {
      m_content = std::make_unique<Key_Share_ClientHello>(reader, extension_size);
      }
   else // Connection_Side::SERVER
      {
      m_content = std::make_unique<Key_Share_ServerHello>(reader, extension_size);

      //TODO: When to create Key_Share_HelloRetryRequest? Should be decided later, during implementation of TLS 1.3.
      //m_content = std::make_unique<Key_Share_HelloRetryRequest>(reader, extension_size);
      }
   }

Key_Share::Key_Share(const Policy& policy, Callbacks& cb, RandomNumberGenerator& rng) :
   m_content(Key_Share_ClientHello::prepare_share_offers(policy, cb, rng))
   {
   }

// Key_Share::Key_Share(const Key_Share_Entry& server_share) :
//    m_content(std::make_unique<Key_Share_ServerHello>(server_share))
//    {
//    }

Key_Share::Key_Share(Named_Group selected_group) :
   m_content(std::make_unique<Key_Share_HelloRetryRequest>(selected_group))
   {
   }

std::vector<uint8_t> Key_Share::serialize(Connection_Side /*whoami*/) const
   {
   return m_content->serialize();
   }

bool Key_Share::empty() const
   {
   return (m_content == nullptr) || m_content->empty();
   }

#endif
}
}