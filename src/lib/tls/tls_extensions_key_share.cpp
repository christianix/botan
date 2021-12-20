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
#include <botan/rng.h>

#if defined(BOTAN_HAS_CURVE_25519)
#include <botan/curve25519.h>
#endif

namespace Botan {

namespace TLS {

#if defined(BOTAN_HAS_TLS_13)

namespace {

class Key_Share_Entry
   {
   public:
      Key_Share_Entry(TLS_Data_Reader &reader)
      {
         // TODO check that the group actually exists before casting...
         const auto m_group = static_cast<Named_Group>(reader.get_uint16_t());
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

      bool empty() const { return ((m_group == Group_Params::NONE) && m_key_exchange.empty()); }
      size_t size() const { return sizeof(m_group) + m_key_exchange.size(); }

      std::vector<uint8_t> serialize() const{
         std::vector<uint8_t> buf;

         const auto group = static_cast<uint16_t>(m_group);
         const auto key_exchange_len = static_cast<uint16_t>(m_key_exchange.size());

         buf.reserve(sizeof(m_group) + sizeof(key_exchange_len) + key_exchange_len);

         buf.push_back(get_byte<0>(group));
         buf.push_back(get_byte<1>(group));

         buf.push_back(get_byte<0>(key_exchange_len));
         buf.push_back(get_byte<1>(key_exchange_len));

         buf.insert(std::end(buf), std::cbegin(m_key_exchange), std::end(m_key_exchange));

         return buf;
      }

   private:
      Named_Group          m_group;
      std::vector<uint8_t> m_key_exchange;
   };

class Key_Share_ClientHello final : public Key_Share_Content
   {
   public:
      explicit Key_Share_ClientHello(TLS_Data_Reader& reader, uint16_t extension_size)
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
      prepare_share_offers(const Policy &policy, RandomNumberGenerator &rng)
      {
         std::unique_ptr<Private_Key> private_key;

         auto x25519 = std::make_unique<X25519_PrivateKey>(rng);
         const auto public_key = x25519->public_value();
         private_key.reset(x25519.release());

         return std::unique_ptr<Key_Share_ClientHello>(new Key_Share_ClientHello(std::vector<Key_Share_Entry>{Key_Share_Entry(Group_Params::X25519, std::move(public_key))}));
      }

      std::vector<uint8_t> serialize() const override
      {     
         std::vector<uint8_t> buf;

         // reserve 2 first bytes for client_key_share_length
         uint16_t client_key_share_length = 0;
         buf.push_back(get_byte<0>(client_key_share_length));
         buf.push_back(get_byte<1>(client_key_share_length));

         for (const auto& client_share : m_client_shares)
            {
            const auto client_share_serialized = client_share.serialize();
            client_key_share_length += client_share_serialized.size();
            buf.insert(buf.end(), client_share_serialized.cbegin(), client_share_serialized.cend());
            }

         // update 2 first bytes with actual client_key_share_length
         buf[0] = get_byte<0>(client_key_share_length);
         buf[1] = get_byte<1>(client_key_share_length);

         return buf;
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
   : m_server_share(Key_Share_Entry(reader)) {}

Key_Share_ServerHello::Key_Share_ServerHello(const Key_Share_Entry& server_share) :
   m_server_share(server_share)
   {
   }

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

Key_Share::Key_Share(const Policy& policy, RandomNumberGenerator& rng) :
   m_content(Key_Share_ClientHello::prepare_share_offers(policy, rng))
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
   return (m_content == nullptr) or m_content->empty();
   }

#endif
}
}