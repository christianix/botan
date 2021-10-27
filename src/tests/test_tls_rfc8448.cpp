/*
* (C) 2021 Jack Lloyd
* (C) 2021 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <memory>

#if defined(BOTAN_HAS_TLS_13)
  #include "test_rng.h"
  #include "test_tls_utils.h"

  #include <botan/auto_rng.h>  // TODO: replace me
  #include <botan/credentials_manager.h>
  #include <botan/rsa.h>
  #include <botan/tls_alert.h>
  #include <botan/tls_callbacks.h>
  #include <botan/tls_client.h>
  #include <botan/tls_policy.h>
  #include <botan/tls_messages.h>
  #include <botan/tls_server.h>
  #include <botan/tls_server_info.h>
  #include <botan/tls_session.h>
  #include <botan/tls_session_manager.h>
  #include <botan/tls_version.h>

  #include <botan/internal/loadstor.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TLS_13)

namespace
{

Botan::RSA_PrivateKey server_private_key()
   {
   return
      {
      Botan::BigInt("0xE435FB7CC83737756DACEA96AB7F59A2CC1069DB7DEB190E17E33A532B273F30A327AA0AAABC58CD67466AF9845FADC675FE094AF92C4BD1F2C1BC33DD2E0515"),
      Botan::BigInt("0xCABD3BC0E0438664C8D4CC9F99977A94D9BBFEAD8E43870ABAE3F7EB8B4E0EEE8AF1D9B4719BA6196CF2CBBAEEEBF8B3490AFE9E9FFA74A88AA51FC645629303"),
      Botan::BigInt("0x010001")
      };
   }

Botan::X509_Certificate server_certificate()
   {
   // self-signed certificate with an RSA1024 public key
   //
   //   [...]
   //   Issuer: CN=rsa
   //   Validity
   //       Not Before: Jul 30 01:23:59 2016 GMT
   //       Not After : Jul 30 01:23:59 2026 GMT
   //   Subject: CN=rsa
   //   [...]
   //   X509v3 extensions:
   //        X509v3 Basic Constraints:
   //            CA:FALSE
   //        X509v3 Key Usage:
   //            Digital Signature, Key Encipherment
   //   [...]
   return Botan::X509_Certificate(
      Botan::hex_decode(
         "308201ac30820115a003020102020102300d06092a864886f70d01010b050030"
         "0e310c300a06035504031303727361301e170d3136303733303031323335395a"
         "170d3236303733303031323335395a300e310c300a0603550403130372736130"
         "819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f"
         "8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91"
         "d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b"
         "1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbf"
         "ae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f02030100"
         "01a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06"
         "092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a726717"
         "0618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6"
         "c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a4"
         "2a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d"
         "402dcc0cc8f8961229ac9187b42b4de10000")
      );
   }

class Test_TLS_13_Callbacks : public Botan::TLS::Callbacks
   {
   public:
      void tls_emit_data(const uint8_t data[], size_t size) override
         {
         send_buffer.insert(send_buffer.end(), data, data + size);
         }

      void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override
         {
         BOTAN_UNUSED(seq_no, data, size);
         // process full TLS record received by tls client, e.g.,
         // by passing it to the application
         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         BOTAN_UNUSED(alert);
         // handle a tls alert received from the tls server
         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {
         BOTAN_UNUSED(session);
         // the session with the tls client was established
         // return false to prevent the session from being cached, true to
         // cache the session in the configured session manager
         return false;
         }

      std::vector<uint8_t> pull_send_buffer() {
         return std::exchange(send_buffer, std::vector<uint8_t>());
      }

   private:
      std::vector<uint8_t> send_buffer;
   };

class Test_Server_Credentials : public Botan::Credentials_Manager
{
   public:
      Test_Server_Credentials() : m_key(server_private_key()) {}

      std::vector<Botan::Certificate_Store*> 
      trusted_certificate_authorities(const std::string &type, const std::string &context) override
         {
         BOTAN_UNUSED(type, context);
         return {};
         }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::string& type,
         const std::string& context) override
         {
         BOTAN_UNUSED(cert_key_types, type, context);
         return { server_certificate() };
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
         const std::string& type,
         const std::string& context) override
         {
         BOTAN_UNUSED(type, context);
         // return the private key associated with the leaf certificate,
         // in this case the one associated with "botan.randombit.net.crt"
         return &m_key;
         }

   private:
      Botan::RSA_PrivateKey m_key;
};

class TLS_Context
   {
   protected:
      TLS_Context(std::unique_ptr<Botan::RandomNumberGenerator> rng_in)
         : rng(std::move(rng_in))
         , session_mgr(*rng)
         , policy(read_tls_policy("rfc8448"))
         {}

   public:
      std::vector<uint8_t> pull_send_buffer() {
         return callbacks.pull_send_buffer();
      }

   public:
      Test_TLS_13_Callbacks   callbacks;
      Test_Server_Credentials creds;

      std::unique_ptr<Botan::RandomNumberGenerator> rng;
      Botan::TLS::Session_Manager_In_Memory         session_mgr;
      Botan::TLS::Text_Policy                       policy;
   };

class Server_Context : public TLS_Context
   {
   public:
      Server_Context(std::unique_ptr<Botan::RandomNumberGenerator> rng_in)
         : TLS_Context(std::move(rng_in))
         , server(callbacks, session_mgr, creds, policy, *rng)
         {}

      Botan::TLS::Server server;
   };

class Client_Context : public TLS_Context
   {
   public:
      Client_Context(std::unique_ptr<Botan::RandomNumberGenerator> rng_in)
         : TLS_Context(std::move(rng_in))
         , client(callbacks, session_mgr, creds, policy, *rng,
                  Botan::TLS::Server_Information(),
                  Botan::TLS::Protocol_Version::TLS_V13)
         {}

      Botan::TLS::Client client;
   };

template <typename Itr>
decltype(auto) slice(Itr begin, Itr end)
   {
   return std::vector<uint8_t>(begin, end);
   }

}

class Test_TLS_RFC8448 final : public Test
   {
   private:
      Test::Result simple_1_rtt_client()
         {
         Test::Result result("Simple 1-RTT (Client side)");

         Client_Context ctx(std::make_unique<Botan::AutoSeeded_RNG>());
         result.confirm("client not closed", !ctx.client.is_closed());

         const auto client_hello_record = ctx.pull_send_buffer();
         result.test_gte("client hello received", client_hello_record.size(), 5);

         // RFC8446 5.1
         // legacy_record_version:  MUST be set to 0x0303 for all records
         //       generated by a TLS 1.3 implementation other than an initial
         //       ClientHello (i.e., one not generated after a HelloRetryRequest),
         //       where it MAY also be 0x0301 for compatibility purposes.
         result.test_eq("TLS client hello record header", slice(client_hello_record.begin(), client_hello_record.begin() + 3), Botan::hex_decode("160303"));
         const auto length_of_handshake_msg = Botan::load_be<uint16_t>(client_hello_record.data() + 3, 0);
         const auto client_hello_msg = slice(client_hello_record.begin() + 5, client_hello_record.end());
         result.test_eq("TLS handshake has correct length", client_hello_msg.size(), length_of_handshake_msg);

         // RFC8446 5.1
         // legacy_record_version:  MUST be set to 0x0303 for all records
         //       generated by a TLS 1.3 implementation other than an initial
         //       ClientHello (i.e., one not generated after a HelloRetryRequest),
         //       where it MAY also be 0x0301 for compatibility purposes.
         result.test_eq("TLS client hello header", slice(client_hello_msg.begin(), client_hello_msg.begin() + 1), Botan::hex_decode("01"));
         auto client_hello_length_bytes = slice(client_hello_msg.begin() + 1, client_hello_msg.begin() + 4);
         client_hello_length_bytes.insert(client_hello_length_bytes.begin(), '\x00');
         const auto length_of_client_hello = Botan::load_be<uint32_t>(client_hello_length_bytes.data(), 0);

         const auto client_hello = slice(client_hello_msg.begin() + 4, client_hello_msg.end());
         result.test_eq("TLS client hello has correct length", client_hello.size(), length_of_client_hello);

         Botan::TLS::Client_Hello hello(client_hello);
         result.test_eq("only one supported version", hello.supported_versions().size(), 1);
         result.test_int_eq("Supported Version is 1.3", hello.supported_versions().front().version_code(), Botan::TLS::Protocol_Version::TLS_V13);

         return result;
         }

      Test::Result simple_1_rtt_server()
         {
         Test::Result result("Simple 1-RTT (Server side)");

         Server_Context ctx(std::make_unique<Botan::AutoSeeded_RNG>());

         // Cipher Suites in this client hello:
         //   AES_128_GCM_SHA256
         //   CHACHA20_POLY1305_SHA256
         //   AES_256_GCM_SHA384
         const auto bytes = ctx.server.received_data(Botan::hex_decode(
            "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d99"
            "12ec18a2ef6283024dece7000006130113031302010000910000000b00090000"
            "06736572766572ff01000100000a00140012001d001700180019010001010102"
            "0103010400230000003300260024001d002099381de560e4bd43d23d8e435a7d"
            "bafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e04"
            "0305030603020308040805080604010501060102010402050206020202002d00"
            "020101001c00024001"));
         result.test_int_eq(bytes, 0, "client hello was fully consumed");

         return result;
         }

   public:
      std::vector<Test::Result> run() override
         {
         return 
            {
            // simple_1_rtt_server()
            simple_1_rtt_client()
            };
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_rfc8448", Test_TLS_RFC8448);

#endif

}
