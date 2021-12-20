/*
* TLS Client Hello Message - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>

#if defined(BOTAN_HAS_CURVE_25519)
#include <botan/curve25519.h>
#endif

#include <botan/dh.h>
#include <botan/ecdh.h>

#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/msg_client_hello_impl_13.h>

#include <botan/hex.h> // TODO remove

namespace Botan {

namespace TLS {

/*
* Create a new Client Hello message
*/
Client_Hello_Impl_13::Client_Hello_Impl_13(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Client_Hello::Settings& client_settings,
                           const std::vector<std::string>& next_protocols) :
   Client_Hello_Impl(io, hash, policy, cb, rng, reneg_info, client_settings, next_protocols)
   {
   // Always use TLS 1.2 as a legacy version
   m_version = Protocol_Version::TLS_V12;

   //TODO: Compatibility mode, does not need to be random
   // m_session_id = make_hello_random(rng, policy);

   // TODO: check when to set these -- setting for rfc8448 now
   m_extensions.add(new Server_Name_Indicator(client_settings.hostname()));

   m_extensions.add(new Renegotiation_Extension());

   m_extensions.add(new Session_Ticket());

   m_extensions.add(new Supported_Groups(policy.key_exchange_groups()));

   m_extensions.add(new Signature_Algorithms(policy.acceptable_signature_schemes()));

   const auto selected_group = policy.key_exchange_groups().front(); // TODO choose wisely

   std::unique_ptr<Private_Key> private_key;
   std::vector<uint8_t> public_key;

   if(selected_group == Group_Params::NONE)  // this cannot really happen, handle in else
      throw TLS_Exception(Alert::HANDSHAKE_FAILURE, "Could not agree with the client");

   if (group_param_is_dh(selected_group)) {
      // TODO: should this use TLS::Callbacks::tls_decode_group_param
      private_key.reset(new DH_PrivateKey(rng, DL_Group(group_param_to_string(selected_group))));
   } else
   // TODO others (see msg_server_kex)
   if(selected_group == Group_Params::X25519) {
#if defined(BOTAN_HAS_CURVE_25519)
      auto x25519 = std::make_unique<X25519_PrivateKey>(rng);
      public_key = x25519->public_value();
      private_key.reset(x25519.release());
#else
      throw Internal_Error("Selected X25519 somehow, but it is disabled");
#endif
   }

   m_extensions.add(new Key_Share(std::vector{Key_Share_Entry(selected_group, public_key)}));

   m_extensions.add(new Supported_Versions(client_settings.protocol_version(), policy));

   cb.tls_modify_extensions(m_extensions, CLIENT);

   hash.update(io.send(*this));
   }

/*
* Create a new Client Hello message (session resumption case)
*/
Client_Hello_Impl_13::Client_Hello_Impl_13(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Session& session,
                           const std::vector<std::string>& next_protocols) :
   Client_Hello_Impl(io, hash, policy, cb, rng, reneg_info, session, next_protocols)
   {
   //TODO: session resumption checks

   // Always use TLS 1.2 as a legacy version
   m_version = Protocol_Version::TLS_V12;

   m_extensions.add(new Supported_Groups(policy.key_exchange_groups()));

   m_extensions.add(new Signature_Algorithms(policy.acceptable_signature_schemes()));

   //TODO: Mandatory Key Share extension to be added

   m_extensions.add(new Supported_Versions(session.version(), policy));

   cb.tls_modify_extensions(m_extensions, CLIENT);

   hash.update(io.send(*this));
   }

Client_Hello_Impl_13::Client_Hello_Impl_13(const std::vector<uint8_t>& buf) :
   Client_Hello_Impl(buf)
   {
   // Common implementation is enough, as received Client_Hello shall be read correctly independent of the version
   }

}

}
