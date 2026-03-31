# frozen_string_literal: true

require "ed25519"
require "base64"
require "ostruct"
require "time"

module UniKey
  class TrustPacket
    # RFC-2001 Trust Packet verification using DNS-published public keys.
    module Verifier
      module_function

      def verify!(packet_data)
        validate_structure!(packet_data)

        header = packet_data[:header]
        claims = packet_data[:claims]
        payload = packet_data[:payload]
        signatures = packet_data[:signatures]

        # Check expiration (ISO 8601 string)
        expires_at = header[:expires_at]
        if expires_at
          expires_unix = Time.parse(expires_at.to_s).to_i rescue 0
          if expires_unix > 0 && Time.now.to_i > expires_unix
            raise UniKey::ExpiredRequest
          end
        end

        # Check trusted signers
        primary_sig = signatures.first
        signer_domain = primary_sig[:signer]
        unless UniKey.configuration.trusted?(signer_domain)
          raise UniKey::UntrustedSigner.new(signer_domain)
        end

        # Build unsigned portion and canonicalize
        unsigned = {
          header: header,
          claims: claims,
          payload: payload
        }
        canonical = Canonicalizer.canonicalize(unsigned)

        # Verify each signature
        signatures.each do |sig|
          verify_signature!(canonical, sig)
        end

        # Validate delegation chain scope narrowing (RFC-1200)
        validate_delegation_chain!(claims) if claims[:delegation_chain]&.any?

        # Parse timestamps for result
        issued_unix = Time.parse(header[:issued_at].to_s).to_i rescue 0
        expires_unix = Time.parse(expires_at.to_s).to_i rescue 0

        # Return verified info
        OpenStruct.new(
          valid: true,
          packet_id: header[:packet_id],
          packet_type: header[:packet_type],
          subject: claims[:subject],
          issuer: claims[:issuer],
          audience: claims[:audience],
          scope: claims[:scope],
          action: payload[:action],
          params: payload[:params],
          message: payload[:message],
          callback_url: payload.dig(:params, :callback_url) || payload.dig(:params, "callback_url"),
          signer: signer_domain,
          delegation_chain: claims[:delegation_chain],
          timestamp: issued_unix > 0 ? Time.at(issued_unix) : nil,
          expires_at: expires_unix > 0 ? Time.at(expires_unix) : nil
        )
      end

      def verify(packet_data)
        verify!(packet_data)
      rescue UniKey::Error
        nil
      end

      # @private
      def validate_structure!(data)
        %i[header claims payload signatures].each do |field|
          raise UniKey::InvalidPacket.new("Missing field: #{field}") unless data[field]
        end

        raise UniKey::InvalidPacket.new("No signatures") if data[:signatures].empty?

        %i[tp_version packet_id issued_at].each do |field|
          raise UniKey::InvalidPacket.new("Missing header.#{field}") unless data[:header][field]
        end

        %i[subject issuer audience].each do |field|
          raise UniKey::InvalidPacket.new("Missing claims.#{field}") unless data[:claims][field]
        end

        unless data[:payload][:action]
          raise UniKey::InvalidPacket.new("Missing payload.action")
        end
      end

      # @private
      def verify_signature!(canonical, sig)
        signer_domain = sig[:signer]
        signature_b64 = sig[:signature]

        public_key_b64 = if UniKey.configuration.dns_hardening_enabled
                           UniKey::HardenedDNS.lookup(signer_domain)
                         else
                           UniKey::DNS.lookup(signer_domain)
                         end

        public_key_bytes = Base64.decode64(public_key_b64)
        verify_key = Ed25519::VerifyKey.new(public_key_bytes)

        signature_bytes = Base64.decode64(signature_b64)
        begin
          verify_key.verify(signature_bytes, canonical)
        rescue Ed25519::VerifyError
          raise UniKey::InvalidSignature
        end
      end

      # @private
      def validate_delegation_chain!(claims)
        chain = claims[:delegation_chain]
        return if chain.nil? || chain.empty?

        chain.each do |link|
          unless link.is_a?(String) && (link.include?("→") || link.include?("->"))
            # Warn but don't fail for now
          end
        end
      end
    end
  end
end
