# frozen_string_literal: true

require "json"
require "securerandom"
require "time"

module UniKey
  # RFC-001 Trust Packet - self-contained cryptographic container
  # for agent-to-agent authenticated communication.
  #
  # A Trust Packet carries claims, payload, and signatures that can be
  # verified using DNS-published public keys. No middleman needed.
  #
  # @example Create and sign a packet
  #   packet = UniKey::TrustPacket.build(
  #     subject: "claude@user.example.com",
  #     audience: "orders@acme-store.com",
  #     action: "purchase_item",
  #     scope: ["purchase:items", "spend:150"],
  #     params: { item: "blue purse", max_price: 150 },
  #     message: "Please purchase a blue purse for my girlfriend.",
  #     signing_key: my_ed25519_key,
  #     signer_domain: "user.example.com"
  #   )
  #
  # @example Verify a received packet
  #   result = UniKey::TrustPacket.verify!(packet_hash)
  #   result.subject     # => "claude@user.example.com"
  #   result.action      # => "purchase_item"
  #   result.valid?      # => true
  #
  class TrustPacket
    PACKET_TYPES = %w[authorization delegation action_request action_response].freeze
    VERSION = "1.0"

    attr_reader :header, :claims, :payload, :signatures

    def initialize(header:, claims:, payload:, signatures: [])
      @header = header
      @claims = claims
      @payload = payload
      @signatures = signatures
    end

    # Build and sign a new Trust Packet
    def self.build(subject:, audience:, action:, signing_key:, signer_domain:,
                   scope: ["*"], params: {}, message: nil, context: "",
                   packet_type: "action_request", delegation_chain: [],
                   ttl: 300)
      now = Time.now.to_i

      header = Header.new(
        tp_version: VERSION,
        packet_type: packet_type,
        packet_id: SecureRandom.uuid,
        issued_at: Time.at(now).utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at: Time.at(now + ttl).utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        nonce: SecureRandom.hex(16),
        canonicalization: "unikey-json-v1"
      )

      claims = Claims.new(
        subject: subject,
        issuer: signer_domain,
        audience: audience,
        scope: Array(scope),
        context: context || "",
        delegation_chain: Array(delegation_chain)
      )

      payload = Payload.new(
        action: action,
        params: params,
        message: message
      )

      packet = new(header: header, claims: claims, payload: payload)

      # Sign the packet
      canonical = Canonicalizer.canonicalize(packet.unsigned_hash)
      sig_bytes = signing_key.sign(canonical)

      signature = Signature.new(
        algorithm: "ed25519",
        signer: signer_domain,
        key_id: "unikey",
        signature: Base64.strict_encode64(sig_bytes)
      )

      packet.instance_variable_set(:@signatures, [signature])
      packet
    end

    # Verify a Trust Packet (raises on failure)
    def self.verify!(packet_data)
      packet_data = deep_symbolize(packet_data) if packet_data.is_a?(Hash)
      Verifier.verify!(packet_data)
    end

    # Verify a Trust Packet (returns nil on failure)
    def self.verify(packet_data)
      verify!(packet_data)
    rescue UniKey::Error
      nil
    end

    # Parse a Trust Packet from a hash (e.g., from JSON)
    def self.from_hash(data)
      data = deep_symbolize(data)

      header = Header.new(**data[:header])
      claims = Claims.new(**data[:claims])
      payload = Payload.new(**data[:payload])
      signatures = (data[:signatures] || []).map { |s| Signature.new(**s) }

      new(header: header, claims: claims, payload: payload, signatures: signatures)
    end

    # Parse from JSON string
    def self.from_json(json_string)
      from_hash(JSON.parse(json_string))
    end

    # The unsigned portion (everything except signatures)
    def unsigned_hash
      {
        header: header.to_h,
        claims: claims.to_h,
        payload: payload.to_h
      }
    end

    def to_h
      {
        header: header.to_h,
        claims: claims.to_h,
        payload: payload.to_h,
        signatures: signatures.map(&:to_h)
      }
    end

    def to_json(*args)
      to_h.to_json(*args)
    end

    # Canonical form for signing/verification
    def canonical_form
      Canonicalizer.canonicalize(unsigned_hash)
    end

    def canonical_hash
      Canonicalizer.hash(unsigned_hash)
    end

    def expired?
      return false unless header.expires_at
      expires_unix = Time.parse(header.expires_at).to_i rescue 0
      expires_unix > 0 && Time.now.to_i > expires_unix
    end

    private

    def self.deep_symbolize(hash)
      return hash unless hash.is_a?(Hash)
      hash.each_with_object({}) do |(k, v), result|
        key = k.is_a?(String) ? k.to_sym : k
        result[key] = case v
                      when Hash then deep_symbolize(v)
                      when Array then v.map { |i| i.is_a?(Hash) ? deep_symbolize(i) : i }
                      else v
                      end
      end
    end

    # ============== Inner Structs ==============

    # RFC-2001 §5.2 Header
    Header = Struct.new(:tp_version, :packet_type, :packet_id, :issued_at, :expires_at, :nonce, :canonicalization, keyword_init: true) do
      def to_h
        { tp_version: tp_version, packet_type: packet_type, packet_id: packet_id,
          issued_at: issued_at, expires_at: expires_at, nonce: nonce, canonicalization: canonicalization }
      end
    end

    # RFC-2001 §5.2 Claims
    Claims = Struct.new(:subject, :issuer, :audience, :scope, :context, :delegation_chain, keyword_init: true) do
      def initialize(scope: ["*"], context: "", delegation_chain: [], **rest)
        super(scope: Array(scope), context: context || "", delegation_chain: Array(delegation_chain), **rest)
      end

      def to_h
        { subject: subject, issuer: issuer, audience: audience,
          scope: scope, context: context, delegation_chain: delegation_chain }
      end
    end

    # RFC-2001 §5.2 Payload
    Payload = Struct.new(:action, :params, :message, keyword_init: true) do
      def initialize(params: {}, **rest)
        super(params: params || {}, **rest)
      end

      def to_h
        { action: action, params: params, message: message }
      end
    end

    # RFC-2001 §5.2 Signature
    Signature = Struct.new(:algorithm, :signer, :key_id, :signature, keyword_init: true) do
      def to_h
        { algorithm: algorithm, signer: signer, key_id: key_id, signature: signature }
      end
    end
  end
end

require_relative "trust_packet/canonicalizer"
require_relative "trust_packet/verifier"
