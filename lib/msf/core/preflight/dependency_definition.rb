# frozen_string_literal: true

module Msf
  module Preflight
    # Normalizes the optional `Dependencies` module metadata into a stable API.
    #
    # Supported shape:
    #
    #   'Dependencies' => {
    #     'SchemaVersion' => 1,
    #     'RequiredModules' => [
    #       {
    #         'Module' => 'auxiliary/scanner/http/example',
    #         'Version' => '>= 1.2.0, < 2.0.0',
    #         'OnVersionMismatch' => 'warn',
    #         'Description' => 'Identifies the application and its version'
    #       }
    #     ],
    #     'RequiresInformation' => [
    #       {
    #         'Name' => 'service.version',
    #         'Type' => 'version',
    #         'Description' => 'Detected application version',
    #         'ManualOption' => 'APP_VERSION'
    #       }
    #     ],
    #     'ProducesInformation' => [
    #       {
    #         'Name' => 'service.version',
    #         'Type' => 'version',
    #         'Datastore' => 'APP_VERSION'
    #       }
    #     ],
    #     'PayloadSelection' => {
    #       'AutoSelect' => true
    #     }
    #   }
    #
    # `RequiredModules`, `RequiresModules`, and `Requires` are accepted as
    # aliases. `RequiredInformation` and `RequiresInformation` are also
    # interchangeable, as are `Produces` and `ProducesInformation`.
    class DependencyDefinition
      MODULE_KEYS = %w[RequiredModules RequiresModules Requires].freeze
      INFORMATION_KEYS = %w[RequiresInformation RequiredInformation].freeze
      PRODUCES_KEYS = %w[ProducesInformation Produces].freeze
      KEY_ALIASES = {
        'schema_version' => 'SchemaVersion',
        'required_modules' => 'RequiredModules',
        'requires_modules' => 'RequiresModules',
        'requires' => 'Requires',
        'requires_information' => 'RequiresInformation',
        'required_information' => 'RequiredInformation',
        'produces_information' => 'ProducesInformation',
        'produces' => 'Produces',
        'payload_selection' => 'PayloadSelection',
        'auto_select' => 'AutoSelect',
        'blocked_by_protections' => 'BlockedByProtections',
        'on_version_mismatch' => 'OnVersionMismatch',
        'version_requirement' => 'VersionRequirement',
        'requires_version' => 'RequiresVersion',
        'manual_option' => 'ManualOption',
        'module' => 'Module',
        'ref' => 'Ref',
        'version' => 'Version',
        'description' => 'Description',
        'information' => 'Information',
        'facts' => 'Facts',
        'metadata' => 'Metadata',
        'name' => 'Name',
        'key' => 'Key',
        'type' => 'Type',
        'value' => 'Value',
        'port' => 'Port',
        'proto' => 'Proto',
        'required' => 'Required',
        'datastore' => 'Datastore',
        'from' => 'From',
        'method' => 'Method'
      }.freeze

      def initialize(raw_definition)
        @raw = raw_definition.is_a?(Hash) ? stringify_keys(raw_definition) : {}
      end

      # @return [Integer]
      def schema_version
        (@raw['SchemaVersion'] || @raw['Version'] || SCHEMA_VERSION).to_i
      end

      # @return [Array<Hash>]
      def required_modules
        normalize_entries(MODULE_KEYS).map { |entry| normalize_module(entry) }
      end

      # @return [Array<Hash>]
      def required_information
        normalize_entries(INFORMATION_KEYS).map { |entry| normalize_information(entry, required: true) }
      end

      # @return [Array<Hash>]
      def produced_information
        normalize_entries(PRODUCES_KEYS).map { |entry| normalize_produced_information(entry) }
      end

      # @return [Hash]
      def payload_selection
        stringify_keys(@raw['PayloadSelection'] || @raw['Payload'] || {})
      end

      # @return [Boolean]
      def any?
        required_modules.any? || required_information.any? || produced_information.any? || payload_selection.any?
      end

      # @return [Boolean]
      def dependency_checks?
        required_modules.any? || required_information.any?
      end

      # @return [Boolean]
      def payload_policy?
        payload_selection.any?
      end

      private

      def normalize_entries(keys)
        keys.each do |key|
          next unless @raw.key?(key)

          value = @raw[key]
          return [] if value.nil?
          return value.compact if value.is_a?(Array)

          return [value]
        end

        []
      end

      def normalize_module(entry)
        if entry.is_a?(String)
          return {
            'Module' => entry,
            'Version' => nil,
            'OnVersionMismatch' => 'warn',
            'Description' => nil,
            'Information' => [],
            'Metadata' => {}
          }
        end

        normalized = stringify_keys(entry)
        if normalized.key?('module')
          normalized = { 'Module' => normalized.delete('module') }.merge(normalized)
        end

        ref = normalized['Module'] || normalized['Ref'] || normalized['Name']
        {
          'Module' => ref.to_s,
          'Version' => normalized['Version'] || normalized['VersionRequirement'] || normalized['RequiresVersion'],
          'OnVersionMismatch' => (normalized['OnVersionMismatch'] || 'warn').to_s.downcase,
          'Description' => normalized['Description'],
          'Information' => Array(normalized['Information'] || normalized['RequiresInformation'] || normalized['Facts']),
          'Metadata' => normalized['Metadata'] || {}
        }
      end

      def normalize_information(entry, required:)
        entry = { 'Name' => entry } if entry.is_a?(String)
        normalized = stringify_keys(entry)
        if normalized.key?('name')
          normalized = { 'Name' => normalized.delete('name') }.merge(normalized)
        end

        {
          'Name' => (normalized['Name'] || normalized['Key']).to_s,
          'Type' => (normalized['Type'] || 'value').to_s.downcase,
          'Value' => normalized['Value'],
          'Port' => normalized['Port'],
          'Proto' => normalized['Proto'],
          'Description' => normalized['Description'],
          'ManualOption' => normalized['ManualOption'] || normalized['Option'],
          'Required' => normalized.key?('Required') ? normalized['Required'] != false : required,
          'Metadata' => normalized['Metadata'] || {}
        }
      end

      def normalize_produced_information(entry)
        entry = { 'Name' => entry } if entry.is_a?(String)
        normalized = stringify_keys(entry)
        if normalized.key?('name')
          normalized = { 'Name' => normalized.delete('name') }.merge(normalized)
        end

        {
          'Name' => (normalized['Name'] || normalized['Key']).to_s,
          'Type' => (normalized['Type'] || 'value').to_s.downcase,
          'Value' => normalized['Value'],
          'Port' => normalized['Port'],
          'Proto' => normalized['Proto'],
          'Datastore' => normalized['Datastore'] || normalized['From'],
          'Method' => normalized['Method'],
          'Description' => normalized['Description'],
          'Metadata' => normalized['Metadata'] || {}
        }
      end

      def stringify_keys(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, child), result|
            key_string = key.to_s
            normalized_key = KEY_ALIASES.fetch(key_string, key_string[0].upcase + key_string[1..])
            result[normalized_key] = stringify_keys(child)
          end
        when Array
          value.map { |child| stringify_keys(child) }
        else
          value
        end
      end
    end
  end
end
