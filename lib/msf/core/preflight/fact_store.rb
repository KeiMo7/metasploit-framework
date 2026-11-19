# frozen_string_literal: true

require 'json'
require 'time'

module Msf
  module Preflight
    # In-memory store for discovered target information and successful module
    # executions. A framework instance owns one store so modules in the same
    # console/RPC session can consume facts produced by earlier modules.
    class FactStore
      def initialize
        @facts = []
        @runs = []
        @mutex = Mutex.new
      end

      # @return [Array<Hash>]
      def facts
        @mutex.synchronize { @facts.map(&:dup) }
      end

      # @return [Array<Hash>]
      def runs
        @mutex.synchronize { @runs.map(&:dup) }
      end

      # @return [Boolean]
      def empty?
        @mutex.synchronize { @facts.empty? && @runs.empty? }
      end

      # Record a discovered fact. Newer values with the same identity replace
      # older values, while facts from different sources remain available.
      #
      # @return [Hash]
      # rubocop:disable Metrics/ParameterLists
      def record_fact(name:, value:, type: nil, target: nil, port: nil, proto: nil,
                      source: 'manual', module_ref: nil, module_version: nil, metadata: {})
        return nil if name.to_s.empty? || value.nil?

        fact = {
          'name' => name.to_s,
          'type' => (type || 'value').to_s.downcase,
          'value' => value,
          'target' => target&.to_s,
          'port' => port&.to_i,
          'proto' => proto&.to_s&.downcase,
          'source' => source.to_s,
          'module' => module_ref&.to_s,
          'module_version' => module_version&.to_s,
          'metadata' => stringify_keys(metadata || {}),
          'recorded_at' => Time.now.utc.iso8601
        }

        @mutex.synchronize do
          @facts.reject! do |existing|
            existing['name'].casecmp?(fact['name']) &&
              existing['target'] == fact['target'] &&
              existing['port'] == fact['port'] &&
              existing['proto'] == fact['proto']
          end
          @facts << fact
        end

        fact
      end
      # rubocop:enable Metrics/ParameterLists

      # Record that a module completed successfully.
      #
      # @return [Hash]
      def record_module_run(module_ref:, module_version: nil, target: nil, workspace: nil,
                            run_id: nil, metadata: {})
        return nil if module_ref.to_s.empty?

        entry = {
          'module' => module_ref.to_s,
          'module_version' => module_version&.to_s,
          'target' => target&.to_s,
          'workspace' => workspace&.to_s,
          'run_id' => run_id&.to_s,
          'metadata' => stringify_keys(metadata || {}),
          'recorded_at' => Time.now.utc.iso8601
        }

        @mutex.synchronize do
          @runs.reject! do |existing|
            existing['module'] == entry['module'] &&
              existing['target'] == entry['target'] &&
              existing['workspace'] == entry['workspace']
          end
          @runs << entry
        end

        entry
      end

      # @return [Hash, nil]
      def module_run(module_ref, target: nil, workspace: nil)
        @mutex.synchronize do
          @runs.reverse.find do |entry|
            entry['module'] == module_ref.to_s &&
              target_filter_match?(entry['target'], target) &&
              workspace_filter_match?(entry['workspace'], workspace)
          end&.dup
        end
      end

      # @return [Array<Hash>]
      def find_facts(name: nil, type: nil, port: nil, proto: nil, target: nil, value: nil)
        @mutex.synchronize do
          @facts.select do |fact|
            name_filter_match?(fact, name) &&
              type_filter_match?(fact, type) &&
              port_filter_match?(fact, port) &&
              proto_filter_match?(fact, proto) &&
              target_filter_match?(fact['target'], target) &&
              value_filter_match?(fact, value)
          end.map(&:dup)
        end
      end

      # @return [Boolean]
      def include?(name:, type: nil, port: nil, proto: nil, target: nil, value: nil)
        find_facts(name: name, type: type, port: port, proto: proto,
                   target: target, value: value).any?
      end

      # Import facts from JSON or a Ruby hash. Both the compact form:
      #
      #   { "service.version": "1.2.3", "open_port": 443 }
      #
      # and the explicit form accepted by {#to_h} are supported.
      #
      # @return [Array<Hash>]
      def import(data, source: 'manual', target: nil)
        parsed = data.is_a?(String) ? JSON.parse(data) : data
        case parsed
        when Array
          parsed.filter_map { |entry| import_fact_entry(entry, source, target) }
        when Hash
          import_hash(parsed, source, target)
        else
          []
        end
      rescue JSON::ParserError => e
        raise ArgumentError, "PREFLIGHT_FACTS is not valid JSON: #{e.message}"
      end

      # @return [Hash]
      def to_h
        {
          'facts' => facts,
          'module_runs' => runs
        }
      end

      # @return [FactStore]
      def merge(other)
        merged = self.class.new
        (facts + Array(other&.facts)).each do |fact|
          merged.record_fact(
            name: fact['name'],
            value: fact['value'],
            type: fact['type'],
            target: fact['target'],
            port: fact['port'],
            proto: fact['proto'],
            source: fact['source'],
            module_ref: fact['module'],
            module_version: fact['module_version'],
            metadata: fact['metadata']
          )
        end
        (runs + Array(other&.runs)).each do |run|
          merged.record_module_run(
            module_ref: run['module'],
            module_version: run['module_version'],
            target: run['target'],
            workspace: run['workspace'],
            run_id: run['run_id'],
            metadata: run['metadata']
          )
        end
        merged
      end

      private

      def import_hash(data, source, target)
        modules = data['modules'] || data['module_runs']
        facts_data = data['facts'] || data
        imported = []

        if modules
          Array(modules).each do |entry|
            if entry.is_a?(Hash)
              record_module_run(
                module_ref: entry['module'] || entry['ref'],
                module_version: entry['version'] || entry['module_version'],
                target: entry['target'] || target,
                workspace: entry['workspace'],
                metadata: entry['metadata'] || {}
              )
            else
              record_module_run(module_ref: entry, target: target)
            end
          end
        end

        case facts_data
        when Array
          facts_data.each { |entry| imported << import_fact_entry(entry, source, target) }
        when Hash
          facts_data.each do |key, value|
            next if %w[facts modules module_runs].include?(key)

            if value.is_a?(Hash)
              imported << record_fact(
                name: value['name'] || key,
                value: value['value'],
                type: value['type'] || infer_type(value['name'] || key),
                target: value['target'] || target,
                port: value['port'] || infer_port(value['name'] || key),
                proto: value['proto'] || infer_proto(value['name'] || key),
                source: value['source'] || source,
                module_ref: value['module'],
                module_version: value['module_version'],
                metadata: value['metadata']
              )
            elsif value.is_a?(Array)
              value.each do |item|
                imported << record_fact(
                  name: key,
                  value: item,
                  type: infer_type(key),
                  target: target,
                  port: infer_port(key),
                  proto: infer_proto(key),
                  source: source
                )
              end
            else
              imported << record_fact(
                name: key,
                value: value,
                type: infer_type(key),
                target: target,
                port: infer_port(key),
                proto: infer_proto(key),
                source: source
              )
            end
          end
        end
        imported.compact
      end

      def import_fact_entry(entry, source, target)
        return nil unless entry.is_a?(Hash)

        record_fact(
          name: entry['name'] || entry['key'],
          value: entry['value'],
          type: entry['type'] || infer_type(entry['name'] || entry['key']),
          target: entry['target'] || target,
          port: entry['port'] || infer_port(entry['name'] || entry['key']),
          proto: entry['proto'] || infer_proto(entry['name'] || entry['key']),
          source: entry['source'] || source,
          module_ref: entry['module'],
          module_version: entry['module_version'],
          metadata: entry['metadata']
        )
      end

      def infer_type(name)
        value = name.to_s.downcase
        return 'port' if value.include?('port') || value.match?(%r{\A\d+/(?:tcp|udp)\z})
        return 'version' if value.include?('version')
        return 'platform' if value.include?('platform') || value == 'os' || value == 'os.family'
        return 'arch' if value.include?('arch')

        'value'
      end

      def infer_port(name)
        value = name.to_s
        match = value.match(%r{(\d+)/(?:tcp|udp)}i) || value.match(/port[._-]?(\d+)/i)
        match ? match[1].to_i : nil
      end

      def infer_proto(name)
        value = name.to_s
        match = value.match(%r{\d+/(tcp|udp)}i)
        match ? match[1].downcase : nil
      end

      def name_filter_match?(fact, name)
        return true if name.nil?

        normalized = name.to_s
        return true if fact['name'].casecmp?(normalized)

        fact['type'].casecmp?(normalized)
      end

      def type_filter_match?(fact, type)
        type.nil? || fact['type'].casecmp?(type.to_s)
      end

      def port_filter_match?(fact, port)
        port.nil? || fact['port'] == port.to_i || fact['value'].to_s == port.to_s
      end

      def proto_filter_match?(fact, proto)
        proto.nil? || fact['proto'].nil? || fact['proto'].casecmp?(proto.to_s)
      end

      def target_filter_match?(entry_target, requested_target)
        requested_target.nil? || entry_target.nil? || entry_target.to_s == requested_target.to_s
      end

      def workspace_filter_match?(entry_workspace, requested_workspace)
        requested_workspace.nil? || entry_workspace.nil? || entry_workspace.to_s == requested_workspace.to_s
      end

      def value_filter_match?(fact, value)
        value.nil? || fact['value'].to_s == value.to_s
      end

      def stringify_keys(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, child), result|
            normalized_key = key.to_s
            result[normalized_key[0].upcase + normalized_key[1..]] = stringify_keys(child)
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
