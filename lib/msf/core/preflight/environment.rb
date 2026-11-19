# frozen_string_literal: true

module Msf
  module Preflight
    # Builds the observed target environment used for payload evaluation.
    # Missing observations are reported as missing rather than replaced with a
    # module's declared target metadata.
    class Environment
      PROTECTION_NAMES = {
        'aslr' => 'ASLR',
        'dep' => 'DEP',
        'nx' => 'NX',
        'av' => 'antivirus',
        'antivirus' => 'antivirus',
        'edr' => 'EDR',
        'firewall' => 'firewall',
        'waf' => 'WAF'
      }.freeze

      attr_reader :target, :platform, :arch, :ports, :protections, :egress_ports, :sources

      def initialize(mod, fact_store:)
        @mod = mod
        @fact_store = fact_store
        @target = target_address
        @sources = {}
        @platform = observed_platform
        @arch = observed_arch
        @ports = observed_ports
        @egress_ports = observed_egress_ports
        @protections = observed_protections
      end

      # @return [Boolean]
      def platform_known?
        !platform.nil? && !platform.empty?
      end

      # @return [Boolean]
      def arch_known?
        !arch.nil? && !arch.empty?
      end

      # @return [Boolean]
      def ports_known?
        ports.any?
      end

      # @return [Boolean]
      def protections_known?
        protections.any?
      end

      # @return [Integer, nil]
      def target_port
        value = (datastore['LPORT'] || datastore['RPORT']) if datastore
        value&.to_i
      end

      # @return [Hash]
      def to_h
        {
          'target' => target,
          'platform' => platform_value,
          'arch' => arch_value,
          'ports' => ports,
          'egress_ports' => egress_ports,
          'protections' => protections,
          'sources' => sources,
          'known' => {
            'platform' => platform_known?,
            'arch' => arch_known?,
            'ports' => ports_known?,
            'protections' => protections_known?
          }
        }
      end

      private

      def platform_value
        return { 'value' => nil, 'source' => nil } if platform.nil?

        { 'value' => platform, 'source' => sources[:platform] }
      end

      def arch_value
        return { 'value' => nil, 'source' => nil } if arch.nil?

        { 'value' => arch, 'source' => sources[:arch] }
      end

      def observed_platform
        fact = first_fact(%w[os.family os.platform platform target.platform])
        if fact
          @sources[:platform] = fact['source']
          return normalize_platform(fact['value'])
        end

        db_platform.tap { |value| @sources[:platform] = 'database' if value }
      end

      def observed_arch
        fact = first_fact(%w[os.arch arch target.arch])
        if fact
          @sources[:arch] = fact['source']
          return normalize_arch(fact['value'])
        end

        db_arch.tap { |value| @sources[:arch] = 'database' if value }
      end

      def observed_ports
        facts = @fact_store.facts.select do |fact|
          target_matches?(fact) && (fact['type'] == 'port' || fact['port'])
        end
        @sources[:ports] = facts.map { |fact| fact['source'] }.uniq if facts.any?
        facts.map do |fact|
          {
            'port' => (fact['port'] || fact['value']).to_i,
            'proto' => fact['proto'] || 'tcp',
            'source' => fact['source']
          }
        end.uniq
      end

      def observed_egress_ports
        facts = @fact_store.facts.select do |fact|
          target_matches?(fact) &&
            (fact['name'].to_s.downcase.include?('egress') ||
              fact['name'].to_s.downcase.include?('outbound'))
        end
        facts.map { |fact| (fact['port'] || fact['value']).to_i }.uniq
      end

      def observed_protections
        result = {}
        @fact_store.facts.each do |fact|
          next unless target_matches?(fact)

          normalized_name = fact['name'].to_s.downcase.sub(/\A(?:protection|protections)[._-]/, '')
          next unless PROTECTION_NAMES.key?(normalized_name)

          result[PROTECTION_NAMES[normalized_name]] = fact['value']
        end

        @sources[:protections] = 'discovered' if result.any?
        result
      end

      def first_fact(names)
        names.each do |name|
          facts = @fact_store.find_facts(name: name, target: target)
          return facts.last if facts.any?
        end
        nil
      end

      def target_matches?(fact)
        target.nil? || fact['target'].nil? || fact['target'].to_s == target.to_s
      end

      def normalize_platform(value)
        value = value.first if value.is_a?(Array)
        case value.to_s.downcase
        when 'win', 'win32', 'win64', 'windows'
          'windows'
        when 'osx', 'macos', 'darwin'
          'osx'
        when 'unix'
          'unix'
        else
          value.to_s.downcase
        end
      end

      def normalize_arch(value)
        value = value.first if value.is_a?(Array)
        case value.to_s.downcase
        when 'amd64', 'x86_64', 'x64'
          'x64'
        when 'i386', 'i686', 'x86'
          'x86'
        when 'aarch64', 'arm64'
          'aarch64'
        else
          value.to_s.downcase
        end
      end

      def target_address
        if @mod.respond_to?(:rhost)
          value = @mod.rhost
          return value.to_s if value && !value.to_s.empty?
        end

        datastore['RHOST']&.to_s
      end

      def datastore
        @mod.datastore if @mod.respond_to?(:datastore)
      end

      def db_platform
        host = db_host
        return nil unless host

        host.respond_to?(:os_name) ? host.os_name : nil
      rescue StandardError
        nil
      end

      def db_arch
        host = db_host
        return nil unless host

        host.respond_to?(:arch) ? host.arch : nil
      rescue StandardError
        nil
      end

      def db_host
        return nil unless target
        return nil unless @mod.respond_to?(:framework)

        framework = @mod.framework
        return nil unless framework.respond_to?(:db) && framework.db&.active

        framework.db.get_host(workspace: @mod.workspace, address: target)
      rescue StandardError
        nil
      end
    end
  end
end
