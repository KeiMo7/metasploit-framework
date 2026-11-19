# frozen_string_literal: true

module Msf
  module Preflight
    # Validates required module executions and discovered information against a
    # {FactStore}. Version mismatches are warnings by default so a module can
    # still be used when a dependency's version cannot be verified.
    class DependencyValidator
      def initialize(definition:, fact_store:, target: nil, workspace: nil)
        @definition = definition
        @fact_store = fact_store
        @target = target
        @workspace = workspace
      end

      # @return [Hash]
      def validate
        missing_dependencies = []
        missing_information = []
        warnings = []

        @definition.required_modules.each do |dependency|
          check_module(dependency, missing_dependencies, warnings)
        end

        @definition.required_information.each do |information|
          check_information(information, missing_information)
        end

        {
          'missing_dependencies' => missing_dependencies,
          'missing_information' => missing_information,
          'warnings' => warnings
        }
      end

      private

      def check_module(dependency, missing, warnings)
        module_ref = dependency['Module']
        run = @fact_store.module_run(module_ref, target: @target, workspace: @workspace)

        unless run
          missing << missing_module(module_ref, dependency['Version'], 'has not completed successfully')
          return
        end

        check_version(dependency, run, warnings)
        Array(dependency['Information']).each do |information_name|
          next if information_available?(information_name)

          warnings << "Required module #{module_ref} ran, but reported information #{information_name} is unavailable"
        end
      end

      def check_version(dependency, run, warnings)
        requirement = dependency['Version']
        return if requirement.nil? || requirement.to_s.strip.empty?

        version = run['module_version']
        unless version && version_parseable?(version)
          warnings << "Cannot verify version constraint #{requirement.inspect} for #{dependency['Module']}: " \
                      "reported version #{version.inspect} is not parseable"
          return
        end

        unless requirement_satisfied?(version, requirement)
          message = "#{dependency['Module']} version #{version} is outside the required range #{requirement}"
          case dependency['OnVersionMismatch']
          when 'block', 'fail'
            warnings << message
          when 'skip'
            warnings << "#{message}; continuing because OnVersionMismatch is skip"
          else
            warnings << "#{message}; continuing because OnVersionMismatch is warn"
          end
        end
      end

      def check_information(information, missing)
        return unless information['Required']

        name = information['Name']
        type = information['Type']
        port = information['Port'] || extract_port(name)
        proto = information['Proto'] || extract_proto(name)
        value = information['Value']

        found = @fact_store.include?(
          name: name,
          type: type,
          port: port,
          proto: proto,
          target: @target,
          value: value
        )
        if !found && name.to_s.empty?
          found = @fact_store.include?(
            name: type,
            type: type,
            port: port,
            proto: proto,
            target: @target,
            value: value
          )
        end
        return if found

        missing << {
          'kind' => 'information',
          'name' => name,
          'type' => type,
          'port' => port,
          'proto' => proto,
          'required_by' => information.dig('Metadata', 'RequiredBy'),
          'manual_option' => information['ManualOption'],
          'message' => information['Description'] || 'required information was not discovered',
          'reason' => 'not_discovered'
        }
      end

      def information_available?(name)
        @fact_store.include?(name: name, target: @target)
      end

      def missing_module(module_ref, version, reason)
        {
          'kind' => 'module',
          'module' => module_ref,
          'required_version' => version,
          'message' => "#{reason}; run it first or provide its output as a preflight fact",
          'reason' => 'not_executed'
        }
      end

      def version_parseable?(version)
        defined?(Rex::Version) && Rex::Version.correct?(version.to_s)
      end

      def requirement_satisfied?(version, requirement)
        requirements = Array(requirement).flat_map { |value| value.to_s.split(',') }.map(&:strip).reject(&:empty?)
        gem_requirement = Gem::Requirement.new(requirements)
        gem_requirement.satisfied_by?(Rex::Version.new(version.to_s))
      rescue ArgumentError
        false
      end

      def extract_port(name)
        match = name.to_s.match(%r{(\d+)/(?:tcp|udp)}i) || name.to_s.match(/port[._-]?(\d+)/i)
        match ? match[1].to_i : nil
      end

      def extract_proto(name)
        match = name.to_s.match(%r{\d+/(tcp|udp)}i)
        match ? match[1].downcase : nil
      end
    end
  end
end
