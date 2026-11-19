# frozen_string_literal: true

require 'json'

module Msf
  module Module
    # Optional preflight metadata and run-time hooks shared by all modules.
    module Dependencies
      attr_accessor :preflight_result, :preflight_cleanup_scope

      # @return [Msf::Preflight::DependencyDefinition]
      def dependency_definition
        @dependency_definition ||= Msf::Preflight::DependencyDefinition.new(module_info && module_info['Dependencies'])
      end

      # @return [Hash, nil]
      def dependency_metadata
        module_info && module_info['Dependencies']
      end

      # @return [Boolean]
      def preflight_enabled?
        dependency_definition.any?
      end

      # @return [Msf::Preflight::FactStore]
      def preflight_fact_store
        if respond_to?(:framework) && framework.respond_to?(:preflight_facts)
          framework.preflight_facts
        else
          @preflight_fact_store ||= Msf::Preflight::FactStore.new
        end
      end

      # @return [String, nil]
      def preflight_target
        if respond_to?(:rhost)
          value = rhost
          return value.to_s if value && !value.to_s.empty?
        end

        datastore['RHOST']&.to_s if datastore
      end

      # @return [String]
      def preflight_module_version
        module_info['Version'].to_s
      end

      # @return [Array<String>]
      def preflight_manual_fact_warnings
        @preflight_manual_fact_warnings || []
      end

      # Import manually supplied facts from `PREFLIGHT_FACTS` and the generated
      # per-requirement options.
      #
      # @return [Msf::Preflight::FactStore]
      def preflight_manual_fact_store
        store = Msf::Preflight::FactStore.new
        @preflight_manual_fact_warnings = []
        import_manual_json_facts(store)
        import_manual_option_facts(store)
        store
      end

      # @return [Msf::Preflight::Result]
      def preflight_check(payload_name: nil, payload: nil, fact_store: nil)
        Msf::Preflight::Runner.new(
          self,
          payload_name: payload_name,
          payload: payload,
          fact_store: fact_store
        ).run
      end

      # Record this module and any declared produced information after a
      # successful execution.
      #
      # @return [void]
      def preflight_record_execution(success: true)
        return unless success && preflight_enabled?

        store = preflight_fact_store
        store.record_module_run(
          module_ref: refname,
          module_version: preflight_module_version,
          target: preflight_target,
          workspace: workspace,
          run_id: (run_uuid if respond_to?(:run_uuid))
        )

        dependency_definition.produced_information.each do |information|
          value = produced_information_value(information)
          next if value.nil?

          store.record_fact(
            name: information['Name'],
            value: value,
            type: information['Type'],
            target: preflight_target,
            port: information['Port'],
            proto: information['Proto'],
            source: 'module',
            module_ref: refname,
            module_version: preflight_module_version,
            metadata: information['Metadata']
          )
        end
      end

      # Print the human-readable preflight report and persist its structured
      # form when requested.
      #
      # @return [void]
      def preflight_publish(result, include_human: true)
        if include_human
          result.human_readable.each do |level, text|
            case level
            when :error
              print_error(text) if respond_to?(:print_error)
            when :warning
              print_warning(text) if respond_to?(:print_warning)
            else
              print_status(text) if respond_to?(:print_status)
            end
          end
        end

        write_preflight_report(result)
        if preflight_json_output? && respond_to?(:print_line)
          print_line(result.to_json)
        end
      end

      # Print and persist the cleanup portion of a completed preflight result.
      #
      # @return [void]
      def preflight_publish_cleanup(result)
        result.cleanup_human_readable.each do |level, text|
          case level
          when :error
            print_error(text) if respond_to?(:print_error)
          when :warning
            print_warning(text) if respond_to?(:print_warning)
          else
            print_status(text) if respond_to?(:print_status)
          end
        end

        write_preflight_report(result)
        if preflight_json_output? && respond_to?(:print_line)
          print_line(result.to_json)
        end
      end

      # Register the optional preflight controls without changing modules that
      # have no preflight metadata.
      #
      # @return [void]
      def setup_preflight_options
        return unless preflight_enabled?

        options_to_register = [
          Msf::OptString.new(
            'PREFLIGHT_FACTS',
            [false, 'Discovered environment facts as JSON, for example {"os.family":"windows","open_port":443}']
          ),
          Msf::OptBool.new(
            'PREFLIGHT_JSON',
            [false, 'Print the structured preflight result as JSON', false]
          ),
          Msf::OptPath.new(
            'PreflightReportFile',
            [false, 'Write the structured preflight and cleanup report to this file']
          )
        ]

        dependency_definition.required_information.each do |information|
          next if information['Name'].to_s.empty?

          option_name = manual_option_name(information)
          next if options.get(option_name)

          options_to_register << Msf::OptString.new(
            option_name,
            [false, "Manually provide #{information['Name']} for preflight validation"]
          )
        end

        register_advanced_options(options_to_register)
      end

      private

      def import_manual_json_facts(store)
        raw = datastore['PREFLIGHT_FACTS'] if datastore
        return if raw.nil? || raw.to_s.strip.empty?

        store.import(raw, source: 'manual', target: preflight_target)
      rescue ArgumentError => e
        @preflight_manual_fact_warnings << e.message
      end

      def import_manual_option_facts(store)
        return unless datastore

        dependency_definition.required_information.each do |information|
          next if information['Name'].to_s.empty?

          option_name = manual_option_name(information)
          value = datastore[option_name]
          next if value.nil? || value.to_s.strip.empty?

          store.record_fact(
            name: information['Name'],
            value: value,
            type: information['Type'],
            target: preflight_target,
            port: information['Port'] || infer_port(information['Name']),
            proto: information['Proto'] || infer_proto(information['Name']),
            source: 'manual',
            metadata: { 'option' => option_name }
          )
        end
      end

      def manual_option_name(information)
        explicit = information['ManualOption']
        return explicit.to_s unless explicit.nil? || explicit.to_s.empty?

        suffix = information['Name'].to_s.upcase.gsub(/[^A-Z0-9]+/, '_').gsub(/\A_+|_+\z/, '')
        "#{Msf::Preflight::DEFAULT_MANUAL_OPTION_PREFIX}#{suffix}"
      end

      def produced_information_value(information)
        return information['Value'] unless information['Value'].nil?

        if information['Datastore'] && datastore
          value = datastore[information['Datastore']]
          return value unless value.nil?
        end

        if information['Method'] && respond_to?(information['Method'], true)
          return send(information['Method'])
        end

        nil
      end

      def preflight_json_output?
        datastore && datastore['PREFLIGHT_JSON']
      end

      def write_preflight_report(result)
        path = datastore && datastore['PreflightReportFile']
        path ||= ENV['MSF_PREFLIGHT_REPORT']
        return if path.nil? || path.to_s.empty?

        File.write(path, JSON.pretty_generate(result.to_h))
      rescue StandardError => e
        print_error("Failed to write preflight report to #{path}: #{e.message}") if respond_to?(:print_error)
        elog('Failed to write preflight report', error: e) if respond_to?(:elog)
      end

      def infer_port(name)
        match = name.to_s.match(%r{(\d+)/(?:tcp|udp)}i) || name.to_s.match(/port[._-]?(\d+)/i)
        match ? match[1].to_i : nil
      end

      def infer_proto(name)
        match = name.to_s.match(%r{\d+/(tcp|udp)}i)
        match ? match[1].downcase : nil
      end
    end
  end
end
