# frozen_string_literal: true

require 'json'

module Msf
  module Preflight
    # Structured result returned by a preflight run.
    class Result
      attr_accessor :cleanup
      attr_reader :warnings, :missing_dependencies, :missing_information,
                  :payload_candidates, :excluded_payloads, :selected_payload,
                  :environment, :module_ref, :module_version, :enforced,
                  :payload_selection_required, :selected_payload_reason
      alias enforced? enforced

      # rubocop:disable Metrics/ParameterLists
      def initialize(module_ref:, module_version:, enforced:, environment:, warnings: [],
                     missing_dependencies: [], missing_information: [],
                     payload_candidates: [], excluded_payloads: [],
                     selected_payload: nil, selected_payload_reason: nil,
                     payload_selection_required: false, cleanup: nil)
        @module_ref = module_ref
        @module_version = module_version
        @enforced = enforced
        @environment = environment || {}
        @warnings = warnings
        @missing_dependencies = missing_dependencies
        @missing_information = missing_information
        @payload_candidates = payload_candidates
        @excluded_payloads = excluded_payloads
        @selected_payload = selected_payload
        @selected_payload_reason = selected_payload_reason
        @payload_selection_required = payload_selection_required
        @cleanup = cleanup
      end
      # rubocop:enable Metrics/ParameterLists

      # @return [Boolean]
      def allowed?
        return true unless enforced?

        missing_dependencies.empty? && missing_information.empty? && !payload_failure
      end

      # @return [String]
      def status
        return 'not_applicable' unless enforced?
        return 'blocked' unless allowed?
        return 'degraded' if warnings.any?

        'ok'
      end

      # @return [Array<Hash>]
      def missing
        missing_dependencies + missing_information + excluded_payloads
      end

      # @return [Boolean, nil]
      def payload_failure
        payload_selection_required && selected_payload.nil?
      end

      # @return [Hash]
      def to_h
        {
          'schema_version' => SCHEMA_VERSION,
          'module' => module_ref,
          'module_version' => module_version,
          'status' => status,
          'allowed' => allowed?,
          'enforced' => enforced?,
          'environment' => environment,
          'missing' => {
            'dependencies' => missing_dependencies,
            'information' => missing_information,
            'payloads' => excluded_payloads
          },
          'warnings' => warnings,
          'payload_candidates' => payload_candidates,
          'selected_payload' => selected_payload,
          'selected_payload_reason' => selected_payload_reason,
          'payload_selection_required' => payload_selection_required,
          'cleanup' => cleanup
        }
      end

      # @return [String]
      def to_json(*)
        to_h.to_json(*)
      end

      # @return [Array<Array(Symbol, String)>]
      def human_readable
        lines = []
        lines << [:status, "Preflight for #{module_ref}:#{module_version}: #{status}"]

        if missing_dependencies.any?
          lines << [:error, 'Missing prerequisite modules:']
          missing_dependencies.each do |item|
            version = item['required_version'] ? " (#{item['required_version']})" : ''
            lines << [:error, "  - #{item['module']}#{version}: #{item['message']}"]
          end
        end

        if missing_information.any?
          lines << [:error, 'Missing required information:']
          missing_information.each do |item|
            hint = if item['manual_option']
                     " (set #{item['manual_option']})"
                   else
                     ' (supply it with PREFLIGHT_FACTS)'
                   end
            lines << [:error, "  - #{item['name']} [#{item['type']}]#{hint}: #{item['message']}"]
          end
        end

        warnings.each do |warning|
          lines << [:warning, "Preflight warning: #{warning}"]
        end

        if payload_candidates.any?
          lines << [:status, 'Payload ranking:']
          payload_candidates.each_with_index do |candidate, index|
            lines << [:status, "  #{index + 1}. #{candidate['payload']} (score #{candidate['score']})"]
            Array(candidate['reasons']).each { |reason| lines << [:status, "     - #{reason}"] }
          end
        end

        if selected_payload
          lines << [:status, "Selected payload: #{selected_payload} (#{selected_payload_reason})"]
        end

        if excluded_payloads.any?
          lines << [:warning, 'Excluded payloads:']
          excluded_payloads.each do |candidate|
            lines << [:warning, "  - #{candidate['payload']}: #{candidate['reason']}"]
          end
        end

        if cleanup
          lines << [:status, 'Cleanup after failed run:']
          lines.concat(cleanup_human_readable)
        end

        lines
      end

      # @return [Array<Array(Symbol, String)>]
      def cleanup_human_readable
        return [] unless cleanup

        cleanup_lines
      end

      def summary
        human_readable.map { |_level, text| text }.join("\n")
      end

      private

      def cleanup_lines
        lines = []
        Array(cleanup['sessions']).each do |session|
          lines << [
            session['status'] == 'failed' ? :error : :status,
            "  - session #{session['sid']}: #{session['status']}#{session['error'] ? " (#{session['error']})" : ''}"
          ]
        end
        Array(cleanup['files']).each do |file|
          lines << [
            file['status'] == 'failed' ? :error : :status,
            "  - #{file['type']} #{file['path']}: #{file['status']}#{file['error'] ? " (#{file['error']})" : ''}"
          ]
        end
        Array(cleanup['errors']).each do |error|
          lines << [:error, "  - #{error['operation']}: failed (#{error['error']})"]
        end
        lines
      end
    end
  end
end
