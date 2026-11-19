# frozen_string_literal: true

module Msf
  module Preflight
    # Evaluates payloads against observed target facts and ranks viable choices
    # by expected success and stealth. The result includes an explanation for
    # every candidate and every exclusion.
    class PayloadSelector
      TRANSPORT_SCORES = {
        'https' => 30,
        'http' => 20,
        'dns' => 24,
        'named_pipe' => 12,
        'tcp' => 6,
        'udp' => 4,
        'sctp' => 5
      }.freeze

      def initialize(exploit, environment:, fact_store:)
        @exploit = exploit
        @environment = environment
        @fact_store = fact_store
        @selection_policy = if exploit.respond_to?(:dependency_definition)
                              exploit.dependency_definition.payload_selection
                            else
                              {}
                            end
      end

      # @param requested_payload [String, nil]
      # @param selection_required [Boolean]
      # @return [Hash]
      def evaluate(requested_payload: nil, selection_required: false)
        candidates = candidate_payloads(requested_payload)
        evaluations = candidates.map { |name, payload| evaluate_payload(name, payload) }
        eligible, excluded_candidates = evaluations.partition { |candidate| candidate['eligible'] }

        selected = if requested_payload
                     eligible.find { |candidate| candidate['payload'] == requested_payload }
                   elsif auto_select?
                     eligible.first
                   end
        if selection_required && evaluations.empty?
          excluded_candidates << excluded(
            requested_payload || 'any',
            'no payload candidates were returned for the selected target',
            code: 'no_candidates'
          )
        end
        selection_reason = selected_reason(selected, eligible, requested_payload)

        missing_information = missing_environment_information(selection_required || requested_payload)

        {
          'selected_payload' => selected&.fetch('payload'),
          'selection_reason' => selection_reason,
          'payload_candidates' => eligible.sort_by { |candidate| [-candidate['score'], candidate['payload']] },
          'excluded_payloads' => excluded_candidates.sort_by { |candidate| candidate['payload'] },
          'missing_information' => missing_information
        }
      end

      def auto_select?
        @selection_policy['AutoSelect'] == true
      end

      private

      def candidate_payloads(requested_payload)
        pairs = if @exploit.respond_to?(:compatible_payloads)
                  @exploit.compatible_payloads(excluded_platforms: ['Multi'])
                else
                  []
                end
        pairs = pairs.to_a

        if requested_payload && pairs.none? { |name, _payload| name == requested_payload }
          pairs << [requested_payload, create_payload(requested_payload)]
        end

        pairs.uniq { |name, _payload| name }
      rescue StandardError => e
        @exploit.respond_to?(:elog) && @exploit.elog('Failed to enumerate compatible payloads', error: e)
        requested_payload ? [[requested_payload, create_payload(requested_payload)]] : []
      end

      def evaluate_payload(name, payload)
        payload = payload_instance(name, payload)
        unless payload
          return excluded(name, 'payload module could not be loaded', code: 'payload_load_error')
        end

        reasons = []
        exclusions = []
        warnings = []

        check_platform(payload, reasons, exclusions, warnings)
        check_arch(payload, reasons, exclusions, warnings)
        check_ports(name, payload, reasons, exclusions, warnings)

        protection_score, protection_reasons, protection_exclusions =
          protection_evaluation(name, payload)
        reasons.concat(protection_reasons)
        exclusions.concat(protection_exclusions)

        return excluded(name, exclusions.join('; '), code: classify_exclusions(exclusions)) if exclusions.any?

        stability_score, stability_details = stability_evaluation(name, payload)
        stealth_score, stealth_details = stealth_evaluation(name)
        reasons.concat(stability_details)
        reasons.concat(stealth_details)
        reasons.concat(warnings)

        success_score = 50 + stability_score + protection_score
        score = success_score + stealth_score

        {
          'payload' => name,
          'eligible' => true,
          'score' => score,
          'success_score' => success_score,
          'stealth_score' => stealth_score,
          'stability_score' => stability_score,
          'rank' => rank_for(payload),
          'staged' => staged?(payload),
          'reasons' => reasons
        }
      rescue StandardError => e
        excluded(name, "payload evaluation failed: #{e.class}: #{e.message}", code: 'evaluation_error')
      end

      def check_platform(payload, reasons, exclusions, warnings)
        if !@environment.platform_known?
          warnings << 'Target platform is not confirmed by discovery; platform match is unverified'
          return
        end

        if payload_platform_all?(payload) || payload_platforms(payload).any? { |value| same_platform?(value, @environment.platform) }
          reasons << "Platform: #{@environment.platform} observed (#{@environment.sources[:platform]})"
        else
          exclusions << "target platform #{@environment.platform.inspect} does not match payload platform " \
                        "#{payload_platforms(payload).join(', ').inspect}"
        end
      end

      def check_arch(payload, reasons, exclusions, warnings)
        payload_arches = Array(payload.arch).map { |value| normalize_arch(value) }
        return if payload_arches.empty? || payload_arches.include?('any')

        if !@environment.arch_known?
          warnings << "Target architecture is not confirmed; payload requires #{payload_arches.join(', ')}"
          return
        end

        actual_arch = normalize_arch(@environment.arch)
        if payload_arches.include?(actual_arch)
          reasons << "Architecture: #{actual_arch} observed (#{@environment.sources[:arch]})"
        else
          exclusions << "target architecture #{actual_arch} is not supported by payload " \
                        "architecture #{payload_arches.join(', ')}"
        end
      end

      def check_ports(name, payload, reasons, exclusions, warnings)
        if bind_payload?(name, payload)
          port = @environment.target_port
          if @environment.ports_known?
            if port && @environment.ports.any? { |entry| entry['port'] == port }
              reasons << "Available port: #{port}/tcp was observed for bind delivery"
            elsif port
              exclusions << "bind port #{port}/tcp was not observed on the target"
            else
              exclusions << 'bind delivery requires a target port, but no open port was observed'
            end
          else
            warnings << "Open target ports are not confirmed for bind delivery#{port ? " (expected #{port}/tcp)" : ''}"
          end
        elsif reverse_payload?(name)
          lport = datastore['LPORT']&.to_i
          if @environment.ports_known? && lport
            reasons << "Observed target ports: #{format_ports(@environment.ports)}"
          elsif lport
            warnings << "Outbound path for reverse payload on port #{lport} is not confirmed"
          end
        elsif @environment.ports_known?
          reasons << "Observed target ports: #{format_ports(@environment.ports)}"
        end
      end

      def protection_evaluation(name, payload)
        reasons = []
        exclusions = []
        score = 0
        protections = @environment.protections

        if protections.empty?
          reasons << 'Protections: no discovered protection facts'
          return [score, reasons, exclusions]
        end

        protection_summary = protections.map { |key, value| "#{key}=#{value}" }.join(', ')
        reasons << "Protections: #{protection_summary}"

        if truthy?(protections['antivirus']) || truthy?(protections['EDR'])
          if encrypted_transport?(name)
            score += 8
            reasons << 'Protection fit: encrypted transport is preferable with antivirus/EDR present'
          elsif command_payload?(name)
            score -= 12
            reasons << 'Protection risk: command payload may be easier for antivirus/EDR to inspect'
          end
        end

        if truthy?(protections['firewall'])
          if bind_payload?(name, payload)
            exclusions << 'firewall was observed and bind delivery is likely blocked'
          elsif reverse_payload?(name)
            score += 5
            reasons << 'Protection fit: reverse payload matches outbound firewall traversal'
          end
        end

        if truthy?(protections['DEP']) || truthy?(protections['NX'])
          if command_payload?(name)
            score += 4
            reasons << 'Protection fit: command payload avoids executable memory requirements'
          else
            reasons << 'Protection note: DEP/NX observed; payload stability score reflects native payload support'
          end
        end

        Array(@selection_policy['BlockedByProtections']).each do |protection|
          display_name = Environment::PROTECTION_NAMES[protection.to_s] || protection.to_s
          if truthy?(protections[display_name])
            exclusions << "payload selection policy blocks payloads when #{protection} is present"
          end
        end

        [score, reasons, exclusions]
      end

      def stability_evaluation(name, payload)
        rank = rank_for(payload)
        score = (rank / 15.0).round
        details = ["Stability: #{rank_name(rank)} module rank (#{rank})"]

        if payload.respond_to?(:notes)
          stability_notes = Array(payload.notes['Stability'])
          details << "Stability notes: #{stability_notes.join(', ')}" if stability_notes.any?
          score += 4 if stability_notes.include?(Msf::CRASH_SAFE)
        end

        if staged?(payload)
          details << 'Stability: staged payload adds a stager-to-stage transition'
        else
          score += 3
          details << 'Stability: stageless payload avoids a second-stage transfer'
        end

        score -= 4 if command_payload?(name)
        [score, details]
      rescue StandardError
        [0, ['Stability: payload stability metadata unavailable']]
      end

      def stealth_evaluation(name)
        transport = detect_transport(name)
        score = TRANSPORT_SCORES.fetch(transport, 0)
        details = []

        if transport
          details << "Stealth: #{transport.upcase} transport (#{score >= 20 ? 'encrypted or common egress' : 'lower overhead'})"
        end

        if name.include?('meterpreter')
          score -= 3
          details << 'Stealth: Meterpreter session has a larger in-memory footprint'
        elsif command_payload?(name)
          score -= 2
          details << 'Stealth: command payload has no persistent session protocol'
        end

        [score, details]
      end

      def missing_environment_information(required)
        return [] unless required

        missing = []
        unless @environment.platform_known?
          missing << environment_requirement('os.family', 'platform', 'target platform')
        end
        unless @environment.arch_known?
          missing << environment_requirement('os.arch', 'arch', 'target architecture')
        end
        if @environment.ports.empty?
          missing << environment_requirement('open_port', 'port', 'observed open target ports')
        end
        missing
      end

      def selected_reason(selected, eligible, requested_payload)
        return nil unless selected

        if requested_payload
          "operator-selected payload passed environment checks; combined score #{selected['score']}"
        else
          runner_up = eligible.find { |candidate| candidate['payload'] != selected['payload'] }
          comparison = runner_up ? " ahead of #{runner_up['payload']} (#{runner_up['score']})" : ''
          "automatically selected highest combined success/stealth score #{selected['score']}#{comparison}"
        end
      end

      def environment_requirement(name, type, description)
        {
          'kind' => 'information',
          'name' => name,
          'type' => type,
          'manual_option' => nil,
          'required_by' => 'payload-selection',
          'reason' => 'not_discovered',
          'message' => "#{description} is required to validate payload suitability"
        }
      end

      def excluded(name, reason, code: 'ineligible')
        {
          'payload' => name,
          'eligible' => false,
          'reason_code' => code,
          'reason' => reason
        }
      end

      def classify_exclusions(exclusions)
        text = exclusions.join(' ')
        return 'platform_mismatch' if text.include?('target platform')
        return 'arch_mismatch' if text.include?('target architecture')
        return 'bind_port_unavailable' if text.include?('bind')
        return 'blocked_by_protection' if text.include?('protection') || text.include?('firewall')

        'environment_mismatch'
      end

      def create_payload(name)
        return nil if name.to_s.empty?

        if @exploit.respond_to?(:framework) && @exploit.framework.respond_to?(:payloads)
          @exploit.framework.payloads.create(name)
        end
      rescue StandardError
        nil
      end

      def payload_instance(name, payload)
        return create_payload(name) if payload.nil?
        return payload unless payload.is_a?(Class)

        create_payload(name) || payload.new
      rescue StandardError
        nil
      end

      def payload_platforms(payload)
        return [] unless payload.respond_to?(:platform)

        payload.platform.respond_to?(:names) ? payload.platform.names : Array(payload.platform)
      end

      def payload_platform_all?(payload)
        return true if payload.respond_to?(:platform) &&
                       payload.platform.respond_to?(:all?) &&
                       payload.platform.all?

        payload_platforms(payload).any? { |value| value.to_s.casecmp?('all') }
      end

      def same_platform?(left, right)
        normalized_left = normalize_platform(left)
        normalized_right = normalize_platform(right)
        return true if normalized_left == normalized_right
        return true if [normalized_left, normalized_right].sort == %w[linux unix]
        return true if [normalized_left, normalized_right].sort == %w[osx unix]

        false
      end

      def normalize_platform(value)
        value = value.first if value.is_a?(Array)
        case value.to_s.downcase
        when 'win', 'win32', 'win64', 'windows'
          'windows'
        when 'osx', 'macos', 'darwin'
          'osx'
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

      def bind_payload?(name, payload = nil)
        return true if name.to_s.include?('bind')

        handler = payload&.handler_klass
        handler && handler.to_s.include?('Bind')
      rescue StandardError
        false
      end

      def reverse_payload?(name)
        name.to_s.include?('reverse')
      end

      def command_payload?(name)
        name.to_s.include?('/cmd/') || name.to_s.start_with?('cmd/')
      end

      def encrypted_transport?(name)
        name.to_s.include?('https') || name.to_s.include?('ssl') || name.to_s.include?('tls')
      end

      def detect_transport(name)
        value = name.to_s.downcase
        return 'https' if value.include?('https') || value.include?('ssl') || value.include?('tls')
        return 'http' if value.include?('http')
        return 'dns' if value.include?('dns')
        return 'named_pipe' if value.include?('named_pipe')
        return 'sctp' if value.include?('sctp')
        return 'udp' if value.include?('udp')
        return 'tcp' if value.include?('tcp')

        nil
      end

      def rank_for(payload)
        payload.respond_to?(:rank) ? payload.rank.to_i : 0
      rescue StandardError
        0
      end

      def rank_name(rank)
        case rank
        when 600.. then 'excellent'
        when 500...600 then 'great'
        when 400...500 then 'good'
        when 300...400 then 'normal'
        when 200...300 then 'average'
        when 100...200 then 'low'
        else 'manual'
        end
      end

      def staged?(payload)
        payload.respond_to?(:staged?) && payload.staged?
      rescue StandardError
        false
      end

      def format_ports(ports)
        ports.map { |entry| "#{entry['port']}/#{entry['proto']}" }.uniq.join(', ')
      end

      def datastore
        @exploit.datastore if @exploit.respond_to?(:datastore)
      end

      def truthy?(value)
        value == true || value.to_s.casecmp?('true') || value.to_s == '1' || value.to_s.casecmp?('yes')
      end
    end
  end
end
