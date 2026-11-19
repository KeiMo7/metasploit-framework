# frozen_string_literal: true

module Msf
  module Preflight
    # Runs dependency and payload checks for a module instance.
    class Runner
      def initialize(mod, payload_name: nil, payload: nil, fact_store: nil)
        @mod = mod
        @payload_name = payload_name || (payload.refname if payload.respond_to?(:refname))
        @fact_store = fact_store
      end

      # @return [Result]
      def run
        definition = @mod.dependency_definition
        unless @mod.preflight_enabled?
          return Result.new(
            module_ref: module_ref,
            module_version: module_version,
            enforced: false,
            environment: {},
            warnings: []
          )
        end

        store = combined_fact_store
        environment = Environment.new(@mod, fact_store: store)
        warnings = []
        if definition.schema_version > SCHEMA_VERSION
          warnings << "Dependency declaration schema #{definition.schema_version} is newer than supported " \
                      "schema #{SCHEMA_VERSION}; unknown fields were ignored"
        end
        if @mod.respond_to?(:preflight_manual_fact_warnings)
          warnings.concat(@mod.preflight_manual_fact_warnings)
        end

        dependency_result = DependencyValidator.new(
          definition: definition,
          fact_store: store,
          target: environment.target,
          workspace: workspace
        ).validate

        selection_required = !@payload_name.nil? || definition.payload_selection['AutoSelect'] == true
        payload_result = PayloadSelector.new(
          @mod,
          environment: environment,
          fact_store: store
        ).evaluate(
          requested_payload: @payload_name,
          selection_required: selection_required
        )

        Result.new(
          module_ref: module_ref,
          module_version: module_version,
          enforced: definition.dependency_checks? || definition.payload_policy?,
          environment: environment.to_h,
          warnings: dependency_result['warnings'] + warnings,
          missing_dependencies: dependency_result['missing_dependencies'],
          missing_information: dependency_result['missing_information'] + payload_result['missing_information'],
          payload_candidates: payload_result['payload_candidates'],
          excluded_payloads: payload_result['excluded_payloads'],
          selected_payload: payload_result['selected_payload'],
          selected_payload_reason: payload_result['selection_reason'],
          payload_selection_required: selection_required
        )
      end

      private

      def combined_fact_store
        base = @fact_store || begin
          @mod.preflight_fact_store if @mod.respond_to?(:preflight_fact_store)
        end
        base ||= FactStore.new
        manual = if @mod.respond_to?(:preflight_manual_fact_store)
                   @mod.preflight_manual_fact_store
                 else
                   FactStore.new
                 end
        base.merge(manual)
      end

      def module_ref
        @mod.refname if @mod.respond_to?(:refname)
      end

      def module_version
        @mod.preflight_module_version if @mod.respond_to?(:preflight_module_version)
      end

      def workspace
        @mod.workspace if @mod.respond_to?(:workspace)
      end
    end
  end
end
