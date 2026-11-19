# frozen_string_literal: true

module Msf
  # Pre-execution validation for module dependencies, discovered environment
  # facts, payload suitability, and run-scoped cleanup.
  #
  # Modules opt in by adding a `Dependencies` entry to their `module_info`
  # hash. Modules without that entry keep the existing execution flow.
  module Preflight
    SCHEMA_VERSION = 1
    DEFAULT_MANUAL_OPTION_PREFIX = 'PREFLIGHT_INFO_'
  end
end
