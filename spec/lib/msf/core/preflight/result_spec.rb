# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Preflight::Result do
  subject(:result) do
    described_class.new(
      module_ref: 'exploit/test/chain',
      module_version: '1.0.0',
      enforced: true,
      environment: { 'platform' => { 'value' => 'windows' } },
      missing_dependencies: [
        {
          'kind' => 'module',
          'module' => 'auxiliary/scanner/http/example',
          'message' => 'has not completed successfully',
          'reason' => 'not_executed'
        }
      ],
      missing_information: [
        {
          'kind' => 'information',
          'name' => 'service.version',
          'type' => 'version',
          'manual_option' => 'APP_VERSION',
          'message' => 'required information was not discovered',
          'reason' => 'not_discovered'
        }
      ],
      excluded_payloads: [
        {
          'payload' => 'windows/x64/meterpreter/reverse_tcp',
          'reason' => 'target architecture x64 is not supported'
        }
      ],
      payload_selection_required: true
    )
  end

  it 'reports a blocked status when dependencies are missing' do
    expect(result.allowed?).to be(false)
    expect(result.status).to eq('blocked')
  end

  it 'provides machine-readable missing entries and payload exclusions' do
    data = result.to_h

    expect(data.dig('missing', 'dependencies')).to include(
      a_hash_including('module' => 'auxiliary/scanner/http/example')
    )
    expect(data.dig('missing', 'information')).to include(
      a_hash_including('name' => 'service.version')
    )
    expect(data.dig('missing', 'payloads')).to include(
      a_hash_including('payload' => 'windows/x64/meterpreter/reverse_tcp')
    )
    expect(data['allowed']).to be(false)
  end

  it 'serializes to JSON for CI consumers' do
    expect(JSON.parse(result.to_json).fetch('status')).to eq('blocked')
  end
end
