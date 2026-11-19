# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Preflight::Runner do
  subject(:result) { described_class.new(mod).run }

  let(:store) { Msf::Preflight::FactStore.new }
  let(:platform_list) { instance_double(Msf::Module::PlatformList, names: ['windows'], all?: false) }
  let(:payload) do
    instance_double(
      Msf::Payload,
      platform: platform_list,
      arch: ['x64'],
      rank: Msf::ExcellentRanking,
      notes: { 'Stability' => [] },
      staged?: false,
      handler_klass: Msf::Handler::ReverseHttp,
      refname: 'windows/x64/meterpreter/reverse_https'
    )
  end
  let(:definition) do
    Msf::Preflight::DependencyDefinition.new(
      'RequiredModules' => [
        {
          'Module' => 'auxiliary/scanner/http/example',
          'Version' => '>= 1.0.0, < 2.0.0'
        }
      ],
      'RequiresInformation' => [
        {
          'Name' => 'service.version',
          'Type' => 'version',
          'ManualOption' => 'APP_VERSION'
        }
      ],
      'PayloadSelection' => {
        'AutoSelect' => true
      }
    )
  end
  let(:mod) do
    double(
      'module',
      dependency_definition: definition,
      preflight_enabled?: true,
      preflight_fact_store: store,
      preflight_manual_fact_warnings: [],
      preflight_manual_fact_store: Msf::Preflight::FactStore.new,
      preflight_module_version: '1.0.0',
      refname: 'exploit/test/chain',
      workspace: 'default',
      datastore: { 'RHOST' => '192.0.2.10', 'LPORT' => 4444 },
      rhost: '192.0.2.10',
      compatible_payloads: [['windows/x64/meterpreter/reverse_https', payload]],
      framework: nil
    )
  end

  it 'blocks with structured prerequisites and missing environment facts' do
    expect(result.status).to eq('blocked')
    expect(result.missing_dependencies).to include(
      a_hash_including('module' => 'auxiliary/scanner/http/example')
    )
    expect(result.missing_information.map { |entry| entry['name'] })
      .to include('service.version', 'os.family', 'os.arch', 'open_port')
  end

  context 'when prerequisite output and payload environment facts are available' do
    before do
      store.record_module_run(
        module_ref: 'auxiliary/scanner/http/example',
        module_version: '1.3.0',
        target: '192.0.2.10'
      )
      store.record_fact(
        name: 'service.version',
        value: '5.4.1',
        type: 'version',
        target: '192.0.2.10',
        source: 'scanner'
      )
      store.record_fact(name: 'os.family', value: 'windows', type: 'platform', target: '192.0.2.10', source: 'scanner')
      store.record_fact(name: 'os.arch', value: 'x64', type: 'arch', target: '192.0.2.10', source: 'scanner')
      store.record_fact(
        name: 'open_port',
        value: 443,
        type: 'port',
        port: 443,
        proto: 'tcp',
        target: '192.0.2.10',
        source: 'scanner'
      )
      store.record_fact(name: 'protection.dep', value: true, target: '192.0.2.10', source: 'scanner')
    end

    it 'allows execution and records the selected payload rationale' do
      expect(result.status).to eq('ok')
      expect(result.selected_payload).to eq('windows/x64/meterpreter/reverse_https')
      expect(result.selected_payload_reason).to include('combined success/stealth score')
    end
  end
end
