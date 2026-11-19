# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Preflight::PayloadSelector do
  subject(:result) do
    described_class.new(exploit, environment: environment, fact_store: store).evaluate(
      requested_payload: requested_payload,
      selection_required: true
    )
  end

  let(:requested_payload) { nil }
  let(:store) { Msf::Preflight::FactStore.new }
  let(:platform_list) { instance_double(Msf::Module::PlatformList, names: ['windows'], all?: false) }
  let(:definition) { Msf::Preflight::DependencyDefinition.new('PayloadSelection' => { 'AutoSelect' => true }) }
  let(:https_payload) do
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
  let(:tcp_payload) do
    instance_double(
      Msf::Payload,
      platform: platform_list,
      arch: ['x64'],
      rank: Msf::GreatRanking,
      notes: { 'Stability' => [] },
      staged?: false,
      handler_klass: Msf::Handler::ReverseTcp,
      refname: 'windows/x64/meterpreter/reverse_tcp'
    )
  end
  let(:x86_payload) do
    instance_double(
      Msf::Payload,
      platform: platform_list,
      arch: ['x86'],
      rank: Msf::NormalRanking,
      notes: { 'Stability' => [] },
      staged?: true,
      handler_klass: Msf::Handler::ReverseTcp,
      refname: 'windows/x86/shell/reverse_tcp'
    )
  end
  let(:exploit) do
    double(
      'exploit',
      datastore: { 'LPORT' => 4444 },
      rhost: '192.0.2.10',
      dependency_definition: definition,
      compatible_payloads: [
        ['windows/x64/meterpreter/reverse_https', https_payload],
        ['windows/x64/meterpreter/reverse_tcp', tcp_payload],
        ['windows/x86/shell/reverse_tcp', x86_payload]
      ],
      framework: nil
    )
  end
  let(:environment) { Msf::Preflight::Environment.new(exploit, fact_store: store) }

  before do
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

  it 'ranks HTTPS ahead of TCP using success and stealth evidence' do
    expect(result['selected_payload']).to eq('windows/x64/meterpreter/reverse_https')
    expect(result['payload_candidates'].first['payload']).to eq('windows/x64/meterpreter/reverse_https')
    expect(result['payload_candidates'].first['score']).to be > result['payload_candidates'][1]['score']
  end

  it 'explains platform, port, protection, and stability evidence' do
    reasons = result['payload_candidates'].first['reasons'].join("\n")

    expect(reasons).to include('Platform: windows observed', '443/tcp', 'Protections: DEP=true', 'Stability: excellent')
  end

  it 'explains why the x86 payload was excluded on an x64 target' do
    expect(result['excluded_payloads']).to include(
      a_hash_including(
        'payload' => 'windows/x86/shell/reverse_tcp',
        'reason' => a_string_including('target architecture x64')
      )
    )
  end

  context 'when a payload is explicitly requested' do
    let(:requested_payload) { 'windows/x64/meterpreter/reverse_tcp' }

    it 'selects the operator choice while preserving the full ranking explanation' do
      expect(result['selected_payload']).to eq('windows/x64/meterpreter/reverse_tcp')
      expect(result['selection_reason']).to include('operator-selected payload')
    end
  end

  context 'when every payload is incompatible with the observed platform' do
    before do
      store.record_fact(
        name: 'os.family',
        value: 'linux',
        type: 'platform',
        target: '192.0.2.10',
        source: 'scanner'
      )
    end

    it 'returns no selected payload and explains every exclusion' do
      expect(result['selected_payload']).to be_nil
      expect(result['excluded_payloads'].map { |entry| entry['reason_code'] })
        .to all(eq('platform_mismatch'))
    end
  end
end
