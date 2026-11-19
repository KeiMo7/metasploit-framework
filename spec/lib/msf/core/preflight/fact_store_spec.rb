# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Preflight::FactStore do
  subject(:store) { described_class.new }

  describe '#import' do
    it 'imports compact JSON facts for manual degradation workflows' do
      store.import(
        {
          'os.family' => 'windows',
          'os.arch' => 'x64',
          'open_port' => { 'value' => 443, 'proto' => 'tcp' }
        },
        source: 'manual',
        target: '192.0.2.10'
      )

      expect(store.include?(name: 'os.family', type: 'platform')).to be(true)
      expect(store.include?(name: 'open_port', type: 'port', port: 443, proto: 'tcp')).to be(true)
    end

    it 'imports recorded prerequisite module executions' do
      store.import(
        {
          'modules' => [
            {
              'module' => 'auxiliary/scanner/http/example',
              'version' => '1.3.0'
            }
          ]
        },
        target: '192.0.2.10'
      )

      expect(store.module_run('auxiliary/scanner/http/example', target: '192.0.2.10'))
        .to include('module_version' => '1.3.0')
    end

    it 'rejects malformed manual JSON' do
      expect { store.import('{not-json') }.to raise_error(ArgumentError, /not valid JSON/)
    end
  end

  it 'keeps facts for different target ports separately' do
    store.record_fact(name: 'open_port', value: 80, type: 'port', port: 80, proto: 'tcp')
    store.record_fact(name: 'open_port', value: 443, type: 'port', port: 443, proto: 'tcp')

    expect(store.find_facts(name: 'open_port', type: 'port').map { |fact| fact['value'] })
      .to contain_exactly(80, 443)
  end
end
