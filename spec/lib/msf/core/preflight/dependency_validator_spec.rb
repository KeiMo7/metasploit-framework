# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Preflight::DependencyValidator do
  subject(:result) do
    described_class.new(
      definition: definition,
      fact_store: store,
      target: '192.0.2.10'
    ).validate
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
      ]
    )
  end
  let(:store) { Msf::Preflight::FactStore.new }

  context 'when the prerequisite module has not run' do
    it 'returns a structured missing module entry' do
      expect(result['missing_dependencies']).to include(
        a_hash_including(
          'kind' => 'module',
          'module' => 'auxiliary/scanner/http/example',
          'required_version' => '>= 1.0.0, < 2.0.0',
          'reason' => 'not_executed'
        )
      )
    end
  end

  context 'when the prerequisite module ran successfully' do
    before do
      store.record_module_run(
        module_ref: 'auxiliary/scanner/http/example',
        module_version: '1.4.2',
        target: '192.0.2.10'
      )
    end

    it 'keeps required information missing until it is discovered or supplied manually' do
      expect(result['missing_dependencies']).to be_empty
      expect(result['missing_information']).to include(
        a_hash_including(
          'name' => 'service.version',
          'manual_option' => 'APP_VERSION',
          'reason' => 'not_discovered'
        )
      )
    end

    it 'accepts manually supplied information' do
      store.record_fact(
        name: 'service.version',
        value: '1.4.2',
        type: 'version',
        target: '192.0.2.10',
        source: 'manual'
      )

      expect(result['missing_information']).to be_empty
    end
  end

  context 'when the prerequisite module version is outside the declared range' do
    before do
      store.record_module_run(
        module_ref: 'auxiliary/scanner/http/example',
        module_version: '2.1.0',
        target: '192.0.2.10'
      )
      store.record_fact(
        name: 'service.version',
        value: '1.4.2',
        type: 'version',
        target: '192.0.2.10'
      )
    end

    it 'reports a warning instead of reusing an out-of-range declaration' do
      expect(result['warnings']).to include(
        a_string_including('outside the required range >= 1.0.0, < 2.0.0')
      )
    end
  end
end
