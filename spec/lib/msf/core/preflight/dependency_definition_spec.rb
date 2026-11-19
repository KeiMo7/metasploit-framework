# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Preflight::DependencyDefinition do
  subject(:definition) do
    described_class.new(
      'SchemaVersion' => 1,
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
      'Produces' => [
        {
          'Name' => 'service.platform',
          'Datastore' => 'APP_PLATFORM'
        }
      ],
      'PayloadSelection' => {
        'AutoSelect' => true
      }
    )
  end

  it 'normalizes all three dependency declaration categories' do
    expect(definition.required_modules.first['Module']).to eq('auxiliary/scanner/http/example')
    expect(definition.required_information.first['Name']).to eq('service.version')
    expect(definition.produced_information.first['Datastore']).to eq('APP_PLATFORM')
  end

  it 'retains the required prerequisite module version range' do
    expect(definition.required_modules.first['Version']).to eq('>= 1.0.0, < 2.0.0')
  end

  it 'exposes payload selection policy from module metadata' do
    expect(definition.payload_selection).to eq('AutoSelect' => true)
  end

  it 'accepts a string prerequisite module declaration for backward compatibility' do
    definition = described_class.new('Requires' => ['auxiliary/scanner/http/example'])

    expect(definition.required_modules).to include(
      a_hash_including('Module' => 'auxiliary/scanner/http/example')
    )
  end
end
