# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Preflight::CleanupScope do
  subject(:scope) { described_class.new(mod) }

  let(:old_session) { instance_double(Msf::Session) }
  let(:new_session) { instance_double(Msf::Session) }
  let(:session_manager) do
    Class.new do
      attr_reader :sessions, :deregistered

      def initialize(sessions)
        @sessions = sessions
        @deregistered = []
      end

      def keys
        sessions.keys
      end

      def [](sid)
        sessions[sid]
      end

      def deregister(session, reason)
        @deregistered << [session, reason]
        sessions.delete(session.sid)
      end
    end.new(1 => old_session)
  end
  let(:framework) { instance_double(Msf::Framework, sessions: session_manager) }
  let(:mod) do
    double(
      'module',
      framework: framework,
      print_error: nil,
      elog: nil,
      file_rm: true,
      'preflight_cleanup_scope=' => nil
    )
  end

  before do
    allow(old_session).to receive(:sid).and_return(1)
    allow(new_session).to receive(:sid).and_return(2)
    scope.start
    session_manager.sessions[2] = new_session
  end

  it 'closes only sessions created by the current run' do
    result = scope.cleanup_failed_run!(reason: 'exploit failed')

    expect(session_manager.deregistered.map(&:first)).to eq([new_session])
    expect(session_manager.sessions).to include(1 => old_session)
    expect(result['sessions']).to include(a_hash_including('sid' => 2, 'status' => 'closed'))
  end

  it 'records artifact cleanup failures instead of silently skipping them' do
    scope.register_artifact('/tmp/dropper.bin')
    scope.record_artifact_cleanup('/tmp/dropper.bin', status: 'failed', error: 'permission denied')

    result = scope.cleanup_failed_run!(reason: 'exploit failed')

    expect(result['files']).to include(
      a_hash_including(
        'path' => '/tmp/dropper.bin',
        'status' => 'failed',
        'error' => 'permission denied'
      )
    )
    expect(result['failed']).to be >= 1
  end
end
