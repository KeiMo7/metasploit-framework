# frozen_string_literal: true

require 'time'

module Msf
  module Preflight
    # Tracks only the sessions and target artifacts created during one module
    # run. On failure, sessions that did not exist before the run are closed
    # and all cleanup outcomes are recorded for the structured report.
    class CleanupScope
      attr_reader :session_ids_before, :artifacts, :events

      def initialize(mod)
        @mod = mod
        @framework = mod.framework if mod.respond_to?(:framework)
        @session_ids_before = current_session_ids
        @artifacts = []
        @events = []
        @cleanup_errors = []
      end

      # @return [void]
      def start
        mod = @mod
        mod.preflight_cleanup_scope = self if mod.respond_to?(:preflight_cleanup_scope=)
      end

      # Register a file or directory before it is created or immediately after
      # the module records it for cleanup.
      #
      # @return [Hash]
      def register_artifact(path, type: 'file', source: 'module')
        entry = {
          'type' => type.to_s,
          'path' => path.to_s,
          'source' => source.to_s,
          'registered_at' => Time.now.utc.iso8601,
          'status' => 'pending'
        }
        @artifacts << entry
        entry
      end

      # Record the outcome of a file/directory cleanup attempt.
      #
      # @return [Hash]
      def record_artifact_cleanup(path, status:, type: 'file', error: nil)
        entry = @artifacts.reverse.find do |artifact|
          artifact['path'] == path.to_s && artifact['type'] == type.to_s
        end
        entry ||= register_artifact(path, type: type, source: 'cleanup')
        entry['status'] = status.to_s
        entry['error'] = error&.to_s
        record_event('artifact', entry)
        log_failure("Failed to clean up #{type} #{path}", error) if status.to_s == 'failed'
        entry
      end

      # Clean sessions created during this run and report any artifacts whose
      # cleanup did not complete. The module's own `cleanup` method is expected
      # to run before this method so existing FileDropper cleanup remains the
      # single implementation for target-side deletion.
      #
      # @return [Hash]
      def cleanup_failed_run!(reason: 'module execution failed')
        cleanup_new_sessions(reason)
        attempt_unhandled_artifacts

        {
          'reason' => reason,
          'sessions' => session_results,
          'files' => artifact_results,
          'errors' => @cleanup_errors,
          'failed' => failure_count,
          'completed_at' => Time.now.utc.iso8601
        }
      end

      # @return [Hash]
      def to_h
        {
          'sessions' => session_results,
          'files' => artifact_results,
          'errors' => @cleanup_errors,
          'failed' => failure_count
        }
      end

      # Record a cleanup operation that failed before it could produce a
      # path-specific result.
      #
      # @return [Hash]
      def record_cleanup_error(operation, error)
        detail = error.respond_to?(:message) ? error.message : error.to_s
        entry = {
          'operation' => operation.to_s,
          'error' => detail,
          'status' => 'failed',
          'recorded_at' => Time.now.utc.iso8601
        }
        @cleanup_errors << entry
        log_failure("Cleanup operation failed: #{operation}", error)
        entry
      end

      private

      def cleanup_new_sessions(reason)
        new_session_ids.each do |sid|
          session = session_by_id(sid)
          unless session
            session_results << {
              'sid' => sid,
              'status' => 'failed',
              'error' => 'session disappeared before cleanup'
            }
            next
          end

          begin
            @framework.sessions.deregister(session, "Preflight cleanup after #{reason}")
            session_results << { 'sid' => sid, 'status' => 'closed' }
          rescue StandardError => e
            session_results << { 'sid' => sid, 'status' => 'failed', 'error' => e.message }
            log_failure("Failed to close session #{sid}", e)
          end
        end
      end

      def attempt_unhandled_artifacts
        @artifacts.each do |artifact|
          next unless artifact['status'] == 'pending'
          next unless @mod.respond_to?(:file_rm)

          begin
            result = if artifact['type'] == 'directory' && @mod.respond_to?(:dir_rm)
                       @mod.dir_rm(artifact['path'])
                     else
                       @mod.file_rm(artifact['path'])
                     end
            record_artifact_cleanup(
              artifact['path'],
              type: artifact['type'],
              status: result ? 'deleted' : 'failed',
              error: result ? nil : 'cleanup API did not confirm deletion'
            )
          rescue StandardError => e
            record_artifact_cleanup(
              artifact['path'],
              type: artifact['type'],
              status: 'failed',
              error: e.message
            )
          end
        end
      end

      def current_session_ids
        return [] unless @framework.respond_to?(:sessions)

        @framework.sessions.keys.map(&:to_i).sort
      rescue StandardError
        []
      end

      def new_session_ids
        current_session_ids - session_ids_before
      end

      def session_by_id(sid)
        @framework.sessions[sid.to_i] if @framework.respond_to?(:sessions)
      rescue StandardError
        nil
      end

      def session_results
        @session_results ||= []
      end

      def artifact_results
        @artifacts.map do |artifact|
          {
            'type' => artifact['type'],
            'path' => artifact['path'],
            'source' => artifact['source'],
            'status' => artifact['status'],
            'error' => artifact['error']
          }
        end
      end

      def failure_count
        session_results.count { |entry| entry['status'] == 'failed' } +
          @artifacts.count { |entry| entry['status'] == 'failed' } +
          @cleanup_errors.length
      end

      def record_event(kind, entry)
        @events << {
          'kind' => kind,
          'entry' => entry.dup,
          'recorded_at' => Time.now.utc.iso8601
        }
      end

      def log_failure(message, error)
        detail = error.respond_to?(:message) ? error.message : error.to_s
        if @mod.respond_to?(:print_error)
          @mod.print_error("#{message}#{detail.empty? ? '' : ": #{detail}"}")
        end
        @mod.elog(message, error: error) if @mod.respond_to?(:elog) && error.is_a?(Exception)
      end
    end
  end
end
