# frozen_string_literal: true

require 'time'

module RunCD4PEJob
  # Class to track logs and timestamps. To be returned as part of the Bolt log output
  #
  # @attr_reader logs [Array<Hash<Symbol => String>>]
  class Logger
    attr_reader :logs

    def initialize
      @logs = []
    end

    # Log a new message
    #
    # @param log [String] log message
    def log(log)
      @logs << { timestamp: Time.now.getutc, message: log }
    end
  end
end
