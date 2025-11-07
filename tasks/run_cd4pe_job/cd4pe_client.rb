# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'

module RunCD4PEJob
  # Client for interacting with CD4PE APIs
  class CD4PEClient
    # @param base_uri [String] Base URI of the CD4PE server
    # @param job_token [String] Job token for authentication
    # @param job_instance_id [String] Job instance ID
    # @param logger [Logger] Logger instance for logging
    # @param ca_cert_file [String, nil] Path to CA certificate file for SSL verification
    def initialize(base_uri:, job_token:, job_instance_id:, logger:, ca_cert_file: nil)
      @base_uri = URI.parse(base_uri)
      @job_token = job_token
      @job_instance_id = job_instance_id
      @logger = logger
      @ca_cert_file = ca_cert_file
    end

    # Send job output to CD4PE
    #
    # @param output [Hash] Job output payload
    #
    # @return [Net::HTTPResponse]
    def save_puppet_agent_job_output(output)
      payload = {
        op: 'SavePuppetAgentJobOutput',
        content: {
          jobInstanceId: @job_instance_id,
          output:,
        },
      }

      post('/ajax', payload)
    end

    # Get job script and control repository
    #
    # @param job_instance_id [String] Job instance ID
    #
    # @return [Net::HTTPResponse]
    def get_job_script_and_control_repo
      parameters = {
        jobInstanceId: @job_instance_id,
      }

      get('/getJobScriptAndControlRepo', parameters)
    end

    private

    # Maximum number of attempts for retrying HTTP requests
    MAX_ATTEMPTS = 3

    # @param path [String] API path to post to
    # @param payload [Hash] JSON payload to send
    #
    # @return [Net::HTTPResponse]
    def post(path, payload = {})
      request!(:post, path, payload)
    end

    # @param path [String] API path to get
    # @param parameters [Hash] Query parameters
    #
    # @return [Net::HTTPResponse]
    def get(path, parameters = {})
      query_string = parameters.empty? ? '' : "?#{URI.encode_www_form(parameters)}"
      request!(:get, "#{path}#{query_string}")
    end

    # Make a HTTP request
    #
    # @param type [Symbol] HTTP method
    # @param path [String] API path to request
    # @param payload [Hash] JSON payload to send
    #
    # @return [Net::HTTPResponse]
    def request!(type, path, payload = {})
      request_path = URI.parse(File.join(@base_uri.to_s, path))
      attempts = 0
      while attempts < MAX_ATTEMPTS
        @logger.log("cd4pe_client: requesting #{type} #{request_path.path} with read timeout: #{http_args[:read_timeout]} seconds")
        attempts += 1

        begin
          request = Net::HTTP.start(@base_uri.host, @base_uri.port, **http_args) do |http|
            case type
            when :get
              http.get(request_path.request_uri, headers)
            when :post
              http.post(request_path.request_uri, payload.to_json, headers)
            else
              raise StandardError, "cd4pe_client#request! called with invalid request type #{type}"
            end
          end
        rescue SocketError => e
          raise StandardError, "Could not connect to the CD4PE service at #{@base_uri.host}: #{e.inspect}"
        rescue Net::ReadTimeout => e
          @logger.log("Timed out at #{request.read_timeout} seconds waiting for response.")
          raise e
        rescue StandardError => e
          @logger.log("Failed to #{type} #{request_path}. #{e.message}.")
          raise e
        end

        case request
        when Net::HTTPSuccess, Net::HTTPRedirection
          return request
        when Net::HTTPInternalServerError
          if attempts < MAX_ATTEMPTS
            sleep(3)
            next
          end

          raise StandardError, "Request error: #{request.code} #{request.body}"
        else
          error = "Request error: #{request.code} #{request.body}"
          @logger.log(error)
          raise StandardError, error
        end
      end
    end

    # Net::HTTP connection arguments
    #
    # @return [Hash]
    def http_args
      return @http_args if @http_args

      @http_args = {}
      if @base_uri.scheme == 'https'
        @http_args[:use_ssl] = true
        @http_args[:verify_mode] = OpenSSL::SSL::VERIFY_PEER
        unless @ca_cert_file.nil?
          store = OpenSSL::X509::Store.new
          store.set_default_paths
          store.add_file(@ca_cert_file)
          @http_args[:cert_store] = store
        end
      end
      @http_args[:read_timeout] = http_timeout
      @http_args
    end

    # HTTP read timeout in seconds
    #
    # @return [Integer]
    def http_timeout
      return @timeout if @timeout

      @timeout = 600
      if ENV['HTTP_READ_TIMEOUT_SECONDS'].to_i == 0
        @logger.log("Invalid HTTP_READ_TIMEOUT_SECONDS value: #{ENV['HTTP_READ_TIMEOUT_SECONDS']}. Using default #{@timeout} seconds.")
      else
        @timeout = ENV['HTTP_READ_TIMEOUT_SECONDS'].to_i
      end
      @timeout
    end

    # HTTP headers
    #
    # @return [Hash]
    def headers
      @headers ||= {
        'Content-Type'  => 'application/json',
        'Authorization' => @job_token
      }
    end
  end
end
