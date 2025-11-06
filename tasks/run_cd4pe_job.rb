#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

require 'json'
require 'base64'
require 'facter'
require 'date'

require_relative 'run_cd4pe_job/logger'
require_relative 'run_cd4pe_job/gzip_helper'
require_relative 'run_cd4pe_job/cd4pe_client'
require_relative 'run_cd4pe_job/cd4pe_job_runner'

module RunCD4PEJob
  class Task
    include RunCD4PEJob

    def initialize
      @logger = Logger.new
    end

    # Main entry point for the task
    def run
      kernel = Facter.value(:kernel)
      windows_job = kernel == 'windows'
      @logger.log("System detected: #{kernel}")

      params = JSON.parse(STDIN.read)

      root_job_dir = File.join(Dir.pwd, 'cd4pe_job_working_dir')
      make_dir(root_job_dir)
      @working_dir = File.join(root_job_dir, "cd4pe_job_instance_#{params['job_instance_id']}_#{DateTime.now.strftime('%Q')}")
      make_dir(@working_dir)

      ca_cert_file = nil
      unless params['base_64_ca_cert'].nil?
        ca_cert_file = File.join(@working_dir, 'ca.crt')
        open(ca_cert_file, 'wb') do |file|
          file.write(Base64.decode64(params['base_64_ca_cert']))
        end
      end
      cd4pe_client = CD4PEClient.new(
        base_uri: File.join(params['cd4pe_web_ui_endpoint'], params['cd4pe_job_owner']),
        job_token: params['cd4pe_token'],
        ca_cert_file:,
        job_instance_id: params['job_instance_id'],
        logger: @logger,
      )
      set_job_env_vars(params)
      set_job_env_secrets(params['secrets'])

      job_runner = CD4PEJobRunner.new(
        working_dir: @working_dir,
        container_image: params['docker_image'],
        container_run_args: params['docker_run_args'],
        image_pull_creds: params['docker_pull_creds'],
        job_owner: params['cd4pe_job_owner'],
        job_instance_id: params['job_instance_id'],
        ca_cert_file:,
        windows_job:,
        secrets: params['secrets'],
        cd4pe_client:,
        logger: @logger,
      )
      job_runner.get_job_script_and_control_repo
      job_runner.update_container_image
      output = job_runner.run_job

      output[:logs] = @logger.logs
      cd4pe_client.save_puppet_agent_job_output(output)

      exit get_combined_exit_code(output)
    rescue StandardError => e
      # Write to stderr because cd4pe_client may not be setup and send_logs captures the error.
      STDERR.puts(e.message)
      STDERR.puts(e.backtrace)
      payload = {
        status: 'failure',
        error: e.message,
        logs: @logger.logs
      }
      puts payload.to_json
      exit 1
    ensure
      delete_dir(@working_dir)
    end
  end

  module_function

  # @return [Hash<String, String>]
  def parse_args(argv)
    params = {}
    argv.each do |arg|
      split = arg.split('=', 2) # split on first instance of '='
      key = split[0]
      value = split[1]
      params[key] = value
    end
    params
  end

  # @return [Integer]
  def get_combined_exit_code(output)
    job = output[:job]
    after_job_success = output[:after_job_success]
    after_job_failure = output[:after_job_failure]

    exit_code_sum = job[:exit_code]
    unless after_job_success.nil?
      exit_code_sum += after_job_success[:exit_code]
    end

    unless after_job_failure.nil?
      exit_code_sum += after_job_failure[:exit_code]
    end

    (exit_code_sum == 0) ? 0 : 1
  end

  def set_job_env_vars(task_params)
    @logger.log('Setting user-specified job environment vars.')
    user_specified_env_vars = task_params['env_vars']
    return unless !user_specified_env_vars.nil?
    user_specified_env_vars.each do |var|
      pair = var.split('=')
      key = pair[0]
      value = pair[1]
      ENV[key] = value
    end
  end

  def set_job_env_secrets(secrets)
    if secrets.nil? || secrets.empty?
      @logger.log('No job secrets found.')
      return
    end

    @logger.log('Setting job secrets in the local environment.')

    secrets.each do |key, value|
      ENV[key] = value
    end
  end

  def make_dir(dir)
    @logger.log("Creating directory #{dir}")
    if !File.exist?(dir)
      Dir.mkdir(dir)
      @logger.log("Successfully created directory: #{dir}")
    else
      @logger.log("Directory already exists: #{dir}")
    end
  end

  def delete_dir(dir)
    @logger.log("Deleting directory #{dir}")
    FileUtils.rm_rf(dir)
  end
end

# This block will only be invoked if this file is executed. Will NOT execute when 'required' (ie. for testing the contained classes)
if __FILE__ == $PROGRAM_NAME
  RunCD4PEJob::Task.new.run
end
