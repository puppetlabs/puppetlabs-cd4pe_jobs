#!/opt/puppetlabs/puppet/bin/ruby

require 'json'
require 'rubygems/package'
require 'open3'
require 'uri'
require 'net/http'
require 'base64'
require 'facter'
require 'date'
require 'etc'

class Logger < Object
  # Class to track logs + timestamps. To be returned as part of the Bolt log output
  def initialize()
    @logs = []
  end

  def log(log)
    @logs.push({ timestamp: Time.now.getutc, message: log})
  end

  def get_logs
    @logs
  end
end

class GZipHelper
  # static class to decompress tar.gz files
  TAR_LONGLINK = '././@LongLink'.freeze
  SYMLINK_SYMBOL = '2'.freeze

  def self.unzip(zipped_file_path, destination_path)
    # helper functions
    def self.make_dir(entry, dest)
      FileUtils.rm_rf(dest) unless File.directory?(dest)
      FileUtils.mkdir_p(dest, :mode => entry.header.mode, :verbose => false)
    end

    def self.make_file(entry, dest)
      FileUtils.rm_rf dest unless File.file? dest
      File.open(dest, "wb") do |file|
        file.print(entry.read)
      end
      FileUtils.chmod(entry.header.mode, dest, :verbose => false)
    end

    def self.preserve_symlink(entry, dest)
      File.symlink(entry.header.linkname, dest)
    end

    # Unzip tar.gz
    Gem::Package::TarReader.new( Zlib::GzipReader.open zipped_file_path ) do |tar|
      dest = nil
      tar.each do |entry|

        # If file/dir name length > 100 chars, its broken into multiple entries.
        # This code glues the name back together
        if entry.full_name == TAR_LONGLINK
          dest = File.join(destination_path, entry.read.strip)
          next
        end

        # If the destination has not yet been set
        # set it equal to the path + file/dir name
        if (dest.nil?)
          dest = File.join(destination_path, entry.full_name)
        end

        # Write the file or dir
        if entry.directory?
          self.make_dir(entry, dest)
        elsif entry.file?
          self.make_file(entry, dest)
        elsif entry.header.typeflag == SYMLINK_SYMBOL
          self.preserve_symlink(entry, dest)
        end

        # reset dest for next entry iteration
        dest = nil
      end
    end
  end
end

class CD4PEClient < Object
  attr_reader :config, :owner_ajax_path

  def initialize(web_ui_endpoint:, job_token:, ca_cert_file: nil, logger:)
    @web_ui_endpoint = web_ui_endpoint
    @job_token = job_token
    @ca_cert_file = ca_cert_file
    @logger = logger

    uri = URI.parse(web_ui_endpoint)
    @http_config = {
      server: uri.host,
      port: uri.port || '8080',
      scheme: uri.scheme || 'http',
    }

  end

  def get_timeout
    timeout = 600
    timeout_env_var = ENV['HTTP_READ_TIMEOUT_SECONDS']
    unless (timeout_env_var.nil?)
      timeout_override = timeout_env_var.to_i
      if (timeout_override != 0)
        timeout = timeout_override
      else
        @logger.log("Unable to use HTTP_READ_TIMEOUT_SECONDS override: #{timeout_env_var}. Must be integer and non-zero.")
      end
    end
    timeout
  end

  def make_request(type, api_url, payload = '')
    connection = Net::HTTP.new(@http_config[:server], @http_config[:port])
    if @http_config[:scheme] == 'https'
      connection.use_ssl = true
      connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
      if !@ca_cert_file.nil?
        store = OpenSSL::X509::Store.new
        store.set_default_paths
        store.add_file(@ca_cert_file)
        connection.cert_store = store
      end
    end

    connection.read_timeout = get_timeout

    headers = {
      'Content-Type' => 'application/json',
      'Authorization' => "Bearer token #{@job_token}",
    }
    uri = URI.parse(api_url)

    max_attempts = 3
    attempts = 0

    while attempts < max_attempts
      attempts += 1
      begin
        @logger.log("cd4pe_client: requesting #{type} #{api_url} with read timeout: #{connection.read_timeout} seconds")
        starttime = Time.now.getutc
        case type
        when :delete
          response = connection.delete(uri, headers)
        when :get
          response = connection.get(uri, headers)
        when :post
          response = connection.post(uri, payload, headers)
        when :put
          response = connection.put(uri, payload, headers)
        else
          raise "cd4pe_client#make_request called with invalid request type #{type}"
        end
      rescue SocketError => e
        raise "Could not connect to the CD4PE service at #{api_url}: #{e.inspect}", e.backtrace
      rescue Net::ReadTimeout => e
        @logger.log("Timed out at #{connection.read_timeout} seconds waiting for response.")
        raise e
      rescue => e
        @logger.log("Failed to #{type} #{api_url}. #{e.message}.")
        raise e
      ensure
        endtime = Time.now.getutc
        duration = endtime - starttime
        @logger.log("Total request time: #{duration} seconds")
      end

      case response
      when Net::HTTPSuccess, Net::HTTPRedirection
        return response
      when Net::HTTPInternalServerError
        if attempts < max_attempts # rubocop:disable Style/GuardClause
          @logger.log("Received #{response} error from #{api_url}, attempting to retry. (Attempt #{attempts} of #{max_attempts})")
          Kernel.sleep(3)
        else
          raise "Received #{attempts} server error responses from the CD4PE service at #{api_url}: #{response.code} #{response.body}"
        end
      else
        error = "Request error: #{response.code} #{response.body}"
        @logger.log(error)
        raise error
      end
    end
  end
end

class CD4PEJobRunner < Object
  # Class for downloading, running, and logging CD4PE jobs
  attr_reader :docker_run_args

  MANIFEST_TYPE = {
    :JOB => "JOB",
    :AFTER_JOB_SUCCESS => "AFTER_JOB_SUCCESS",
    :AFTER_JOB_FAILURE => "AFTER_JOB_FAILURE" }

  DOCKER_CERTS = '/etc/docker/certs.d'

  def initialize(working_dir:, job_token:, web_ui_endpoint:, job_owner:, job_instance_id:, logger:, windows_job: false, base_64_ca_cert: nil, docker_image: nil, docker_run_args: nil, docker_pull_creds: nil)
    @working_dir = working_dir
    @job_token = job_token
    @web_ui_endpoint = web_ui_endpoint
    @job_owner = job_owner
    @job_instance_id = job_instance_id
    @docker_image = docker_image
    @docker_run_args = docker_run_args.nil? ? '' : docker_run_args.join(' ')
    @docker_based_job = !blank?(docker_image)
    @windows_job = windows_job

    @logger = logger

    job_dir_name = windows_job ? "windows" : "unix"
    @local_jobs_dir = File.join(@working_dir, "cd4pe_job", "jobs", job_dir_name)
    @local_repo_dir = File.join(@working_dir, "cd4pe_job", "repo")

    @ca_cert_file = nil
    if (!base_64_ca_cert.nil?)
      ca_cert = Base64.decode64(base_64_ca_cert)
      @ca_cert_file = File.join(@working_dir, "ca.crt")
      open(@ca_cert_file, "wb") do |file|
        file.write(ca_cert)
      end
    end

    @docker_pull_config = nil
    if (!docker_pull_creds.nil?)
      creds = Base64.decode64(docker_pull_creds)
      @docker_pull_config = File.join(@working_dir, ".docker")
      make_dir(@docker_pull_config)
      open(File.join(@docker_pull_config, "config.json"), "wb") do |file|
        file.write(creds)
      end

      # Ensure the ca_cert_file is added for each Docker registry we might use.
      if @ca_cert_file
        docker_conf = JSON.parse(creds)
        docker_conf['auths'].each do |host, _cred|
          dir = File.join(DOCKER_CERTS, host)
          FileUtils.mkdir_p(dir)
          cert = File.join(dir, 'ca.crt')
          begin
            FileUtils.link(@ca_cert_file, cert, force: true)
          rescue Errno::EEXIST => e
            # FileUtils.link with force=true deletes the file before linking. That leaves a race
            # condition where two calls to FileUtils.link try to link after the file has been
            # deleted. One will error with EEXIST, which shouldn't be an issue - presumably both
            # jobs use a valid cert - but we log it in case it causes unforeseen problems.
            @logger.log("Another job updated #{cert}")
          end
        end
      end
    end

    set_home_env_var
    set_repo_dir_env_var

  end

  def set_home_env_var
    # when the puppet orchestrator runs a Bolt task, it does so as a user without $HOME set.
    # We need to ensure $HOME is set so jobs that rely on this env var can succeed.
    if (!@windows_job)
      # if not windows, we must use a ruby solution to ensure cross-system compatibility.
      # $HOME is set by default on windows.
      ENV['HOME'] = Etc.getpwuid.dir
    end
  end

  def set_repo_dir_env_var
    ENV['REPO_DIR'] = @local_repo_dir
  end

  def get_job_script_and_control_repo
    @logger.log("Downloading job scripts and control repo from CD4PE.")
    target_file = File.join(@working_dir, "cd4pe_job.tar.gz")

    # download payload bytes
    api_endpoint = File.join(@web_ui_endpoint, @job_owner, 'getJobScriptAndControlRepo')
    job_instance_endpoint = "#{api_endpoint}?jobInstanceId=#{@job_instance_id}"
    client = CD4PEClient.new(web_ui_endpoint: job_instance_endpoint, job_token: @job_token, ca_cert_file: @ca_cert_file, logger: @logger)
    response = client.make_request(:get, job_instance_endpoint)

    # write payload bytes to file
    begin
      open(target_file, "wb") do |file|
        file.write(response.body)
      end
    rescue => e
      @logger.log("Failed to write CD4PE repo/script payload response to local file. Error: #{e.message}")
      raise e
    end

    # unzip file
    begin
      @logger.log("Unzipping #{target_file} to #{@working_dir}")
      GZipHelper.unzip(target_file, @working_dir)
    rescue => e
      @logger.log("Failed to decompress CD4PE repo/script payload. This can occur if the downloaded file is not in gzip format, or if the endpoint hit returned nothing. Error: #{e.message}")
      raise e
    end

    target_file
  end

  def send_job_output_to_cd4pe(output)
    @logger.log("Sending logs to CD4PE.")

    api_endpoint = File.join(@web_ui_endpoint, @job_owner, 'ajax')
    payload = {
      op: 'SavePuppetAgentJobOutput',
      content: {
        jobInstanceId: @job_instance_id,
        output: output
      },
    }

    client = CD4PEClient.new(web_ui_endpoint: api_endpoint, job_token: @job_token, ca_cert_file: @ca_cert_file, logger: @logger)

    begin
      response = client.make_request(:post, api_endpoint, payload.to_json)
      if (!response.is_a?(Net::HTTPSuccess))
        @logger.log("Unable to send logs directly to CD4PE. Printing logs to std out. #{response.code} #{response.body}")
        puts output.to_json
      end
    rescue => e
      @logger.log("Problem sending logs to CD4PE. Printing logs to std out. Error message: #{e.message}")
      puts output.to_json
    end
  end

  def run_job
    @logger.log("Running job instance #{@job_instance_id}.")

    result = execute_manifest(MANIFEST_TYPE[:JOB])
    combined_result = {}
    if (result[:exit_code] == 0)
      combined_result = on_job_complete(result, MANIFEST_TYPE[:AFTER_JOB_SUCCESS])
    else
      combined_result = on_job_complete(result, MANIFEST_TYPE[:AFTER_JOB_FAILURE])
    end

    @logger.log("Job instance #{@job_instance_id} run complete.")
    combined_result
  end

  def on_job_complete(result, next_manifest_type)
    output = {}
    output[:job] = {
      exit_code: result[:exit_code],
      message: result[:message]
    }

    # if a AFTER_JOB_SUCCESS or AFTER_JOB_FAILURE script exists, run it now!
    run_followup_script = false
    if (@windows_job)
      run_followup_script = File.exists?(File.join(@local_jobs_dir, "#{next_manifest_type}.ps1"))
    else
      run_followup_script = File.exists?(File.join(@local_jobs_dir, next_manifest_type))
    end

    if (run_followup_script)
      @logger.log("#{next_manifest_type} script specified.")
      followup_script_result = execute_manifest(next_manifest_type)
      output[next_manifest_type.downcase.to_sym] = {
        exit_code: followup_script_result[:exit_code],
        message: followup_script_result[:message]
      }
    end

    output
  end

  def execute_manifest(manifest_type)
    @logger.log("Executing #{manifest_type} manifest.")
    result = {}
    if (@docker_based_job)
      @logger.log("Docker image specified. Running #{manifest_type} manifest on docker image: #{@docker_image}.")
      result = run_with_docker(manifest_type)
    else
      @logger.log("No docker image specified. Running #{manifest_type} manifest directly on machine.")
      result = run_with_system(manifest_type)
    end

    if (result[:exit_code] == 0)
      @logger.log("#{manifest_type} succeeded!")
    else
      @logger.log("#{manifest_type} failed with exit code: #{result[:exit_code]}: #{result[:message]}")
    end
    result
  end

  def run_with_system(manifest_type)
    local_job_script = File.join(@local_jobs_dir, manifest_type)

    cmd_to_execute = local_job_script
    if (@windows_job)
      cmd_to_execute = "powershell \"& {&'#{local_job_script}'}\""
    end

    run_system_cmd(cmd_to_execute)
  end

  def get_docker_pull_cmd
    if @docker_pull_config.nil?
      "docker pull #{@docker_image}"
    else
      "docker --config #{@docker_pull_config} pull #{@docker_image}"
    end
  end

  def update_docker_image
    if (@docker_based_job)
      @logger.log("Updating docker image: #{@docker_image}")
      result = run_system_cmd(get_docker_pull_cmd)
      @logger.log(result[:message])
    end
  end

  def get_docker_run_cmd(manifest_type)
    repo_volume_mount = "\"#{@local_repo_dir}:/repo\""
    scripts_volume_mount = "\"#{@local_jobs_dir}:/cd4pe_job\""
    docker_bash_script = "\"/cd4pe_job/#{manifest_type}\""
    "docker run --rm #{@docker_run_args} -v #{repo_volume_mount} -v #{scripts_volume_mount} #{@docker_image} #{docker_bash_script}"
  end

  def run_with_docker(manifest_type)
    docker_cmd = get_docker_run_cmd(manifest_type)
    run_system_cmd(docker_cmd)
  end

  def run_system_cmd(cmd)
    output = ''
    exit_code = 0

    @logger.log("Executing system command: #{cmd}")
    output, wait_thr = Open3.capture2e(cmd)
    exit_code = wait_thr.exitstatus

    { :exit_code => exit_code, :message => output }
  end

  def blank?(str)
    str.nil? || str.empty?
  end
end

def parse_args(argv)
  params = {}
  argv.each do |arg|
    split = arg.split("=", 2) # split on first instance of '='
    key = split[0]
    value = split[1]
    params[key] = value
  end
  params
end

def get_combined_exit_code(output)
  job = output[:job]
  after_job_success = output[:after_job_success]
  after_job_failure = output[:after_job_failure]

  exit_code_sum = job[:exit_code]
  if (!after_job_success.nil?)
    exit_code_sum = exit_code_sum + after_job_success[:exit_code]
  end

  if (!after_job_failure.nil?)
    exit_code_sum = exit_code_sum + after_job_failure[:exit_code]
  end

  exit_code_sum == 0 ? 0 : 1
end

def set_job_env_vars(task_params)
  @logger.log("Setting user-specified job environment vars.")
  user_specified_env_vars = task_params['env_vars']
    if (!user_specified_env_vars.nil?)
      user_specified_env_vars.each do |var|
        pair = var.split("=")
        key = pair[0]
        value = pair[1]
        ENV[key] = value
      end
    end
end

def make_dir(dir)
  @logger.log("Creating directory #{dir}")
  if (!File.exists?(dir))
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

if __FILE__ == $0 # This block will only be invoked if this file is executed. Will NOT execute when 'required' (ie. for testing the contained classes)
  @logger = Logger.new
  begin

    kernel = Facter.value(:kernel)
    windows_job = kernel == 'windows'
    @logger.log("System detected: #{kernel}")

    params = JSON.parse(STDIN.read)

    docker_image = params['docker_image']
    docker_run_args = params["docker_run_args"]
    docker_pull_creds = params['docker_pull_creds']
    job_instance_id = params["job_instance_id"]
    web_ui_endpoint = params['cd4pe_web_ui_endpoint']
    job_token = params['cd4pe_token']
    job_owner = params['cd4pe_job_owner']
    base_64_ca_cert = params['base_64_ca_cert']

    set_job_env_vars(params)

    root_job_dir = File.join(Dir.pwd, 'cd4pe_job_working_dir')
    make_dir(root_job_dir)
    @working_dir = File.join(root_job_dir, "cd4pe_job_instance_#{job_instance_id}_#{DateTime.now.strftime('%Q')}")
    make_dir(@working_dir)

    job_runner = CD4PEJobRunner.new(
      working_dir: @working_dir,
      docker_image: docker_image,
      docker_run_args: docker_run_args,
      docker_pull_creds: docker_pull_creds,
      job_token: job_token,
      web_ui_endpoint: web_ui_endpoint,
      job_owner: job_owner,
      job_instance_id: job_instance_id,
      base_64_ca_cert: base_64_ca_cert,
      windows_job: windows_job,
      logger: @logger)
    job_runner.get_job_script_and_control_repo
    job_runner.update_docker_image
    output = job_runner.run_job

    output[:logs] = @logger.get_logs
    job_runner.send_job_output_to_cd4pe(output)

    exit get_combined_exit_code(output)
  rescue => e
    # Write to stderr because job_runner may not be setup and send_job_output_to_cd4pe captures the error.
    STDERR.puts(e.message)
    STDERR.puts(e.backtrace)
    job_runner.send_job_output_to_cd4pe({ status: 'failure', error: e.message, logs: @logger.get_logs })
    exit 1
  ensure
    delete_dir(@working_dir)
  end
end
