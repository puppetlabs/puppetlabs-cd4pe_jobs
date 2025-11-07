# frozen_string_literal: true

require 'etc'
require 'open3'

module RunCD4PEJob
  # Class for downloading, running, and logging CD4PE jobs
  class CD4PEJobRunner
    include RunCD4PEJob

    def initialize(working_dir:, job_owner:, job_instance_id:, logger:, secrets:, cd4pe_client:, windows_job: false, ca_cert_file: nil, container_image: nil, container_run_args: nil,
                  image_pull_creds: nil)
      @logger = logger
      @image_repo = nil
      @container_image = container_image
      @container_run_args = container_run_args.nil? ? '' : container_run_args.join(' ')
      @containerized_job = !blank?(container_image)
      @windows_job = windows_job
      @runtime = get_runtime
      @cert_dir = (@runtime == 'podman') ? PODMAN_CERTS : DOCKER_CERTS
      @working_dir = working_dir
      @job_owner = job_owner
      @job_instance_id = job_instance_id
      @secrets = secrets
      @ca_cert_file = ca_cert_file
      @cd4pe_client = cd4pe_client

      job_dir_name = windows_job ? 'windows' : 'unix'
      @local_jobs_dir = File.join(@working_dir, 'cd4pe_job', 'jobs', job_dir_name)
      @local_repo_dir = File.join(@working_dir, 'cd4pe_job', 'repo')

      @image_pull_config = nil
      unless image_pull_creds.nil?
        creds = Base64.decode64(image_pull_creds)
        # podman-login manpage states it uses `.docker/config.json`, so this
        # applies to both runtimes
        @image_pull_config = File.join(@working_dir, '.docker')
        make_dir(@image_pull_config)
        open(File.join(@image_pull_config, 'config.json'), 'wb') do |file|
          file.write(creds)
        end

        # Ensure the ca_cert_file is added for each registry we might use.
        if @ca_cert_file
          runtime_conf = JSON.parse(creds)
          runtime_conf['auths'].each do |host, _cred|
            dir = File.join(@cert_dir, host)
            FileUtils.mkdir_p(dir)
            cert = File.join(dir, 'ca.crt')
            begin
              FileUtils.ln_s(@ca_cert_file, cert, force: true)
            rescue Errno::EEXIST
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

    # Download job script and control repo from CD4PE and unzip to working dir
    #
    # @return [String] path to the downloaded tar.gz file
    def get_job_script_and_control_repo
      @logger.log('Downloading job scripts and control repo from CD4PE.')
      target_file = File.join(@working_dir, 'cd4pe_job.tar.gz')

      # download payload bytes
      response = @cd4pe_client.get_job_script_and_control_repo

      # write payload bytes to file
      begin
        open(target_file, 'wb') do |file|
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

    # Update the container image
    def update_container_image
      return unless @containerized_job

      @logger.log("Updating container image: #{@container_image}")
      result = run_system_cmd(get_image_pull_cmd)
      if result[:exit_code] == 125
        @logger.log('Failed to pull using given image name. Re-try directly from docker.io.')
        @image_repo = 'docker.io'
        result = run_system_cmd(get_image_pull_cmd)
      end

      @logger.log(result[:message])

      return unless result[:exit_code] != 0
      @logger.log("Unable to update image #{@container_image}, falling back to local image.")
    end

    # Run the job manifest
    #
    # @return [Hash<Symbol => String>]
    def run_job
      @logger.log("Running job instance #{@job_instance_id}.")

      result = execute_manifest(MANIFEST_TYPE[:JOB])
      combined_result = if result[:exit_code] == 0
                          on_job_complete(result, MANIFEST_TYPE[:AFTER_JOB_SUCCESS])
                        else
                          on_job_complete(result, MANIFEST_TYPE[:AFTER_JOB_FAILURE])
                        end

      @logger.log("Job instance #{@job_instance_id} run complete.")
      combined_result
    end

    private

    MANIFEST_TYPE = {
      JOB: 'JOB',
      AFTER_JOB_SUCCESS: 'AFTER_JOB_SUCCESS',
      AFTER_JOB_FAILURE: 'AFTER_JOB_FAILURE'
    }.freeze

    DOCKER_CERTS = '/etc/docker/certs.d'
    PODMAN_CERTS = '/etc/containers/certs.d'

    # When the puppet orchestrator runs a Bolt task, it does so as a user without $HOME set.
    # We need to ensure $HOME is set so jobs that rely on this env var can succeed.
    def set_home_env_var
      return if @windows_job
      # if not windows, we must use a ruby solution to ensure cross-system compatibility.
      # $HOME is set by default on windows.
      ENV['HOME'] = Etc.getpwuid.dir
    end

    # Set REPO_DIR env var to point to the local control repo dir
    def set_repo_dir_env_var
      ENV['REPO_DIR'] = @local_repo_dir
    end

    # Combined result of job and follow-up script (if any)
    #
    # @return [Hash<Symbol => String>]
    def on_job_complete(result, next_manifest_type)
      output = {}
      output[:job] = {
        exit_code: result[:exit_code],
        message: result[:message]
      }

      # if a AFTER_JOB_SUCCESS or AFTER_JOB_FAILURE script exists, run it now!
      run_followup_script = if @windows_job
                              File.exist?(File.join(@local_jobs_dir, "#{next_manifest_type}.ps1"))
                            else
                              File.exist?(File.join(@local_jobs_dir, next_manifest_type))
                            end

      if run_followup_script
        @logger.log("#{next_manifest_type} script specified.")
        followup_script_result = execute_manifest(next_manifest_type)
        output[next_manifest_type.downcase.to_sym] = {
          exit_code: followup_script_result[:exit_code],
          message: followup_script_result[:message]
        }
      end

      output
    end

    # Execute the specified manifest type
    #
    # @param manifest_type [String] the type of manifest to execute
    #
    # @return [Hash<Symbol => Integer, String>]
    def execute_manifest(manifest_type)
      @logger.log("Executing #{manifest_type} manifest.")
      result = {}
      if @containerized_job
        @logger.log("Container image specified. Running #{manifest_type} manifest on container image: #{@container_image}.")
        result = run_in_container(manifest_type)
      else
        @logger.log("No container image specified. Running #{manifest_type} manifest directly on machine.")
        result = run_with_system(manifest_type)
      end

      if result[:exit_code] == 0
        @logger.log("#{manifest_type} succeeded!")
      else
        @logger.log("#{manifest_type} failed with exit code: #{result[:exit_code]}: #{result[:message]}")
      end
      result
    end

    # @return [Hash<Symbol => Integer, String>]
    def run_with_system(manifest_type)
      local_job_script = File.join(@local_jobs_dir, manifest_type)

      cmd_to_execute = local_job_script
      if @windows_job
        cmd_to_execute = "powershell \"& {&'#{local_job_script}';exit $LASTEXITCODE}\""
      end

      run_system_cmd(cmd_to_execute)
    end

    # @return [String]
    def get_image_pull_cmd
      image = @image_repo.nil? ? @container_image : "#{@image_repo}/#{@container_image}"
      if @image_pull_config.nil?
        "#{@runtime} pull #{image}"
      else
        "#{@runtime} --config #{@image_pull_config} pull #{image}"
      end
    end

    # Generates the container run command
    #
    # @return [String]
    def get_container_run_cmd(manifest_type)
      suffix = (@runtime == 'podman') ? ':z' : ''
      repo_volume_mount = "\"#{@local_repo_dir}:/repo#{suffix}\""
      scripts_volume_mount = "\"#{@local_jobs_dir}:/cd4pe_job#{suffix}\""
      container_bash_script = "\"/cd4pe_job/#{manifest_type}\""
      "#{@runtime} run --rm #{@container_run_args} #{get_container_secrets_cmd} -v #{repo_volume_mount} -v #{scripts_volume_mount} #{@container_image} #{container_bash_script}"
    end

    # Generates the container secrets command
    #
    # @return [String]
    def get_container_secrets_cmd
      return '' if @secrets.nil?

      @secrets.keys.reduce('') do |memo, key|
        memo += "-e #{key} "
      end
    end

    # Detects the container runtime to use
    #
    # @return [String, nil]
    def get_runtime
      return nil unless @containerized_job

      unless ENV['RUNTIME_OVERRIDE'].nil?
        @logger.log("Runtime override detected. Using '#{ENV['RUNTIME_OVERRIDE']}' as runtime.")
        return ENV['RUNTIME_OVERRIDE']
      end

      # Try to detect podman first to avoid the possibility that the podman-docker
      # shim is installed. If the shim is present, we will find podman first and use it
      # directly.
      begin
        run_system_cmd('podman --version', false)
        @logger.log("Podman runtime detected. Use 'RUNTIME_OVERRIDE' environment variable to override.")
        'podman'
      rescue Errno::ENOENT
        begin
          run_system_cmd('docker --version', false)
          @logger.log("Docker runtime detected. Use 'RUNTIME_OVERRIDE' environment variable to override.")
          'docker'
        rescue Errno::ENOENT
          raise('Configured for containerized run, but no container runtime detected. Ensure docker or podman is available in the PATH.')
        end
      end
    end

    # @return [Hash<Symbol => Integer, String>]
    def run_in_container(manifest_type)
      cmd = get_container_run_cmd(manifest_type)
      run_system_cmd(cmd)
    end

    # Run a system command and return the output
    #
    # @param cmd [String] command to run
    # @param log_output [Boolean] whether to log the command being run
    #
    # @return [Hash<Symbol => Integer, String>]
    def run_system_cmd(cmd, log_output = true)
      @logger.log("Executing system command: #{cmd}") unless !log_output
      output, wait_thr = Open3.capture2e(cmd)
      output = output.encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')
      exit_code = wait_thr.exitstatus

      { exit_code:, message: scrub_secrets(output) }
    end

    # Scrub secrets from command output
    #
    # @param cmd_output [String] command output to scrub
    #
    # @return [String]
    def scrub_secrets(cmd_output)
      return cmd_output if @secrets.nil? || @secrets.empty? || blank?(cmd_output)

      @logger.log('Scrubbing secrets from job output.')

      redacted_value = 'Sensitive [value redacted]'

      regex = @secrets.values.map do |value|
        sanitized = value.tr("\n", ' ')
        if sanitized == value
          Regexp.quote(value)
        else
          [Regexp.quote(value), Regexp.quote(sanitized)]
        end
      end

      cmd_output.gsub(%r{(#{regex.flatten.join("|")})}, redacted_value)
    end

    # @return [Boolean]
    def blank?(str)
      str.nil? || str.empty?
    end
  end
end