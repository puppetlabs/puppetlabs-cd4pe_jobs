require 'open3'
require 'base64'
require 'json'
require 'fileutils'
require_relative '../../tasks/run_cd4pe_job.rb'

describe 'run_cd4pe_job' do
  before(:all) do
    @logger = RunCD4PEJob::Logger.new
  end

  before(:each) do
    @working_dir = File.join(Dir.getwd, 'test_working_dir')
    Dir.mkdir(@working_dir)

    # Ensure tests don't write to /etc/docker/certs.d
    @certs_dir = File.join(@working_dir, 'certs.d')
    RunCD4PEJob::CD4PEJobRunner.send(:remove_const, :DOCKER_CERTS)
    RunCD4PEJob::CD4PEJobRunner.const_set(:DOCKER_CERTS, @certs_dir)

    @web_ui_endpoint = 'https://testtest.com'
    @job_token = 'alksjdbhfnadhsbf'
    @job_owner = 'carls cool carl'
    @job_instance_id = '17'
    @secrets = {
      secret1: 'hello',
      secret2: 'friend',
    }
    @windows_job = ENV['RUN_WINDOWS_UNIT_TESTS']
    @cd4pe_client = nil
  end

  after(:each) do
    FileUtils.remove_dir(@working_dir)
    $stdout = STDOUT
  end

  describe 'set_job_env_vars' do
    it 'Sets the user-specified environment params.' do
      user_specified_env_vars = ['TEST_VAR_ONE=hello!', 'TEXT_VAR_TWO=yellow-bird', 'TEST_VAR_THREE=carl']

      params = { 'env_vars' => user_specified_env_vars }

      RunCD4PEJob::Task.new.send(:set_job_env_vars, params)

      expect(ENV['TEST_VAR_ONE']).to eq('hello!')
      expect(ENV['TEXT_VAR_TWO']).to eq('yellow-bird')
      expect(ENV['TEST_VAR_THREE']).to eq('carl')
    end
  end

  describe 'make_dir' do
    it 'Makes working directory as specified.' do
      # validate dir does not exist
      test_dir = File.join(@working_dir, 'test_dir')
      expect(File.exist?(test_dir)).to be(false)

      # create dir and validate it exists
      RunCD4PEJob::Task.new.send(:make_dir, test_dir)
      expect(File.exist?(test_dir)).to be(true)

      # attempt to create again to validate it does not throw
      RunCD4PEJob::Task.new.send(:make_dir, test_dir)
    end
  end

  describe 'get_combined_exit_code' do
    it('is 0 if job and after_job_success are 0') do
      output = { job: { exit_code: 0 }, after_job_success: { exit_code: 0 } }
      test_code = RunCD4PEJob::Task.new.send(:get_combined_exit_code, output)
      expect(test_code).to eq(0)
    end

    it('is 1 if job or after_job_success are not 0') do
      output = { job: { exit_code: 1 }, after_job_success: { exit_code: 0 } }
      test_code = RunCD4PEJob::Task.new.send(:get_combined_exit_code, output)
      expect(test_code).to eq(1)

      output = { job: { exit_code: 125 }, after_job_success: { exit_code: 0 } }
      test_code = RunCD4PEJob::Task.new.send(:get_combined_exit_code, output)
      expect(test_code).to eq(1)

      output = { job: { exit_code: 0 }, after_job_success: { exit_code: 1 } }
      test_code = RunCD4PEJob::Task.new.send(:get_combined_exit_code, output)
      expect(test_code).to eq(1)

      output = { job: { exit_code: 0 }, after_job_success: { exit_code: 125 } }
      test_code = RunCD4PEJob::Task.new.send(:get_combined_exit_code, output)
      expect(test_code).to eq(1)

      output = { job: { exit_code: 1 }, after_job_success: { exit_code: 125 } }
      test_code = RunCD4PEJob::Task.new.send(:get_combined_exit_code, output)
      expect(test_code).to eq(1)
    end

    it('is 1 if job or after_job_failure are not 0') do
      output = { job: { exit_code: 1 }, after_job_failure: { exit_code: 0 } }
      test_code = RunCD4PEJob::Task.new.send(:get_combined_exit_code, output)
      expect(test_code).to eq(1)

      output = { job: { exit_code: 125 }, after_job_failure: { exit_code: 0 } }
      test_code = RunCD4PEJob::Task.new.send(:get_combined_exit_code, output)
      expect(test_code).to eq(1)

      output = { job: { exit_code: 0 }, after_job_failure: { exit_code: 1 } }
      test_code = RunCD4PEJob::Task.new.send(:get_combined_exit_code, output)
      expect(test_code).to eq(1)

      output = { job: { exit_code: 0 }, after_job_failure: { exit_code: 125 } }
      test_code = RunCD4PEJob::Task.new.send(:get_combined_exit_code, output)
      expect(test_code).to eq(1)

      output = { job: { exit_code: 1 }, after_job_failure: { exit_code: 125 } }
      test_code = RunCD4PEJob::Task.new.send(:get_combined_exit_code, output)
      expect(test_code).to eq(1)
    end
  end

  describe 'parse_args' do
    it 'parses args appropriately' do
      key1 = 'key1'
      value1 = 'value1'
      key2 = 'key2'
      value2 = 'value2'
      key3 = 'key3'
      value3 = 'value3'

      args = [
        "#{key1}=#{value1}",
        "#{key2}=#{value2}",
        "#{key3}=#{value3}",
      ]

      parsed_args = RunCD4PEJob::Task.new.send(:parse_args, args)

      expect(parsed_args[key1]).to eq(value1)
      expect(parsed_args[key2]).to eq(value2)
      expect(parsed_args[key3]).to eq(value3)
    end
  end

  describe 'cd4pe_job_helper::initialize' do
    it 'Passes the container run args through without modifying the structure.' do
      arg1 = '--testarg=woot'
      arg2 = '--otherarg=hello'
      arg3 = '--whatever=isclever'
      user_specified_container_run_args = [arg1, arg2, arg3]

      job_helper = RunCD4PEJob::CD4PEJobRunner.new(windows_job: @windows_job, working_dir: @working_dir, container_run_args: user_specified_container_run_args, job_owner: @job_owner,
job_instance_id: @job_instance_id, logger: @logger, secrets: @secrets, cd4pe_client: @cd4pe_client)

      expect(job_helper.instance_variable_get(:@container_run_args)).to eq("#{arg1} #{arg2} #{arg3}")
    end

    it 'Sets the HOME and REPO_DIR env vars' do
      job_helper = RunCD4PEJob::CD4PEJobRunner.new(windows_job: @windows_job, working_dir: @working_dir, job_owner: @job_owner, job_instance_id: @job_instance_id, logger: @logger, secrets: @secrets,
cd4pe_client: @cd4pe_client)

      expect(!ENV['HOME'].nil?).to be(true)
      expect(ENV['REPO_DIR']).to eq("#{@working_dir}/cd4pe_job/repo")
    end
  end
end

describe 'cd4pe_job_helper::run_job' do
  before(:all) do
    @logger = RunCD4PEJob::Logger.new
    @working_dir = File.join(Dir.getwd, 'test_working_dir')
    cd4pe_job_dir = File.join(@working_dir, 'cd4pe_job')
    jobs_dir = File.join(cd4pe_job_dir, 'jobs')
    os_dir = File.join(jobs_dir, 'unix')
    @job_script = File.join(os_dir, 'JOB')
    @after_job_success_script = File.join(os_dir, 'AFTER_JOB_SUCCESS')
    @after_job_failure_script = File.join(os_dir, 'AFTER_JOB_FAILURE')

    @windows_job = ENV['RUN_WINDOWS_UNIT_TESTS']
    if @windows_job
      os_dir = File.join(jobs_dir, 'windows')
      @job_script = File.join(os_dir, 'JOB.ps1')
      @after_job_success_script = File.join(os_dir, 'AFTER_JOB_SUCCESS.ps1')
      @after_job_failure_script = File.join(os_dir, 'AFTER_JOB_FAILURE.ps1')
    end

    Dir.mkdir(@working_dir)
    Dir.mkdir(cd4pe_job_dir)
    Dir.mkdir(jobs_dir)
    Dir.mkdir(os_dir)

    File.write(@job_script, '')
    File.chmod(0o775, @job_script)
    File.write(@after_job_success_script, '')
    File.chmod(0o775, @after_job_success_script)
    File.write(@after_job_failure_script, '')
    File.chmod(0o775, @after_job_failure_script)
  end

  after(:all) do
    FileUtils.remove_dir(@working_dir)
  end

  it 'Runs the success script after a successful script run' do
    $stdout = StringIO.new

    expected_output = 'in job script'
    after_job_success_message = 'in after success script'

    File.write(@job_script, "echo \"#{expected_output}\"")
    File.write(@after_job_success_script, "echo \"#{after_job_success_message}\"")

    job_helper = RunCD4PEJob::CD4PEJobRunner.new(windows_job: @windows_job, working_dir: @working_dir, job_owner: @job_owner, job_instance_id: @job_instance_id, logger: @logger, secrets: @secrets,
cd4pe_client: @cd4pe_client)
    output = job_helper.run_job

    expect(output[:job][:exit_code]).to eq(0)
    expect(output[:job][:message]).to eq("#{expected_output}\n")
    expect(output[:after_job_success][:exit_code]).to eq(0)
    expect(output[:after_job_success][:message]).to eq("#{after_job_success_message}\n")
  end

  it 'Runs the failure script after a failed script run' do
    $stdout = StringIO.new

    if @windows_job
      after_job_failure_message = 'in after failure script'
      File.write(@job_script, "$ErrorActionPreference = 'Stop'; this command does not exist")
      File.write(@after_job_failure_script, "echo \"#{after_job_failure_message}\"")

      job_helper = RunCD4PEJob::CD4PEJobRunner.new(windows_job: @windows_job, working_dir: @working_dir, job_owner: @job_owner, job_instance_id: @job_instance_id, logger: @logger, secrets: @secrets,
cd4pe_client: @cd4pe_client)
      output = job_helper.run_job

      expect(output[:job][:exit_code]).to eq(1)
      expect(output[:job][:message].start_with?("this : The term 'this' is not recognized as the name of a cmdlet")).to be(true)
      expect(output[:after_job_failure][:exit_code]).to eq(0)
      expect(output[:after_job_failure][:message]).to eq("#{after_job_failure_message}\n")
    else
      after_job_failure_message = 'in after failure script'
      File.write(@job_script, 'this command does not exist')
      File.write(@after_job_failure_script, "echo \"#{after_job_failure_message}\"")

      job_helper = RunCD4PEJob::CD4PEJobRunner.new(windows_job: @windows_job, working_dir: @working_dir, job_owner: @job_owner, job_instance_id: @job_instance_id, logger: @logger, secrets: @secrets,
cd4pe_client: @cd4pe_client)
      output = job_helper.run_job

      expect(output[:job][:exit_code]).to eq(127)
      expect(output[:job][:message].end_with?("command not found\n")).to be(true)
      expect(output[:after_job_failure][:exit_code]).to eq(0)
      expect(output[:after_job_failure][:message]).to eq("#{after_job_failure_message}\n")
    end
  end

  it 'Fails the job if the job script fails' do
    File.write(@job_script, 'exit 1;')

    job_helper = RunCD4PEJob::CD4PEJobRunner.new(windows_job: @windows_job, working_dir: @working_dir, job_owner: @job_owner, job_instance_id: @job_instance_id, logger: @logger, secrets: @secrets,
cd4pe_client: @cd4pe_client)
    output = job_helper.run_job

    expect(output[:job][:exit_code]).to eq(1)
  end
end

describe 'cd4pe_job_helper::unzip' do
  before(:all) do
    @windows_job = ENV['RUN_WINDOWS_UNIT_TESTS']
    @working_dir = File.join(Dir.getwd, 'test_working_dir')
    @test_tar_files_dir = File.join(Dir.getwd, 'spec', 'fixtures', 'test_tar_files')
    Dir.mkdir(@working_dir)
  end

  after(:all) do
    FileUtils.remove_dir(@working_dir)
  end

  it 'unzips a single file tar.gz' do
    single_file_tar = File.join(@test_tar_files_dir, 'gzipSingleFileTest.tar.gz')
    single_file = File.join(@working_dir, 'gzipSingleFileTest')
    RunCD4PEJob::GZipHelper.unzip(single_file_tar, @working_dir)

    expect(File.exist?(single_file)).to be(true)

    file_data = File.read(single_file)
    expect(file_data).to eql('test data')
  end

  it 'unzips a single level directory tar.gz' do
    single_level_dir_tar = File.join(@test_tar_files_dir, 'gzipSingleLevelDirectoryTest.tar.gz')
    single_level_dir = File.join(@working_dir, 'gzipSingleLevelDirectoryTest')
    RunCD4PEJob::GZipHelper.unzip(single_level_dir_tar, @working_dir)

    expect(File.exist?(single_level_dir)).to be(true)
    test_file_1 = File.join(single_level_dir, 'testFile1')
    test_file_2 = File.join(single_level_dir, 'testFile2')
    expect(File.exist?(test_file_1)).to be(true)
    expect(File.exist?(test_file_2)).to be(true)

    file_1_data =  File.read(test_file_1)
    file_2_data =  File.read(test_file_2)
    expect(file_1_data).to eql('I am test file 1!')
    expect(file_2_data).to eql('I am test file 2!')
  end

  it 'unzips a multi level directory tar.gz' do
    multi_level_dir_tar = File.join(@test_tar_files_dir, 'gzipMultiLevelDirectoryTest.tar.gz')
    multi_level_dir = File.join(@working_dir, 'gzipMultiLevelDirectoryTest')
    sub_dir = File.join(multi_level_dir, 'subDir')
    RunCD4PEJob::GZipHelper.unzip(multi_level_dir_tar, @working_dir)

    # root dir
    expect(File.exist?(multi_level_dir)).to be(true)
    root_file_1 = File.join(multi_level_dir, 'rootFile1')
    root_file_2 = File.join(multi_level_dir, 'rootFile2')
    expect(File.exist?(root_file_1)).to be(true)
    expect(File.exist?(root_file_2)).to be(true)

    root_file_1_data =  File.read(root_file_1)
    root_file_2_data =  File.read(root_file_2)
    expect(root_file_1_data).to eql('I am in root 1!')
    expect(root_file_2_data).to eql('I am in root 2!')

    # sub dir
    expect(File.exist?(sub_dir)).to be(true)
    sub_file_1 = File.join(sub_dir, 'subDirFile1')
    sub_file_2 = File.join(sub_dir, 'subDirFile2')
    expect(File.exist?(sub_file_1)).to be(true)
    expect(File.exist?(sub_file_2)).to be(true)

    sub_file_1_data =  File.read(sub_file_1)
    sub_file_2_data =  File.read(sub_file_2)
    expect(sub_file_1_data).to eql('I am in sub 1!')
    expect(sub_file_2_data).to eql('I am in sub 2!')
  end

  it 'maintains file permissions when extracting' do
    executable_tar = File.join(@test_tar_files_dir, 'executableFileTest.tar.gz')
    executable = File.join(@working_dir, 'executableFileTest')

    if @windows_job
      executable_tar = File.join(@test_tar_files_dir, 'executableWindowsFileTest.tar.gz')
      filePath = File.join(@working_dir, 'windows', 'executableWindowsFileTest.ps1')
      executable = "powershell \"& {&'#{filePath}'}\""
    end

    RunCD4PEJob::GZipHelper.unzip(executable_tar, @working_dir)

    output = ''
    exit_code = 0

    Open3.popen2e(executable) do |_stdin, stdout_stderr, wait_thr|
      exit_code = wait_thr.value.exitstatus
      output = stdout_stderr.read
    end

    expect(exit_code).to eql(0)
    expect(output).to eql("hello!\n")
  end

  it 'unzips a file with a filename > 100 characters' do
    single_level_dir_tar = File.join(@test_tar_files_dir, 'long_file_name.tar.gz')
    single_level_dir = File.join(@working_dir, 'long_file_name')
    RunCD4PEJob::GZipHelper.unzip(single_level_dir_tar, @working_dir)

    expect(File.exist?(single_level_dir)).to be(true)
    test_file_1 = File.join(single_level_dir,
'IAMASUPERLONGFILENAMEIAMASUPERLONGFILENAMEIAMASUPERLONGFILENAMEIAMASUPERLONGFILENAMEIAMASUPERLONGFILENAMEIAMASUPERLONGFILENAMEIAMASUPERLONGFILENAMEIAMASUPERLONGFILENAMEIAMASUPE')
    expect(File.exist?(test_file_1)).to be(true)
  end

  it 'unzips a file with PAX Headers' do
    single_level_dir_tar = File.join(@test_tar_files_dir, 'with_pax_headers.tar.gz')
    single_level_dir = File.join(@working_dir, 'cd4pe_job')
    RunCD4PEJob::GZipHelper.unzip(single_level_dir_tar, @working_dir)

    expect(File.exist?(single_level_dir)).to be(true)
    test_file_1 = File.join(single_level_dir,
'/repo/manifests/controls/rhel_8/v3_0_0/access_authentication_and_authorization/configure_jobs_for_testing_is_this_File_path_too_long_to_unzip_i_am_not_sure_what_if_it_is_too_long.pp')
    expect(File.exist?(test_file_1)).to be(true)
  end
end
