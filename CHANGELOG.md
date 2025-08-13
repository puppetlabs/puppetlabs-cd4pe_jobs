# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

No unreleased changes.

## [1.7.2](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.7.2)

### Added
- Added logging to indicate that when the image pull fails, the module will assume the image is present
  locally and attempt to use that to run the job.

### Fixed
- The module's main task is now marked as private, since users are not expected to run it directly.


## [1.7.1](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.7.1)

### Fixed
- Issue where jobs would report success even if the script returns 1 on Windows (Powershell)

## [1.7.0](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.7.0)

### Added
- Added podman support for containerized jobs. If podman is detected on a job hardware node, it will be used instead of docker.

## [1.6.3](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.6.3)

### Fixed
- Fixed misleading Puppet version requirements accidentally released in 1.6.2.

## [1.6.2](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.6.2)

### Fixed
- Fixed issue in tarball unpacking where pax header lines were causing some long filenames to be truncated.


## [1.6.1](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.6.1)

### Fixed
- Updated module to use File#exist? instead of deprecated (and removed in Ruby 3.2.0/Puppet 8) File#exists?

## [1.6.0](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.6.0)

### Added

- Added optional parameter for passing in secrets that should be set as environment variables before running the job script

## [1.5.0](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.5.0)

### Added

- Added verbose logging for failed http requests.

## [1.4.0](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.4.0)

### Added

- Added the ability to include registry credentials when pulling the Docker image.
- Added the ability to trust registries that use the same CA as CD4PE when pulling the Docker image.

## [1.3.0](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.3.0)

### Added

- Added the ability to pass a custom net http timeout to jobs in order to increase the time a job waits for a response when hitting CD4PE endpoints.

## [1.2.1](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.2.1)

### Fixed

- Fixed a problem where jobs with large output could hang indefinitely.

## [1.2.0](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.2.0)

### Fixed

- Improved support for jobs with substantial log output.

## [1.1.1](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.1.1)

### Fixed

- No longer fail when setting \$HOME on windows machines.

## [1.1.0](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.1.0)

### Added

- When writing job scripts, user now has access to HOME and REPO_DIR environment variables.

### Fixed

- Increase read_timeout to 600 to accomadate large repositories

## [1.0.0](https://github.com/puppetlabs/puppetlabs-cd4pe_jobs/tree/1.0.0)

Initial release: Support for running jobs for Continuous Delivery for Puppet Enterprise on Puppet Agents managed by the Puppet Enterprise Orchestrator.
