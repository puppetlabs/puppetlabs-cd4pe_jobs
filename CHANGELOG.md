# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

No unreleased changes.

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
