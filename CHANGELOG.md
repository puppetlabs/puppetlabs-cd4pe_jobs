# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

No unreleased changes.

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
