# cd4pe_jobs

This module exists for Continuous Delivery for Puppet Enterprise to run jobs on Puppet Agents via Bolt. It contains a single task to do this and works with both \*nix and Windows.

To run tests (from root of repo):
`bundle exec rspec spec`

## Release puppetlabs-cd4pe_jobs

1. Create a branch off `master` using the following convention:
```shell
git checkout -b 1.6.0-release
```
2. On the new branch, update CHANGELOG.md with any changes in this release and metadata.json with the new version number.
3. Commit these changes
4. Tag the new branch with the new version number
```shell
git tag -a 1.6.0 -m "1.6.0"
```
5. Push your changes to origin for PR review and merge
```shell
git push origin 1.6.0-release --follow-tags
```   
6. Run `pdk build` in the root of the module to get the new tarball
7. Log into https://forge.puppet.com as 'puppetlabs' and publish the new module version
