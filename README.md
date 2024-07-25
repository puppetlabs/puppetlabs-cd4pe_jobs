# cd4pe_jobs

This module exists for Continuous Delivery for Puppet Enterprise to run jobs on Puppet Agents via Bolt. It contains a single task to do this and works with both \*nix and Windows.

To run tests (from root of repo):
`bundle exec rspec spec`

## Release puppetlabs-cd4pe_jobs

1. Create a branch off `master` using the following convention:
```shell
git checkout -b 1.7.0-release
```
2. On a new branch based on the release branch, update CHANGELOG.md with any changes in this release and metadata.json with the new version number.
3. Commit these changes and put up a PR against the release branch you created in Step 1 and get review.
4. Once the changes have been approved and merged to the release branch, pull down the updated release branch and tag the module.
```shell
git tag -a 1.7.0 -m "1.7.0"
```
6. Run the https://github.com/puppetlabs/PipelinesInfra/actions/workflows/release-cd4pe_jobs.yml workflow with the release branch created above to build the tarball and push it to the forge.
7. Update the ref in PE: https://github.com/puppetlabs/pe-tasks-vanagon/blob/main/configs/components/puppetlabs-cd4pe_jobs.json. This will ensure that the new version is shipped with the next PE release.
8. Push your new tag up to the repo
```shell
git push --tags
```
9. Make a PR from the release branch back to `master`. Once this is merged the release branch should be deleted.
