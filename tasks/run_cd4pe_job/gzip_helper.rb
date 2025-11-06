# frozen_string_literal: true

require 'rubygems/package'

module RunCD4PEJob
  # Class to decompress tar.gz files
  class GZipHelper
    # Unzip tar.gz
    #
    # @param zipped_file_path [String] path to the tar.gz file
    # @param destination_path [String] path to extract the contents to
    def self.unzip(zipped_file_path, destination_path)
      Gem::Package::TarReader.new(Zlib::GzipReader.open(zipped_file_path)) do |tar|
        dest = nil
        tar.each do |entry|
          # skip 'PaxHeaders.X' entries as they interfere with the TAR_LONGLINK logic
          if entry.header.typeflag == PAX_HEADER
            next
          end

          # If file/dir name length > 100 chars, its broken into multiple entries.
          # This code glues the name back together
          if entry.full_name == TAR_LONGLINK
            dest = File.join(destination_path, entry.read.strip)
            next
          end

          # If the destination has not yet been set
          # set it equal to the path + file/dir name
          if dest.nil?
            dest = File.join(destination_path, entry.full_name)
          end

          # Write the file or dir
          if entry.directory?
            # Make directory
            FileUtils.rm_rf(dest) unless File.directory?(dest)
            FileUtils.mkdir_p(dest, mode: entry.header.mode, verbose: false)
          elsif entry.file?
            # Make file
            FileUtils.rm_rf dest unless File.file? dest
            File.open(dest, 'wb') do |file|
              file.print(entry.read)
            end
            FileUtils.chmod(entry.header.mode, dest, verbose: false)
          elsif entry.header.typeflag == SYMLINK_SYMBOL
            # Preserve symlink
            File.symlink(entry.header.linkname, dest)
          end

          # reset dest for next entry iteration
          dest = nil
        end
      end
    end

    private

    TAR_LONGLINK = '././@LongLink'
    SYMLINK_SYMBOL = '2'
    PAX_HEADER = 'x'
  end
end
