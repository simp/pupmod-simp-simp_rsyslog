# Merges a hash of arrays
#
Puppet::Functions.create_function(:'simp_rsyslog::merge_hash_of_arrays') do
  # @param first_hash
  #   First hash to be merged.  Must be a Hash of Arrays.
  #
  # @param additional_hashes
  #   1 more more additional hashes to be merged.  Each must be a Hash
  #   of Arrays.
  #
  # @return Hash
  #   Hash containing the superset of keys found in all parameters
  #   and merged Array values
  #
  dispatch :merge_hash_of_arrays do
    required_param          'Hash', :first_hash
    required_repeated_param 'Hash', :additional_hashes_to_merge
  end

  def merge_hash_of_arrays(first_hash, *additional_hashes)
    require 'deep_merge'
    validate(first_hash)
    merged_hash = first_hash.dup
    additional_hashes.each do |hash|
      validate(hash)
      merged_hash.deep_merge!(hash)
    end
    return merged_hash
  end

  def validate(hash)
    hash.each do |tag,value|
      fail("'#{hash}' is not a Hash of Arrays") unless value.is_a?(Array)
    end
  end
end
