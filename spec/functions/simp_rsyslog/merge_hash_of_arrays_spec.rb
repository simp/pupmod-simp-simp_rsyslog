#!/usr/bin/env ruby -S rspec
require 'spec_helper'

describe 'simp_rsyslog::merge_hash_of_arrays' do
  let(:hash1) do
    {
      'programs'   => ['program1', 'program2'],
    'facilities' => ['facility1'],
    'msg_starts' => ['start1', 'start2']
    }
  end

  let(:hash2) do
    {
      'programs'   => ['program2', 'program3'],
    'msg_starts' => ['start0']
    }
  end

  let(:hash3) do
    {
      'programs'   => ['program1', 'program4', 'program0'],
    'facilities' => ['facility3'],
    'msg_starts' => [],
    'msg_regex'  => ['msg[0-9]+']
    }
  end

  context 'with valid parameters' do
    it { is_expected.to run.with_params(hash1, {}).and_return(hash1) }
    it { is_expected.to run.with_params({}, hash1).and_return(hash1) }
    it {
      is_expected.to run.with_params(hash1, hash2, hash3).and_return(
        {
          'programs'   => ['program1', 'program2', 'program3', 'program4', 'program0'],
          'facilities' => ['facility1', 'facility3'],
          'msg_starts' => ['start1', 'start2', 'start0'],
          'msg_regex'  => ['msg[0-9]+']
        },
      )
    }
  end

  context 'with bad parameters' do
    it {
      is_expected.to run.with_params({ 'programs' => 'program0' }, hash3).and_raise_error(%r{is not a Hash of Arrays})
    }

    it {
      is_expected.to run.with_params(hash1, { 'programs' => 'program5' }).and_raise_error(%r{is not a Hash of Arrays})
    }
  end
end
