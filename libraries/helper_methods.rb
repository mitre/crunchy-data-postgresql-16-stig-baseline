module CustomHelpers
  def report_result(description)
    yield
    puts "#{description}: OK"
  rescue RSpec::Expectations::ExpectationNotMetError => e
    puts "#{description}: FAILED"
    raise e
  end
end

# Include your module so the methods are available globally
# This is required in InSpec profiles
class ::Inspec::ProfileContext
  include CustomHelpers
end
