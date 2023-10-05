require 'test/unit'

$LOAD_PATH.unshift(File.expand_path(File.join(__dir__, '..')))
exit Test::Unit::AutoRunner.run(true, __dir__)