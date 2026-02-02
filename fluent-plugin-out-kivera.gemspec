# -*- encoding: utf-8 -*-

Gem::Specification.new do |gem|
  gem.name          = "fluent-plugin-out-kivera"
  gem.version       = "1.0.4"
  gem.authors       = ["Tyler Matheson"]
  gem.email         = ["tyler@kivera.io"]
  gem.summary       = "Fluentd plugin for Kivera"
  gem.description   = "A Fluentd output plugin for sending Kivera proxy logs to the Kivera log ingestion service"
  gem.homepage      = "https://github.com/kivera-io/fluent-plugin-out-kivera"
  gem.licenses      = ["Apache-2.0"]

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.required_ruby_version  = '>= 2.1.0'

  gem.add_runtime_dependency "yajl-ruby", "~> 1.0"
  gem.add_runtime_dependency "fluentd", [">= 0.14.22", "< 2"]
  gem.add_runtime_dependency "jwt", '~> 2.2'
  gem.add_development_dependency "bundler"
  gem.add_development_dependency "rake"
  gem.add_development_dependency "test-unit", ">= 3.1.0"
  gem.add_development_dependency "webrick"
end
