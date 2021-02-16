# -*- encoding: utf-8 -*-

Gem::Specification.new do |gem|
  gem.name          = "fluent-plugin-out-kivera"
  gem.version       = "1.3.3"
  gem.authors       = ["Tyler Matheson", "Marica Odagaki"]
  gem.email         = ["tyler@kivera.io"]
  gem.summary       = %q{A Fluentd output plugin to send Kivera proxy logs to Kivera log ingestion service}
  gem.description   = gem.summary
  gem.homepage      = "https://github.com/kivera-io/fluent-plugin-out-kivera"
  gem.licenses      = ["Apache-2.0"]

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.required_ruby_version  = '>= 2.1.0'

  gem.add_runtime_dependency "yajl-ruby", "~> 1.0"
  gem.add_runtime_dependency "fluentd", [">= 0.14.22", "< 2"]
  gem.add_development_dependency "jwt"
  gem.add_development_dependency "bundler"
  gem.add_development_dependency "rake"
  gem.add_development_dependency "test-unit", ">= 3.1.0"
end
