SHELL=/bin/bash
.ONESHELL:
.EXPORT_ALL_VARIABLES:

build:
	@if [ "${VER}" = "" ]; then echo "VER not set"; exit 1; else echo "VER=${VER}"; fi
	sed -i '' 's/  gem.version.*/  gem.version       = "${VER}"/g' fluent-plugin-out-kivera.gemspec
	gem build fluent-plugin-out-kivera

push:
	@if [ "${VER}" = "" ]; then echo "VER not set"; exit 1; else echo "VER=${VER}"; fi
	gem push fluent-plugin-out-kivera-${VER}.gem
