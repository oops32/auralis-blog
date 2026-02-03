source "https://rubygems.org"

# gem "jekyll", "~> 4.3.0" # Commented out - using github-pages gem instead
gem "github-pages", "~> 232", group: :jekyll_plugins
gem "webrick", "~> 1.8" # Required for Ruby 3.0+

group :jekyll_plugins do
  gem "jekyll-feed", "~> 0.12"
  gem "jekyll-seo-tag", "~> 2.8"
end

platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

gem "wdm", "~> 0.1", :platforms => [:mingw, :x64_mingw, :mswin]
gem "http_parser.rb", "~> 0.6.0", :platforms => [:jruby]
