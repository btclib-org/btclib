# The btclib.org website, and only that: GitHub Pages builds it on its own
# side, so nothing here is installed to serve the site. What this file is
# for is a build that can fail out loud -- .github/workflows/website.yml,
# and a local `bundle exec jekyll serve` preview.
#
# github-pages is the gem GitHub publishes to reproduce that builder, and
# it pins jekyll, the theme and everything under them exactly, which is
# why there is no Gemfile.lock beside this: the version below is the lock.
# 232 is what Pages runs today, and
# https://pages.github.com/versions.json is what says so -- ruby 3.3.4,
# jekyll 3.10.0, jekyll-theme-minimal 0.2.0, the theme _config.yml names.
# Dependabot's bundler ecosystem moves this line, so the day GitHub
# upgrades its builder arrives as a pull request that builds the site with
# the new one rather than as a page that stopped rendering
source 'https://rubygems.org'
gem 'github-pages', '232', group: :jekyll_plugins
