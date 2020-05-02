env = ENV['RACK_ENV'].to_sym

require "bundler/setup"
Bundler.require(:default, env)

Dotenv.load unless env == :production

require 'rack/csrf'
require './app'
run Sinatra::Application
