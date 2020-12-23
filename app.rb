# frozen_string_literal: true

configure do
  # use a cookie that lasts for 1 minute
  secret = ENV['COOKIE_SECRET'] || SecureRandom.hex(20)
  use Rack::Session::Cookie, secret: secret, expire_after: 60

  use Rack::SSL if settings.production?

  REDIS = Redis.new(url: ENV['REDIS_URL'])

  use OmniAuth::Builder do
    provider :github, ENV['GITHUB_KEY'], ENV['GITHUB_SECRET'], scope: 'user'
  end

  unless settings.production?
    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:github] = OmniAuth::AuthHash.new({
                                                                  provider: 'github',
                                                                  uid: ENV['GITHUB_USERNAME'],
                                                                  info: { nickname: ENV['GITHUB_USERNAME'] }
                                                                })
  end
end

helpers do
  def set_auth(code, me, scope, code_challenge, code_challenge_method)
    json = { me: me, scope: scope, code_challenge: code_challenge, code_challenge_method: code_challenge_method }.to_json
    REDIS.set(code, json)
    logger.info "Setting auth key #{code} with json #{json}"
    REDIS.expire(code, 60)
  end

  def get_auth(code)
    json = REDIS.get(code)
    logger.info "Getting auth key #{code} and found json #{json}"
    JSON.parse(json)
  end

  def set_token(token, me, scope, client_id)
    json = { me: me, scope: scope, client_id: client_id }.to_json
    REDIS.set(token, json)
    logger.info "Setting token #{token} with json #{json}"
    token_expiry(token)
  end

  def get_token(token)
    json = REDIS.get(token)
    logger.info "Getting token #{token} and found json #{json}"
    data = JSON.parse(json)
    # reset expiry with every use
    token_expiry(token)
    data
  end

  def token_expiry(token)
    # token lasts for 30 days
    REDIS.expire(token, 2_592_000)
  end

  def render_data(data)
    if request.accept?('application/json')
      content_type :json
      data.to_json
    else
      content_type 'application/x-www-form-urlencoded'
      URI.encode_www_form(data)
    end
  end

  def halt_error(message)
    logger.info "Halted on error #{message}"
    halt message
  end

  def verify_code_verifier(verifier, challenge)
    Base64.urlsafe_encode64(Digest::SHA256.digest(verifier)).gsub(/=/, '') == challenge
  end

  def h(text)
    Rack::Utils.escape_html(text)
  end
end

get '/' do
  'Authorization server'
end

get '/auth' do
  %w[me client_id redirect_uri state].each do |param|
    unless params.key?(param) && !params[param].empty?
      halt_error("Authorization request was missing '#{param}' parameter.")
    end
  end

  session[:redirect_uri] = params[:redirect_uri]
  session[:client_id] = params[:client_id]
  session[:me] = params[:me]
  session[:state] = params[:state]
  session[:scope] = params[:scope] || ''
  session[:code_challenge] = params[:code_challenge] || ''
  session[:code_challenge_method] = params[:code_challenge_method] || ''

  # TODO: Get the microformats from the client and show this on the auth page - https://indieauth.spec.indieweb.org/#client-information-discovery
  erb :auth
end

get '/auth/github/callback' do
  # confirm auth'd github username matches my github username
  username = request.env['omniauth.auth']['info']['nickname']
  halt_error("GitHub username (#{username}) does not match.") unless username == ENV['GITHUB_USERNAME']

  halt_error('Session has expired during authorization. Please try again.') if session.empty?

  code = SecureRandom.hex(20)
  set_auth(code, session[:me], session[:scope], session[:code_challenge], session[:code_challenge_method])

  query = URI.encode_www_form({
                                code: code,
                                state: session[:state],
                                me: session[:me]
                              })
  url = "#{session[:redirect_uri]}?#{query}"
  session.clear

  logger.info "Callback is redirecting to #{url}"
  redirect url
end

get '/auth/failure' do
  params[:message]
end

post '/auth' do
  auth = get_auth(params[:code])
  data = { me: auth['me'] }
  render_data(data)
end

post '/token' do
  %w[code redirect_uri client_id].each do |param|
    unless params.key?(param) && !params[param].empty?
      halt_error("Authorization request was missing '#{param}' parameter.")
    end
  end

  # verify against auth
  auth = get_auth(params[:code])
  if auth.nil? || auth.empty?
    halt_error('Authorization could not be found (or has expired).')
  end

  # Verify the code_challenge
  if params[:code_verifier] &&
     auth['code_challenge'] != '' &&
     !verify_code_verifier(params[:code_verifier], auth['code_challenge'])
    halt_error('Authorization request code verification failed')
  end

  token = SecureRandom.hex(50)
  set_token(token, auth['me'], auth['scope'], params[:client_id])

  data = {
    access_token: token,
    scope: auth['scope'],
    me: auth['me']
  }
  render_data(data)
end

get '/token' do
  token = request.env['HTTP_AUTHORIZATION'] || params['access_token'] || ''
  token.sub!(/^Bearer /, '')
  halt_error('Access token was not found in request header or body.') if token.empty?

  data = get_token(token)
  halt_error('Token not found (or has expired).') if data.nil? || data.empty?

  render_data(data)
end
