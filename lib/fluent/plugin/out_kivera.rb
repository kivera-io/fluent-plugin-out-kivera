require 'net/http'
require 'uri'
require 'yajl'
require 'fluent/plugin/output'
require 'tempfile'
require 'openssl'
require 'zlib'
require 'jwt'

class Fluent::Plugin::HTTPOutput < Fluent::Plugin::Output
  Fluent::Plugin.register_output('kivera', self)

  class RecoverableResponse < StandardError; end

  helpers :compat_parameters, :formatter, :storage

  DEFAULT_STORAGE_TYPE = "local"
  DEFAULT_BUFFER_TYPE = "memory"
  DEFAULT_FORMATTER = "json"
  TOKEN_EXPIRY_OFFSET = 300

  def initialize
    super
  end

  # Endpoint URL ex. http://localhost.local/api/
  config_param :endpoint_url, :string, default: ""

  # Set Net::HTTP.verify_mode to `OpenSSL::SSL::VERIFY_NONE`
  config_param :ssl_no_verify, :bool, :default => false

  # Simple rate limiting: ignore any records within `rate_limit_msec`
  # since the last one.
  config_param :rate_limit_msec, :integer, :default => 0

  # Raise errors that were rescued during HTTP requests?
  config_param :raise_on_error, :bool, :default => true

  # Specify recoverable error codes
  config_param :recoverable_status_codes, :array, value_type: :integer, default: [503]

  # kivera proxy client config file
  config_param :config_file, :string, default: ""

  # kivera proxy client id
  config_param :client_id, :string, default: ""

  # kivera proxy client secret
  config_param :client_secret, :string, default: ""

  # kivera audience api
  config_param :audience, :string, default: ""

  # explicit Kivera auth0 certificate as a string
  config_param :auth0_cert, :string, default: ""

  # Kivera auth0 certificate file
  config_param :auth0_cert_file, :string, default: ""

  # Kivera auth0 domain
  config_param :auth0_domain, :string, default: ""

  # custom headers
  config_param :custom_headers, :hash, :default => nil

  # Switch non-buffered/buffered plugin
  config_param :bulk_request, :bool, :default => true
  config_param :buffered, :bool, :default => false
  # Compress with gzip except for form serializer
  config_param :compress_request, :bool, :default => false

  config_section :buffer do
    config_set_default :@type, DEFAULT_BUFFER_TYPE
    config_set_default :chunk_keys, ['tag']
  end

  config_section :format do
    config_set_default :@type, DEFAULT_FORMATTER
  end

  def configure(conf)
    compat_parameters_convert(conf, :buffer, :formatter)
    super

    @ssl_verify_mode = if @ssl_no_verify
                         OpenSSL::SSL::VERIFY_NONE
                       else
                         OpenSSL::SSL::VERIFY_PEER
                       end

    @last_request_time = nil
    raise Fluent::ConfigError, "'tag' in chunk_keys is required." if !@chunk_key_tag && @buffered

    if @formatter_config = conf.elements('format').first
      @formatter = formatter_create
    end

    if @bulk_request
      class << self
        alias_method :format, :bulk_request_format
      end
      @formatter = formatter_create(type: :json)
      @serializer = :x_ndjson # secret settings for bulk_request
    else
      class << self
        alias_method :format, :split_request_format
      end
      @serializer = :json
    end

    # Create local storage for persisting JWT token
    config = conf.elements(name: 'storage').first
    @storage = storage_create(usage: 'jwt_token', conf: config, default_type: 'local')

    if ! @config_file.empty?
      creds =  File.read(@config_file)
      parsed = Yajl::Parser.new.parse(StringIO.new(creds))
      @client_id = parsed.fetch("client_id", @client_id)
      @client_secret = parsed.fetch("client_secret", @client_secret)
      @audience = parsed.fetch("audience", @audience)
      @auth0_cert = parsed.fetch("auth0_cert", @auth0_cert)
      @auth0_cert_file = parsed.fetch("auth0_cert", @auth0_cert_file)
      @auth0_domain = parsed.fetch("auth0_domain", @auth0_domain)
    end

    if @auth0_cert.empty? && ! @auth0_cert_file.empty?
      @auth0_cert = File.read(@auth0_cert_file)
    end

    if @client_id.empty? && 
        @client_secret.empty? && 
        @audience.empty? && 
        @auth0_cert.empty? && 
        @auth0_domain.empty?
      params = "client_id, client_secret, audience, auth0_cert and auth0_domain"
      raise Fluent::ConfigError, "Missing configuration. Either specify a config_file or set the #{params} parameters"
    end

    if @endpoint_url.empty?
      @endpoint_url = "https://#{@auth0_domain.sub("auth", "logs")}"
      log.info "Using logs endpoint #{@endpoint_url}"
    end

  end

  def start
    super
  end

  def shutdown
    super
  end

  def format_url(tag, time, record)
    @endpoint_url
  end

  def set_body(req, tag, time, record)
    if @serializer == :json
      set_json_body(req, record)
    elsif @serializer == :x_ndjson
      set_bulk_body(req, record)
    else
      req.set_form_data(record)
    end
    req
  end

  def set_header(req, tag, time, record)
    if @custom_headers
      @custom_headers.each do |k,v|
        req[k] = v
      end
      req
    else
      req
    end
  end

  def refresh_jwt_token
    if @storage.get(:jwt_token)
      if token_expired
        @storage.put(:jwt_token, new_jwt_token)
      end
    else
      @storage.put(:jwt_token, new_jwt_token)
    end
  end

  def token_expired
    x509 = OpenSSL::X509::Certificate.new(@auth0_cert)
    begin
      decoded_token = JWT.decode @storage.get(:jwt_token), x509.public_key, true, { algorithm: 'RS256' }
    rescue => e
        log.info 'JWT token expired'
        return true
    else
      if decoded_token[0]['exp'] - Time.now.to_f < TOKEN_EXPIRY_OFFSET
        log.info 'JWT token about to expire'
        return true
      end
      return false
    end
  end

  def new_jwt_token
    url = "https://" + @auth0_domain + "/oauth/token"
    uri = URI.parse(url)
    req = Net::HTTP::Post.new(uri.to_s)
    payload = { 
      "client_id" =>      @client_id,
			"client_secret" =>  @client_secret,
			"audience" =>       @audience,
      "grant_type" =>     "client_credentials"
    }
    set_json_body(req, payload)
    res = https(uri).request(req)
    case res
    when Net::HTTPSuccess then
      parsed = Yajl::Parser.new.parse(StringIO.new(res.body))
      log.info 'Generated new JWT token'
      parsed['access_token']
    else
      log.warn "Failed to get token for client #{@client_id}"
    end
  end

  def https(uri)
    Net::HTTP.new(uri.host, uri.port).tap { |http|
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    }
  end

  def compress_body(req, data)
    return unless @compress_request
    gz = Zlib::GzipWriter.new(StringIO.new)
    gz << data

    req['Content-Encoding'] = "gzip"
    req.body = gz.close.string
  end

  def set_json_body(req, data)
    req.body = Yajl.dump(data)
    req['Content-Type'] = 'application/json'
    compress_body(req, req.body)
  end

  def set_bulk_body(req, data)
    req.body = data.to_s
    req['Content-Type'] = 'application/x-ndjson'
    compress_body(req, req.body)
  end

  def set_jwt_auth(req)
    refresh_jwt_token
    req['Authorization'] = "Bearer #{@storage.get(:jwt_token)}"
  end

  def create_request(tag, time, record)
    url = format_url(tag, time, record)
    uri = URI.parse(url)
    req = Net::HTTP::Put.new(uri.request_uri)
    set_body(req, tag, time, record)
    set_header(req, tag, time, record)
    set_jwt_auth(req)
    return req, uri
  end

  def http_opts(uri)
    opts = {
      :use_ssl => uri.scheme == 'https'
    }
    opts[:verify_mode] = @ssl_verify_mode if opts[:use_ssl]
    opts
  end

  def proxies
    ENV['HTTPS_PROXY'] || ENV['HTTP_PROXY'] || ENV['http_proxy'] || ENV['https_proxy']
  end

  def send_request(req, uri)
    is_rate_limited = (@rate_limit_msec != 0 and not @last_request_time.nil?)
    if is_rate_limited and ((Time.now.to_f - @last_request_time) * 1000.0 < @rate_limit_msec)
      log.info('Dropped request due to rate limiting')
      return
    end

    res = nil

    begin

      log.debug "Sending #{req.body.bytesize}B to #{uri}"

      if proxy = proxies
        proxy_uri = URI.parse(proxy)

        res = Net::HTTP.start(uri.host, uri.port,
                              proxy_uri.host, proxy_uri.port, proxy_uri.user, proxy_uri.password,
                              **http_opts(uri)) {|http| http.request(req) }
      else
        res = Net::HTTP.start(uri.host, uri.port, **http_opts(uri)) {|http| http.request(req) }
      end

    rescue => e # rescue all StandardErrors
      # server didn't respond
      log.warn "Net::HTTP.#{req.method.capitalize} raises exception: #{e.class}, '#{e.message}'"
      raise e if @raise_on_error
    else
       unless res and res.is_a?(Net::HTTPSuccess)
          res_summary = if res
                           "#{res.code} #{res.message} #{res.body}"
                        else
                           "res=nil"
                        end
          if @recoverable_status_codes.include?(res.code.to_i)
            raise RecoverableResponse, res_summary
          else
            log.warn "failed to #{req.method} #{uri} (#{res_summary})"
          end
       end #end unless
    end # end begin
  end # end send_request

  def handle_record(tag, time, record)
    if @formatter_config
      record = @formatter.format(tag, time, record)
    end
    req, uri = create_request(tag, time, record)
    send_request(req, uri)
  end

  def handle_records(tag, time, chunk)
    req, uri = create_request(tag, time, chunk.read)
    send_request(req, uri)
  end

  def prefer_buffered_processing
    @buffered
  end

  def format(tag, time, record)
    # For safety.
  end

  def split_request_format(tag, time, record)
    [time, record].to_msgpack
  end

  def bulk_request_format(tag, time, record)
    @formatter.format(tag, time, record)
  end

  def formatted_to_msgpack_binary?
    if @bulk_request
      false
    else
      true
    end
  end

  def multi_workers_ready?
    true
  end

  def process(tag, es)
    es.each do |time, record|
      handle_record(tag, time, record)
    end
  end

  def write(chunk)
    tag = chunk.metadata.tag
    @endpoint_url = extract_placeholders(@endpoint_url, chunk)

    log.debug { "#{@http_method.capitalize} data to #{@endpoint_url} with chunk(#{dump_unique_id_hex(chunk.unique_id)})" }

    if @bulk_request
      time = Fluent::Engine.now
      handle_records(tag, time, chunk)
    else
      chunk.msgpack_each do |time, record|
        handle_record(tag, time, record)
      end
    end
  end
end
