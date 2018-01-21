require "cgi"
require "base64"
require "openssl"
require "digest/sha1"
#require "faraday"
require "time"
require "uri"
require "net/https"

module Alexa
  class Connection
    attr_accessor :secret_access_key, :access_key_id
    attr_writer :params


    SIGNATURE_ALGORITHM = "AWS4-HMAC-SHA256"

    def initialize(credentials = {})
      self.secret_access_key = credentials.fetch(:secret_access_key)
      self.access_key_id     = credentials.fetch(:access_key_id)
    end


    def params
      @params ||= {}
    end

    def get(params = {})
      self.params = params
      handle_response(request).body.force_encoding(Encoding::UTF_8)
    end

    def handle_response(response)
      case response.code.to_i
      when 200...300
        response
      when 300...600
        if response.body.nil?
          raise ResponseError.new(nil, response)
        else
          xml = MultiXml.parse(response.body)
          message = xml["Response"]["Errors"]["Error"]["Message"]
          raise ResponseError.new(message, response)
        end
      else
        raise ResponseError.new("Unknown code: #{response.code}", response)
      end
    end

    def getSignatureKey(key, dateStamp, regionName, serviceName)
      kDate    = OpenSSL::HMAC.digest('sha256', "AWS4" + key, dateStamp)
      kRegion  = OpenSSL::HMAC.digest('sha256', kDate, regionName)
      kService = OpenSSL::HMAC.digest('sha256', kRegion, serviceName)
      kSigning = OpenSSL::HMAC.digest('sha256', kService, "aws4_request")
      kSigning
    end

    def request
      url = "https://" + Alexa::API_HOST + Alexa::API_URI + "?" + query
      uri = URI(url)
      puts "Making request to:\n#{url}\n\n"
      req = Net::HTTP::Get.new(uri)
      req["Accept"] = "application/xml"
      req["Content-Type"] = "application/xml"
      req["x-amz-date"] = timestamp
      req["Authorization"] = authorization_header

      Net::HTTP.start(uri.host, uri.port,
        :use_ssl => uri.scheme == 'https') {|http|
        http.request(req)
      }

    end

    def timestamp
      @timestamp ||= ( Time::now ).utc.strftime("%Y%m%dT%H%M%SZ")
    end

    def datestamp
      @datestamp ||= ( Time::now ).utc.strftime("%Y%m%d")
    end

    def headers 
      {
        "host"        => API_ENDPOINT,
        "x-amz-date"  => timestamp
      }
    end





    def uri
      URI.parse("http://#{Alexa::API_HOST}/?" + query + "&Signature=" + CGI::escape(signature))
    end

    #### Potentially delete this 
    def default_params
      {
        "AWSAccessKeyId"   => access_key_id,
        "SignatureMethod"  => "HmacSHA256",
        "SignatureVersion" => "2",
        "Timestamp"        => timestamp,
        "Version"          => Alexa::API_VERSION
      }
    end
    ####

    ##replaced by string_to_sign
    def sign
      "GET\n" + Alexa::API_HOST + "\n/\n" + query
    end
    ##

    def query
      params.sort.map{|k,v| k + "=" + escapeRFC3986(v.to_s())}.join('&')
    end

    def headers_str
      headers.sort.map{|k,v| k + ":" + v}.join("\n") + "\n"
    end
    
    def headers_lst 
      headers.sort.map{|k,v| k}.join(";")
    end

    def payload_hash 
      Digest::SHA256.hexdigest ""
    end
    
    def canonical_request 
      "GET" + "\n" + Alexa::API_URI + "\n" + query + "\n" + headers_str + "\n" + headers_lst + "\n" + payload_hash
    end

    def credential_scope 
      datestamp + "/" + Alexa::API_REGION + "/" + Alexa::API_NAME + "/" + "aws4_request"
    end 

    def string_to_sign 
      SIGNATURE_ALGORITHM + "\n" +  timestamp + "\n" +  credential_scope + "\n" + (Digest::SHA256.hexdigest canonical_request)
    end

    def signature
      signing_key = getSignatureKey(secret_access_key, datestamp, Alexa::API_REGION, Alexa::API_NAME)
      OpenSSL::HMAC.hexdigest('sha256', signing_key, string_to_sign)
    end

    def authorization_header 
      SIGNATURE_ALGORITHM + " " + "Credential=" + access_key_id + "/" + credential_scope + ", " +  "SignedHeaders=" + headers_lst + ", " + "Signature=" + signature;
    end




    # escape str to RFC 3986
    def escapeRFC3986(str)
      return URI.escape(str,/[^A-Za-z0-9\-_.~]/)
    end

  end
end
