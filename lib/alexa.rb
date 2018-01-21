require "multi_xml"

require "alexa/version"
require "alexa/utils"
require "alexa/exceptions"
require "alexa/connection"
require "alexa/client"
require "alexa/api/category_browse"
require "alexa/api/category_listings"
require "alexa/api/sites_linking_in"
require "alexa/api/traffic_history"
require "alexa/api/url_info"

module Alexa
  API_VERSION = "2005-07-11"
  API_HOST    = "awis.amazonaws.com"
  API_ENDPOINT = "awis.us-west-1.amazonaws.com"
  API_PORT = 443
  API_URI = "/api"
  API_REGION = "us-west-1"
  API_NAME = "awis"
end
