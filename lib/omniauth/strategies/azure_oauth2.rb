require 'omniauth/strategies/oauth2'
require 'jwt'

module OmniAuth
  module Strategies
    class AzureOauth2 < OmniAuth::Strategies::OAuth2
      BASE_AZURE_URL = 'https://login.microsoftonline.com'
      DEFAULT_SCOPE = 'openid profile email'
      
      option :name, 'azure_oauth2'

      option :tenant_provider, nil

      # AD resource identifier
      option :resource, '00000002-0000-0000-c000-000000000000'

      # tenant_provider must return client_id, client_secret and optionally tenant_id and base_azure_url
      args [:tenant_provider]

      def client
        if options.tenant_provider
          provider = options.tenant_provider.new(self)
        else
          provider = options  # if pass has to config, get mapped right on to options
        end

        options.client_id = provider.client_id
        options.client_secret = provider.client_secret
        options.tenant_id =
          provider.respond_to?(:tenant_id) ? provider.tenant_id : 'common'
        options.base_azure_url =
          provider.respond_to?(:base_azure_url) ? provider.base_azure_url : BASE_AZURE_URL

        options.authorize_params = provider.authorize_params if provider.respond_to?(:authorize_params)
        options.authorize_params.domain_hint = provider.domain_hint if provider.respond_to?(:domain_hint) && provider.domain_hint
        options.authorize_params.prompt = request.params['prompt'] if defined? request && request.params['prompt']
        options.client_options.authorize_url = "#{options.base_azure_url}/#{options.tenant_id}/oauth2/v2.0/authorize"
        options.client_options.token_url = "#{options.base_azure_url}/#{options.tenant_id}/oauth2/v2.0/token"

        options.authorize_params.scope = if provider.respond_to?(:scope) && provider.scope
          provider.scope
        else
          DEFAULT_SCOPE
        end
        super
      end

      uid {
        raw_info['sub']
      }

      info do
        {
          name: raw_info['name'],
          nickname: raw_info['unique_name'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          email: raw_info['email'] || raw_info['upn'],
          oid: raw_info['oid'],
          tid: raw_info['tid']
        }
      end

      extra do
        { raw_info: raw_info }
      end

      def token_params
        azure_resource = request.env['omniauth.params'] && request.env['omniauth.params']['azure_resource']
        # resource not supported for v2
        #super.merge(resource: azure_resource || options.resource)
      end

      def callback_url
        full_host + script_name + callback_path
      end

      # https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
      #
      # Some account types from Microsoft seem to only have a decodable ID token,
      # with JWT unable to decode the access token. Information is limited in those
      # cases. Other account types provide an expanded set of data inside the auth
      # token, which does decode as a JWT.
      #
      # Merge the two, allowing the expanded auth token data to overwrite the ID
      # token data if keys collide, and use this as raw info.
      #
      def raw_info
        Rails.logger.fatal("RAW INFO")
        if @raw_info.nil?
          id_token_data = begin
            ::JWT.decode(access_token.params['id_token'], nil, false).first
          rescue StandardError
            {}
          end
          auth_token_data = begin
            ::JWT.decode(access_token.token, nil, false).first
          rescue StandardError
            {}
          end

          id_token_data.merge!(auth_token_data)
          @raw_info = id_token_data
        end
   Rails.logger.fatal(@raw_info)
        @raw_info
      end
    
     # def raw_info
        # it's all here in JWT http://msdn.microsoft.com/en-us/library/azure/dn195587.aspx
        #@raw_info ||= ::JWT.decode(access_token.token, nil, false).first
      #  jw = ::JWT.decode(access_token.token, nil, false)
      #  Rails.logger.fatal("AZURE JWT count #{jw.count}:  #{jw}")
      #  @raw_info ||= jw.first
      #end

    end
  end
end
