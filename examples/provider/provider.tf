# basic auth configuration example
provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

# oauth configuration example
provider "keyfactor" {
  client_id     = "my_oauth_client_id"
  client_secret = "my_oauth_client_secret"
  scopes        = "enroll,agents,cert:admin" # These are example, fictitious, scopes and will vary based on identity provider.
  token_url     = "https://mykfinstance.kfdelivery.com:8444/realms/Keyfactor/protocol/openid-connect/token"
  hostname      = "mykfinstance.kfdelivery.com"

  alias = "keyfactor_command_oauth" # This isn't required
}