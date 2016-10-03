This project demonstrates how to use Oauth 2.0 protocol using the Resource Owner Password Grant
 flow 
The client then sends a POST request with following body parameters to the authorization server:
grant_type with the value password
- client_id with the the client’s ID
- client_secret with the client’s secret
- username with the user’s username
- password with the user’s password

The authorization server will respond with a JSON object containing the following properties:

- expires_in with an integer representing the TTL of the access token
- access_token the access token itself(This is a JWT token, it contains information about ROLES and SCOPES that have been granted to the - client making the request based on the credential passed to the Authentication server)
- refresh_token a refresh token that can be used to acquire a new access (A JWT token to renew the access token)


# spring-oauth-demo

To generate auth tokens use the following command:

curl acme:acmeSecret@localhost:8080/oauth/token -d grant_type=password -d username=user1 -d password=password

