package com.amitra;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.UserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@SpringBootApplication public class SpringOauthDemoApplication {

  private static Logger LOGGER = LogManager.getLogger(SpringOauthDemoApplication.class);

  public static void main(String[] args) {
    SpringApplication.run(SpringOauthDemoApplication.class, args);
  }

  @Configuration
  @EnableWebSecurity
  @EnableGlobalMethodSecurity(prePostEnabled = true)
  protected static class SecurityConfig
      extends WebSecurityConfigurerAdapter {

    @Value("${authentication.userKeys}")
    private String userKeys;

    @Value("${authentication.passwords}")
    private String passwords;

    @Value("${authentication.userRoles}")
    private String userRoles;

    @Override
    @Autowired // <-- This is crucial otherwise Spring Boot creates its own
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      Logger LOGGER=Logger.getLogger(SpringOauthDemoApplication.class);

      LOGGER.info("Defining inMemoryAuthentication");


      String[] userKeysArr = userKeys.split(",");
      String[] passwordsArr = passwords.split(",");
      String[] userRolesArr = userRoles.split(",");

      if (userKeys == null || userKeysArr.length == 0) {
        throw new IllegalArgumentException("application must be initialized with at least one db auth entry for an user.");
      }

      List<String> userKeysList = Arrays.stream(userKeysArr).collect(Collectors.toList());
      List<String> passwordsList = Arrays.stream(passwordsArr).collect(Collectors.toList());
      List<String> userRolesList = Arrays.stream(userRolesArr).collect(Collectors.toList());

      List<User> users = userKeysList.stream().map(
          x -> new User(x, passwordsList.get(userKeysList.indexOf(x)), userRolesList.get(userKeysList.indexOf(x))))
          .collect(Collectors.toList());

      if(users!=null && users.size()>0) {
        UserDetailsManagerConfigurer<AuthenticationManagerBuilder, InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder>>.UserDetailsBuilder authConfigurer = auth
            .inMemoryAuthentication().withUser(users.get(0).getUserName()).password(users.get(0).getPassword())
            .roles(users.get(0).getRoles().split(","));
        users.stream().skip(1).forEach(
            x -> authConfigurer.and().withUser(x.getUserName()).password(x.getPassword())
                .roles(x.getRoles().split(",")));

      }
    }

    @Override protected void configure(HttpSecurity http) throws Exception {
      http.formLogin()

          .and()

          .httpBasic().disable().anonymous().disable().authorizeRequests().anyRequest().authenticated();
    }

    /**
     * for storing user properties
     */
    private class User {
      private String userName;
      private String password;
      private String roles;

      public User(String userName, String password, String roles) {
        this.userName = userName;
        this.password = password;
        this.roles = roles;
      }

      public String getUserName() {
        return userName;
      }

      public String getPassword() {
        return password;
      }

      public String getRoles() {
        return roles;
      }
    }
  }

  @Configuration
  @EnableAuthorizationServer
  protected static class AuthorizationServerConfig
      extends AuthorizationServerConfigurerAdapter {

    @Value("${config.oauth2.token.expirytime}")
    private Integer expiryTimeInSeconds;

    @Value("${config.oauth2.refreshtoken.expirytime}")
    private Integer refreshTokenExpiryTimeInSeconds;

    @Value("${config.oauth2.privateKey}")
    private String privateKey;

    @Value("${config.oauth2.publicKey}")
    private String publicKey;

    @Value("${authentication.userKeys}")
    private String userNameKeys;

    @Value("${authentication.passwords}")
    private String userPasswords;

    @Value("${authentication.userRoles}")
    private String userRoles;

    @Value("${authentication.client}")
    private String clientIds;

    @Value("${authentication.clientSecret}")
    private String clientSecrets;

    @Value("${authentication.oauthScopes}")
    private String oauthScopes;

    @Value("${authentication.oauthAuthorities}")
    private String oauthAuthorities;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Bean public JwtAccessTokenConverter tokenEnhancer() {
      LOGGER.info("Initializing JWT with public key:\n" + publicKey);
      JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
      converter.setSigningKey(privateKey);
      converter.setVerifierKey(publicKey);
      return converter;
    }

    @Bean public JwtTokenStore tokenStore() {
      return new JwtTokenStore(tokenEnhancer());
    }

    /**
     * Defines the security constraints on the token endpoints /oauth/token_key and /oauth/check_token
     * Client credentials are required to access the endpoints
     *
     * @param oauthServer
     * @throws Exception
     */
    @Override public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
      oauthServer.tokenKeyAccess("isAnonymous() || hasRole('ROLE_TRUSTED_CLIENT')") // permitAll()
          .checkTokenAccess("hasRole('TRUSTED_CLIENT')"); // isAuthenticated()
    }

    /**
     * Defines the authorization and token endpoints and the token services
     *
     * @param endpoints
     * @throws Exception
     */
    @Override public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
      endpoints
          // Which authenticationManager should be used for the password grant
          // If not provided, ResourceOwnerPasswordTokenGranter is not configured
          .authenticationManager(authenticationManager)
              // Use JwtTokenStore and our jwtAccessTokenConverter
          .tokenStore(tokenStore())
          .accessTokenConverter(tokenEnhancer())
          .reuseRefreshTokens(false);
    }

    @Override public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
      String[] userKeys = userNameKeys.split(",");

      if (userKeys == null || userKeys.length == 0) {
        throw new IllegalArgumentException(
            "application must be initialized with at least one db auth entry for an user.");
      }
      String[] oauthAuthoritiesArr=oauthAuthorities.split(",");
      String[] oauthScopesArr=oauthScopes.split(":");
      String[] clientIdsArr=clientIds.split(",");
      String[] clientSecretssArr=clientSecrets.split(",");

      ClientDetailsServiceBuilder<InMemoryClientDetailsServiceBuilder>.ClientBuilder inMemoryClientDetailsServiceBuilder =
          clients.inMemory().withClient(clientIdsArr[0]).secret(clientSecretssArr[0]).authorities(oauthAuthoritiesArr[0])
          .authorizedGrantTypes("client_credentials", "password", "authorization_code", "refresh_token")
          .accessTokenValiditySeconds(expiryTimeInSeconds).refreshTokenValiditySeconds(refreshTokenExpiryTimeInSeconds).scopes(oauthScopesArr[0]);

      for(int i=1;i<userKeys.length;i++) {
        inMemoryClientDetailsServiceBuilder.and().withClient(clientIdsArr[i]).secret(clientSecretssArr[i])
            .authorities(oauthAuthoritiesArr[i])
            .authorizedGrantTypes("client_credentials", "password", "authorization_code", "refresh_token")
            .accessTokenValiditySeconds(expiryTimeInSeconds)
            .refreshTokenValiditySeconds(refreshTokenExpiryTimeInSeconds).scopes(oauthScopesArr[i]);
      }

      LOGGER.info("InMemoryClientDetails set up successfully.");

    }

    /**
     * Inner class to store Oauth client settings.
     */
    private class OauthClientSettings
    {
      private String grants;
      private String authorities;
      private String scopes;
      private String clientId;

      private String clientSecret;

      public OauthClientSettings(String grants, String authorities, String scopes, String clientId,
          String clientSecret) {
        this.grants = grants;
        this.authorities = authorities;
        this.scopes = scopes;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
      }

      public String getGrants() {
        return grants;
      }

      public String getAuthorities() {
        return authorities;
      }

      public String getScopes() {
        return scopes;
      }

      public String getClientId() {
        return clientId;
      }

      public String getClientSecret() {
        return clientSecret;
      }
    }


  }

}
