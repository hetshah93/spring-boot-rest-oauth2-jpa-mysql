package com.ahasan.rest.auth;

import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;


/**
 *
 * @author Ahasan Habib
 * @since 03 06 20
 */

@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfiguration implements AuthorizationServerConfigurer {

  @Autowired
  private BCryptPasswordEncoder passwordEncoder;

  @Autowired
  private DataSource dataSource;

  @Autowired
  private AuthenticationManager authenticationManager;


  @Bean
  TokenStore jdbcTokenStore() {
    return new JdbcTokenStore(dataSource);
  }

  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    security.checkTokenAccess("isAuthenticated()").tokenKeyAccess("isAuthenticated()");

  }

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients.jdbc(dataSource);

  }

  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    endpoints.tokenStore(jdbcTokenStore());
    endpoints.authenticationManager(authenticationManager);
  }

  // @Bean
  // public FilterRegistrationBean<CorsFilter> corsFilter() {
  // UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
  // CorsConfiguration config = new CorsConfiguration();
  // config.setAllowCredentials(true);
  // config.addAllowedOrigin("*");
  // config.addAllowedHeader("*");
  // config.addAllowedMethod("*");
  // source.registerCorsConfiguration("/**", config);
  // FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
  // bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
  // return bean;
  // }
}
