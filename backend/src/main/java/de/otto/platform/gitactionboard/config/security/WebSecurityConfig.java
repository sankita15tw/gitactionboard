package de.otto.platform.gitactionboard.config.security;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter.Directive.ALL;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;

@EnableWebSecurity
@Profile("beta")
public class WebSecurityConfig {

  private static HttpSecurity getDefaultSettings(HttpSecurity http) throws Exception {
    return http.cors().disable().csrf().disable().formLogin().disable();
  }

  @Configuration
  @Order(1)
  @ConditionalOnMissingBean(NoOpsWebSecurityConfig.class)
  public static class WhiteListSecurityConfig extends WebSecurityConfigurerAdapter {
    private final String actuatorBasePath;

    public WhiteListSecurityConfig(
        @Value("${management.endpoints.web.base-path:/actuator}") String actuatorBasePath) {
      this.actuatorBasePath = actuatorBasePath;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      final String healthEndPoint = String.format("%s/health", actuatorBasePath);

      getDefaultSettings(http)
          .requestMatchers()
          .antMatchers(healthEndPoint)
          .and()
          .authorizeRequests()
          .antMatchers(healthEndPoint)
          .permitAll();
    }
  }

  @Slf4j
  @Order(2)
  @Configuration
  @ConditionalOnExpression(
      "T(org.springframework.util.StringUtils).hasText('${BASIC_AUTH_USER_DETAILS_FILE_PATH:}')")
  @ConditionalOnMissingBean(NoOpsWebSecurityConfig.class)
  public static class BasicAuthSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final String CREDENTIAL_SEPARATOR = ":";

    private final String basicAuthFilePath;
    private final boolean githubAuthDisabled;

    public BasicAuthSecurityConfig(
        @Value("${BASIC_AUTH_USER_DETAILS_FILE_PATH}") String basicAuthFilePath,
        @Value("${GITHUB_OAUTH2_CLIENT_ID:}") String githubAuthClientId) {
      this.basicAuthFilePath = basicAuthFilePath;
      this.githubAuthDisabled = githubAuthClientId.isBlank();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
    }

    @Bean(name = "basicAuthUsers")
    public List<UserDetails> getBasicAuthUsers(@Value("${BASIC_AUTH_USER_DETAILS_FILE_PATH}") String basicAuthFilePath)
        throws IOException {
      return Files.readAllLines(Path.of(basicAuthFilePath)).stream()
          .filter(line -> !line.isBlank())
          .map(
              line -> {
                final String[] credentials = line.split(CREDENTIAL_SEPARATOR);
                return new AbstractMap.SimpleImmutableEntry<>(credentials[0], credentials[1]);
              })
          .map(
              authDetails ->
                  User.withUsername(authDetails.getKey())
                      .password(authDetails.getValue())
                      .authorities("ROLE_USER")
                      .build())
          .collect(Collectors.toList());
    }

    @Bean("basicAuthenticationManager")
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
      return super.authenticationManagerBean();
    }

    @Bean
    public InMemoryUserDetailsManager basicAuthUserDetailsManager(@Qualifier("basicAuthUsers") List<UserDetails> basicAuthUsers){
      return new InMemoryUserDetailsManager(basicAuthUsers);
    }

    @PostConstruct
    @SuppressWarnings("PMD.UnusedPrivateMethod")
    private void logInfo() {
      log.info(
          "Enabled Basic authentication as value is present for BASIC_AUTH_USER_DETAILS_FILE_PATH");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http.cors()
          .disable()
          .csrf()
          .disable()
          .formLogin()
          .disable()
          .requestMatcher(
              request -> {
                final String auth = request.getHeader(AUTHORIZATION);
                return githubAuthDisabled || auth != null && auth.startsWith("Basic");
              })
          .authorizeRequests().antMatchers("/login/basic").permitAll()
          .and().authorizeRequests()
          .anyRequest()
          .authenticated()
          .and()
          .httpBasic()
          .and()
          .logout()
          .addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(ALL)))
          .invalidateHttpSession(true);
    }
  }

  @Slf4j
  @Order(3)
  @Configuration
  @RequiredArgsConstructor
  @ConditionalOnProperty("GITHUB_OAUTH2_CLIENT_ID")
  @ConditionalOnMissingBean(NoOpsWebSecurityConfig.class)
  public static class GithubOauthSecurityConfig extends WebSecurityConfigurerAdapter {
    private final GithubAuthenticationSuccessHandler authenticationSuccessHandler;

    @PostConstruct
    @SuppressWarnings("PMD.UnusedPrivateMethod")
    private void logInfo() {
      log.info("Enabled Github authentication as value is present for GITHUB_OAUTH2_CLIENT_ID");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http.cors()
          .disable()
          .csrf()
          .disable()
          .formLogin()
          .disable()
          .httpBasic()
          .disable()
          .authorizeRequests()
          .antMatchers("/login/oauth2/**", "/oauth2/**")
          .permitAll()
          .and()
          .authorizeRequests()
          .anyRequest()
          .authenticated()
          .and()
          .oauth2Login()
          .successHandler(authenticationSuccessHandler)
          .and()
          .logout()
          .addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(ALL)))
          .invalidateHttpSession(true);
    }
  }
}
