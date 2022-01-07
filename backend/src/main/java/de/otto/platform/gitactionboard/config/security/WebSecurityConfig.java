package de.otto.platform.gitactionboard.config.security;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter.Directive.ALL;

import de.otto.platform.gitactionboard.domain.AuthenticationMechanism;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
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
import org.springframework.util.StringUtils;

@EnableWebSecurity
@Profile("beta")
public class WebSecurityConfig {

  public static final String LOGIN_PATH = "/#/login";
  public static final String DASHBOARD_PATH = "/#/dashboard";

  private static HttpSecurity getDefaultSettings(HttpSecurity http) throws Exception {
    return http.cors().disable().csrf().disable().formLogin().disable();
  }

  @Bean
  public List<AuthenticationMechanism> availableAuths(
      @Value("${BASIC_AUTH_USER_DETAILS_FILE_PATH:}") String basicAuthDetailsFilePath,
      @Value("${spring.security.oauth2.client.registration.github.client-id:-}")
          String githubClientId) {
    final ArrayList<AuthenticationMechanism> authenticationMechanisms = new ArrayList<>();

    if (StringUtils.hasText(basicAuthDetailsFilePath))
      authenticationMechanisms.add(AuthenticationMechanism.BASIC_AUTH);
    if (!"-".equals(githubClientId)) authenticationMechanisms.add(AuthenticationMechanism.OAUTH2);

    return authenticationMechanisms;
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

      final String[] whitelistUrls = {
        healthEndPoint,
        "/available-auths",
        "/",
        "/index.html",
        "/css/*.css",
        "/js/*.js",
        "favicon.ico",
        "/login/basic"
      };

      getDefaultSettings(http)
          .requestMatchers()
          .antMatchers(whitelistUrls)
          .and()
          .authorizeRequests()
          .antMatchers(whitelistUrls)
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

    private final boolean githubAuthDisabled;

    public BasicAuthSecurityConfig(
        @Value("${GITHUB_OAUTH2_CLIENT_ID:}") String githubAuthClientId) {
      this.githubAuthDisabled = githubAuthClientId.isBlank();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
    }

    @Bean(name = "basicAuthUsers")
    public List<UserDetails> getBasicAuthUsers(
        @Value("${BASIC_AUTH_USER_DETAILS_FILE_PATH}") String basicAuthFilePath)
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
    public InMemoryUserDetailsManager basicAuthUserDetailsManager(
        @Qualifier("basicAuthUsers") List<UserDetails> basicAuthUsers) {
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
          .usernameParameter("username")
          .passwordParameter("password")
          .loginPage(LOGIN_PATH)
          .loginProcessingUrl("/login/basic")
          .failureForwardUrl(LOGIN_PATH)
          .defaultSuccessUrl(DASHBOARD_PATH, true)
          .failureUrl(LOGIN_PATH)
          .and()
          .requestMatcher(
              request -> {
                final String auth = request.getHeader(AUTHORIZATION);
                return githubAuthDisabled || auth != null && auth.startsWith("Basic");
              })
          .authorizeRequests()
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
  @ConditionalOnExpression(
      "T(org.springframework.util.StringUtils).hasText('${GITHUB_OAUTH2_CLIENT_ID:}')")
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
          .loginPage(LOGIN_PATH)
          .failureUrl(LOGIN_PATH)
          .successHandler(authenticationSuccessHandler)
          .and()
          .logout()
          .addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(ALL)))
          .invalidateHttpSession(true);
    }
  }
}
