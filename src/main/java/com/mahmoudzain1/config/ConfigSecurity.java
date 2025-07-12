package com.mahmoudzain1.config;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.mahmoudzain1.config.Security.JWTAuthenticationConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Configuration
public class ConfigSecurity {

//    @Value("${keySetURI}")
//    private String keySetUri;

    private final JWTAuthenticationConverter converter;

    public ConfigSecurity(JWTAuthenticationConverter converter) {
        this.converter = converter;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain AuthorizationServerSetting (HttpSecurity http) throws Exception {

      OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
      http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

      http.exceptionHandling(excption ->
              excption.authenticationEntryPoint(
                      new LoginUrlAuthenticationEntryPoint("/login")
              ));

        return http.build();
    }




    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {

        http.
                 authorizeHttpRequests(a -> a.anyRequest().authenticated())
                 .formLogin(Customizer.withDefaults());

        http.oauth2ResourceServer(server ->
                  server.jwt(jwt -> jwt.jwkSetUri("http://localhost:8080/oauth2/jwks")
                        .jwtAuthenticationConverter(converter)));



        return http.build();
    }





    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails admin = User.builder().username("Mahmoud").password(passwordEncoder()
                        .encode("password")).roles("ADMIN", "USER").build();

        UserDetails user = User.builder().username("user").password(passwordEncoder()
                        .encode("user123")).roles("USER").build();

        UserDetails developer = User.builder().username("developer").password(passwordEncoder()
                        .encode("dev123")).roles("USER", "DEVELOPER").build();

        UserDetails tester = User.builder().username("tester").password(passwordEncoder()
                        .encode("test123")).roles("USER", "TESTER").build();

        UserDetails manager = User.builder().username("manager").password(passwordEncoder()
                        .encode("manager123")).roles("USER", "MANAGER", "ADMIN").build();

        return new InMemoryUserDetailsManager(admin, user, developer, tester, manager);
    }




    @Bean
    public RegisteredClientRepository registeredClientRepository(){

        RegisteredClient EduHup = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/client")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope("write")
                .scope("admin")
                .scope("read")
                .clientSettings(ClientSettings.builder().
                        requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2))
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(EduHup);


    }



    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        KeyPair keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey =  new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet =  new JWKSet(rsaKey);

        return new JWKSource<SecurityContext>() {
            @Override
            public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
                return jwkSelector.select(jwkSet);
            }
        };

    }



    @Bean
    public AuthorizationServerSettings authorizationServerSettings (){
        return AuthorizationServerSettings.builder().build();
    }


    @Bean
    public OAuth2AuthorizationService service(RegisteredClientRepository registeredClientRepository){
        return new InMemoryOAuth2AuthorizationService();
    }



    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(){
        return context -> {
            JwtClaimsSet.Builder builder = context.getClaims();
            Authentication authentication = context.getPrincipal();
            if(authentication != null && authentication.getAuthorities() !=null){
                List<String> list = authentication.getAuthorities().stream()
                        .map(grantedAuthority -> grantedAuthority.getAuthority())
                        .toList();
                builder.claim("Roles" ,  list);
            }
         ;
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
