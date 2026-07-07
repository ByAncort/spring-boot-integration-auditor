# Spring Boot 3.x — Vulnerable vs Hardened Patterns

> Part of the `spring-boot-integration-auditor` skill — back to [SKILL.md](../SKILL.md)

Reference catalog of copy-pasteable Spring Boot 3.x code, vulnerable vs hardened. For each pattern: OWASP/CWE mapping, severity, and the secure alternative that compiles against Spring Boot 3.3+ / Java 17+.

---

## 1. Security Filter Chain

### Vulnerable (Spring Security 6 lambda DSL, common misconfig)

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll()        // VULN: everything public
            )
            .csrf(csrf -> csrf.disable())        // VULN: CSRF disabled for browser sessions
            .cors(cors -> cors.disable())        // VULN: no CORS, browser still applies defaults
            .headers(headers -> headers.disable()); // VULN: clickjacking / XSS / MIME-sniff
        return http.build();
    }
}
```

### Hardened

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .requestMatchers("/actuator/**").hasRole("ADMIN")
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().denyAll()  // default deny
            )
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers("/api/**")  // only if using stateless JWT
            )
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; script-src 'self'; object-src 'none'"
                ))
                .frameOptions(frame -> frame.deny())
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000))
                .referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER))
            )
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            );
        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration c = new CorsConfiguration();
        c.setAllowedOrigins(List.of("https://app.example.com"));
        c.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        c.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        c.setAllowCredentials(true);
        c.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/api/**", c);
        return src;
    }
}
```

---

## 2. Password Storage

### Vulnerable

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();  // VULN: plaintext
}
```

```java
@Bean
public UserDetailsService users() {
    UserDetails u = User.withDefaultPasswordEncoder()  // VULN: deprecated
        .username("admin")
        .password("admin")
        .roles("ADMIN")
        .build();
    return new InMemoryUserDetailsManager(u);
}
```

### Hardened

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);  // cost >= 12
}

// Users loaded from DB / IdP
@Bean
public UserDetailsService userDetailsService(UserRepository repo) {
    return username -> repo.findByUsername(username)
        .map(u -> User.withUsername(u.getUsername())
            .password(u.getPassword())
            .disabled(!u.isEnabled())
            .accountLocked(u.isLocked())
            .authorities(u.getAuthorities().stream()
                .map(a -> new SimpleGrantedAuthority(a.getName()))
                .toList())
            .build())
        .orElseThrow(() -> new UsernameNotFoundException(username));
}
```

---

## 3. JWT Validation

### Vulnerable

```java
public Claims parse(String token) {
    return Jwts.parser()  // VULN: no signature verification in some versions
        .setSigningKey(SECRET.getBytes())
        .parseClaimsJws(token)
        .getBody();
}
```

```java
// VULN: alg=none or no algorithm pinned
Jwts.parser().parse(token);
```

### Hardened

```java
@Value("${app.jwt.secret}")
private String secret;

private final SecretKey key;

@PostConstruct
void init() {
    this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
}

public Jws<Claims> parse(String token) {
    return Jwts.parser()
        .verifyWith(key)
        .requireIssuer("auth.example.com")
        .requireAudience("api.example.com")
        .clockSkewSeconds(60)
        .build()
        .parseSignedClaims(token);
}
```

---

## 4. JPA / JPQL Injection

### Vulnerable

```java
@Query("SELECT u FROM User u WHERE u.name = '" + name + "'")
List<User> findByName(String name);  // VULN: JPQL injection

em.createNativeQuery("SELECT * FROM users WHERE id = " + id)
    .getResultList();  // VULN: native SQL injection
```

### Hardened

```java
@Query("SELECT u FROM User u WHERE u.name = :name")
List<User> findByName(@Param("name") String name);

@Query(value = "SELECT * FROM users WHERE id = :id", nativeQuery = true)
List<User> findById(@Param("id") Long id);

// JPA Criteria for dynamic queries
public List<User> search(String name, String email) {
    CriteriaBuilder cb = em.getCriteriaBuilder();
    CriteriaQuery<User> cq = cb.createQuery(User.class);
    Root<User> root = cq.from(User.class);
    List<Predicate> preds = new ArrayList<>();
    if (name != null)  preds.add(cb.equal(root.get("name"), name));
    if (email != null) preds.add(cb.equal(root.get("email"), email));
    cq.where(preds.toArray(new Predicate[0]));
    return em.createQuery(cq).getResultList();
}
```

---

## 5. Deserialization

### Vulnerable SnakeYAML

```java
public Map<String, Object> parse(String input) {
    return new Yaml().load(input);  // VULN: RCE via constructor tags
}
```

### Hardened SnakeYAML 2.x

```java
public Map<String, Object> parse(String input) {
    LoaderOptions opts = new LoaderOptions();
    return new Yaml(new SafeConstructor(opts)).load(input);
}
```

### Vulnerable Jackson

```java
ObjectMapper om = new ObjectMapper();
om.enableDefaultTyping();  // VULN: polymorphic deserialization -> RCE
om.readValue(input, Object.class);
```

### Hardened Jackson

```java
ObjectMapper om = new ObjectMapper()
    .activateDefaultTyping(
        BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType(MyDto.class)
            .allowIfSubType("com.example.dto.")
            .build(),
        ObjectMapper.DefaultTyping.NON_FINAL
    )
    .readValue(input, MyDto.class);
```

### Vulnerable Java native

```java
public Object deserialize(byte[] data) throws Exception {
    return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    // VULN: gadget chains (commons-collections, Spring AOP, etc.)
}
```

### Hardened Java native

```java
// Use Jackson with strict allowlist, or protobuf / record only
public record Payload(String name, long ts) {}

public Payload deserialize(byte[] data) throws Exception {
    return new ObjectMapper().readValue(data, Payload.class);
}
```

---

## 6. Actuator

### Vulnerable

```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    env:
      enabled: true
    heapdump:
      enabled: true
  # No port separation, no auth
```

### Hardened

```yaml
# application-prod.yml
management:
  server:
    port: 9090        # separate port, not 8080
    address: 127.0.0.1  # bind to localhost only; expose via reverse proxy
  endpoints:
    web:
      exposure:
        include: health, info, prometheus, metrics
      base-path: /actuator
  endpoint:
    health:
      show-details: when-authorized
      probes:
        enabled: true
    env:
      enabled: false
    heapdump:
      enabled: false
    beans:
      enabled: false
    configprops:
      enabled: false
    loggers:
      enabled: false
    mappings:
      enabled: false
  prometheus:
    metrics:
      export:
        enabled: true
```

```java
// Custom health indicator with auth
@Component
@Endpoint(id = "internal", access = AccessMode.READ_ONLY)
public class InternalEndpoint {

    @ReadOperation
    public Map<String, Object> status() {
        return Map.of("status", "ok", "ts", Instant.now());
    }
}
```

---

## 7. SQL — JdbcTemplate

### Vulnerable

```java
jdbcTemplate.queryForObject(
    "SELECT * FROM users WHERE email = '" + email + "'",  // VULN
    (rs, i) -> new User(rs.getString("id"), rs.getString("email"))
);
```

```java
String sql = String.format(
    "SELECT * FROM users WHERE email = '%s' AND status = '%s'",
    email, status
);  // VULN
```

### Hardened

```java
jdbcTemplate.queryForObject(
    "SELECT * FROM users WHERE email = ? AND status = ?",
    (rs, i) -> new User(rs.getString("id"), rs.getString("email")),
    email, status  // bound parameters
);

// For dynamic IN clause, use NamedParameterJdbcTemplate
String sql = "SELECT * FROM users WHERE id IN (:ids)";
MapSqlParameterSource params = new MapSqlParameterSource("ids", idList);
namedJdbcTemplate.query(sql, params, rowMapper);
```

---

## 8. OS Command / Process

### Vulnerable

```java
public String ping(String host) throws IOException {
    return new String(Runtime.getRuntime().exec(
        "ping -c 1 " + host
    ).getInputStream().readAllBytes());  // VULN: command injection
}
```

### Hardened (avoid OS command; if necessary, allowlist)

```java
private static final Pattern HOST_RE = Pattern.compile(
    "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
);

public String ping(String host) throws IOException {
    if (!HOST_RE.matcher(host).matches()) {
        throw new IllegalArgumentException("invalid host");
    }
    Process p = new ProcessBuilder("ping", "-c", "1", host)
        .redirectErrorStream(true)
        .start();
    return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
}
```

---

## 9. SpEL (Spring Expression)

### Vulnerable

```java
public Object eval(String expression) {
    return parser.parseExpression(expression).getValue();  // VULN: RCE
}
```

### Vulnerable — string-built SpEL

```java
public Object evalUser(String userInput) {
    return parser.parseExpression("T(java.lang.Runtime).getRuntime().exec('" + userInput + "')")
        .getValue();  // VULN: string-built SpEL injection
}
```

### Hardened

```java
private final ExpressionParser parser = new SpelExpressionParser();
private final SimpleEvaluationContext ctx = SimpleEvaluationContext
    .forReadOnlyDataBinding()
    .build();

public Object eval(String expression) {
    // Validate expression shape before parsing
    if (!expression.matches("^[a-zA-Z0-9._-]{1,64}$")) {
        throw new IllegalArgumentException("invalid expression");
    }
    return parser.parseExpression(expression).getValue(ctx);
}

// Never use StandardEvaluationContext with user input
```

---

## 10. SSRF / Outbound HTTP

### Vulnerable

```java
public String fetch(String url) throws IOException {
    return restTemplate.getForObject(url, String.class);  // VULN: SSRF
}
```

### Hardened

```java
private static final Set<String> ALLOWED_HOSTS = Set.of(
    "api.trusted.com", "cdn.trusted.com"
);

public String fetch(String input) throws IOException {
    URI uri;
    try {
        uri = new URI(input);
    } catch (URISyntaxException e) {
        throw new IllegalArgumentException("invalid url");
    }
    String host = uri.getHost();
    if (host == null) throw new IllegalArgumentException("no host");
    InetAddress addr = InetAddress.getByName(host);
    if (addr.isAnyLocalAddress() || addr.isLoopbackAddress()
        || addr.isSiteLocalAddress() || addr.isMulticastAddress()
        || addr.isLinkLocalAddress()) {
        throw new IllegalArgumentException("internal address not allowed: " + host);
    }
    if (!ALLOWED_HOSTS.contains(host.toLowerCase())) {
        throw new IllegalArgumentException("host not in allowlist: " + host);
    }
    if (uri.getScheme() == null ||
        !(uri.getScheme().equals("https") || uri.getScheme().equals("http"))) {
        throw new IllegalArgumentException("scheme must be http(s)");
    }
    return restTemplate.getForObject(uri, String.class);
}
```

---

## 11. CSRF — Browser Session

### Vulnerable (state-changing GET, no CSRF token)

```java
@DeleteMapping("/api/orders/{id}")
public void cancel(@PathVariable Long id) { ... }  // VULN: GET for state change + no CSRF

http.csrf(csrf -> csrf.disable());  // VULN if browser sessions
```

### Hardened (state-changing + CSRF token)

```java
@DeleteMapping("/api/orders/{id}")
@PreAuthorize("hasRole('CUSTOMER') and @orderService.owns(#id, authentication.principal)")
public void cancel(@PathVariable Long id) { ... }  // POST/DELETE only

// In SecurityFilterChain: keep CSRF enabled
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
);
// Frontend reads cookie, sends back as X-XSRF-TOKEN header
```

---

## 12. Cookies

### Vulnerable

```java
Cookie c = new Cookie("SESSION", sessionId);  // VULN: no HttpOnly, no Secure
response.addCookie(c);
```

### Hardened

```java
Cookie c = new Cookie("SESSION", sessionId);
c.setHttpOnly(true);
c.setSecure(true);
c.setPath("/");
c.setMaxAge(1800);  // 30 min
c.setAttribute("SameSite", "Strict");  // Servlet 6 / Spring 6
response.addCookie(c);
```

---

## 13. CORS

### Vulnerable

```java
cors.setAllowedOrigins(List.of("*"));            // VULN
cors.setAllowCredentials(true);                  // VULN: with wildcard = browser rejects anyway,
//                                                but if set to "*" via setOriginPatterns it works = BOLA
cors.setAllowedOriginPatterns(List.of("*"));     // VULN: dynamic wildcard with credentials
```

### Hardened

```java
CorsConfiguration c = new CorsConfiguration();
c.setAllowedOrigins(List.of("https://app.example.com"));  // explicit list
c.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
c.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
c.setExposedHeaders(List.of("X-Total-Count"));
c.setAllowCredentials(true);
c.setMaxAge(3600L);
```

---

## 14. TLS Configuration (application.yml / properties)

### Vulnerable

```yaml
server:
  port: 8080
  # No SSL
```

```yaml
server:
  ssl:
    enabled: true
    enabled-protocols: TLSv1,TLSv1.1   # VULN: deprecated
```

### Hardened

```yaml
server:
  port: 8443
  ssl:
    enabled: true
    protocol: TLS
    enabled-protocols: TLSv1.3,TLSv1.2
    ciphers: TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256
    key-store: classpath:keystore.p12
    key-store-password: ${KEYSTORE_PWD}
    key-store-type: PKCS12
    key-alias: app-tls
    client-auth: need          # mTLS for OT-facing services
    trust-store: classpath:truststore.p12
    trust-store-password: ${TRUSTSTORE_PWD}
    trust-store-type: PKCS12
```

---

## 15. Database Migration

### Vulnerable

```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: update  # VULN in prod: attacker can mutate schema via SQL injection
```

### Hardened

```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: validate  # strict, no auto-DDL
  flyway:
    enabled: true
    locations: classpath:db/migration
    baseline-on-migrate: false
```

---

## 16. Logging — Sensitive Data

### Vulnerable

```java
log.info("User login: " + user);  // VULN: may include password
log.debug("Request body: " + request);  // VULN: PII / secrets
log.info("Auth header: " + authHeader);  // VULN: token logged
```

### Hardened

```java
log.info("User login: {}", user.getUsername());
log.debug("Request body: {}", sanitize(request));
log.info("Auth header present: {}", authHeader != null);

// Sanitize helper
private String sanitize(Object o) {
    // remove known fields
    ...
}
```

```xml
<!-- logback-spring.xml: structured JSON, no PII, retention policy -->
<configuration>
  <appender name="JSON" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>/var/log/app/app.json</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
      <fileNamePattern>/var/log/app/app.%d{yyyy-MM-dd}.%i.json.gz</fileNamePattern>
      <maxFileSize>100MB</maxFileSize>
      <maxHistory>90</maxHistory>
      <totalSizeCap>10GB</totalSizeCap>
    </rollingPolicy>
    <encoder class="net.logstash.logback.encoder.LogstashEncoder">
      <includeMdcKeyName>correlationId</includeMdcKeyName>
      <customFields>{"app":"my-spring-boot","env":"prod"}</customFields>
    </encoder>
  </appender>
  <root level="INFO">
    <appender-ref ref="JSON"/>
  </root>
</configuration>
```

---

## 17. CORS Preflight / Method Override

### Vulnerable

```yaml
spring:
  mvc:
    pathmatch:
      matching-strategy: ant_path_matcher  # VULN with trailing slash bypass
```

### Hardened

```yaml
spring:
  mvc:
    pathmatch:
      matching-strategy: path_pattern_parser
```

```java
// Force trailing slash handling consistently
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/**").authenticated()
);
```

---

## 18. Rate Limiting

### Vulnerable (no rate limiting)

```java
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    // No rate limit
    return authService.authenticate(req);
}
```

### Hardened (Bucket4j)

```java
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain)
            throws ServletException, IOException {
        String key = req.getRemoteAddr() + ":" + req.getRequestURI();
        Bucket bucket = buckets.computeIfAbsent(key, k -> Bucket.builder()
            .addLimit(Bandwidth.classic(20,
                Refill.intervally(20, Duration.ofMinutes(1))))
            .build());
        if (bucket.tryConsume(1)) {
            chain.doFilter(req, res);
        } else {
            res.setStatus(429);
            res.getWriter().write("{\"error\":\"rate_limited\"}");
        }
    }
}
```

---

## 19. Secrets Management

### Vulnerable

```java
@Value("${app.db.password}")
private String dbPassword;  // VULN if set in application-prod.yml in repo
```

```yaml
# application-prod.yml in git
spring:
  datasource:
    password: "ProductionP@ssw0rd!"  # VULN: secret in repo
```

### Hardened

```yaml
# application-prod.yml — references only
spring:
  datasource:
    url: ${DB_URL}
    username: ${DB_USER}
    password: ${DB_PASSWORD}    # from env / vault
```

```bash
# In deployment env / vault
export DB_PASSWORD="$(vault kv get -field=password secret/myapp/db)"
```

```java
// Use Jasypt for at-rest encryption of properties
@EncryptablePropertySource
@Configuration
public class AppConfig {
    @Value("${app.secret}")
    private String secret;  // encrypted in source: ENC(base64...)
}
```

---

## 20. mTLS for OT-facing Spring Boot Service

```yaml
server:
  port: 8443
  ssl:
    enabled: true
    protocol: TLS
    enabled-protocols: TLSv1.3
    key-store: classpath:ot-keystore.p12
    key-store-password: ${OT_KEYSTORE_PWD}
    key-store-type: PKCS12
    key-alias: ot-service
    trust-store: classpath:ot-truststore.p12
    trust-store-password: ${OT_TRUSTSTORE_PWD}
    client-auth: need    # REQUIRE mTLS
```

```java
@Bean
SecurityFilterChain otFilterChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/api/ot/**")
        .authorizeHttpRequests(a -> a
            .requestMatchers(HttpMethod.GET, "/api/ot/read/**").hasRole("OT_READ")
            .requestMatchers("/api/ot/write/**").hasRole("OT_WRITE")
            .anyRequest().denyAll()
        )
        .x509(x509 -> x509
            .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
            .userDetailsService(certUserDetailsService())
        )
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .csrf(csrf -> csrf.disable());
    return http.build();
}

@Bean
UserDetailsService certUserDetailsService() {
    return username -> {
        // map cert CN to UserDetails
        ...
    };
}
```

---

## 21. Spring Boot + Eclipse Milo (OPC UA)

### Vulnerable

```java
EndpointConfiguration.Builder builder = EndpointConfiguration.newBuilder()
    .addTokenPolicies(AnonymousAuthenticationTokenPolicy.INSTANCE)  // VULN
    .setSecurityPolicies(Set.of(SecurityPolicy.None))             // VULN
    .setSecurityModes(MessageSecurityMode.None);                   // VULN
```

### Hardened

```java
EndpointConfiguration.Builder builder = EndpointConfiguration.newBuilder()
    .addTokenPolicies(CertificateAuthenticationTokenPolicy.INSTANCE)
    .setSecurityPolicies(Set.of(
        SecurityPolicy.Basic256Sha256,
        SecurityPolicy.Aes256Sha256RsaPss
    ))
    .setSecurityModes(MessageSecurityMode.SignAndEncrypt)
    .setCertificate(cert)
    .setCertificateChain(chain);
```

---

## 22. Spring Boot + HiveMQ MQTT

### Vulnerable

```java
MqttClient client = new MqttClient("tcp://broker:1883", "client");  // VULN: plain
MqttConnectOptions opts = new MqttConnectOptions();
opts.setUserName("client");                                          // VULN: shared
opts.setPassword("password".toCharArray());                           // VULN: shared
```

### Hardened (mTLS)

```java
MqttClient client = new MqttClient("ssl://broker:8883", "ot-client-001",
    new MemoryPersistence());

MqttConnectOptions opts = new MqttConnectOptions();
KeyStore ks = KeyStore.getInstance("PKCS12");
ks.load(new FileInputStream("client.p12"), pwd);
KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
kmf.init(ks, pwd);
TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
tmf.init((KeyStore) truststore);
SSLContext ctx = SSLContext.getInstance("TLSv1.3");
ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
opts.setSocketFactory(ctx.getSocketFactory());
opts.setCleanSession(false);   // durable session for OT
opts.setAutomaticReconnect(true);
opts.setKeepAliveInterval(30);
opts.setConnectionTimeout(10);
opts.setMaxInflight(100);
opts.setMqttVersion(MqttConnectOptions.MQTT_VERSION_5);
```

---

## How to Use This Reference

1. During audit, when finding a vulnerable pattern: cite this file + the line in the audited code
2. For remediation, copy the "Hardened" block directly
3. For each hardened pattern, note the Spring Boot / Java version tested
4. If the audit target uses an older version, mark the pattern as "requires Spring Boot 3.x upgrade"

## References

- Spring Security 6.x: https://docs.spring.io/spring-security/reference/
- Spring Boot 3.x: https://docs.spring.io/spring-boot/docs/3.3.x/reference/
- JJWT: https://github.com/jwtk/jjwt
- Bucket4j: https://bucket4j.com/
- Eclipse Milo: https://eclipse.dev/milo/
- HiveMQ: https://www.hivemq.com/docs/
- j2mod: https://github.com/steveohara/j2mod
