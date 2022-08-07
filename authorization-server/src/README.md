# Authorization Server 구축

## dependency
- implementation("org.springframework.boot:spring-boot-starter-web")
  - @EnableWebSecurity > WebSecurityConfiguration 설정을 위해 javax.servlet.Filter가 필요함
- implementation("org.springframework.security:spring-security-oauth2-authorization-server:0.3.1")
- implementation("org.springframework.boot:spring-boot-starter-security")

## config
### authorization server 설정
- OAuth Client 등록
```kotlin
@Bean
fun registeredClientRepository(): RegisteredClientRepository {
  val registeredClient =
    RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("client1")
      .clientSecret("{noop}secret")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .redirectUri("http://127.0.0.1:8080/login/oauth2/code/users-client-oidc")
      .redirectUri("http://127.0.0.1:8080/authorized")
      .scope(OidcScopes.OPENID)
      .scope("read")
      .build()
  return InMemoryRegisteredClientRepository(registeredClient)
}
```
  - clientId, clientSecret
    - OAuth Client application의 credentials
    - {noop}
      - spring security 5.0 이상부터는 입력된 패스워드를 PasswordEncoder를 통해 해시 인코딩 후 비교한다.
      - 인코딩을 하지 않음
      - 다른 인코딩 방식
        - {bcrypt}, {script} 등..
  - clientAuthenticationMethod
    - CLIENT_SECRET_BASIC
      - http request header에 Basic Auth Credentials(client id, client secret)를 포함시켜야 한다.
    - CLIENT_SECRET_POST
      - client id와 client secret을 http request의 post body에 추가해야 한다.
  - redirectUri
    - http://127.0.0.1:8080/authorized
      - 인증서버로부터 authorization code와 함께 redirect되는 OAuth Client application 경로
  - InMemoryRegisteredClientRepository
    - client 정보를 저장하기 위한 JDBCRegiteredClientRepository를 지원한다.

## JWT access token 얻기
### OAuth code 얻기
1. URL에 다음 경로를 입력한다.
```text
http://127.0.0.1:8000/oauth2/authorize?response_type=code&client_id=client1&redirect_uri=http://127.0.0.1:8080/authorized&scope=openid read
```
2. 로그인 페이지에서 Spring Security에 설정한 사용자 id/password(admin/password)를 입력
3. 다음과 같은 code를 포함한 경로로 redirect된다.
```text
http://127.0.0.1:8080/authorized?code=K5q0FysUc1m0h-fGQtrM6a_2G4LnohKpjS8StMnZIY-mhExqzKQoIRxvLe1DDH-79YDHIPn5wgJmksxPcGPG6KweUASSQbY5rFat41jAUxNYCLVCog2se923ESy2_abJ
```

### JWT access token 얻기
4. postman에서 다음 내용을 입력하고 요청을 보낸다.
   - POST
   - Authorization 탭에 아래 내용 추가
     - type
       - Basic Auth
     - Username: client1
     - Password: secret
   - Body 탭에 아래 내용 추가
     - grant type
       - authorization_code
     - code
       - 3번의 결과 code
     - redirect_uri
       - http://127.0.0.1:8080/authorized
5. 아래와 같은 응답을 받는다.
```json
{
  "access_token": "eyJraWQiOiJiZWIyYjhkMC1jNjM1LTQ3OWItYTQzMy02MWMzZDliZTllMTkiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZXJnZXkiLCJhdWQiOiJjbGllbnQxIiwibmJmIjoxNjQ3NTM2Njc1LCJzY29wZSI6WyJyZWFkIiwib3BlbmlkIl0sImlzcyI6Imh0dHA6XC9cL2F1dGgtc2VydmVyOjgwMDAiLCJleHAiOjE2NDc1MzY5NzUsImlhdCI6MTY0NzUzNjY3NX0.Qn80d_Sl-ZUzJQNoipPddsAwCKpYVknreKTN6cydJOHJAVb_E3NVqc22hWgen8--JKzM10wDDXjr54dn0WhrAf4qxuMAMWCvCJyLXw5AvSILQSE-80Kj4oDf5SIKoAdy5p0SdCjpuZf3ylFMS41VcqnkpaUtvNYWxcPe-LpIZ7ZZeZBdMb73aBwsz_9LR8M20C4b1Q1w1Ry-fAdT-HG5-dZK-pevS_smFk7k6fUgP7IAO_sK2IncS5pEhtJ-jnvCfZuATWKcQZCIwYCugPIDuSUT9QIw6lmogsEBOR6Aw-KDWZsG_sJZ2SrEC-_oFr6AhSDcMZSXnadf3W1FQ-luEA",
  "refresh_token": "IeHFNgDxjJzZ99D3wWeTNolzN1G-KqV-NRzXGQV0_Npzw2UhcRM-q2x0-EW-eiuMkm1gEbvma2G1Ea3XxWonMab50HXkkMjUJJWDI1S19TniCGlIrTPBcJNuP_hqDUNc",
  "scope": "read openid",
  "id_token": "eyJraWQiOiJiZWIyYjhkMC1jNjM1LTQ3OWItYTQzMy02MWMzZDliZTllMTkiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZXJnZXkiLCJhdWQiOiJjbGllbnQxIiwiYXpwIjoiY2xpZW50MSIsImlzcyI6Imh0dHA6XC9cL2F1dGgtc2VydmVyOjgwMDAiLCJleHAiOjE2NDc1Mzg0NzUsImlhdCI6MTY0NzUzNjY3NX0.haVz6tbBQZJcQBRV8DZGha6TCW7OKt7WCDE6TKTeFYdo0muKcHFBju1qq8UKApNGw0MteQ2Oh49XJ9W5uh1qVf_IqlVCKY23Fj5ubzGKY7j6u9wU9c8fr9YwWvuJExPeejCaR-T4ge6crh3IG-pDs21_izqcUlmvSnHqmTvwGWYrCEYeNyAJkG0H7Har9LG1Ds-HKrY077evDJWNwQt5zJgWK9mCe7m1mo6DGmubzBY4pF49eJwRWyTMhttbXo8XEJ3hUQVF6QbwnnPbiEV6UkIsRZh-eg0tpBurqz9Mju1secpbL1ITrRQXDxWb5RvHZTqEsctME3_0POzPUoLgiQ",
  "token_type": "Bearer",
  "expires_in": 299
}
```

# Reference
- https://spring.io/projects/spring-authorization-server#overview
- https://github.com/spring-projects/spring-authorization-server
- https://www.appsdeveloperblog.com/spring-authorization-server-tutorial/