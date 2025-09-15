
```
mermaid
classDiagram
    class User {
        -String id
        -String email
        -String passwordHash
        -List~Role~ roles
        -boolean enabled
        -boolean accountNonExpired
        -boolean credentialsNonExpired
        -boolean accountNonLocked
        -Instant createdAt
        -Instant lastLogin
        +UserDetails getAuthorities()
        +boolean isAccountNonExpired()
        +boolean isAccountNonLocked()
        +boolean isCredentialsNonExpired()
        +boolean isEnabled()
    }

    class Role {
        -String id
        -String name
        -String description
        -List~Permission~ permissions
    }

    class Permission {
        -String id
        -String name
        -String description
    }

    class JwtToken {
        -String token
        -String refreshToken
        -Instant expiration
        -Instant refreshExpiration
        -String userId
        -boolean revoked
    }

    class AuthenticationRequest {
        -String email
        -String password
    }

    class AuthenticationResponse {
        -String accessToken
        -String refreshToken
        -Instant expiresAt
        -User user
    }

    class SecurityConfig {
        -JwtAuthenticationFilter jwtAuthenticationFilter
        -UserDetailsService userDetailsService
        -PasswordEncoder passwordEncoder
        -CorsConfigurationSource corsConfigurationSource
        +SecurityFilterChain filterChain()
    }

    class JwtAuthenticationFilter {
        -JwtService jwtService
        -UserDetailsService userDetailsService
        +doFilterInternal()
    }

    class JwtService {
        -String secretKey
        -Long expiration
        +String generateToken()
        +String extractUsername()
        +boolean isTokenValid()
        +String generateRefreshToken()
    }

    class AuthenticationController {
        -AuthenticationService authenticationService
        +login()
        +refreshToken()
        +logout()
    }

    class AuthenticationService {
        -UserRepository userRepository
        -JwtService jwtService
        -PasswordEncoder passwordEncoder
        -AuthenticationManager authenticationManager
        +authenticate()
        +refreshToken()
        +logout()
    }

    User "1" --* "many" Role : has
    Role "1" --* "many" Permission : has
    User "1" --o "many" JwtToken : generates
    AuthenticationController --> AuthenticationService
    AuthenticationService --> JwtService
    AuthenticationService --> UserRepository
    SecurityConfig --> JwtAuthenticationFilter
    JwtAuthenticationFilter --> JwtService
```
