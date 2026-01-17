// package com.hc.Security.security;

// import java.io.IOException;

// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.oauth2.core.user.OAuth2User;
// import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
// import org.springframework.stereotype.Component;

// import com.hc.Security.entity.User;
// import com.hc.Security.repository.UserDAO;
// import com.hc.Security.security.jwt.JwtTokenProvider;
// import com.hc.Security.service.RefreshTokenService;

// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// @Component
// public class OAuthSuccessHandler implements AuthenticationSuccessHandler {

//     private final UserDAO userRepository;
//     private final JwtTokenProvider jwtTokenProvider;
//     private final RefreshTokenService refreshTokenService;
//     private final CustomUserDetailsService customUserDetailsService;

//     public OAuthSuccessHandler(
//             UserDAO userRepository,
//             JwtTokenProvider jwtTokenProvider,
//             RefreshTokenService refreshTokenService,
//             CustomUserDetailsService customUserDetailsService) {
//         this.userRepository = userRepository;
//         this.jwtTokenProvider = jwtTokenProvider;
//         this.refreshTokenService = refreshTokenService;
//         this.customUserDetailsService = customUserDetailsService;
//     }

//     @Override
//     public void onAuthenticationSuccess(
//             HttpServletRequest request,
//             HttpServletResponse response,
//             Authentication authentication
//     ) throws IOException {

//         OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();

//         String email = oauthUser.getAttribute("email");
//         String googleId = oauthUser.getAttribute("sub");

//         User user = userRepository.findByEmail(email)
//                 .orElseThrow(() -> new IOException("User not found with email: " + email));

//         UserDetails userDetails = customUserDetailsService
//                 .loadUserByUsername(user.getUsername());

//         Authentication auth = new UsernamePasswordAuthenticationToken(
//                 userDetails,
//                 null,
//                 userDetails.getAuthorities());
//         String accessToken = jwtTokenProvider.generateToken(auth);
//         String refreshToken = refreshTokenService.create(user.getId());

//         // Send tokens to frontend
//         response.sendRedirect(
//             "http://frontend-app/login/success"
//             + "?token=" + accessToken
//         );
//     }
// }
