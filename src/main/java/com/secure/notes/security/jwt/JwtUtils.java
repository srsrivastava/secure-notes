package com.secure.notes.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.jwtExpirationMs}")
    private int jwtExpirationMs;

    /**
     * Extracts the JWT from the Authorization header of the request.
     * Assumes the format is "Bearer <token>".
     *
     * @param request The HttpServletRequest.
     * @return The JWT string, or null if not found or not in "Bearer" format.
     */
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);

        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Remove "Bearer " prefix
        }

        return null;
    }

    /**
     * Generates a JWT for the given UserDetails (username).
     *
     * @param userDetails The user details containing the username.
     * @return The generated JWT string.
     */
    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                // Calculate expiration date
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    /**
     * Extracts the username (subject) from a JWT token.
     *
     * @param token The JWT string.
     * @return The username.
     */
    public String getUsernameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key()) // Specify the key for verification
                .build()
                .parseSignedClaims(token) // Parse the token
                .getPayload()
                .getSubject(); // Get the subject (username)
    }

    /**
     * Creates the signing key from the base64 encoded secret.
     *
     * @return The Key object.
     */
    private Key key() {
        // Decode the base64 secret and create an HMAC-SHA key
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    /**
     * Validates a JWT token.
     *
     * @param authToken The JWT string to validate.
     * @return true if the token is valid, false otherwise.
     */
    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate"); // Consider using logger instead of System.out
            Jwts.parser()
                    .verifyWith((SecretKey) key()) // Specify the key for verification
                    .build()
                    .parseSignedClaims(authToken); // Try to parse and validate
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        // General Exception catch can be added if other issues are possible
        // but the current catches cover the most common JWT validation issues.

        return false;
    }
}