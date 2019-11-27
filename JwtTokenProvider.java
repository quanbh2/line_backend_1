package vn.edu.topica.edumall.security.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import vn.edu.topica.edumall.mysql.model.SumoUser;
import vn.edu.topica.edumall.mysql.service.SumoUserService;
import vn.edu.topica.edumall.security.model.UserToken;

/**
 * This class to define token provider storage token use JWT ( JSON Web Tokens ) <br>
 * Active profile: <b>jwt_security</b>
 *
 * @author quanbh2
 */
@Component
@Slf4j
@Profile({"jwt_security"})
public class JwtTokenProvider implements TokenProvider {

  /** The value is secret key of JWT that only is known by server side. */
  @Value("${authen.jwt.secret}")
  private String jwtSecret;

  /** The value is expired time of JWT ( milliseconds ). */
  @Value("${authen.jwt.expiredTime}")
  private long jwtExpiration;

  @Autowired private SumoUserService sumoUserService;

  /**
   * Generate a token given a {@link vn.edu.topica.edumall.mysql.model.SumoUser}
   *
   * @param sumoUser
   * @return a token string
   */
  @Override
  public String generateToken(SumoUser sumoUser) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtExpiration);

    return Jwts.builder()
        .setSubject(sumoUser.getEmail())
        .setIssuedAt(new Date())
        .setExpiration(expiryDate)
        .signWith(SignatureAlgorithm.HS512, jwtSecret)
        .compact();
  }

  /**
   * Parser token by secret key and Validate token
   *
   * @param authToken
   * @return return {@code true} if token is valid, {@code false} otherwise
   */
  @Override
  public boolean validateToken(String authToken) {
    try {
      Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
      return true;
    } catch (MalformedJwtException ex) {
      log.error("Invalid JWT token");
    } catch (ExpiredJwtException ex) {
      log.error("Expired JWT token");
    } catch (UnsupportedJwtException ex) {
      log.error("Unsupported JWT token");
    } catch (IllegalArgumentException ex) {
      log.error("JWT claims string is empty.");
    }
    return false;
  }

  /**
   * Returns user's email stored in the subject of token
   *
   * @param token
   * @return user's email parsed from the subject of the token
   */
  @Override
  public String getUserEmailFromToken(String token) {
    Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
    return claims.getSubject();
  }

  /**
   * Get authentication by token
   *
   * @param token
   * @return an authentication object which represent for token if token is valid, null otherwise
   */
  @Override
  public Authentication getAuthentication(String token) {
    try {

      if (!StringUtils.isBlank(token) && validateToken(token)) {
        String email = getUserEmailFromToken(token);

        SumoUser sumoUser = sumoUserService.findByEmail(email);

        // get list String privilege
        Set<String> listPrivilege = new HashSet<>();
        // TODO: get listPrivilege from DB then add to GrantedAuthority.

        List<GrantedAuthority> authorities =
            listPrivilege.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(sumoUser.getEmail(), null, authorities);
      } else {
        log.error("(Can not authentication from token {} because null or empty", token);
      }

    } catch (Exception ex) {
      log.error(ExceptionUtils.getStackTrace(ex));
    }

    return null;
  }

  /**
   * Generate a {@link vn.edu.topica.edumall.security.model.UserToken} given a {@link
   * vn.edu.topica.edumall.mysql.model.SumoUser}
   *
   * @param {@link vn.edu.topica.edumall.mysql.model.SumoUser sumoUser} user need to generate token
   * @return an userToken object including token and some user info
   */
  @Override
  public UserToken generateUserToken(SumoUser sumoUser) {

    String jwtToken = generateToken(sumoUser);

    UserToken userToken =
        UserToken.builder().accessToken(jwtToken).name(sumoUser.getName()).build();

    return userToken;
  }
}
