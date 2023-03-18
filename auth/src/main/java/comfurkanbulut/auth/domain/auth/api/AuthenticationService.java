package comfurkanbulut.auth.domain.auth.api;

import comfurkanbulut.auth.domain.auth.web.AuthenticationRequest;
import comfurkanbulut.auth.domain.auth.web.AuthenticationResponse;
import comfurkanbulut.auth.domain.auth.web.RegisterRequest;

public interface AuthenticationService {
    AuthenticationResponse register(RegisterRequest request);
    AuthenticationResponse authenticate(AuthenticationRequest request);
    void validateToken(String token);
}
