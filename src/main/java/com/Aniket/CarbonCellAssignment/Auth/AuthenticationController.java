package com.Aniket.CarbonCellAssignment.Auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    @GetMapping("/Homepage")
    public ResponseEntity<String> homepage(){
        return ResponseEntity.ok("Homepage is not Secured");
    }
    @GetMapping("/secured")
    public ResponseEntity<String> securedApi(){
        return ResponseEntity.ok("Api is Secured only Accessed by Authenticated users");
    }
    @GetMapping("/admins")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<String> adminsApi(){
        return ResponseEntity.ok("Api only Accessed by user who has a role of admin");
    }
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest registerRequest){
        return ResponseEntity.ok(authenticationService.register(registerRequest));
    }
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest authenticationRequest){
        return ResponseEntity.ok(authenticationService.authenticate(authenticationRequest));
    }
}
