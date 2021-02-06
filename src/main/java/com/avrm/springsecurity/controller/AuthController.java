package com.avrm.springsecurity.controller;

import com.avrm.springsecurity.dto.request.LoginRequest;
import com.avrm.springsecurity.dto.request.SignupRequest;
import com.avrm.springsecurity.dto.response.JwtResponse;
import com.avrm.springsecurity.dto.response.MessageResponse;
import com.avrm.springsecurity.model.ERole;
import com.avrm.springsecurity.model.Role;
import com.avrm.springsecurity.model.User;
import com.avrm.springsecurity.repository.RoleRepository;
import com.avrm.springsecurity.repository.UserRepository;
import com.avrm.springsecurity.security.jwt.JwtUtil;
import com.avrm.springsecurity.security.service.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtUtil.generateToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                                                         .map(item -> item.getAuthority())
                                                         .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getId(),
                                                      userDetails.getUsername(),
                                                      userDetails.getPassword(),
                                                      roles));

    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest){

        if (userRepository.existByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest()
                                 .body(new MessageResponse("Error: Username is already taken!"));
        }
        if (userRepository.existEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest()
                                 .body(new MessageResponse("Error: Email is already taken!"));
        }

        // Create new user account
        User user = new User(signupRequest.getUsername(),
                             signupRequest.getEmail(),
                             signupRequest.getPassword() );

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                          .orElseThrow(() -> new RuntimeException("Error: Roles not found"));
            roles.add(userRole);
        } else {
            strRoles.forEach( role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                                       .orElseThrow(() -> new RuntimeException("Error: Role not found"));
                        roles.add(adminRole);
                        break;
                    case "mode":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                                     .orElseThrow(() -> new RuntimeException("Error: Role not found"));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                                      .orElseThrow(() -> new RuntimeException("Error: Role not found"));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User Registered successfully!"));
    }
}

