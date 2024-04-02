package com.Aniket.CarbonCellAssignment.Auth;


import com.Aniket.CarbonCellAssignment.Model.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String userName;
    private String userEmail;
    private String userPassword;
    private Role role;
}
