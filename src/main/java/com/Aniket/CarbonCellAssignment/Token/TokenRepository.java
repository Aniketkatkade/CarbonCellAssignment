package com.Aniket.CarbonCellAssignment.Token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;



@Repository
public interface TokenRepository extends JpaRepository<Token,Integer> {
    @Query(value = "select t.* " +
            "from Token t " +
            "inner join user u" +
            " on t.user_id = u.user_id " +
            "where u.user_id = :userId and (t.expired = false or t.revoked = false) ",nativeQuery = true)
    List<Token> findAllValidTokensByUser(Integer userId);
    Optional<Token> findByToken(String token);
}
