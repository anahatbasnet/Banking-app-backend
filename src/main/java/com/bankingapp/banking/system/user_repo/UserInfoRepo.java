package com.bankingapp.banking.system.user_repo;

import aj.org.objectweb.asm.commons.Remapper;
import com.bankingapp.banking.system.entity.UserInfoEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserInfoRepo extends JpaRepository<UserInfoEntity,Long> {
    Optional<UserInfoEntity> findByEmailId(String emailId);
}
