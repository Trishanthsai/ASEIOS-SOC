package com.syntrace.mapper;

import com.syntrace.dto.auth.UserDTO;
import com.syntrace.entity.Role;
import com.syntrace.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * MODULE 10 - MapStruct mapping for accounts. The password hash has no target field, which
 * makes it structurally impossible to leak through the API.
 */
@Mapper(unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface UserMapper {

    /**
     * @param user persisted account
     * @return safe projection
     */
    @Mapping(target = "roles", source = "roles", qualifiedByName = "roleNames")
    UserDTO toDto(User user);

    /**
     * @param users persisted accounts
     * @return safe projections in the same order
     */
    List<UserDTO> toDtoList(List<User> users);

    /**
     * @param roles granted roles
     * @return Spring Security authority names
     */
    @Named("roleNames")
    default Set<String> roleNames(Set<Role> roles) {
        return roles == null ? Set.of() : roles.stream().map(Role::authority).collect(Collectors.toSet());
    }
}
