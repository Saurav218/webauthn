package jp.sbrahma.repository;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.namedparam.BeanPropertySqlParameterSource;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.stereotype.Repository;

import jp.sbrahma.entity.Credential;

import javax.sql.DataSource;
import java.util.List;
import java.util.Optional;

@Repository
public class CredentialRepository {
    private NamedParameterJdbcOperations jdbc;

    private SimpleJdbcInsert insertCredential;

    public CredentialRepository(NamedParameterJdbcOperations jdbc, DataSource dataSource) {
        this.jdbc = jdbc;
        this.insertCredential = new SimpleJdbcInsert(dataSource).withTableName("credential");
    }

    public List<Credential> finds(byte[] userId) {
        var sql = "SELECT * FROM credential WHERE user_id = :userId";
        return jdbc.query(
                sql,
                new MapSqlParameterSource()
                        .addValue("userId", userId),
                new BeanPropertyRowMapper<>(Credential.class));
    }

    public void insert(Credential credential) {
        insertCredential.execute(new BeanPropertySqlParameterSource(credential));
    }

    public Optional<Credential> find(byte[] credentialId) {
        var sql = "SELECT * FROM credential WHERE credential_id = :credentialId";
        try {
            var credential = jdbc.queryForObject(
                    sql,
                    new MapSqlParameterSource()
                            .addValue("credentialId", credentialId),
                    new BeanPropertyRowMapper<>(Credential.class));
            return Optional.of(credential);
        } catch (EmptyResultDataAccessException ignore) {
            return Optional.empty();
        }
    }

    public void update(Credential credential) {
        var sql = "UPDATE credential SET signature_counter = :signatureCounter WHERE credential_id = :credentialId";
        jdbc.update(sql, new MapSqlParameterSource()
                .addValue("credentialId", credential.getCredentialId())
                .addValue("signatureCounter", credential.getSignatureCounter()));
    }
}