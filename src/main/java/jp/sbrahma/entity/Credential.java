package jp.sbrahma.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class Credential {
    private byte[] credentialId;
    private byte[] userId;
    private byte[] publicKey;
    private long signatureCounter;
}