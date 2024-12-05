package com.java;

import java.security.*;
import java.util.Base64;

public class ChallengeSignature {

    public static void main(String[] args) {
        try {
            // Step 1: Generate Key Pair
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Step 2: Generate Challenge
            String challenge = generateChallenge();
            System.out.println("Generated Challenge: " + challenge);

            // Step 3: Sign the Challenge
            String signedChallenge = signChallenge(challenge, privateKey);
            System.out.println("Signed Challenge: " + signedChallenge);

            // Step 4: Validate the Signed Challenge
            boolean isValid = validateChallenge(challenge, signedChallenge, publicKey);
            System.out.println("Is the Signed Challenge Valid? " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Generate RSA Key Pair
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    // Generate a Random Challenge String
    public static String generateChallenge() {
        return Base64.getEncoder().encodeToString("ThisIsARandomChallenge".getBytes());
    }

    // Sign the Challenge with the Private Key
    public static String signChallenge(String challenge, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(challenge.getBytes());
        byte[] signedBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signedBytes);
    }

    // Validate the Signed Challenge with the Public Key
    public static boolean validateChallenge(String challenge, String signedChallenge, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(challenge.getBytes());
        byte[] signedBytes = Base64.getDecoder().decode(signedChallenge);
        return signature.verify(signedBytes);
    }
}
