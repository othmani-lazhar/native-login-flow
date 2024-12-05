package com.java;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resource.RealmResourceProvider;
import org.slf4j.Logger;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class ChallengeApi implements RealmResourceProvider {
    Logger logger = org.slf4j.LoggerFactory.getLogger(ChallengeApi.class);
    private final KeycloakSession keycloakSession;

    public ChallengeApi(KeycloakSession keycloakSession) {
        this.keycloakSession = keycloakSession;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }

    @GET
    @Path("/challenge")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCustomData() {
        try {
            logger.info("GET /challenge");
            var auth = checkAuth();
            UserModel user = auth.getUser();
            SubjectCredentialManager credentialManager = user.credentialManager();
            var challenge = generateChallenge();
            logger.info("User: " + user.getUsername());
            if (credentialManager.getStoredCredentialByNameAndType("challenge", CredentialModel.SECRET)==null) {

                CredentialModel credential = new CredentialModel();
                credential.setType(CredentialModel.SECRET);
                credential.setSecretData(challenge);
                credential.setCreatedDate(System.currentTimeMillis());
                credential.setUserLabel("challenge");
                credentialManager.createStoredCredential(credential);
            }else
            {
                logger.info("Challenge value [{}]", credentialManager.getStoredCredentialByNameAndType("challenge", CredentialModel.SECRET).getSecretData());
            }


            // Create a stored credential certificate
            if (credentialManager.getStoredCredentialByNameAndType("challenge", CredentialModel.SECRET)==null) {
                CredentialModel certificate = new CredentialModel();
                certificate.setType(CredentialModel.CLIENT_CERT);
                certificate.setSecretData(Base64.getEncoder().encodeToString(ChallengeSignature.generateKeyPair().getPublic().getEncoded()));
                certificate.setCreatedDate(System.currentTimeMillis());
                certificate.setUserLabel("certificate");
                credentialManager.createStoredCredential(certificate);
            }
            else
            {
                logger.info("Certificate value [{}]", credentialManager.getStoredCredentialByNameAndType("certificate", CredentialModel.CLIENT_CERT).getSecretData());
            }
            return Response.ok(Map.of("challenge", challenge)).build();
        } catch (Exception e) {
            logger.error("Error", e);
            throw new InternalServerErrorException(e);
        }

    }

    private AuthResult checkAuth() {
        AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(keycloakSession).authenticate();
        logger.info("Auth: " + auth.getToken());
        return auth;
    }

    private String generateChallenge() {
        SecureRandom random = new SecureRandom();
        byte[] challengeBytes = new byte[32];
        random.nextBytes(challengeBytes);
        return Base64.getEncoder().encodeToString(challengeBytes);
    }
}
