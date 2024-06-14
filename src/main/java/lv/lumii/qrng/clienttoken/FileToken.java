package lv.lumii.qrng.clienttoken;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.cactoos.scalar.Sticky;
import org.cactoos.scalar.Unchecked;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

public class FileToken implements Token {

    private final char[] password;
    private final String alias;
    private final Unchecked<KeyStore> keyStore;

    public FileToken(String pfxFileName, String password, String alias) {
        this.password = password.toCharArray();
        this.alias = alias;
        this.keyStore = new Unchecked<>(new Sticky<>(() -> loadKeyStore(pfxFileName)));
    }

    public FileToken(String[] pemCertFileNames, String pemKeyFileName, String keyPassword) {
        this.password = keyPassword.toCharArray();
        this.alias = "client/server";
        this.keyStore = new Unchecked<>(new Sticky<>(() -> createKeyStoreFromPemFiles(pemCertFileNames, pemKeyFileName, keyPassword, this.alias)));
    }

    private KeyStore loadKeyStore(String fileName) throws Exception {
        KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
        // ^^^ If "Algorithm HmacPBESHA256 not available" error => need jdk16+ (new pkx format hash)

        File f = new File(fileName);
        FileInputStream instream = new FileInputStream(f);
        try {
            clientKeyStore.load(instream, password);
        } finally {
            instream.close();
        }
        return clientKeyStore;
    }

    private KeyStore createKeyStoreFromPemFiles(String[] pemCertFileNames, String pemKeyFileName, String keyPassword, String desiredAlias) throws Exception {
        // Load the private key
        PEMParser pemParser = new PEMParser(new FileReader(pemKeyFileName));
        PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) pemParser.readObject();
        // TODO: use keyPassword
        if (!keyPassword.isEmpty())
            throw new Exception("Password-encrypted PEM key files are not yet supported.");

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
        pemParser.close();

        // Load the certificates
        ArrayList<X509Certificate> certs = new ArrayList<>();

        for (String certFileName : pemCertFileNames) {
            FileInputStream certReader = new FileInputStream(certFileName);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certReader);
            certReader.close();
            certs.add(certificate);
        }

        // Create the KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(desiredAlias, privateKey, keyPassword.toCharArray(), certs.toArray(new java.security.cert.Certificate[]{}));

        return keyStore;
    }

    @Override
    public Key key() {
        try {
            return this.keyStore.value().getKey(alias, password);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public char[] password() {
        return this.password;
    }

    @Override
    public byte[] signed(byte[] message) throws Exception {
        throw new UnsupportedOperationException("The private key (returned by the key() function) must be used to sign messages using this FileToken.");
    }

    @Override
    public Certificate[] certificateChain() {
        try {
            return this.keyStore.value().getCertificateChain(this.alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
