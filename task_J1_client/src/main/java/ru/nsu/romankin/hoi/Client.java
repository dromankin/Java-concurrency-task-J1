package ru.nsu.romankin.hoi;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class Client {
    private final String serverHost;
    private final int serverPort;
    private final String name;
    private final int delaySeconds;
    private final boolean exitBeforeReading;

    public Client(String serverHost, int serverPort, String name,
                        int delaySeconds, boolean exitBeforeReading) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.name = name;
        this.delaySeconds = delaySeconds;
        this.exitBeforeReading = exitBeforeReading;
    }

    public void run() throws Exception {
        if (delaySeconds > 0) {
            System.out.println("Waiting for " + delaySeconds + " seconds...");
            TimeUnit.SECONDS.sleep(delaySeconds);
            System.out.println("Waiting ended");
        }

        try (Socket socket = new Socket(serverHost, serverPort);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream())) {

            dos.write(name.getBytes("ASCII"));
            dos.write(0);
            dos.flush();

            if (exitBeforeReading) {
                System.out.println("Exiting before reading response (simulating crash)");
                return;
            }

            int responseLength = dis.readInt();
            byte[] responseBytes = new byte[responseLength];
            dis.readFully(responseBytes);

            DataInputStream responseDis = new DataInputStream(new ByteArrayInputStream(responseBytes));

            int privateKeyLength = responseDis.readInt();
            byte[] privateKeyBytes = new byte[privateKeyLength];
            responseDis.readFully(privateKeyBytes);

            int certLength = responseDis.readInt();
            byte[] certBytes = new byte[certLength];
            responseDis.readFully(certBytes);

            saveKeyAndCertificate(privateKeyBytes, certBytes);

            System.out.println("Successfully received and saved key pair for: " + name);

        } catch (SocketException e) {
                e.printStackTrace();

        }
    }

    private void saveKeyAndCertificate(byte[] privateKeyBytes, byte[] certBytes) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        String keyPem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder().encodeToString(privateKeyBytes) +
                "\n-----END PRIVATE KEY-----";

        Files.write(Paths.get(name + ".key"), keyPem.getBytes());

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory
                .generateCertificate(new ByteArrayInputStream(certBytes));

        String certPem = "-----BEGIN CERTIFICATE-----\n" +
                Base64.getMimeEncoder().encodeToString(certBytes) +
                "\n-----END CERTIFICATE-----";

        Files.write(Paths.get(name + ".crt"), certPem.getBytes());
    }
    public static void main(String[] args) throws Exception {

        String serverHost = args[0];
        int serverPort = Integer.parseInt(args[1]);
        String name = args[2];
        int delaySeconds = args.length > 3 ? Integer.parseInt(args[3]) : 0;
        boolean exitBeforeReading = args.length > 4 && Boolean.parseBoolean(args[4]);

        Client client = new Client(serverHost, serverPort, name,
                delaySeconds, exitBeforeReading);
        client.run();
    }
}
