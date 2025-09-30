package ru.nsu.romankin.hoi;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.KeyGenerator;
import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

public class Server {

    private int port;
    private int threadNum;
    private Selector selector;
    private ServerSocketChannel ssc;
    private ExecutorService es;
    private ExecutorService ioEs;
    private List<Future<CertKeyPair>> futures;
    private PrivateKey privateKey;
    private String issuer;
    private final Map<String, CertKeyPair> keyCache = new ConcurrentHashMap<>();
    private final BlockingQueue<ClientRequest> generationQueue = new LinkedBlockingQueue<>();
    private final BlockingQueue<CompletedRequest> completionQueue = new LinkedBlockingQueue<>();
    public Server(int port, int threadNum, String issuer, PrivateKey privateKey){
        this.port = port;
        this.threadNum = threadNum;
        this.issuer = issuer;
        this.privateKey = privateKey;
        futures = new ArrayList<>();
        Security.addProvider(new BouncyCastleProvider());
    }

    public void run() throws IOException, NoSuchAlgorithmException {
        ssc = ServerSocketChannel.open();
        ssc.configureBlocking(false);
        ssc.socket().bind(new InetSocketAddress(port));
        selector = Selector.open();
        ssc.register(selector, SelectionKey.OP_ACCEPT);

        es = Executors.newFixedThreadPool(threadNum);
        ioEs = Executors.newSingleThreadExecutor();
        for (int i = 0; i < threadNum; i++) {
            futures.add(i, es.submit(new KeyGeneratorThread()));
        }
        ioEs.submit(new ioThread());

        System.out.println("Server started on port " + port);

        while (!Thread.currentThread().isInterrupted()) {
            selector.select();
            Iterator<SelectionKey> keys = selector.selectedKeys().iterator();

            while (keys.hasNext()) {
                SelectionKey key = keys.next();
                keys.remove();

                if (!key.isValid()) continue;

                if (key.isAcceptable()) {
                    acceptConnection(key);
                } else if (key.isReadable()) {
                    readRequest(key);
                }
            }
        }
    }
    private static class ClientContext {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
    }
    private void acceptConnection(SelectionKey key) throws IOException {
        ServerSocketChannel serverChannel = (ServerSocketChannel) key.channel();
        SocketChannel clientChannel = serverChannel.accept();
        clientChannel.configureBlocking(false);
        clientChannel.register(selector, SelectionKey.OP_READ, new ClientContext());
    }

    private void readRequest(SelectionKey key) throws IOException {
        SocketChannel channel = (SocketChannel) key.channel();
        ClientContext context = (ClientContext) key.attachment();

        ByteBuffer buffer = context.buffer;
        int bytesRead = channel.read(buffer);

        if (bytesRead == -1) {
            channel.close();
            return;
        }

        buffer.flip();
        int nullIndex = -1;
        for (int i = buffer.position(); i < buffer.limit(); i++) {
            if (buffer.get(i) == 0) {
                nullIndex = i;
                break;
            }
        }

        if (nullIndex != -1) {
            byte[] nameBytes = new byte[nullIndex - buffer.position()];
            buffer.get(nameBytes);
            buffer.get();

            String name = new String(nameBytes, "ASCII");
            handleNameRequest(name, channel, key);

            buffer.compact();
        } else {
            buffer.compact();
        }
    }
    private void handleNameRequest(String name, SocketChannel channel, SelectionKey key) {
        CertKeyPair cached = keyCache.get(name);
        if (cached != null) {
            sendResponse(channel, cached);
            return;
        }
        ClientRequest request = new ClientRequest(name, channel, key);
        generationQueue.offer(request);
    }

    private void sendResponse(SocketChannel channel, CertKeyPair keyPairWithCert) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            byte[] privateKeyBytes = keyPairWithCert.keyPair.getPrivate().getEncoded();
            dos.writeInt(privateKeyBytes.length);
            dos.write(privateKeyBytes);

            byte[] certBytes = keyPairWithCert.certificate.getEncoded();
            dos.writeInt(certBytes.length);
            dos.write(certBytes);

            byte[] response = baos.toByteArray();

            ByteBuffer buffer = ByteBuffer.allocate(response.length + 4);
            buffer.putInt(response.length);
            buffer.put(response);
            buffer.flip();

            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }

        } catch (Exception e) {
            try { channel.close(); } catch (IOException ignored) {}
        }
    }
    private class KeyGeneratorThread implements Callable<CertKeyPair> {

        CertKeyPair result;
        @Override
        public CertKeyPair call(){
            try {

                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(8192);

                while (!Thread.currentThread().isInterrupted()) {
                    ClientRequest request = generationQueue.take();
                    CertKeyPair cached = keyCache.get(request.name);
                    if (cached != null) {
                        completionQueue.offer(new CompletedRequest(request, cached));
                        continue;
                    }

                    try {
                        KeyPair keyPair = keyGen.generateKeyPair();
                        X509Certificate cert = generateCertificate(request.name, keyPair);

                        CertKeyPair result = new CertKeyPair(keyPair, cert);
                        keyCache.put(request.name, result);

                        completionQueue.offer(new CompletedRequest(request, result));

                    } catch (Exception e) {
                        System.err.println("Error generating keys for " + request.name + ": " + e.getMessage());
                        try { request.channel.close(); } catch (IOException ignored) {}
                    }
                }
            } catch (InterruptedException | NoSuchAlgorithmException e) {
                Thread.currentThread().interrupt();
            }
            return result;
        }
    }

    private class ioThread implements Runnable {

        @Override
        public void run() {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    CompletedRequest completed = completionQueue.take();
                    sendResponse(completed.request.channel, completed.result);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private class ClientRequest {
        String name;
        SocketChannel channel;
        SelectionKey key;

        ClientRequest(String name, SocketChannel channel, SelectionKey key) {
            this.name = name;
            this.channel = channel;
            this.key = key;
        }
    }

    private class CertKeyPair {
        KeyPair keyPair;
        X509Certificate certificate;

        CertKeyPair(KeyPair keyPair, X509Certificate certificate) {
            this.keyPair = keyPair;
            this.certificate = certificate;
        }
    }

    private X509Certificate generateCertificate(String subjectName, KeyPair keyPair)
            throws OperatorCreationException, CertificateException, NoSuchAlgorithmException {

        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(Duration.ofDays(365)));

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        X500Name subject = new X500Name("CN=" + subjectName);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name(issuer),
                serial,
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .build(privateKey);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signer));
    }

    private class CompletedRequest {
        final ClientRequest request;
        final CertKeyPair result;

        CompletedRequest(ClientRequest request, CertKeyPair result) {
            this.request = request;
            this.result = result;
        }

    }



    public static void main(String[] args) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        int port = Integer.parseInt(args[0]);
        int threadNum = Integer.parseInt(args[1]);
        String keyFile = args[2];
        String issuer = args[3];
        String ksPassword = args[4];
        KeyStore ks = KeyStore.getInstance("PKCS12");
        FileInputStream fileInputStream = new FileInputStream(keyFile);
        ks.load(fileInputStream, ksPassword.toCharArray());

        String alias = ks.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey)ks.getKey(alias, ksPassword.toCharArray());
        fileInputStream.close();
        Server server = new Server(port, threadNum, issuer,privateKey);
        server.run();
    }
}