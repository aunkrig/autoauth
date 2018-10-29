
package de.unkrig.autoauth.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.Authenticator.RequestorType;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.SocketException;
import java.net.URL;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import de.unkrig.commons.lang.ThreadUtil;
import de.unkrig.commons.lang.java6.Base64;
import de.unkrig.commons.lang.protocol.ConsumerWhichThrows;
import de.unkrig.commons.lang.protocol.RunnableWhichThrows;
import de.unkrig.commons.lang.protocol.Stoppable;
import de.unkrig.commons.net.TcpClient;
import de.unkrig.commons.net.TcpServer;
import de.unkrig.commons.net.TcpServer.ConnectionHandler;
import de.unkrig.commons.net.authenticator.CustomAuthenticator;
import de.unkrig.commons.net.http.HttpClientConnectionHandler;
import de.unkrig.commons.net.http.HttpRequest;
import de.unkrig.commons.net.http.HttpRequest.Method;
import de.unkrig.commons.net.http.HttpResponse;
import de.unkrig.commons.net.http.servlett.Servlett;
import de.unkrig.commons.nullanalysis.Nullable;
import de.unkrig.commons.util.CommandLineOptions;
import de.unkrig.commons.util.annotation.CommandLineOption;
import de.unkrig.commons.util.annotation.CommandLineOption.Cardinality;
import de.unkrig.commons.util.logging.formatter.PrintfFormatter;

public
class Main {

    public static final Logger LOGGER = Logger.getLogger(Main.class.getName());

    public static void
    main(String[] args) throws IOException, Exception {

        Main main = new Main();
        args = CommandLineOptions.parse(args, main);

        main.run();
    }

    @CommandLineOption public void
    setDebug() {
        Logger l = Logger.getLogger("de");
        l.setLevel(Level.FINEST);
        l.setUseParentHandlers(false);
        ConsoleHandler h = new ConsoleHandler();
        h.setLevel(Level.FINEST);
        h.setFormatter(new PrintfFormatter(PrintfFormatter.FORMAT_STRING_SIMPLE));
        l.addHandler(h);
    }

    @Nullable private InetAddress endpointAddress = null;
    private int                   endpointPort    = -1;
    @Nullable private InetAddress targetAddress   = null;
    private int                   targetPort      = -1;
    private String                prompt          = "autoauth";

    @CommandLineOption() public void
    setEndpointAddress(InetAddress value) { this.endpointAddress = value; }

    @CommandLineOption(cardinality = Cardinality.MANDATORY) public void
    setEndpointPort(int value) { this.endpointPort = value; }

    @CommandLineOption(cardinality = Cardinality.MANDATORY) public void
    setTargetAddress(InetAddress value) { this.targetAddress = value; }

    @CommandLineOption(cardinality = Cardinality.MANDATORY) public void
    setTargetPort(int value) { this.targetPort = value; }

    @CommandLineOption() public void
    setPrompt(String value) { this.prompt = value; }

    private void
    run() throws Exception {

        final InetSocketAddress targetAddress = new InetSocketAddress(this.targetAddress, this.targetPort);

        Authenticator.setDefault(new CustomAuthenticator(
            CustomAuthenticator.CacheMode.USER_NAMES_AND_PASSWORDS,
            CustomAuthenticator.StoreMode.USER_NAMES_AND_PASSWORDS
        ));
        String proxyAuthorization = basicCredentials(Authenticator.requestPasswordAuthentication(
            targetAddress.getHostName(),      // host
            targetAddress.getAddress(),       // addr
            targetAddress.getPort(),          // port
            "http",                           // protocol
            this.prompt,                      // prompt
            "basic",                          // scheme
            new URL("http://x"),              // url
            RequestorType.PROXY               // reqType
        ));

        // Create a custom ConnectionHandler, because we don't just want to process HTTP requests, but want to be
        // informed when a new connection is accepted, and then create a connection to the proxy.
        ConnectionHandler cch = new ConnectionHandler() {

            @Override public void
            handleConnection(
                InputStream       in,
                OutputStream      out,
                InetSocketAddress localSocketAddress,
                InetSocketAddress remoteSocketAddress,
                Stoppable         stoppable
            ) throws Exception {

                LOGGER.fine(
                    ""
                    + "S<< Connecting to server '"
                    + targetAddress
                    + "' -- '"
                    + targetAddress
                    + "'"
                );
                final TcpClient tcpClient = new TcpClient(targetAddress.getAddress(), targetAddress.getPort());

                new HttpClientConnectionHandler(
                    new Servlett() {

                        public void
                        close() throws IOException {
                            ;
                        }

                        public HttpResponse
                        handleRequest(
                            HttpRequest                                    httpRequest,
                            ConsumerWhichThrows<HttpResponse, IOException> sendProvisionalResponse
                        ) throws IOException {

                            httpRequest.setHeader("Proxy-Authorization", proxyAuthorization);

                            return Main.processRequest(tcpClient, httpRequest, sendProvisionalResponse);
                        }
                    }
                ).handleConnection(in, out, localSocketAddress, remoteSocketAddress, stoppable);
            }
        };

        new TcpServer(
            new InetSocketAddress(this.endpointAddress, this.endpointPort), // endpoint
            0,                                                              // backlog
            cch                                                             // clientConnectionHandler
        ).run();
    }

    /**
     * Submits the <var>httpRequest</var> to the <var>targetAddress</var>, passes any provisional responses (100...199)
     * to <var>sendProvisionalResponse</var>, and returns the non-provisional (200+) response.
     */
    private static HttpResponse
    processRequest(
        TcpClient                                      tcpClient,
        final HttpRequest                              httpRequest,
        ConsumerWhichThrows<HttpResponse, IOException> sendProvisionalResponse
    ) throws IOException {

        LOGGER.fine("S<< Sending request to remote proxy");
        ThreadUtil.runInBackground(new RunnableWhichThrows<IOException>() {

            @Override public void
            run() throws IOException {
                try {
                    httpRequest.write(tcpClient.getOutputStream(), "S<< ");
                    tcpClient.getOutputStream().flush();
                } catch (SocketException se) {
                    LOGGER.fine("S<< " + se);
                }
            }
        }, Thread.currentThread().getName() + "-request");

        // According to the HTTP spec (RFC 2616) there can be MORE than one response to a request: First,
        // zero or more "provisional" responses (status codes 1XX), then ONE "final" response.
        for (;;) {

            LOGGER.fine("S>> Reading response from remote server");

            HttpResponse httpResponse = HttpResponse.read(
                tcpClient.getInputStream(),
                httpRequest.getHttpVersion(),
                httpRequest.getMethod() == Method.HEAD,
                "S>> "
            );

            LOGGER.fine(
                httpRequest.getMethod()
                + " "
                + httpRequest.getUri()
                + " => "
                + httpResponse.getStatus()
                + " completely processed"
            );

            // And return the (final) response to the client.
            if (!httpResponse.isProvisional()) return httpResponse;

            // Send any provisional (i.e. 1XX) response to the client and wait for another response from the
            // server.
            sendProvisionalResponse.consume(httpResponse);
        }
    }

    @Nullable private static String
    basicCredentials(@Nullable PasswordAuthentication passwordAuthentication) {

        if (passwordAuthentication == null) return null;

        String userName = passwordAuthentication.getUserName();
        char[] password = passwordAuthentication.getPassword();
        if (userName == null || password == null) return null;

        return "Basic " + Base64.encode((userName + ":" + new String(password)).getBytes());
    }
}
