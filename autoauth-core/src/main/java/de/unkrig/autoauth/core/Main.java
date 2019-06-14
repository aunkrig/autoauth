
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
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import de.unkrig.commons.io.IoUtil;
import de.unkrig.commons.lang.ExceptionUtil;
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
import de.unkrig.commons.net.http.HttpResponse;
import de.unkrig.commons.net.http.servlett.Servlett;
import de.unkrig.commons.nullanalysis.Nullable;
import de.unkrig.commons.util.CommandLineOptions;
import de.unkrig.commons.util.annotation.CommandLineOption;
import de.unkrig.commons.util.annotation.CommandLineOption.Cardinality;
import de.unkrig.commons.util.logging.SimpleLogging;

public
class Main {

    public static final Logger LOGGER = Logger.getLogger(Main.class.getName());
    { SimpleLogging.init(); }

    /**
     * Implements an HTTP proxy that forwards requests to another HTTP proxy.
     *
     * <p>
     *   Usage:
     * </p>
     * <p>
     *   {@code autoauth} [ <var>command-line-option</var> ] ...
     * </p>
     * <p>
     *   Valid command line options are:
     * </p>
     *
     * {@main.commandLineOptions}
     */
    public static void
    main(String[] args) throws IOException, Exception {

        Main main = new Main();
        args = CommandLineOptions.parse(args, main);

        main.run();
    }

    private InetAddress           endpointAddress            = InetAddress.getLoopbackAddress();
    private int                   endpointPort               = 0;
    @Nullable private InetAddress targetAddress              = null;
    private int                   targetPort                 = -1;
    private String                prompt                     = "autoauth";
    private boolean               handleProxyAuthentication  = true;
    private boolean               handleServerAuthentication = false;

    // ---------------------------- BEGIN COMMAND LINE OPTIONS ----------------------------

    /**
     * Prints this text.
     */
    @CommandLineOption public void
    help() throws IOException {
        IoUtil.copyResource(Main.class, "Main.main(String[]).txt", System.out, false);
        System.exit(0);
    }

    /**
     * The address of the interface that AUTOAUTH binds to.
     * Default is to bind to the "loopback address" (often 127.0.0.1), which allows only <em>local</em> processes to
     * connect.
     * "any" binds to the "wildcard address", so clients can connect on <em>any</em> interface.
     *
     * @param address &lt;host-name-or-ip-address>
     */
    @CommandLineOption public void
    setEndpointAddress(InetAddress address) { this.endpointAddress = address; }

    /**
     * The port that AUTOAUTH binds to. "0", which is also the default, means to pick an "ephemeral port".
     */
    @CommandLineOption public void
    setEndpointPort(int portNumber) { this.endpointPort = portNumber; }

    /**
     * The address of the "real" HTTP proxy to connect to.
     *
     * @param address &lt;host-name-or-ip-address>
     */
    @CommandLineOption(cardinality = Cardinality.MANDATORY) public void
    setTargetAddress(InetAddress address) { this.targetAddress = address; }

    /**
     * The port of the "real" HTTP proxy to connect to.
     */
    @CommandLineOption(cardinality = Cardinality.MANDATORY) public void
    setTargetPort(int portNumber) { this.targetPort = portNumber; }

    /**
     * The "realm" string that is displayed in the proxy authentication dialog.
     */
    @CommandLineOption public void
    setPrompt(String text) { this.prompt = text; }

    /**
     * Handle 401 responses; default is to return them to the client.
     */
    @CommandLineOption public void
    setHandleServerAuthentication() { this.handleServerAuthentication = true; }

    /**
     * Don't handle 407 responses, but return them to the client.
     */
    @CommandLineOption public void
    dontHandleProxyAuthentication() { this.handleProxyAuthentication = false; }

    /**
     * Don't print warnings.
     */
    @CommandLineOption public void
    noWarn() { SimpleLogging.setNoWarn(); }

    /**
     * Reset to default output.
     */
    @CommandLineOption public void
    normal()  { SimpleLogging.setNormal();  }

    /**
     * Only print warnings and errors.
     */
    @CommandLineOption public void
    quiet() { SimpleLogging.setQuiet(); }

    /**
     * Log request URLs and response status to STDOUT.
     */
    @CommandLineOption public void
    verbose() { SimpleLogging.setVerbose(); }

    /**
     * Enable logging; repeat for more logging.
     */
    @CommandLineOption(cardinality = Cardinality.ANY) public void
    debug() { SimpleLogging.setDebug(); }

    // ---------------------------- END OF COMMAND LINE OPTIONS ----------------------------

    private void
    run() throws Exception {

        LOGGER.log(
            Level.INFO,
            "AUTOAUTH {0} starting up...",
            Main.getMavenArtifactVersionNoException("de.unkrig.autoauth", "autoauth-core")
        );

        final String[] cachedAuthorization = new String[1];

        final InetSocketAddress targetAddress = new InetSocketAddress(this.targetAddress, this.targetPort);

        Authenticator.setDefault(new CustomAuthenticator(
            CustomAuthenticator.CacheMode.USER_NAMES_AND_PASSWORDS,
            CustomAuthenticator.StoreMode.USER_NAMES_AND_PASSWORDS
        ));

        String proxyAuthorization = (
            this.handleProxyAuthentication
            ? basicCredentials(Authenticator.requestPasswordAuthentication(
                targetAddress.getHostName(),      // host
                targetAddress.getAddress(),       // addr
                targetAddress.getPort(),          // port
                "http",                           // protocol
                this.prompt,                      // prompt
                "basic",                          // scheme
                new URL("http://x"),              // url
                RequestorType.PROXY               // reqType
            ))
            : null
        );

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

                Servlett servlett = new Servlett() {

                    public void
                    close() throws IOException {
                        ;
                    }

                    public HttpResponse
                    handleRequest(
                        HttpRequest                                    httpRequest,
                        ConsumerWhichThrows<HttpResponse, IOException> sendProvisionalResponse
                    ) throws IOException {

                        if (proxyAuthorization != null) {
                            httpRequest.setHeader("Proxy-Authorization", proxyAuthorization);
                        }

                        // Log provisional responses.
                        final Level l = Level.CONFIG;
                        if (LOGGER.isLoggable(l)) {
                            final ConsumerWhichThrows<HttpResponse, IOException> tmp = sendProvisionalResponse;
                            sendProvisionalResponse = new ConsumerWhichThrows<HttpResponse, IOException>() {

                                @Override public void
                                consume(HttpResponse provisionalResponse) throws IOException {
                                    LOGGER.log(
                                        l,
                                        "{0} {1} => {2}",
                                        new Object[] {
                                            httpRequest.getMethod(),
                                            httpRequest.getUri(),
                                            provisionalResponse.getStatus(),
                                        }
                                    );
                                    tmp.consume(provisionalResponse);
                                }
                            };
                        }

                        HttpResponse
                        finalResponse = Main.processRequest(tcpClient, httpRequest, sendProvisionalResponse);

                        // Log final response.
                        LOGGER.log(
                            l,
                            "{0} {1} => {2}",
                            new Object[] {
                                httpRequest.getMethod(),
                                httpRequest.getUri(),
                                finalResponse.getStatus(),
                            }
                        );
                        return finalResponse;
                    }
                };

                {
                    final Servlett delegate = servlett;
                    servlett = new Servlett() {

                        @Override public void
                        close() throws IOException { delegate.close(); }

                        @Override public HttpResponse
                        handleRequest(
                            HttpRequest                                    request,
                            ConsumerWhichThrows<HttpResponse, IOException> sendProvisionalResponse
                        ) throws IOException {

                            if (!Main.this.handleServerAuthentication) {
                                return delegate.handleRequest(request, sendProvisionalResponse);
                            }

                            HttpResponse response = delegate.handleRequest(request, sendProvisionalResponse);
                            if (response.getStatus() != HttpResponse.Status.UNAUTHORIZED) return response;

                            for (;;) {

                                String wwwAuthenticate = response.getHeader("WWW-Authenticate");
                                Matcher m = Pattern.compile("(\\w+)(?: +realm *= *\"([^\"]*)\")?.*").matcher(wwwAuthenticate);
                                if (!m.matches()) break;

                                String scheme = m.group(1);
                                String realm  = m.group(2);

                                if (!"basic".equalsIgnoreCase(scheme)) break;

                                String authorization = cachedAuthorization[0] != null ? cachedAuthorization[0] : basicCredentials(Authenticator.requestPasswordAuthentication(
                                    request.getHeader("Host"),                         // host
                                    InetAddress.getByName(request.getUri().getHost()), // addr
                                    request.getUri().getPort(),                        // port
                                    "http",                                            // protocol
                                    realm,                                             // prompt
                                    scheme,                                            // scheme
                                    request.getUri().toURL(),                          // url
                                    RequestorType.SERVER                               // reqType
                                ));
                                request.setHeader("Authorization", authorization);

                                response = delegate.handleRequest(request, sendProvisionalResponse);

                                if (response.getStatus() != HttpResponse.Status.UNAUTHORIZED) {
                                    cachedAuthorization[0] = authorization;
                                    break;
                                }

                                cachedAuthorization[0] = null;
                            }

                            return response;
                        }
                    };
                }

                HttpClientConnectionHandler hcch = new HttpClientConnectionHandler(servlett);
                hcch.handleConnection(
                    in,
                    out,
                    localSocketAddress,
                    remoteSocketAddress,
                    stoppable
                );
            }
        };

        TcpServer tcpServer = new TcpServer(
            new InetSocketAddress(this.endpointAddress, this.endpointPort), // endpoint
            0,                                                              // backlog
            cch                                                             // clientConnectionHandler
        );

        LOGGER.info("Accepting HTTP requests on " + tcpServer.getEndpointAddress());

        tcpServer.run();
    }

    public static
    class PomException extends Exception {
        private static final long serialVersionUID = 1L;

        public PomException(String message)  { super(message); }
        public PomException(Throwable cause) { super(cause);   }
    }

    private static String
    getMavenArtifactVersionNoException(String groupId, String artifactId) {
        try {
            return getMavenArtifactVersion(groupId, artifactId);
        } catch (IOException | PomException | RuntimeException e) {
            return "(" + e + ")";
        }
    }

    /**
     * @return              The version of the given maven artifact
     * @throws PomException The designated artifact is not on the classpath
     * @throws PomException The artifact's POM could not be parsed
     * @throws PomException The artifact's version could not be determined from the POM
     */
    private static String
    getMavenArtifactVersion(String groupId, String artifactId) throws IOException, PomException {

        // The "maven-compiler-plugin" copies the artifact's POM into the.jar file, where we can read it, parse it,
        // and extract the artifact's version.
        // The "maven-assembly-plugin" copies all artifacts' POMs into the jar-with-dependencies.jar.
        String pomXmlResourceName = "META-INF/maven/" + groupId + "/" + artifactId + "/pom.xml";

        try (InputStream is = Main.class.getClassLoader().getResourceAsStream(pomXmlResourceName)) {
            if (is == null) throw new PomException("pom.xml not found");

            // Create DocumentBuilder.
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();

            // Parse POM.
            Document doc = db.parse(new InputSource(is));

            // Get artifact version from "<project>...<version>x.y.z".
            String version = XPathFactory.newInstance().newXPath().compile("/project/version").evaluate(doc).trim();
            if (version.isEmpty()) throw new PomException("project.version missing");
            return version;
        } catch (ParserConfigurationException | SAXException | XPathExpressionException e) {
            throw new AssertionError(e);
        }
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
                } catch (IOException ioe) {
                    throw ExceptionUtil.wrap("Sending request to remote proxy", ioe);
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
                httpRequest.getMethod(),
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
