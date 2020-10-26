
package de.unkrig.autoauth.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.Authenticator;
import java.net.Authenticator.RequestorType;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.SocketException;
import java.net.URI;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
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
import de.unkrig.commons.net.http.HttpRequest.Method;
import de.unkrig.commons.net.http.HttpResponse;
import de.unkrig.commons.net.http.servlett.Servlett;
import de.unkrig.commons.nullanalysis.Nullable;
import de.unkrig.commons.text.pattern.Glob;
import de.unkrig.commons.text.pattern.Pattern2;
import de.unkrig.commons.util.CommandLineOptions;
import de.unkrig.commons.util.annotation.CommandLineOption;
import de.unkrig.commons.util.annotation.CommandLineOption.Cardinality;
import de.unkrig.commons.util.annotation.RegexFlags;
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

        try {
            Main main = new Main();
            args = CommandLineOptions.parse(args, main);
    
            main.run();
        } catch (Throwable t) {
            StringWriter sw = new StringWriter();

            try (PrintWriter pw = new PrintWriter(sw)) {
                t.printStackTrace(pw);
            }
            
            showErrorDialog("<html><pre>" + sw + "</pre>");
            System.exit(1);
        }
    }

    /**
     * Shows an error dialog with the given <var>message</var>. Returns only when the user clicks the "OK" button.
     * <p>
     *   If the message is prefixed with {@code "<html>"}, then it may contain (limited) HTML markup:
     * </p>
     * <p>
     *   <b>The following HTML tags appear to work as expected:</b>
     * </p>
     * <dl>
     *   <dd>{@code <a href="http://www.google.de">A link</a>} (underlined, but not clickable)</dd>
     *   <dd>{@code <a name="myanchor" />} (not useful)</dd>
     *   <dd>{@code <address>An address</address>}</dd>
     *   <dd>{@code <b>Bold text</b>}</dd>
     *   <dd>{@code <big>Bigger text</big>}</dd>
     *   <dd>{@code <blockquote>A block quote</blockquote>}</dd>
     *   <dd>{@code <br />}</dd>
     *   <dd>{@code <center>Centered block</center>}</dd>
     *   <dd>{@code <cite>A citation, italics</cite>}</dd>
     *   <dd>{@code <code>Monospaced code</code>}</dd>
     *   <dd>{@code <dfn>A definition, italics</dfn>}</dd>
     *   <dd>{@code <dir><li>foo.java</li><li>bar.java</li></dir>}</dd>
     *   <dd>{@code <div>A block</div>}</dd>
     *   <dd>{@code <dl><dt>Definition term</dt><dd>Definition description</dd></dl>}</dd>
     *   <dd>{@code <em>Emphasized text</em>}</dd>
     *   <dd>{@code <font color="red" size="17">Alternate font</font>}</dd>
     *   <dd>{@code <form>Input form</form>} (not submittable)</dd>
     *   <dd>{@code <h1>Heading 1</h1>}</dd>
     *   <dd>{@code <h2>Heading 2</h2>}</dd>
     *   <dd>{@code <h3>Heading 3</h3>}</dd>
     *   <dd>{@code <h4>Heading 4</h4>}</dd>
     *   <dd>{@code <h5>Heading 5</h5>}</dd>
     *   <dd>{@code <h6>Heading 6</h6>}</dd>
     *   <dd>{@code <head><base href="xyz" /></head>} (has no effect)</dd>
     *   <dd>{@code <head><basefont color="red" /></head>} (has no effect)</dd>
     *   <dd>{@code <head><meta name="author" content="me" /></head>} (prints as text)</dd>
     *   <dd>{@code <head><noscript>NOSCRIPT</noscript></head>} (prints as text)</dd>
     *   <dd>
     *     {@code <head><style>h1 }<code>{ </code>{@code color:red; }<code>}</code>{@code </style></head>}
     *     (must be the first tag after "&lt;html>")
     *   </dd>
     *   <dd>{@code <hr>Horizontal ruler</hr>}</dd>
     *   <dd>{@code <i>Italic text</i>}</dd>
     *   <dd>{@code <img src="icon.png" />}</dd>
     *   <dd>{@code <input type="text" />}</dd>
     *   <dd>{@code <input type="checkbox" />}</dd>
     *   <dd>{@code <input type="radio" />}</dd>
     *   <dd>{@code <input type="reset" />} (not functional)</dd>
     *   <dd>{@code <kbd>Keyboard input</kbd>}</dd>
     *   <dd>{@code <map><area /></map>} (not useful)</dd>
     *   <dd>{@code <menu><menuitem label="foo" /></menu>} (ignored)</dd>
     *   <dd>{@code <ol><li>Ordered list item</li></ol>}</dd>
     *   <dd>{@code <p>Paragraph</p>}</dd>
     *   <dd>{@code <pre>Preformatted text, monospaced</pre>}</dd>
     *   <dd>{@code <samp>Sample output, monospaced</samp>}</dd>
     *   <dd>{@code <select><option>Selection option</option></select>}</dd>
     *   <dd>{@code <small>Smaller text</small>}</dd>
     *   <dd>{@code <span style="color:red">Grouped inline elements</span>}</dd>
     *   <dd>{@code <strike>Crossed-out text</strike>}</dd>
     *   <dd>{@code <s>Text that is no longer correkt (strikethrough)</s>}</dd>
     *   <dd>{@code <strong>Strong text, bold</strong>}</dd>
     *   <dd>{@code <sub>Subscript text</sub>}</dd>
     *   <dd>{@code <sup>Superscript text</sup>}</dd>
     *   <dd>{@code <table border=1><caption>A caption</caption><tr><th>Heading</th><td>Cell</td></tr></table>}</dd>
     *   <dd>{@code <textarea rows="4">A multi-line text area</textarea>}</dd>
     *   <dd>{@code <tt>Teletype text</tt>}</dd>
     *   <dd>{@code <u>Underlined text</u>}</dd>
     *   <dd>{@code <ul><li>li</li></ul>}</dd>
     *   <dd>{@code <var>A variable, italics</var>}</dd>
     * </p>
     * <p>
     *   <b>The following HTML tags throw exceptions and are therefore not useful:</b>
     * </p>
     * <dl>
     *   <dt>{@code <applet>}</dt>
     *   <dd>java.lang.ClassCastException: javax.swing.JLabel cannot be cast to javax.swing.text.JTextComponent</dd>
     *   <dt>{@code <frame>}</dt>
     *   <dd>java.lang.RuntimeException: Can't build aframeset, BranchElement(frameset) 226,227</dd>
     *   <dt>{@code <frameset>}</dt>
     *   <dd>java.lang.RuntimeException: Can't build aframeset, BranchElement(frameset) 226,227</dd>
     *   <dt>{@code <head><link rel="stylesheet" type="text/css" href="theme.css" /></head>}</dd>
     *   <dd>java.lang.ClassCastException: javax.swing.JLabel cannot be cast to javax.swing.text.JTextComponent</dd>
     *   <dt>{@code <head><script>alert('Hi there!');</script></head>}</dd>
     *   <dd>java.lang.ClassCastException: javax.swing.JLabel cannot be cast to javax.swing.text.JTextComponent</dd>
     *   <dt>{@code <head><title>TITLE</title></head>}</dd>
     *   <dd>java.lang.ClassCastException: javax.swing.JLabel cannot be cast to javax.swing.text.JTextComponent</dd>
     *   <dt>{@code <input type="submit" />}</dt>
     *   <dd>Exception in thread "AWT-EventQueue-0" java.lang.NullPointerException</dd>
     *   <dt>{@code <link>}</dt>
     *   <dd>javax.swing.JLabel cannot be cast to javax.swing.text.JTextComponent</dd>
     *   <dt>{@code <noframes>}</dt>
     *   <dd>java.lang.ClassCastException: javax.swing.JLabel cannot be cast to javax.swing.text.JTextComponent</dd>
     *   <dt>{@code <script>}</dt>
     *   <dd>java.lang.ClassCastException: javax.swing.JLabel cannot be cast to javax.swing.text.JTextComponent</dd>
     *   <dt>{@code <title>}</dt>
     *   <dd>java.lang.ClassCastException: javax.swing.JLabel cannot be cast to javax.swing.text.JTextComponent</dd>
     * </dl>
     * <p>
     *   <b>The following HTML tags create unexpected results and are therefore not useful:</b>
     * </p>
     * <dl>
     *   <dt>{@code <body>body</body>}</dt>
     *   <dd>Terminates the document</dd>
     *   <dt>{@code <html>html</html>}</dt>
     *   <dd>Terminates the document</dd>
     *   <dt>{@code <isindex>isindex</isindex>}</dt>
     *   <dd>Breaks the layout</dd>
     *   <dt>{@code <object><param name="x" value="y" /></object>}</dt>
     *   <dd>Displays "??"</dd>
     * </dl>
     */
    private static void
    showErrorDialog(String message) {
        JOptionPane.showMessageDialog(
            null,                      // parentComponent
            new JLabel(message),       // message
            "Error",                   // title
            JOptionPane.ERROR_MESSAGE  // messageType
        );
    }

    private InetAddress           endpointAddress            = InetAddress.getLoopbackAddress();
    private int                   endpointPort               = 0;
    @Nullable private InetAddress targetAddress              = null;
    private int                   targetPort                 = -1;
    private String                prompt                     = "autoauth";
    private boolean               handleProxyAuthentication  = true;
    private boolean               handleServerAuthentication = false;
    protected Glob                noProxy                    = null;

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
     * Connect directly (not through the target proxy) iff host (or host:port) matches the <var>glob</var>.
     * 
     * @param noProxy &lt;glob>
     */
    @CommandLineOption public void
    setNoProxy(@RegexFlags(Pattern2.WILDCARD) Glob noProxy) { this.noProxy = noProxy; }

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

                        TcpClient tcpClient2 = tcpClient;

                        NO_PROXY:
                        if (Main.this.noProxy != null) {
                            URI         targetUri         = httpRequest.getUri();              // E.g. "https://user:pass@unkrig.de/index.html"
                            String      targetHost        = targetUri.getHost();               // E.g. "unkrig.de"
                            int         targetPort        = targetUri.getPort();               // E.g. -1
                            InetAddress targetInetAddress = InetAddress.getByName(targetHost); // E.g. "unkrig.de/193.141.3.72"

                            // targetInetAddress...
                            // .getAddress()           => byte[4] { -63, -115, 3, 72 }
                            // .getHostName()          => "unkrig.de"
                            // .getHostAddress()       => "193.141.3.72"
                            // .getCanonicalHostName() => "a08.rzone.de"

                            if (targetPort == -1) targetPort = 80;

                            for (String s1 : new String[] {
                                targetInetAddress.getHostName(),
                                targetInetAddress.getCanonicalHostName(),
                                targetInetAddress.getHostAddress(),
                            }) {
                                for (String s2 : new String[] { "", ":" + targetPort }) {
                                    if (Main.this.noProxy.matches(s1 + s2)) {
                                        tcpClient2 = new TcpClient(targetInetAddress, targetPort);
                                        break NO_PROXY;
                                    }
                                }
                            }
                        }

                        final Level logResponseLevel = Level.CONFIG;
                        final boolean throughTarget = tcpClient2 == tcpClient;
                        ConsumerWhichThrows<HttpResponse, IOException>
                        logResponse = new ConsumerWhichThrows<HttpResponse, IOException>() {

                            @Override public void
                            consume(HttpResponse response) throws IOException {
                                LOGGER.log(
                                    logResponseLevel,
                                    "{0} {1} {2} {3}",
                                    new Object[] {
                                        httpRequest.getMethod(),
                                        httpRequest.getUri(),
                                        throughTarget ? "=>" : "->",
                                        response.getStatus(),
                                    }
                                );
                            }
                        };

                        // Provision logging of provisional responses.
                        if (LOGGER.isLoggable(logResponseLevel)) {
                            final ConsumerWhichThrows<HttpResponse, IOException> tmp = sendProvisionalResponse;
                            sendProvisionalResponse = new ConsumerWhichThrows<HttpResponse, IOException>() {

                                @Override public void
                                consume(HttpResponse provisionalResponse) throws IOException {
                                    logResponse.consume(provisionalResponse);
                                    tmp.consume(provisionalResponse);
                                }
                            };
                        }

                        // Process the request.
                        HttpResponse
                        finalResponse = Main.processRequest(tcpClient2, httpRequest, sendProvisionalResponse);

                        // Log the final response.
                        logResponse.consume(finalResponse);

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
                    if (httpRequest.getMethod() == Method.CONNECT) {
                        // Some clients send "CONNECT", "Content-Length: 0", which we ignore.
                        httpRequest.removeHeader("Content-Length");
                        httpRequest.write(tcpClient.getOutputStream(), "S<< ");
                        LOGGER.fine("S<< CONNECT Request completely processed");
                        tcpClient.getOutputStream().close();
                        return;
                    }
                    httpRequest.write(tcpClient.getOutputStream(), "S<< ");
                    tcpClient.getOutputStream().flush();
                    LOGGER.fine("S<< Request completely processed");
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
