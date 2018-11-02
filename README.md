# AUTOAUTH

### Life made easier when you're sitting behind an HTTP proxy!

If you are behind an HTTP proxy that requires "proxy authentication", then you are prompted for credentials when you attempt to connect to a server behind the proxy (typically the entire internet). While this is not a problem when you access the web through the web browser, it is problematic for your *tools* that need to access the internet via HTTP, e.g. GIT, MAVEN or SUBVERSION.

These tools require that you configure them for the HTTP proxy, e.g. for MAVEN you'd have to put the following in your `settings.xml` file:

```xml
  <proxies>
    <proxy>
      <id>http-proxy</id>
      <active>true</active>
      <protocol>http</protocol>
      <host>proxy.acme.com</host>
      <port>8080</port>
      <username>john.doe</username>
      <password>Geheim</password>
      <nonProxyHosts>*.intra.acme.com</nonProxyHosts>
    </proxy>
    <!-- Same for protocol "https". -->
  </proxies>
```

You have to put your credentials for the proxy authentication (which are often identical with your "company credentials") in clear text into the configuration; a security nightmare. Also, when the credentials change (most enterprises enforce regular password changes), you have to update *all* configurations of the tools you use. Forgetting one typically means that your account is quickly locked after a few attempts to authenticate with the outdated password.

Also, some tools get confused if they must "double-authenticate" (to the HTTP proxy *and* the remote server), namely when the credentials are different.

Now the concept of AUTOAUTH is to run an *additional* HTTP proxy that forwards all requests to the existing proxy, and silently authenticate to it (with HTTP "basic authentication"). Effectively, clients see an HTTP proxy that does *not* require proxy authentication.

First, download the latest version of the "jar-with-dependencies.jar", or the MS WINDOWS executable (.exe) from [here](https://oss.sonatype.org/content/repositories/releases/de/unkrig/autoauth/autoauth-core/).

Then you'd start AUTOAUTH like this:

```
C:\path\to\autoauth-core-0.1.exe --endpoint-port 999 --target-address proxy.acme.de --target-port 8080
```

AUTOAUTH will ask you immediately for your credentials and use them for proxy authentication until it terminates. It also offers you to store the credentials in a password-protected store in a file named `%USERPROFILE%\.customAuthenticator_credentials`.

Then you'd change your MAVEN configuration like this:

```xml
  <proxies>
    <proxy>
      <id>http-proxy</id>
      <active>true</active>
      <protocol>http</protocol>
      <host>localhost</host>
      <port>999</port>
      <nonProxyHosts>*.intra.acme.com</nonProxyHosts>
    </proxy>
    <!-- Same for protocol "https". -->
  </proxies>
```

Now you no longer have the credentials in your tools' configuration, and when the credentials change, you merely have to stop and restart AUTOAUTH.
