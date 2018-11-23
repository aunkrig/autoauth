
package de.unkrig.autoauth.test;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import de.unkrig.commons.io.InputStreams;

public
class AutoAuthTest {

	/**
	 * This is not a headless test - AUTOAUTH must be correctly configured and running.
	 */
	@Test @Ignore public void
	testHttp() throws Exception {

		URLConnection conn = (
			new URL("http://httpbin.org:80/basic-auth/user/passwd")
			.openConnection(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", 999)))
		);

		String contentEncoding = conn.getContentEncoding();
		Charset charset = Charset.forName(contentEncoding != null ? contentEncoding : "UTF-8");

		String doc = InputStreams.readAll(
			conn.getInputStream(),
			charset,
			true // closeInputStream
		);

		doc = doc.replaceAll("\\s+", " ");

		Assert.assertEquals("{ \"authenticated\": true, \"user\": \"user\" } ", doc);
	}
}
