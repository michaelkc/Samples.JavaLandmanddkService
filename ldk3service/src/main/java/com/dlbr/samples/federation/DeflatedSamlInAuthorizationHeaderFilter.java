package com.dlbr.samples.federation;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.validation.ValidationException;
import org.xml.sax.SAXException;

import com.auth10.federation.FederatedHttpServletRequest;
import com.auth10.federation.FederatedPrincipal;
import com.auth10.federation.FederationException;

public class DeflatedSamlInAuthorizationHeaderFilter implements Filter {

	public void init(FilterConfig config) throws ServletException {
	}

	public void doFilter(
			ServletRequest request, 
			ServletResponse response, 
			FilterChain chain) throws IOException, ServletException {

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		//HttpServletResponse httpResponse = (HttpServletResponse) response;
		
		String encodedToken = this.extractEncodedTokenFromAuthorizationHeader(httpRequest);
		if (encodedToken == null)
		{
			System.out.println("No/Unparseable Authorization header, skipping authorization");
			chain.doFilter(request,response);
			return;
		}
		
		DeflatedSamlTokenHeaderEncoder decoder = new DeflatedSamlTokenHeaderEncoder();
		String token = decoder.Decode(encodedToken);
		if (token == null)
		{
			System.out.println("Could not decode token:");
			System.out.println(encodedToken);
			chain.doFilter(request,response);
			return;
		}
		
		TokenValidator tokenValidator = new TokenValidator();
		FederatedPrincipal principal = null;
		try {
			principal = tokenValidator.validate(token);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FederationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ValidationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnmarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (principal == null)
		{
			System.out.println("Could not validate token:");
			System.out.println(token);
			chain.doFilter(request,response);
			return;
		}
			
		chain.doFilter(new FederatedHttpServletRequest(httpRequest, principal), response);
	}

	
	private String extractEncodedTokenFromAuthorizationHeader(
			HttpServletRequest httpRequest) {
		String authorizationHeader = httpRequest.getHeader("Authorization");
		if (authorizationHeader == null)
		{
			System.out.println("No authorization header value");
			return null;
		}
		String[] parts = authorizationHeader.split(Pattern.quote(" "));
		if (parts.length != 2)
		{
			System.out.println("More or less than two tokens in split Authorization header");
			return null;
		}
		String scheme = parts[0];
		String encodedToken = parts[1];
		if (!scheme.trim().toLowerCase().equals("bearer")){
			System.out.println("Authorization header scheme is not Bearer");
			System.out.println(scheme);
			System.out.println("'" + scheme.trim().toLowerCase() + "'");
			System.out.println(scheme.trim().toLowerCase() == "bearer");
			System.out.println("'" + encodedToken + "'");
			return null;
		}
		return encodedToken;
	}

	public void destroy() {
	}
}
