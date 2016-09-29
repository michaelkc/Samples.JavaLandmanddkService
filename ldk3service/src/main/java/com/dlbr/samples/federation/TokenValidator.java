package com.dlbr.samples.federation;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.validation.ValidationException;
import org.xml.sax.SAXException;

import com.auth10.federation.Claim;
import com.auth10.federation.FederatedConfiguration;
import com.auth10.federation.FederatedPrincipal;
import com.auth10.federation.FederationException;
import com.auth10.federation.SamlTokenValidator;

public class TokenValidator {

	public final FederatedPrincipal validate(String token) throws 	FederationException, 
																		ConfigurationException, 
																		CertificateException, 
																		KeyException, 
																		NoSuchAlgorithmException, 
																		ParserConfigurationException, 
																		SAXException, 
																		IOException, 
																		SecurityException, 
																		ValidationException, 
																		UnmarshallingException, 
																		URISyntaxException {
		List<Claim> claims = null;

		SamlTokenValidator validator = new SamlTokenValidator();

		this.setTrustedIssuers(validator);
		
		this.setAudienceUris(validator);

		this.setThumbprint(validator);
		
		String fakeRstrWrappedToken = FakeRstrWrap(token);

		claims = validator.validate(fakeRstrWrappedToken);

		FederatedPrincipal principal = new FederatedPrincipal(claims, token);
		
		return principal;			

	}
		
	private String FakeRstrWrap(String token) {
		String wrappedToken = 
		"<RequestSecurityTokenResponse>" + token + "</RequestSecurityTokenResponse>";
		return wrappedToken;
	}

	protected void setTrustedIssuers(SamlTokenValidator validator) 
			throws FederationException {
		String[] trustedIssuers = FederatedConfiguration.getInstance().getTrustedIssuers();
		if (trustedIssuers != null) {
			validator.getTrustedIssuers().addAll(Arrays.asList(trustedIssuers));
		}		
	}
	
	protected void setAudienceUris(SamlTokenValidator validator) 
			throws FederationException {
		String[] audienceUris = FederatedConfiguration.getInstance().getAudienceUris();
		for (String audienceUriStr : audienceUris) {
			try {
				validator.getAudienceUris().add(new URI(audienceUriStr));
			} catch (URISyntaxException e) {
				throw new FederationException("Federated Login Configuration failure: Invalid Audience URI", e);
			}
		}
	}
	
	protected void setThumbprint(SamlTokenValidator validator)
			throws FederationException {
		String thumbprint = FederatedConfiguration.getInstance().getThumbprint();
		validator.setThumbprint(thumbprint);
	}
}
