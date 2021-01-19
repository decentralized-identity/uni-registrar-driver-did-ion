package uniregistrar.driver.did.ion;


import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uniregistrar.RegistrationException;
import uniregistrar.driver.AbstractDriver;
import uniregistrar.request.DeactivateRequest;
import uniregistrar.request.RegisterRequest;
import uniregistrar.request.UpdateRequest;
import uniregistrar.state.DeactivateState;
import uniregistrar.state.RegisterState;
import uniregistrar.state.UpdateState;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class DidIonDriver extends AbstractDriver {
	private static final Logger log = LogManager.getLogger(DidIonDriver.class);
	private static final String DEFAULT_API_URL = "http://localhost:3000/operations";
	private static final ObjectMapper mapper;

	static {
		mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);
	}

	private URL apiUrl;
	private Map<String, Object> properties;

	public DidIonDriver() {
		this(getPropertiesFromEnvironment());
	}

	public DidIonDriver(Map<String, Object> properties) {
		setProperties(properties);
		if (apiUrl == null) {
			log.info("API URL is not defined, trying with: {}", DEFAULT_API_URL);
			try {
				apiUrl = new URL(DEFAULT_API_URL);
			} catch (MalformedURLException e) {
				throw new IllegalArgumentException("Default API URL: " + DEFAULT_API_URL);
			}
		}
	}

	private static Map<String, Object> getPropertiesFromEnvironment() {

		log.debug("Loading from environment: {}", System::getenv);

		Map<String, Object> properties = new HashMap<>();

		try {

			String env_sidetreeApi = System.getenv("uniregistrar_driver_did_sidetreeApi");

			if (!Strings.isNullOrEmpty(env_sidetreeApi)) properties.put("sidetreeApi", env_sidetreeApi);
		} catch (Exception ex) {

			throw new IllegalArgumentException(ex.getMessage(), ex);
		}

		return properties;

	}

	@Override
	public RegisterState register(RegisterRequest request) throws RegistrationException {
		log.info("Received new registration request");
		log.debug("Request:\n{}", request::toString);

		HttpURLConnection con;

		try {
			con = (HttpURLConnection) apiUrl.openConnection();
		} catch (IOException e) {
			log.error(e.getMessage(), e);
			throw new RegistrationException("Sidetree API is not reachable..");
		}

		try {
			con.setRequestMethod("POST");
		} catch (ProtocolException e) {
			log.error(e.getMessage(), e);
			throw new IllegalArgumentException(e);
		}

		con.setRequestProperty("Content-Type", "application/json; utf-8");
		con.setRequestProperty("Accept", "application/json");
		con.setDoOutput(true);

		// TODO ...

		throw new RuntimeException("Not implemented.");
	}

	@Override
	public UpdateState update(UpdateRequest request) throws RegistrationException {
		throw new RuntimeException("Not implemented.");
	}

	@Override
	public DeactivateState deactivate(DeactivateRequest request) throws RegistrationException {
		throw new RuntimeException("Not implemented.");
	}

	@Override
	public Map<String, Object> properties() throws RegistrationException {
		throw new RuntimeException("Not implemented.");
	}

	public final void setProperties(Map<String, Object> properties) {
		this.properties = properties;
		configureFromProperties();
	}


	public Map<String, Object> getProperties() {
		return properties;
	}

	private void configureFromProperties() {

		log.debug("Configuring from properties: {}", this::getProperties);
		try {

			String prop_sidetreeApi = (String) properties.get("sidetreeApi");

			if (!Strings.isNullOrEmpty(prop_sidetreeApi)) this.apiUrl = new URL(prop_sidetreeApi);
		} catch (Exception ex) {

			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}
}
