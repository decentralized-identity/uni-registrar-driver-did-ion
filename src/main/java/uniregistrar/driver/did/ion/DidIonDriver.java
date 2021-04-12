package uniregistrar.driver.did.ion;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uniregistrar.RegistrationException;
import uniregistrar.driver.AbstractDriver;
import uniregistrar.driver.did.ion.model.*;
import uniregistrar.driver.did.ion.util.KeyUtils;
import uniregistrar.driver.did.ion.util.ParsingException;
import uniregistrar.driver.did.ion.util.SidetreeUtils;
import uniregistrar.request.CreateRequest;
import uniregistrar.request.DeactivateRequest;
import uniregistrar.request.UpdateRequest;
import uniregistrar.state.CreateState;
import uniregistrar.state.DeactivateState;
import uniregistrar.state.SetCreateStateFinished;
import uniregistrar.state.UpdateState;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class DidIonDriver extends AbstractDriver {
	public static final int CONN_TIMEOUT = 5000; // ms
	public static final int READ_TIMEOUT = 5000; // ms
	private static final Logger log = LogManager.getLogger(DidIonDriver.class);
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
		if (apiUrl == null) throw new IllegalArgumentException("Sidetree operations API URL is not configured!");
	}

	private static Map<String, Object> getPropertiesFromEnvironment() {

		log.debug("Loading from environment: {}", System::getenv);

		Map<String, Object> properties = new HashMap<>();

		try {

			String env_ion_api = System.getenv("uniregistrar_driver_did_ion_api");

			if (!Strings.isNullOrEmpty(env_ion_api)) properties.put("ion_api", env_ion_api);
		} catch (Exception ex) {

			throw new IllegalArgumentException(ex.getMessage(), ex);
		}

		return properties;

	}

	public final void setProperties(Map<String, Object> properties) {
		Preconditions.checkState(this.properties == null, "Properties are already set!");
		this.properties = Map.copyOf(properties);
		configureFromProperties();
	}

	private void configureFromProperties() {

		log.debug("Configuring from properties: {}", properties::toString);
		try {

			String prop_ion_api = (String) properties.get("ion_api");

			if (!Strings.isNullOrEmpty(prop_ion_api)) this.apiUrl = new URL(prop_ion_api);
		} catch (MalformedURLException ex) {
			throw new IllegalArgumentException(ex.getMessage());
		}
	}

	@Override
	public CreateState create(CreateRequest request) throws RegistrationException {

		if (request == null) throw new RegistrationException("Request is null!");

		// Create required keys.

		Optional<PublicKeyModel> spk = KeyUtils.extractPublicKeyModel(KeyUtils.KeyTag.SIGNING, request.getSecret());
		Optional<PublicKeyModel> upk = KeyUtils.extractPublicKeyModel(KeyUtils.KeyTag.UPDATE, request.getSecret());
		Optional<PublicKeyModel> rpk = KeyUtils.extractPublicKeyModel(KeyUtils.KeyTag.RECOVERY, request.getSecret());

		PublicKeyModel signingKeyPublic;
		PublicKeyModel updateKeyPublic;
		PublicKeyModel recoveryKeyPublic;

		PrivateKeyModel signingKey = null;
		PrivateKeyModel updateKey = null;
		PrivateKeyModel recoveryKey = null;

		if (spk.isPresent()) {
			signingKeyPublic = spk.get();
		}
		else {
			signingKey = PrivateKeyModel.generateNewPrivateKey(KeyUtils.KeyTag.SIGNING);
			signingKeyPublic = signingKey.getPublicKeyModel();
		}

		if (upk.isPresent()) {
			updateKeyPublic = upk.get();
		}
		else {
			updateKey = PrivateKeyModel.generateNewPrivateKey(KeyUtils.KeyTag.UPDATE);
			updateKeyPublic = updateKey.getPublicKeyModel();
		}

		if (rpk.isPresent()) {
			recoveryKeyPublic = rpk.get();
		}
		else {
			recoveryKey = PrivateKeyModel.generateNewPrivateKey(KeyUtils.KeyTag.RECOVERY);
			recoveryKeyPublic = recoveryKey.getPublicKeyModel();
		}

		// Obtain commitments from keys

		String updateCommitment;
		String recoveryCommitment;

		try {
			updateCommitment = SidetreeUtils.canonicalizeThenDoubleHashThenEncode(updateKeyPublic.getPublicKey());
			recoveryCommitment = SidetreeUtils.canonicalizeThenDoubleHashThenEncode(recoveryKeyPublic.getPublicKey());
		} catch (IOException e) {
			log.error(e.getMessage(), e);
			throw new RegistrationException("Key error!");
		}

		List<PublicKeyModel> publicKeyModels = new LinkedList<>();
		publicKeyModels.add(signingKeyPublic);

		List<PublicKeyModel> fromDidDoc = null;
		if (request.getDidDocument() != null) {
			try {
				fromDidDoc = KeyUtils.extractPublicKeyModels(request.getDidDocument());
			} catch (ParsingException | InvalidKeySpecException | NoSuchAlgorithmException e) {
				throw new RegistrationException(e.getMessage());
			}
		}

		if (fromDidDoc != null) {
			publicKeyModels.addAll(fromDidDoc);
		}


		Document document = new Document(publicKeyModels, request.getDidDocument() == null ? null :
														  request.getDidDocument().getServices());
		Patch patch = new Patch("replace", document);
		Delta delta = new Delta(updateCommitment, Collections.singletonList(patch));
		String deltaHash;
		try {
			deltaHash = SidetreeUtils.canonicalizeThenHashThenEncode(delta.toJSONString());
		} catch (IOException e) {
			log.error(e.getMessage(), e);
			throw new RegistrationException("Canonicalization error!");
		}
		SuffixData suffixData = new SuffixData(deltaHash, recoveryCommitment);
		SidetreeCreateRequest sidetreeCreateRequest = new SidetreeCreateRequest("create", suffixData, delta);

		log.debug("New ION did creation request prepared: {}", sidetreeCreateRequest::toJSONString);

		// Send creation request to the sidetree node

		HttpURLConnection con;

		try {
			con = (HttpURLConnection) apiUrl.openConnection();
		} catch (IOException e) {
			log.error(e);
			throw new RegistrationException("Sidetree Node is not reachable!");
		}

		try {
			con.setRequestMethod("POST");
		} catch (ProtocolException e) {
			log.error(e.getMessage(), e);
			throw new IllegalArgumentException(e);
		}

		con.setConnectTimeout(CONN_TIMEOUT);
		con.setReadTimeout(READ_TIMEOUT);
		con.setRequestProperty("Content-Type", "application/json; utf-8");
		con.setRequestProperty("Accept", "application/json");
		con.setDoOutput(true);

		try (OutputStream os = con.getOutputStream()) {
			byte[] input = sidetreeCreateRequest.toJSONString().getBytes(StandardCharsets.UTF_8);
			os.write(input, 0, input.length);
		} catch (IOException e) {
			log.error(e.getMessage());
			throw new RegistrationException("Sidetree node error!");
		}


		int status;
		try {
			status = con.getResponseCode();
		} catch (IOException e) {
			log.error(e.getMessage(), e);
			throw new RegistrationException("Sidetree node error!");
		}

		String response;
		if (status != HttpStatus.SC_OK) {
			// Get error message
			try {
				response = readResponse(con.getErrorStream());
			} catch (IOException e) {
				log.error(e);
				throw new RegistrationException("Internal error: " + e.getMessage());
			}
			throw new RegistrationException("Sidetree Node Error: " + response);
		}
		else {
			// Read the response
			try {
				response = readResponse(con.getInputStream());
			} catch (IOException e) {
				throw new RegistrationException("Internal error: " + e.getMessage());
			}
		}


		con.disconnect();

		ObjectNode jsonNode;
		try {
			jsonNode = (ObjectNode) mapper.readTree(response);
		} catch (JsonProcessingException e) {
			log.error(e.getMessage(), e);
			throw new RegistrationException("Response is not parseable");
		}

		// Extract Method Metadata

		CreateState state = CreateState.build();
		Map<String, Object> didDocumentMetadata = mapper.convertValue(jsonNode.get("didDocumentMetadata"),
																	  new TypeReference<Map<String, Object>>() {});
		jsonNode.remove("didDocumentMetadata"); // Remove to prevent duplication
		jsonNode.remove("@context");

		// Generate Long-Form DID
		String did = jsonNode.get("didDocument").get("id").asText();
		String longFormDid = "";
		try {
			longFormDid = SidetreeUtils.generateLongFormDID(did, sidetreeCreateRequest.toJSONString());
		} catch (IOException e) {
			log.error("Cannot generate long-form did", e);
		}

		didDocumentMetadata.put("longFormDid", longFormDid);
		state.setMethodMetadata(didDocumentMetadata);

		// Put secrets

		Map<String, Object> secrets = new LinkedHashMap<>();
		if (signingKey != null) secrets.put("signingKey", signingKey.toJSONObject());
		if (updateKey != null) secrets.put("updateKey", updateKey.toJSONObject());
		if (recoveryKey != null) secrets.put("recoveryKey", recoveryKey.toJSONObject());

		state.setDidState(mapper.convertValue(jsonNode, new TypeReference<Map<String, Object>>() {}));
		SetCreateStateFinished.setStateFinished(state, jsonNode.get("didDocument").get("id").asText(), secrets);

		return state;
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
		return Collections.unmodifiableMap(properties);
	}

	private static String readResponse(InputStream is) throws IOException {

		StringBuilder response;
		try (BufferedReader br = new BufferedReader(
				new InputStreamReader(is, StandardCharsets.UTF_8))) {
			response = new StringBuilder();
			String responseLine;
			while ((responseLine = br.readLine()) != null) {
				response.append(responseLine.trim());
			}
		} catch (IOException e) {
			log.error(e.getMessage(), e);
			throw new IOException(e);
		}

		return response.toString();
	}
}
