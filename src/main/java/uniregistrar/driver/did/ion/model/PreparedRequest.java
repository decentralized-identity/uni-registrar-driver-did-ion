package uniregistrar.driver.did.ion.model;

import java.util.List;

public class PreparedRequest {
	private final CreateRequest createRequest;
	private final List<PrivateKeyModel> privateKeys;

	public PreparedRequest(CreateRequest createRequest, List<PrivateKeyModel> privateKeys) {
		this.createRequest = createRequest;
		this.privateKeys = privateKeys;
	}

	public CreateRequest getCreateRequest() {
		return createRequest;
	}

	public List<PrivateKeyModel> getPrivateKeys() {
		return privateKeys;
	}
}
