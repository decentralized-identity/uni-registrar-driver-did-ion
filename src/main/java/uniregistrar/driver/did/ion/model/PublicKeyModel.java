package uniregistrar.driver.did.ion.model;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.JSONObjectUtils;

import java.util.*;

public class PublicKeyModel {
	private JWK publicKeyJwk;
	private List<String> purposes;
	private String id;
	private String type;

	public PublicKeyModel(String id, String type, JWK publicKeyJwk, List<String> purposes) {
		this.id = id;
		this.type = type;
		this.publicKeyJwk = publicKeyJwk;
		this.purposes = purposes;
	}

	public PublicKeyModel() {

	}

	public static Builder from() {
		return new Builder();
	}

	public String getID() { return id; }

	public String getType() { return type; }

	public JWK getPublicKeyJwk() { return publicKeyJwk; }

	public List<String> getPurposes() { return purposes; }

	public String toJSONString() {
		return JSONObjectUtils.toJSONString(toJSONObject());
	}

	public Map<String, Object> toJSONObject() {
		Map<String, Object> o = new LinkedHashMap<>();
		o.put("id", id);
		o.put("type", type);
		o.put("publicKeyJwk", publicKeyJwk.toJSONObject());
		o.put("purposes", purposes);

		return o;
	}

	public static final class Builder {
		public static final String DEFAULT_KEY_ID = "signingKey";
		public static final String DEFAULT_KEY_TYPE = "EcdsaSecp256k1VerificationKey2019";
		public static final List<String> DEFAULT_PURPOSES = Arrays.asList("authentication", "assertionMethod", "capabilityInvocation",
																		  "capabilityDelegation", "keyAgreement");

		private JWK publicKeyJwk;
		private List<String> purposes;
		private String id;
		private String type;

		private Builder() {}

		public Builder publicKeyJwk(JWK publicKeyJwk) {
			this.publicKeyJwk = publicKeyJwk;
			return this;
		}

		public Builder purposes(List<String> purposes) {
			this.purposes = purposes;
			return this;
		}

		public Builder id(String id) {
			this.id = id;
			return this;
		}

		public Builder type(String type) {
			this.type = type;
			return this;
		}

		public PublicKeyModel get() {
			Objects.requireNonNull(publicKeyJwk);
			return new PublicKeyModel(id == null ? DEFAULT_KEY_ID : id,
									  type == null ? DEFAULT_KEY_TYPE : type,
									  publicKeyJwk,
									  purposes == null ? DEFAULT_PURPOSES : purposes);
		}
	}
}
