package uniregistrar.driver.did.ion.model;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.JSONObjectUtils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public class PublicKeyModel {

	private final JWK publicKeyJwk;
	private final String[] purposes;
	private final String id;
	private final String type;

	public PublicKeyModel(String id, String type, JWK publicKeyJwk, String[] purposes) {
		this.id = id;
		this.type = type;
		this.publicKeyJwk = publicKeyJwk;
		this.purposes = purposes.clone();
	}

	public String getID() { return id; }

	public String getType() { return type; }

	public JWK getPublicKeyJwk() { return publicKeyJwk; }

	public String[] getPurposes() { return purposes.clone(); }

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
		public static final String[] DEFAULT_PURPOSES = {"authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation", "keyAgreement"};

		private JWK publicKeyJwk;
		private String[] purposes;
		private String id;
		private String type;

		private Builder() {}

		public static Builder get() { return new Builder(); }

		public Builder withPublicKeyJwk(JWK publicKeyJwk) {
			this.publicKeyJwk = publicKeyJwk;
			return this;
		}

		public Builder withPurposes(String[] purposes) {
			this.purposes = purposes;
			return this;
		}

		public Builder withId(String id) {
			this.id = id;
			return this;
		}

		public Builder withType(String type) {
			this.type = type;
			return this;
		}

		public PublicKeyModel build() {
			Objects.requireNonNull(publicKeyJwk);
			return new PublicKeyModel(id == null ? DEFAULT_KEY_ID : id,
									  type == null ? DEFAULT_KEY_TYPE : type,
									  publicKeyJwk,
									  purposes == null ? DEFAULT_PURPOSES : purposes);
		}
	}
}
