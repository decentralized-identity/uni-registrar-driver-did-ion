package uniregistrar.driver.did.ion.model;

import com.nimbusds.jose.util.JSONObjectUtils;
import uniregistrar.driver.did.ion.util.KeyUtils;

import java.util.*;

public class PublicKeyModel {
	private Map<String, Object> publicKey;
	private List<String> purposes;
	private String id;
	private String type;
	private String keyFormat;

	public PublicKeyModel(String id, String type, String keyFormat, Map<String, Object> publicKey, List<String> purposes) {
		this.id = id;
		this.type = type;
		this.publicKey = publicKey;
		this.purposes = purposes;
		this.keyFormat = keyFormat;
	}

	public PublicKeyModel() {
	}

	public static Builder builder() {
		return new Builder();
	}

	public String getID() { return id; }

	public String getType() { return type; }

	public Map<String, Object> getPublicKey() { return publicKey; }

	public List<String> getPurposes() { return purposes; }

	public String toJSONString() {
		return JSONObjectUtils.toJSONString(toJSONObject());
	}

	public Map<String, Object> toJSONObject() {
		Map<String, Object> o = new LinkedHashMap<>();
		o.put("id", id);
		o.put("type", type);
		if ("publicKeyJwk".equals(keyFormat)) {
			o.put(keyFormat, publicKey);
		}
		else {
			Map.Entry<String, Object> entry = publicKey.entrySet().iterator().next();
			o.put(entry.getKey(), entry.getValue());
		}
		o.put("purposes", purposes.toArray());

		return o;
	}

	public static final class Builder {

		private Map<String, Object> publicKey;
		private List<String> purposes;
		private String id;
		private String type;

		private String keyFormat;

		private Builder() {}

		public Builder publicKey(Map<String, Object> publicKeyJwk) {
			this.publicKey = publicKeyJwk;
			return this;
		}

		public Builder keyFormat(String keyFormat) {
			this.keyFormat = keyFormat;
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

		public PublicKeyModel build() {
			Objects.requireNonNull(publicKey);
			return new PublicKeyModel(id == null ? KeyUtils.DEFAULT_KEY_ID : id,
									  type == null ? KeyUtils.DEFAULT_KEY_TYPE : type,
									  keyFormat,
									  publicKey,
									  purposes == null ? KeyUtils.DEFAULT_KEY_PURPOSES : purposes);
		}
	}
}
