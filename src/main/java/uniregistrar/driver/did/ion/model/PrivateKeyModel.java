package uniregistrar.driver.did.ion.model;


import com.nimbusds.jose.jwk.JWK;
import uniregistrar.driver.did.ion.util.KeyUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PrivateKeyModel {
	public static final String DEFAULT_PUB_KEY_FORMAT = "publicKeyJwk";
	private final KeyUtils.KeyTag keyTag;
	private final JWK privateKey;
	private final PublicKeyModel publicKeyModel;
	private Map<String, Object> optionals;

	public PrivateKeyModel(KeyUtils.KeyTag keyTag, JWK privateKey, PublicKeyModel publicKeyModel) {
		this.keyTag = keyTag;
		this.privateKey = privateKey;
		this.publicKeyModel = publicKeyModel;
	}

	public void addProperty(String key, Object value) {
		if (optionals == null) {
			optionals = new LinkedHashMap<>();
		}
		optionals.put(key, value);
	}

	public boolean removePropertyWithKey(String key) {
		if (optionals == null) {
			return false;
		}

		return optionals.remove(key) != null;
	}

	public boolean removePropertyWithValue(Object value) {
		if (optionals == null) {
			return false;
		}

		return optionals.values().remove(value);
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyUtils.KeyTag keyTag) {
		JWK jwk = KeyUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.builder()
				.keyFormat(DEFAULT_PUB_KEY_FORMAT)
				.publicKey(jwk.toPublicJWK().toJSONObject())
				.build();

		return new PrivateKeyModel(keyTag, jwk, pkm);
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyUtils.KeyTag keyTag, List<String> purposes) {
		JWK jwk = KeyUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.builder()
				.keyFormat(DEFAULT_PUB_KEY_FORMAT)
				.publicKey(jwk.toPublicJWK().toJSONObject())
				.purposes(purposes)
				.build();

		return new PrivateKeyModel(keyTag, jwk, pkm);
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyUtils.KeyTag keyTag, List<String> purposes, String type) {
		JWK jwk = KeyUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.builder()
				.keyFormat(DEFAULT_PUB_KEY_FORMAT)
				.publicKey(jwk.toPublicJWK().toJSONObject())
				.purposes(purposes)
				.type(type)
				.build();

		return new PrivateKeyModel(keyTag, jwk, pkm);
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyUtils.KeyTag keyTag, String type) {
		JWK jwk = KeyUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.builder()
				.keyFormat(DEFAULT_PUB_KEY_FORMAT)
				.publicKey(jwk.toPublicJWK().toJSONObject())
				.type(type)
				.build();

		return new PrivateKeyModel(keyTag, jwk, pkm);
	}

	public JWK getPublicKey() {
		return privateKey.toPublicJWK();
	}

	public KeyUtils.KeyTag getKeyTag() {
		return keyTag;
	}

	public JWK getPrivateKey() {
		return privateKey;
	}

	public PublicKeyModel getPublicKeyModel() {
		return publicKeyModel;
	}

	public String toJSONString() {
		return privateKey.toJSONString();
	}

	public Map<String, Object> toJSONObject() {
		Map<String, Object> collected = new LinkedHashMap<>();
		if (optionals != null && !optionals.isEmpty()) {
			collected.putAll(optionals);
		}
		collected.put("type", publicKeyModel.getType());
		collected.put("privateKeyJwk", privateKey.toJSONObject());
		collected.put("purpose", publicKeyModel.getPurposes().toArray());

		return collected;
	}


}
