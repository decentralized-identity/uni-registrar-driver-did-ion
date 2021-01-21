package uniregistrar.driver.did.ion.model;


import com.nimbusds.jose.jwk.JWK;
import uniregistrar.driver.did.ion.util.KeyUtils;

import java.util.List;
import java.util.Map;

public class PrivateKeyModel {
	private final KeyUtils.KeyTag keyTag;
	private final JWK privateKey;
	private final PublicKeyModel publicKeyModel;

	public PrivateKeyModel(KeyUtils.KeyTag keyTag, JWK privateKey, PublicKeyModel publicKeyModel) {
		this.keyTag = keyTag;
		this.privateKey = privateKey;
		this.publicKeyModel = publicKeyModel;
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyUtils.KeyTag keyTag) {
		JWK jwk = KeyUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.builder()
										   .publicKeyJwk(jwk.toPublicJWK())
										   .build();

		return new PrivateKeyModel(keyTag, jwk, pkm);
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyUtils.KeyTag keyTag, List<String> purposes) {
		JWK jwk = KeyUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.builder()
										   .publicKeyJwk(jwk.toPublicJWK())
										   .purposes(purposes)
										   .build();

		return new PrivateKeyModel(keyTag, jwk, pkm);
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyUtils.KeyTag keyTag, List<String> purposes, String type) {
		JWK jwk = KeyUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.builder()
										   .publicKeyJwk(jwk.toPublicJWK())
										   .purposes(purposes)
										   .type(type)
										   .build();

		return new PrivateKeyModel(keyTag, jwk, pkm);
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyUtils.KeyTag keyTag, String type) {
		JWK jwk = KeyUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.builder()
										   .publicKeyJwk(jwk.toPublicJWK())
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
		return privateKey.toJSONObject();
	}


}
