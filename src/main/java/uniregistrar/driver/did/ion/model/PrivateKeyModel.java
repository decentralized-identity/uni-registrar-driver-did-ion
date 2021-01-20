package uniregistrar.driver.did.ion.model;


import com.nimbusds.jose.jwk.JWK;
import uniregistrar.driver.did.ion.util.SidetreeUtils;

import java.util.Map;

public class PrivateKeyModel {
	private final KeyTag keyTag;
	private final JWK privateKey;
	private final PublicKeyModel publicKeyModel;

	public PrivateKeyModel(KeyTag keyTag, JWK privateKey, PublicKeyModel publicKeyModel) {
		this.keyTag = keyTag;
		this.privateKey = privateKey;
		this.publicKeyModel = publicKeyModel;
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyTag keyTag) {
		JWK jwk = SidetreeUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.from()
										   .publicKeyJwk(jwk.toPublicJWK())
										   .get();

		return new PrivateKeyModel(keyTag, jwk, pkm);
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyTag keyTag, String[] purposes) {
		JWK jwk = SidetreeUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.from()
										   .publicKeyJwk(jwk.toPublicJWK())
										   .purposes(purposes)
										   .get();

		return new PrivateKeyModel(keyTag, jwk, pkm);
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyTag keyTag, String[] purposes, String type) {
		JWK jwk = SidetreeUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.from()
										   .publicKeyJwk(jwk.toPublicJWK())
										   .purposes(purposes)
										   .type(type)
										   .get();

		return new PrivateKeyModel(keyTag, jwk, pkm);
	}

	public static PrivateKeyModel generateNewPrivateKey(KeyTag keyTag, String type) {
		JWK jwk = SidetreeUtils.generateEs256kKeyPairInJwk();
		PublicKeyModel pkm = PublicKeyModel.from()
										   .publicKeyJwk(jwk.toPublicJWK())
										   .type(type)
										   .get();

		return new PrivateKeyModel(keyTag, jwk, pkm);
	}

	public JWK getPublicKey() {
		return privateKey.toPublicJWK();
	}

	public KeyTag getKeyTag() {
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


	public enum KeyTag {
		UPDATE, RECOVERY, SIGNING
	}
}
