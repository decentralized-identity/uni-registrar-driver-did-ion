package uniregistrar.driver.did.ion.util;

import com.danubetech.keyformats.PrivateKey_to_JWK;
import com.danubetech.keyformats.PublicKey_to_JWK;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.nimbusds.jose.jwk.JWK;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import uniregistrar.driver.did.ion.model.PublicKeyModel;

import java.text.ParseException;
import java.util.*;

import static org.bitcoinj.core.Utils.HEX;

public class KeyUtils {

	public static final List<String> KEY_PURPOSES = Arrays.asList("authentication", "assertionMethod", "capabilityInvocation",
																  "capabilityDelegation", "keyAgreement");
	public static final String EcdsaSecp256k1_TERM = "EcdsaSecp256k1VerificationKey2019";
	public static final String Ed25519_TERM = "Ed25519VerificationKey2018";

	public static final String[] SUPPORTED_KEY_TYPES = {"RsaSignature2018", "Ed25519VerificationKey2018", "EcdsaSecp256k1VerificationKey2019"};
	private static final ObjectMapper mapper = new ObjectMapper();

	public static JWK generateEs256kKeyPairInJwk() {
		ECKey key = new ECKey();
		return PrivateKey_to_JWK.secp256k1PrivateKey_to_JWK(key, null, null);
	}


	public static List<PublicKeyModel> extractPublicKeyModels(DIDDocument didDocument) throws ParsingException {
		Preconditions.checkNotNull(didDocument);

		if (didDocument.getVerificationMethods() == null) {
			return null;
		}


		List<PublicKeyModel> keys = new LinkedList<>();
		PublicKeyModel pkm;

		for (VerificationMethod vm : didDocument.getVerificationMethods()) {
			Map<String, Object> pk = convertToJWK(vm);

			if (pk != null) {
				pkm = PublicKeyModel.builder()
									.id(vm.getId().toString())
									.keyFormat("publicKeyJwk")
									.type(vm.getType())
									.publicKey(pk)
									.purposes(parsePurposes(vm.getId().toString(), didDocument))
									.build();
				keys.add(pkm);
			}
		}

		return keys;
	}

	public static Map<String, Object> convertToJWK(VerificationMethod vm) throws ParsingException {
		var keyType = vm.getType();
		if (!EcdsaSecp256k1_TERM.equals(keyType) && !Ed25519_TERM.equals(keyType)) {
			throw new ParsingException("Unsupported key type: " + keyType);
		}

		if (vm.getPublicKeyJwk() != null) {
			return vm.getPublicKeyJwk();
		}
		else if (vm.getPublicKeyBase58() != null) {
			if (EcdsaSecp256k1_TERM.equals(vm.getType())) {
				return PublicKey_to_JWK.secp256k1PublicKeyBytes_to_JWK(Base58.decode(vm.getPublicKeyBase58()), null, null)
									   .toPublicJWK()
									   .toJSONObject();
			}
			else {
				return PublicKey_to_JWK.Ed25519PublicKeyBytes_to_JWK(Base58.decode(vm.getPublicKeyBase58()), null, null)
									   .toPublicJWK()
									   .toJSONObject();
			}
		}
		else if (vm.getPublicKeyBase64() != null) {
			if (EcdsaSecp256k1_TERM.equals(vm.getType())) {
				return PublicKey_to_JWK.secp256k1PublicKeyBytes_to_JWK(Base64.getDecoder().decode(vm.getPublicKeyBase64()), null, null)
									   .toPublicJWK()
									   .toJSONObject();
			}
			else {
				return PublicKey_to_JWK.Ed25519PublicKeyBytes_to_JWK(Base64.getDecoder().decode(vm.getPublicKeyBase64()), null, null)
									   .toPublicJWK()
									   .toJSONObject();
			}
		}

		else if (vm.getPublicKeyHex() != null) {
			if (EcdsaSecp256k1_TERM.equals(vm.getType())) {
				return PublicKey_to_JWK.secp256k1PublicKeyBytes_to_JWK(HEX.decode(vm.getPublicKeyHex()), null, null)
									   .toPublicJWK()
									   .toJSONObject();
			}
			else {
				return PublicKey_to_JWK.Ed25519PublicKeyBytes_to_JWK(HEX.decode(vm.getPublicKeyHex()), null, null)
									   .toPublicJWK()
									   .toJSONObject();
			}
		}
		else if (vm.getPublicKeyPem() != null) {

			String key = vm.getPublicKeyPem();
			key = key.replace("-----BEGIN PUBLIC KEY-----\n", "");
			key = key.replace("-----END PUBLIC KEY-----", "");

			if (EcdsaSecp256k1_TERM.equals(vm.getType())) {
				return PublicKey_to_JWK.secp256k1PublicKeyBytes_to_JWK(Base64.getDecoder().decode(key), null, null)
									   .toPublicJWK()
									   .toJSONObject();
			}
			else {
				return PublicKey_to_JWK.Ed25519PublicKeyBytes_to_JWK(Base64.getDecoder().decode(key), null, null)
									   .toPublicJWK()
									   .toJSONObject();
			}
		}
		else
			return null;
	}

	public static List<String> parsePurposes(String keyId, DIDDocument document) throws ParsingException {
		Preconditions.checkNotNull(document);

		JsonNode jsonNode = mapper.convertValue(document.getJsonObject(), JsonNode.class);
		List<String> purposes = new ArrayList<>();

		for (String p : KEY_PURPOSES) {
			JsonNode n = jsonNode.get(p);

			if (n == null) continue;

			Iterator<JsonNode> nodeIterator = n.elements();
			while (nodeIterator.hasNext()) {
				JsonNode keyNode = nodeIterator.next();

				if (keyNode.size() > 1) {
					JsonNode vm = keyNode.get("verificationMethod");
					if (vm != null && keyId.equals(vm.asText().substring(1))) {
						purposes.add(p);
					}
				}
				else {
					String vm = keyNode.asText();
					String kid;
					if (vm.startsWith("#")) {
						kid = vm.substring(1);
					}
					else {
						String[] parseKeyId = vm.split("#");
						if (parseKeyId.length != 2) {
							throw new ParsingException();
						}
						kid = parseKeyId[1];
					}
					if (keyId.equals(kid)) {
						purposes.add(p);
					}
				}
			}

		}

		return purposes;

	}

	public static Map<String, Object> convertFromPubKeyBytesToJwk(String keyType, byte[] key) {
		switch (keyType) {
			case EcdsaSecp256k1_TERM:
				return PublicKey_to_JWK.secp256k1PublicKeyBytes_to_JWK(key, null, null).toPublicJWK().toJSONObject();
			case Ed25519_TERM:
				return PublicKey_to_JWK.Ed25519PublicKeyBytes_to_JWK(key, null, null).toPublicJWK().toJSONObject();
			default:
				throw new IllegalArgumentException("Key Type (" + keyType + ") is not supported!");
		}
	}

	public static Optional<PublicKeyModel> extractPublicKeyModel(KeyTag keyTag, Map<String, Object> secret) {
		if (secret == null || !secret.containsKey("publicKeys") || secret.get("publicKeys") == null) {
			return Optional.empty();
		}

		JsonNode publicKeys = mapper.convertValue(secret.get("publicKeys"), JsonNode.class);
		JsonNode found = null;

		String keyId = null;
		for (JsonNode cur : publicKeys) {
			keyId = cur.get("id").asText();
			if (!Strings.isNullOrEmpty(keyId) && KeyTag.fromId(keyId) == keyTag) {
				found = cur;
				break;
			}
		}
		if (found == null) {
			return Optional.empty();
		}

		JsonNode pubKeyJwk = found.get("publicKeyJwk");
		if (pubKeyJwk == null) {
			return Optional.empty();
		}

		JWK pkj;
		try {
			pkj = JWK.parse(pubKeyJwk.toString());
		} catch (ParseException e) {
			return Optional.empty();
		}

		PublicKeyModel pkm = PublicKeyModel.builder()
										   .keyFormat("publicKeyJwk")
										   .publicKey(pkj.toJSONObject())
										   .id(keyId)
										   .type(found.get("type") == null ? null : found.get("type").asText())
										   .purposes(found.get("purposes") == null ? null :
													 mapper.convertValue(found.get("purposes"), new TypeReference<List<String>>() {}))
										   .build();
		return Optional.of(pkm);
	}

	public enum KeyTag {
		UPDATE("updateKey"), RECOVERY("recoveryKey"), SIGNING("signingKey"), UNKNOWN("unknownKey");

		public final String value;

		KeyTag(String value) {
			this.value = value;
		}

		public static KeyTag fromId(String keyId) {
			String id = keyId.toUpperCase();
			if (id.startsWith("SIGNING")) {
				return SIGNING;
			}
			else if (id.startsWith("UPDATE")) {
				return UPDATE;
			}
			else if (id.startsWith("RECOVERY")) {
				return RECOVERY;
			}
			else return UNKNOWN;
		}

		public static KeyTag fromString(String keyTagString) {
			switch (keyTagString.toUpperCase()) {
				case "UPDATE":
					return UPDATE;
				case "RECOVERY":
					return RECOVERY;
				case "SIGNING":
					return SIGNING;
				default:
					return UNKNOWN;
			}
		}
	}
}
