package uniregistrar.driver.did.ion.util;

import com.danubetech.keyformats.PrivateKey_to_JWK;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.nimbusds.jose.jwk.JWK;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import org.bitcoinj.core.ECKey;
import uniregistrar.driver.did.ion.model.PublicKeyModel;

import java.text.ParseException;
import java.util.*;

public class KeyUtils {

	public static final List<String> KEY_PURPOSES = Arrays.asList("authentication", "assertionMethod", "capabilityInvocation",
																  "capabilityDelegation", "keyAgreement");
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

		for (VerificationMethod vm : didDocument.getVerificationMethods()) {
			JWK jwk = null;
			if (vm.getPublicKeyJwk() != null) {
				try {
					jwk = JWK.parse(vm.getPublicKeyJwk());
				} catch (ParseException ignored) {
				}
			}

			// TODO: Check other key formats

			if (jwk != null) {
				PublicKeyModel pkm = PublicKeyModel.builder()
												   .id(vm.getId().toString())
												   .type(vm.getType())
												   .publicKeyJwk(jwk)
												   .purposes(parsePurposes(vm.getId().toString(), didDocument))
												   .build();

				keys.add(pkm);
			}
		}

		return keys;
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
										   .publicKeyJwk(pkj)
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
