package uniregistrar.driver.did.ion.util;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.ipfs.multibase.Multibase;
import io.ipfs.multihash.Multihash;
import org.bitcoinj.core.Sha256Hash;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

public class SidetreeUtils {

	private SidetreeUtils() {}

	public static String fromBase64UrlToBase58Btc(String data) {
		final byte[] decoded = Base64.getUrlDecoder().decode(data);
		return Multibase.encode(Multibase.Base.Base58BTC, decoded).substring(1); // Return with removing the prefix char
	}

	public static Multihash multihashFromBase64Url(String base64Url) {
		return multihashFromBase58(fromBase58BtcToBase64Url(base64Url));
	}

	public static Multihash multihashFromBase58(String base58Str) {
		return Multihash.fromBase58(base58Str);
	}

	public static String fromBase58BtcToBase64Url(String data) {
		final byte[] decoded = Multibase.decode(data);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
	}

	public static String canonicalizeThenDoubleHashThenEncode(String value) throws IOException {
		JsonCanonicalizer jc = new JsonCanonicalizer(value);
		byte[] hashed = Sha256Hash.hashTwice(jc.getEncodedString().getBytes(StandardCharsets.US_ASCII));
		Multihash multihash = new Multihash(Multihash.Type.sha2_256, hashed);

		return Base64.getUrlEncoder().withoutPadding().encodeToString(multihash.toBytes());
	}

	public static String canonicalizeThenDoubleHashThenEncode(Map<String, Object> value) throws IOException {

		JsonCanonicalizer jc = new JsonCanonicalizer(JSONObjectUtils.toJSONString(value));
		byte[] hashed = Sha256Hash.hashTwice(jc.getEncodedString().getBytes(StandardCharsets.US_ASCII));
		Multihash multihash = new Multihash(Multihash.Type.sha2_256, hashed);

		return Base64.getUrlEncoder().withoutPadding().encodeToString(multihash.toBytes());
	}

	public static String canonicalizeThenHashThenEncode(String value) throws IOException {

		// Used for hashing delta

		JsonCanonicalizer jc = new JsonCanonicalizer(value);
		byte[] hashed = Sha256Hash.hash(jc.getEncodedString().getBytes(StandardCharsets.US_ASCII));
		Multihash multihash = new Multihash(Multihash.Type.sha2_256, hashed);

		return Base64.getUrlEncoder().withoutPadding().encodeToString(multihash.toBytes());
	}

	public static String canonicalizeThenDoubleHashThenEncode(JWK jwk) throws IOException {
		JsonCanonicalizer jc = new JsonCanonicalizer(jwk.toPublicJWK().toJSONString());
		byte[] hashed = Sha256Hash.hashTwice(jc.getEncodedString().getBytes(StandardCharsets.US_ASCII));
		Multihash multihash = new Multihash(Multihash.Type.sha2_256, hashed);

		return Base64.getUrlEncoder().withoutPadding().encodeToString(multihash.toBytes());
	}
}
