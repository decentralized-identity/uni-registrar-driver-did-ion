package uniregistrar.driver.did.ion.util;

import com.danubetech.keyformats.PrivateKey_to_JWK;
import com.nimbusds.jose.jwk.JWK;
import io.ipfs.multibase.Multibase;
import io.ipfs.multihash.Multihash;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;

public class SidetreeUtils {

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

	public static String canonicalizeThenDoubleHashThenEncode(String jwkString) throws ParseException, IOException {
		return canonicalizeThenDoubleHashThenEncode(JWK.parse(jwkString));
	}

	public static String canonicalizeThenDoubleHashThenEncode(JWK jwk) throws IOException {
		JsonCanonicalizer jc = new JsonCanonicalizer(jwk.toPublicJWK().toJSONString());
		byte[] hashed = Sha256Hash.hashTwice(jc.getEncodedString().getBytes(StandardCharsets.US_ASCII));
		Multihash multihash = new Multihash(Multihash.Type.sha2_256, hashed);

		return Base64.getUrlEncoder().withoutPadding().encodeToString(multihash.toBytes());
	}

	public static JWK generateEs256kKeyPairInJwk() {
		ECKey key = new ECKey();
		return PrivateKey_to_JWK.secp256k1PrivateKey_to_JWK(key, null, null);
	}

}
