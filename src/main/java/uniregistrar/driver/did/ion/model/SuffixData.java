package uniregistrar.driver.did.ion.model;

import com.nimbusds.jose.util.JSONObjectUtils;

import java.util.LinkedHashMap;
import java.util.Map;

public class SuffixData {
	private String deltaHash;
	private String recoveryCommitment;

	public SuffixData(String deltaHash, String recoveryCommitment) {
		this.deltaHash = deltaHash;
		this.recoveryCommitment = recoveryCommitment;
	}

	public String getDeltaHash() { return deltaHash; }

	public void setDeltaHash(String value) { this.deltaHash = value; }

	public String getRecoveryCommitment() { return recoveryCommitment; }

	public void setRecoveryCommitment(String value) { this.recoveryCommitment = value; }

	public String toJSONString() {
		return JSONObjectUtils.toJSONString(toJSONObject());
	}

	public Map<String, Object> toJSONObject() {
		Map<String, Object> o = new LinkedHashMap<>();
		o.put("deltaHash", deltaHash);
		o.put("recoveryCommitment", recoveryCommitment);
		return o;
	}


}
