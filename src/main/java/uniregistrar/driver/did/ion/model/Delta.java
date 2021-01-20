package uniregistrar.driver.did.ion.model;

import com.nimbusds.jose.util.JSONObjectUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class Delta {
	private String updateCommitment;
	private List<Patch> patches;

	public Delta(String updateCommitment, List<Patch> patches) {
		this.updateCommitment = updateCommitment;
		this.patches = patches;
	}

	public String getUpdateCommitment() { return updateCommitment; }

	public void setUpdateCommitment(String value) { this.updateCommitment = value; }

	public List<Patch> getPatches() { return patches; }

	public void setPatches(List<Patch> value) { this.patches = value; }

	public String toJSONString() {
		return JSONObjectUtils.toJSONString(toJSONObject());
	}

	public Map<String, Object> toJSONObject() {
		Map<String, Object> o = new LinkedHashMap<>();
		o.put("updateCommitment", updateCommitment);
		if (patches != null) {
			o.put("patches", patches.stream().map(Patch::toJSONObject).collect(Collectors.toList()));
		}
		return o;
	}
}
