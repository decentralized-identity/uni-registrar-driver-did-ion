package uniregistrar.driver.did.ion.model;

import com.google.common.base.Preconditions;
import com.nimbusds.jose.util.JSONObjectUtils;

import java.util.LinkedHashMap;
import java.util.Map;

public class CreateRequest {
	private String type;
	private SuffixData suffixData;
	private Delta delta;

	public CreateRequest(String type, SuffixData suffixData, Delta delta) {
		Preconditions.checkNotNull(type);
		Preconditions.checkNotNull(suffixData);
		Preconditions.checkNotNull(delta);

		this.type = type;
		this.suffixData = suffixData;
		this.delta = delta;
	}

	public String getType() { return type; }

	public void setType(String value) { this.type = value; }

	public SuffixData getSuffixData() { return suffixData; }

	public void setSuffixData(SuffixData value) { this.suffixData = value; }

	public Delta getDelta() { return delta; }

	public void setDelta(Delta value) { this.delta = value; }

	public String toJSONString() {
		return JSONObjectUtils.toJSONString(toJSONObject());
	}

	public Map<String, Object> toJSONObject() {
		Map<String, Object> o = new LinkedHashMap<>();
		o.put("type", type);
		o.put("suffixData", suffixData.toJSONObject());
		o.put("delta", delta.toJSONObject());
		return o;
	}
}
