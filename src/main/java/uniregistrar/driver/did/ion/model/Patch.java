package uniregistrar.driver.did.ion.model;

import com.nimbusds.jose.util.JSONObjectUtils;

import java.util.LinkedHashMap;
import java.util.Map;

public class Patch {

	public static final String DEFAULT_ACTION = "replace"; // To provide initial state

	private String action;
	private Document document;

	public Patch(String action, Document document) {
		this.action = action;
		this.document = document;
	}

	public String getAction() { return action; }

	public void setAction(String value) { this.action = value; }

	public Document getDocument() { return document; }

	public void setDocument(Document value) { this.document = value; }


	public String toJSONString() {
		return JSONObjectUtils.toJSONString(toJSONObject());
	}

	public Map<String, Object> toJSONObject() {
		Map<String, Object> o = new LinkedHashMap<>();
		o.put("action", action);
		if (document != null) {
			o.put("document", document.toJSONObject());
		}
		return o;
	}
}
