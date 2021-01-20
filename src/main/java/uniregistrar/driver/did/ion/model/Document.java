package uniregistrar.driver.did.ion.model;

import com.nimbusds.jose.util.JSONObjectUtils;
import foundation.identity.did.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class Document {
	private List<PublicKeyModel> publicKeyModels;
	private List<Service> services;

	public Document(List<PublicKeyModel> publicKeyModels, List<Service> services) {
		this.publicKeyModels = publicKeyModels;
		this.services = services;
	}

	public List<PublicKeyModel> getPublicKeys() { return publicKeyModels; }

	public void setPublicKeys(List<PublicKeyModel> value) { this.publicKeyModels = value; }

	public List<Service> getServices() { return services; }

	public void setServices(List<Service> value) { this.services = value; }

	public String toJSONString() {
		return JSONObjectUtils.toJSONString(toJSONObject());
	}

	public Map<String, Object> toJSONObject() {
		Map<String, Object> o = new LinkedHashMap<>();
		if (publicKeyModels != null) {
			o.put("publicKeys", publicKeyModels.stream().map(PublicKeyModel::toJSONObject).collect(Collectors.toList()));
		}
		if (services != null) {
			o.put("services", services.stream().map(Document::getServiceModel).collect(Collectors.toList()));
		}
		return o;
	}

	public static Map<String, Object> getServiceModel(Service service) {
		Map<String, Object> serviceMap = new LinkedHashMap<>();
		serviceMap.put("type", service.getType());
		serviceMap.put("id", service.getId().toString());
		serviceMap.put("serviceEndpoint", service.getServiceEndpoint());

		return serviceMap;
	}
}
