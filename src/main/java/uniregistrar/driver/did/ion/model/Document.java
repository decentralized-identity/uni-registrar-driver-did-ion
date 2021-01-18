package uniregistrar.driver.did.ion.model;

public class Document {
	private PublicKeyModel[] publicKeyModels;
	private Service[] services;

	public PublicKeyModel[] getPublicKeys() { return publicKeyModels; }
	public void setPublicKeys(PublicKeyModel[] value) { this.publicKeyModels = value; }

	public Service[] getServices() { return services; }
	public void setServices(Service[] value) { this.services = value; }
}
