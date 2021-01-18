package uniregistrar.driver.did.ion.model;

public class CreateRequest {
	private String type;
	private SuffixData suffixData;
	private Delta delta;

	public String getType() { return type; }

	public void setType(String value) { this.type = value; }

	public SuffixData getSuffixData() { return suffixData; }

	public void setSuffixData(SuffixData value) { this.suffixData = value; }

	public Delta getDelta() { return delta; }

	public void setDelta(Delta value) { this.delta = value; }
}
