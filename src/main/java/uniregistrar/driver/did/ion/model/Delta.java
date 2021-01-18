package uniregistrar.driver.did.ion.model;

public class Delta {
	private String updateCommitment;
	private Patch[] patches;

	public String getUpdateCommitment() { return updateCommitment; }

	public void setUpdateCommitment(String value) { this.updateCommitment = value; }

	public Patch[] getPatches() { return patches; }

	public void setPatches(Patch[] value) { this.patches = value; }
}
