package uniregistrar.driver.did.ion;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uniregistrar.RegistrationException;
import uniregistrar.driver.AbstractDriver;
import uniregistrar.request.DeactivateRequest;
import uniregistrar.request.RegisterRequest;
import uniregistrar.request.UpdateRequest;
import uniregistrar.state.DeactivateState;
import uniregistrar.state.RegisterState;
import uniregistrar.state.UpdateState;

import java.util.Map;

public class DidIonDriver extends AbstractDriver {

	private static final Logger log = LogManager.getLogger(DidIonDriver.class);


	@Override
	public RegisterState register(RegisterRequest request) throws RegistrationException {
		throw new RuntimeException("Not implemented.");
	}

	@Override
	public UpdateState update(UpdateRequest request) throws RegistrationException {
		throw new RuntimeException("Not implemented.");
	}

	@Override
	public DeactivateState deactivate(DeactivateRequest request) throws RegistrationException {
		throw new RuntimeException("Not implemented.");
	}

	@Override
	public Map<String, Object> properties() throws RegistrationException {
		throw new RuntimeException("Not implemented.");
	}
}
