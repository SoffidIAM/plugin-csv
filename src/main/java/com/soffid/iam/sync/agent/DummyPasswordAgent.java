package com.soffid.iam.sync.agent;

import java.rmi.RemoteException;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.intf.UserMgr;

public class DummyPasswordAgent extends Agent implements UserMgr {
	

	public void removeUser(String arg0) throws RemoteException,
			InternalErrorException {
		
	}

	public void updateUser(String arg0, Usuari arg1) throws RemoteException,
			InternalErrorException {
		
	}

	public void updateUser(String arg0, String arg1) throws RemoteException,
			InternalErrorException {
		
	}

	public void updateUserPassword(String arg0, Usuari arg1, Password arg2,
			boolean arg3) throws RemoteException, InternalErrorException {
		
	}

	public boolean validateUserPassword(String arg0, Password pass)
			throws RemoteException, InternalErrorException {
		return pass.getPassword().equals(getDispatcher().getParam0());
	}

}
