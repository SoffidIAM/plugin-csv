package es.caib.seycon.agent;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import com.soffid.iam.api.User;

import es.caib.seycon.ng.comu.Dispatcher;
import es.caib.seycon.ng.comu.DispatcherAccessControl;
//import es.caib.seycon.InternalErrorException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownGroupException;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.util.TimedProcess;
import es.caib.seycon.ng.comu.ControlAcces;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.TipusDada;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.servei.DadesAddicionalsService;
import es.caib.seycon.ng.servei.GrupService;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.bootstrap.QueryHelper;
import es.caib.seycon.ng.sync.intf.AccessControlMgr;
import es.caib.seycon.ng.sync.intf.AccessLogMgr;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeChangeIdentifier;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource;
import es.caib.seycon.ng.sync.intf.LogEntry;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;

/**
 * Agent to retrieve information from peopleosft
 */

public class CSVIdentitySource implements
		AuthoritativeIdentitySource {
	long lastFileModification = 0;
	Set<String> notifiedUsers = new HashSet<String>();
	
	private CSVAgent csvAgent;
	


	/**
	 * Constructor
	 * @param csvAgent 
	 * 
	 * @param params
	 *            vector con parámetros de configuración: <LI>0 = usuario</LI>
	 *            <LI>1 = contraseña oracle</LI> <LI>2 = cadena de conexión a la
	 *            base de datos</LI> <LI>3 = contraseña con la que se protegerán
	 *            los roles</LI>
	 */
	public CSVIdentitySource(CSVAgent csvAgent) throws java.rmi.RemoteException {
		this.csvAgent = csvAgent;
	}

	/**
	 * Inicializar el agente.
	 */
	public void init() throws InternalErrorException {
	}


	@SuppressWarnings("rawtypes")
	public Collection<AuthoritativeChange> getChanges()
			throws InternalErrorException {
		try {
			File f = new File( csvAgent.getUsersFile() );

			long ts = f.lastModified();
			if (f.canRead() && ts > lastFileModification)
			{
				notifiedUsers.clear();
				lastFileModification = ts;
			}
			
			LinkedList<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();

			CSVFile prop = CSVFile.load( csvAgent.getUsersFile());

			
			for (String account : prop.getAccounts())
			 {
				if ( ! notifiedUsers.contains(account))
				{
					Map<String, String> csvEntry = prop.getUserData(account);
					User user = csvAgent.fromCSVEntry(csvEntry);
					
					AuthoritativeChangeIdentifier id = new AuthoritativeChangeIdentifier();
					id.setEmployeeId(account);
					Usuari u = Usuari.toUsuari(user);

					AuthoritativeChange change = new AuthoritativeChange();
					change.setUser(u);
					change.setId(id);						
					change.setAttributes((Map)csvAgent.getAttributes (csvEntry));
					change.setGroups(csvAgent.getGroups(csvEntry));
					for (String group: change.getGroups())
						createGroup (group);
					if (u.getCodiGrupPrimari() != null && u.getCodiGrupPrimari().length() > 0)
						createGroup (u.getCodiGrupPrimari());
					changes.add(change);
				}
			}
			return changes;
		} catch (Exception e) {
			throw new InternalErrorException("Error getting changes: "+e.toString());
		}
	}

	private Grup createGroup(String group) throws InternalErrorException, SQLException, IOException {
		try {
			Grup groupInfo = csvAgent.getServer().getGroupInfo(group, csvAgent.getCodi());
			return groupInfo;
		} catch (UnknownGroupException e) {
			RemoteServiceLocator rsl = new RemoteServiceLocator();
			GrupService gs = (GrupService) rsl.getRemoteService("/seycon/GrupService");
			Grup grup = new Grup();
			grup.setCodi(group);
			grup.setCodiPare("enterprise");
			grup.setDescripcio("Autocreated group "+group);
			grup.setObsolet(Boolean.FALSE);
			grup.setNomServidorOfimatic("null");
			gs.create(grup);
			return grup;
		}
	}

	public void commitChange(AuthoritativeChangeIdentifier id)
			throws InternalErrorException {
		notifiedUsers.add(id.getEmployeeId().toString());
	}

}