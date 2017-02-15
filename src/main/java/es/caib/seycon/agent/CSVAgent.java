package es.caib.seycon.agent;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.rmi.RemoteException;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import com.soffid.iam.api.User;

import au.com.bytecode.opencsv.CSVReader;
import au.com.bytecode.opencsv.CSVWriter;

import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeChangeIdentifier;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource;
import es.caib.seycon.ng.sync.intf.ReconcileMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;

public class CSVAgent extends Agent implements UserMgr, ReconcileMgr, AuthoritativeIdentitySource
{
	private String usersFile;

	public String getUsersFile() {
		return usersFile;
	}


	public CSVIdentitySource getSource() {
		return source;
	}


	public CSVAgent () throws RemoteException
	{
	}

	
	public void init ()
	{
		usersFile = getDispatcher().getParam0();
	}

	public void updateUser (String userName, Usuari userData)
					throws InternalErrorException
	{
		System.out.println(getDispatcher().getCodi() + ": UpdateUser " + userName);
		try {
			CSVFile prop = CSVFile.load(usersFile);
			Map<String, String> map = prop.getUserData(userData.getCodi());
			if (map == null)
			{
				map = new HashMap<String, String>();
				
			}
			User user = User.toUser(userData);
			
			for (String column: prop.getColumns())
			{
				if (column.equals("roles"))
				{
					StringBuffer sb = new StringBuffer();
					for (RolGrant rg: getServer().getUserRoles(user.getId(), getCodi()))
					{
						if (sb.length() > 0)
							sb.append (" ");
						sb.append (rg.getRolName());
					}
					map.put(column, sb.toString());
				}
				else if (column.equals("groups"))
				{
					StringBuffer sb = new StringBuffer();
					for (Grup rg: getServer().getUserGroups(user.getId()))
					{
						if (sb.length() > 0)
							sb.append (" ");
						sb.append (rg.getCodi());
					}
					map.put(column, sb.toString());
				}
				else if (column.equals( "password"))
				{
					if (map.get(column) == null)
					{
						Password p = getServer().getOrGenerateUserPassword(userName, getCodi());
						map.put(column, p.getPassword());
					}
				}
				else if (column.equals ("accountName"))
				{
					map.put(column, userName);
				}
				else
				{
					Method m = getGetter(column);
					if (m != null)
					{
						Object obj = m.invoke(user);
						if (obj != null)
							map.put(column, obj.toString());
					}
					else
					{
						DadaUsuari data = getServer().getUserData(user.getId(), column);
						if (data != null)
							map.put(column, data.getValorDada());
					}
				}
			}
			prop.addUserData(userName, map);
			prop.save(usersFile);
		} catch (Exception e) {
			throw new InternalErrorException("Error updating CSV File", e);
		}
	}


	private Method getGetter(String column) throws NoSuchMethodException {
		String methodName = "get" + column.substring(0, 1).toUpperCase()+column.substring(1);
		Method m = null;
		try {
			m = User.class.getMethod(methodName, new Class[0]);
		} catch (NoSuchMethodException e) {
		}
		if (m == null)
		{
			methodName = "is" + column.substring(0, 1).toUpperCase()+column.substring(1);
			try {
				m = User.class.getMethod(methodName, new Class[0]);
			} catch (NoSuchMethodException e) {
				return null;
			}
		}
		return m;
	}

	private Method getSetter(String column) throws NoSuchMethodException {
		Method getter = getGetter(column);
		Method m = null;
		if (getter != null)
		{
			String methodName = "set" + column.substring(0, 1).toUpperCase()+column.substring(1);
			try 
			{
				m = User.class.getMethod(methodName, new Class[] { getter.getReturnType()});
			} catch (NoSuchMethodException e) {
				return null;
			}
		}
		return m;
	}


	public void removeUser (String userName) throws RemoteException,
					InternalErrorException
	{
		System.out.println(getDispatcher().getCodi() + ": UpdateUser " + userName);
		try {
			CSVFile prop = CSVFile.load(usersFile);
			prop.remove(userName);
			prop.save(usersFile);
		} catch (Exception e) {
			throw new InternalErrorException("Error updating CSV File", e);
		}
	}

	public void updateUserPassword (String userName, Usuari userData, Password password,
					boolean mustchange) throws RemoteException, InternalErrorException
	{
		System.out.println(getDispatcher().getCodi() + ": UpdateUserPassword "
						+ userName + "/" + password.getPassword());
		try {
			CSVFile prop = CSVFile.load(usersFile);
			Map<String, String> user = prop.getUserData(userName);
			if (user == null)
			{
				updateUser(userName, userData);
				user = prop.getUserData(userName);
			}
			if (user != null)
			{
				user.put("password", password.getPassword());
				prop.save(usersFile);
			}
		} catch (Exception e) {
			throw new InternalErrorException("Error updating CSV File", e);
		}
	}

	public boolean validateUserPassword (String userName, Password password)
					throws RemoteException, InternalErrorException
	{
		try {
			CSVFile prop = CSVFile.load(usersFile);
			Map<String, String> user = prop.getUserData(userName);
			if (user != null)
			{
				String pass = user.get("password");
				if (pass != null && pass.equals (password.getPassword()))
					return true;
			}
			return false;
		} catch (Exception e) {
			throw new InternalErrorException("Error updating CSV File", e);
		}
	}

	// Get user account list on properties file
	public List<String> getAccountsList () throws RemoteException,
					InternalErrorException
	{
		try {
			CSVFile prop = CSVFile.load(usersFile);
			return new LinkedList<String>( prop.getAccounts ());
		} catch (Exception e) {
			throw new InternalErrorException("Error updating CSV File", e);
		}
	}

	
	public User fromCSVEntry (Map<String,String> csvEntry) throws IllegalArgumentException, IllegalAccessException, InvocationTargetException, NoSuchMethodException
	{
		User user = new User ();
		for (String key: csvEntry.keySet())
		{
			String  value = csvEntry.get(key);
			if (value != null)
			{
				Method m = getSetter(key);
				if (m != null)
				{
					Class<?> param = m.getParameterTypes()[0];
					if (param.isAssignableFrom(String.class))
						m.invoke(user, value);
					else if (param.isAssignableFrom(Boolean.class))
						m.invoke(user, Boolean.parseBoolean(value));
					else if (param.isAssignableFrom(Integer.class))
						m.invoke(user, Integer.decode(value));
					else if (param.isAssignableFrom(Long.class))
						m.invoke(user, Long.decode(value));
					else if (param.isAssignableFrom(Calendar.class))
					{
						Calendar c = Calendar.getInstance();
						c.setTimeInMillis(Date.parse(value));
						m.invoke(user, c);
					}
					else if (param.isAssignableFrom(Date.class))
						m.invoke(user, new Date (Date.parse(value)));
				}
			}
		}
		return user;
	}
	
	
	public Map<String, String> getAttributes(Map<String, String> csvEntry) throws NoSuchMethodException
	{
		Map<String,String> attrs = new HashMap<String, String>();
		for (String key: csvEntry.keySet())
		{
			String  value = csvEntry.get(key);
			if (key.equals ("password") || key.equals("roles") || key.equals("groups") || key.equals("accountName"))
			{
				// Nothing to do
			}
			else if (value != null)
			{
				Method m = getGetter(key);
				if (m == null)
				{
					attrs.put(key, value);
				}
			}
		}
		return attrs;
	}

	// Get user info on properties file
	public Usuari getUserInfo (String userAccount) throws RemoteException,
					InternalErrorException
	{
		try {
			CSVFile prop = CSVFile.load(usersFile);
			Map<String, String> csvEntry = prop.getUserData(userAccount);
			if (csvEntry == null)
				return null;
			else
			{
				User user = fromCSVEntry(csvEntry);
				return Usuari.toUsuari(user);
			}
		} catch (Exception e) {
			throw new InternalErrorException("Error loading CSV File", e);
		}
	}

	// Get roles names on properties file
	public List<String> getRolesList () throws RemoteException, InternalErrorException
	{
		HashSet<String> roles = new HashSet<String>();
		try {
			CSVFile prop = CSVFile.load(usersFile);
			for (String account: prop.getAccounts())
			{
				Map<String, String> csvEntry = prop.getUserData(account);
				
				String userRoles = csvEntry.get("roles");
				if (userRoles != null && userRoles.length() > 0)
				{
					for (String userRole: userRoles.split(" +"))
					{
						roles.add(userRole);
					}
							
				}
			}
			return new LinkedList<String>(roles);
		} catch (Exception e) {
			throw new InternalErrorException("Error loading CSV File", e);
		}
	}

	// Get role full information
	public Rol getRoleFullInfo (String roleName) throws RemoteException,
					InternalErrorException
	{
		Rol roleInfo = new Rol(); // Role info
		roleInfo.setNom(roleName);
		roleInfo.setBaseDeDades(getCodi());
		roleInfo.setDescripcio("Imported role "+roleName);
		return roleInfo;
	}

	// Get roles granted
	public List<RolGrant> getAccountsRoleGranted () throws RemoteException,
					InternalErrorException
	{
		List<RolGrant> roles = new LinkedList<RolGrant>();
		try {
			CSVFile prop = CSVFile.load(usersFile);
			for (String account: prop.getAccounts())
			{
				Map<String, String> csvEntry = prop.getUserData(account);
				
				String userRoles = csvEntry.get("roles");
				if (userRoles != null && userRoles.length() > 0)
				{
					for (String userRole: userRoles.split(" +"))
					{
						RolGrant rg = new RolGrant ();
						rg.setOwnerAccountName(account);
						rg.setOwnerDispatcher(getCodi());
						rg.setRolName(userRole);
						rg.setDispatcher(getCodi());
						roles.add(rg);
					}
							
				}
			}
			return roles;
		} catch (Exception e) {
			throw new InternalErrorException("Error loading CSV File", e);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see es.caib.seycon.ng.sync.intf.ReconcileMgr#getAccountRoles(java.lang.String)
	 */
	public List<Rol> getAccountRoles (String userAccount) throws RemoteException,
					InternalErrorException
	{
		List<Rol> roles = new LinkedList<Rol>();
		try {
			CSVFile prop = CSVFile.load(usersFile);
			Map<String, String> csvEntry = prop.getUserData(userAccount);
			if (csvEntry != null)
			{
				String userRoles = csvEntry.get("roles");
				if (userRoles != null)
				{
					if (userRoles != null && userRoles.length() > 0)
					{
						for (String userRole: userRoles.split(" +"))
						{
							Rol rol = new Rol();
							rol.setBaseDeDades(getCodi());
							rol.setNom(userRole);
							rol.setDescripcio("Autoloaded fole "+userRole);
							roles.add(rol);
						}
					}	
				}
			}
			return roles;
		} catch (Exception e) {
			throw new InternalErrorException("Error loading CSV File", e);
		}
	}


	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {

	}


	
	CSVIdentitySource source = new CSVIdentitySource (this);
	public Collection<AuthoritativeChange> getChanges()
			throws InternalErrorException {
		return source.getChanges();
	}


	public void commitChange(AuthoritativeChangeIdentifier id)
			throws InternalErrorException {
		source.commitChange(id);
		
	}


	public Set<String> getGroups(Map<String, String> csvEntry) {
		Set<String> groups = new HashSet<String>();
		String userGroups = csvEntry.get("groups");
		if (userGroups != null && userGroups.length() >  0)
		{
			for (String userGroup: userGroups.split(" +"))
			{
				groups.add(userGroup);
			}
					
		}
		
		return groups;
	}

	
}
