package es.caib.seycon.agent;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.intf.ReconcileMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;

public class TestAgent extends Agent implements UserMgr, ReconcileMgr
{
	private String usersFile;
//	private String rolesFile;

	public TestAgent () throws RemoteException
	{
	}

	private Properties loadProperties () throws InternalErrorException
	{
		Properties prop = new Properties();
		try
		{
			prop.load(new FileInputStream(usersFile));
		}
		catch (FileNotFoundException e)
		{
		}
		catch (IOException e)
		{
			throw new InternalErrorException(e.toString());
		}
		return prop;
	}

	public void init ()
	{
		usersFile = getDispatcher().getParam0();
//		rolesFile = getDispatcher().getParam1();
	}

	public void updateUser (String userName, Usuari userData)
					throws InternalErrorException
	{
		System.out.println(getDispatcher().getCodi() + ": UpdateUser " + userName);
		Properties prop = loadProperties();
		prop.setProperty(userName,
						userData.getNom() + " " + userData.getPrimerLlinatge() + " "
										+ userData.getSegonLlinatge());
		Collection<Grup> groupList;
		try
		{
			groupList = getServer().getUserGroups(userName, getCodi());

			StringBuffer groups = new StringBuffer();
			for (Grup grup : groupList)
			{
				if (groups.length() > 0)
					groups.append(", ");
				groups.append(grup.getCodi());
			}
			prop.put(userName + ".groups", groups.toString());

			Collection<RolGrant> roleList = getServer().getUserRoles(userData.getId(),
							null);
			StringBuffer roles = new StringBuffer();
			for (RolGrant role : roleList)
			{
				if (roles.length() > 0)
					roles.append(", ");
				roles.append(role.getRolName() + "/" + role.getDomainValue() + "@"
								+ role.getDispatcher());
			}
			prop.put(userName + ".roles", roles.toString());

			roleList = getServer().getUserRoles(userData.getId(), getCodi());

			roles = new StringBuffer();
			for (RolGrant role : roleList)
			{
				if (roles.length() > 0)
					roles.append(", ");
				roles.append(role.getRolName() + "/" + role.getDomainValue() + "@"
								+ role.getDispatcher());
			}
			prop.put(userName + ".roles.test", roles.toString());
			if(getServer().getAccountPassword(userName, getCodi())!=null)
				prop.put(userName + ".pass", getServer().getAccountPassword(userName, getCodi()).toString());
			prop.store(new FileOutputStream(usersFile), "TestAgent properties");
		}
		catch (UnknownUserException e1)
		{
			throw new InternalErrorException("Internal error", e1);
		}
		catch (IOException e)
		{
			throw new InternalErrorException(e.toString());
		}
	}

	public void removeUser (String userName) throws RemoteException,
					InternalErrorException
	{
		Properties prop = loadProperties();
		prop.remove(userName);
		prop.remove(userName + ".pass");
		prop.remove(userName + ".roles");
		prop.remove(userName + ".groups");
		try
		{
			prop.store(new FileOutputStream(usersFile), "TestAgent properties");
		}
		catch (IOException e)
		{
			throw new InternalErrorException(e.toString());
		}
	}

	public void updateUserPassword (String userName, Usuari userData, Password password,
					boolean mustchange) throws RemoteException, InternalErrorException
	{
		System.out.println(getDispatcher().getCodi() + ": UpdateUserPassword "
						+ userName + "/" + password.getPassword());
		Properties prop = loadProperties();
		prop.setProperty(userName + ".pass", password.getPassword());
		try
		{
			prop.store(new FileOutputStream(usersFile), "TestAgent properties");
		}
		catch (IOException e)
		{
			throw new InternalErrorException(e.toString());
		}
	}

	public boolean validateUserPassword (String userName, Password password)
					throws RemoteException, InternalErrorException
	{
		Properties prop = loadProperties();
		String realPass = prop.getProperty(userName + ".pass");
		return password.getPassword().equals(realPass);
	}

	public String createUserKey (Usuari userData) throws RemoteException,
					InternalErrorException
	{
		return null;
	}

	// Get user account list on properties file
	public List<String> getAccountsList () throws RemoteException,
					InternalErrorException
	{
		LinkedList<String> userAccounts = new LinkedList<String>(); // User accounts
		Properties prop = loadProperties(); // Properties file handler
		Set<String> keys; // Keys on properties file

		try
		{
			keys = prop.stringPropertyNames();

			// Obtain users
			for (String propKey : keys)
			{
				// Search delimiter '.'of property on key
				if (propKey.toString().indexOf(".") == -1)
				{
					userAccounts.add(propKey.toString());
				}
			}
		}

		catch (Exception e)
		{
			throw new InternalErrorException(e.toString());
		}

		return userAccounts;
	}

	// Get user info on properties file
	public Usuari getUserInfo (String userAccount) throws RemoteException,
					InternalErrorException
	{
		Usuari userInfo = new Usuari(); // User data on properties
		Properties prop = loadProperties(); // Properties file handler

		try
		{
			// Check user found
			if (prop.getProperty(userAccount) != null)
			{
				userInfo.setCodi(userAccount);
				userInfo.setNom(prop.getProperty(userAccount));
			}
		}

		catch (Exception ex)
		{
			throw new InternalErrorException(ex.toString());
		}

		return userInfo;
	}

	// Get roles names on properties file
	public List<String> getRolesList () throws RemoteException, InternalErrorException
	{
		LinkedList<String> rolesNames = new LinkedList<String>(); // Roles names
		Properties prop = loadProperties(); // Properties file handler
		Set<Entry<Object, Object>> propValues; // Values on properties file
		String rolesValue; // All roles values
		String extracted; // Extracted role of complete
		int sepRoles = 0; // Index of roles separator
		int startIndex = 0; // Start index to search

		try
		{
			propValues = prop.entrySet();

			// Obtain roles names
			for (Entry<Object, Object> entry : propValues)
			{
				// Check roles parameter
				if (entry.getKey().toString().contains(".roles")
								&& (!entry.getValue().toString().isEmpty()))
				{
					sepRoles = 0;
					startIndex = 0;

					rolesValue = entry.getValue().toString();

					sepRoles = rolesValue.indexOf(" ", sepRoles);

					do
					{
						// Only one role
						if (sepRoles == -1)
						{
							sepRoles = rolesValue.length();
							extracted = extractRole(rolesValue, sepRoles, startIndex);
						}

						else
						{
							extracted = extractRole(rolesValue, sepRoles, startIndex);
						}
						
						// Check existing role
						if (!rolesNames.contains(extracted))
						{
							rolesNames.add(extracted);
						}

						startIndex = sepRoles + 1;
						sepRoles = rolesValue.indexOf(" ", startIndex);

					} while (startIndex < rolesValue.length());
				}
			}
		}

		catch (Exception ex)
		{
			throw new InternalErrorException(ex.toString());
		}

		return rolesNames;
	}

	// Get role full information
	public Rol getRoleFullInfo (String roleName) throws RemoteException,
					InternalErrorException
	{
		Rol roleInfo = new Rol(); // Role info
		Grup group; // Group of user
		Properties prop = loadProperties(); // Properties file handler
		LinkedList<Grup> groups = new LinkedList<Grup>(); // Roles group
		Set<Entry<Object, Object>> propValues; // Values on properties file
		String user; // User role
		int indexDelim; // Delimiter position

		try
		{
			propValues = prop.entrySet();

			// Obtain roles group
			for (Entry<Object, Object> entry : propValues)
			{
				// Check key role name
				if (entry.getKey().toString().contains(".roles")
								&& entry.getValue().toString().contains(roleName))
				{
					indexDelim = entry.getKey().toString().indexOf(".roles");

					// Obtain role user key
					user = entry.getKey().toString().substring(0, indexDelim);

					// Check group not added previously
					if (!groups.contains(prop.get(user + ".groups"))
									&& (prop.get(user + ".groups") != null))
					{
						group = new Grup();
						group.setCodi(prop.get(user + ".groups").toString());

						groups.add(group);
					}
				}
			}

			roleInfo.setNom(roleName);
			roleInfo.setDescripcio(roleName);
			roleInfo.setOwnerGroups(groups);
		}

		catch (Exception ex)
		{
			throw new InternalErrorException(ex.toString());
		}

		return roleInfo;
	}

	// Get roles granted
	public List<RolGrant> getAccountsRoleGranted () throws RemoteException,
					InternalErrorException
	{
		Properties prop = loadProperties(); // Properties file handler
		LinkedList<RolGrant> rolesGranted = new LinkedList<RolGrant>(); // Roles
																		// granted
																		// list
		Set<Entry<Object, Object>> propValues; // Values properties on file
		String fullRoles; // Complete roles on key
		String completeRole; // Complete role on full roles obtained
		String role; // Role extracted
		int indexSepFullRole; // Index of separator for complete roles on key
		RolGrant roleGranted; // Role granted to insert

		try
		{
			propValues = prop.entrySet();

			for (Entry<Object, Object> entry : propValues)
			{
				// Check role key
				if (entry.getKey().toString().contains(".roles"))
				{
					fullRoles = entry.getValue().toString();

					indexSepFullRole = 0;

					// Read to end complete roles values of key
					while (indexSepFullRole != -1)
					{
						indexSepFullRole = fullRoles.indexOf(" ", indexSepFullRole);

						completeRole = fullRoles.substring(indexSepFullRole,
										fullRoles.indexOf(" ", indexSepFullRole));

						indexSepFullRole = fullRoles.indexOf(" ", indexSepFullRole);

						role = completeRole.substring(0, completeRole.indexOf("/"));

						// Check existing role
						if (!rolesGranted.contains(role))
						{
							roleGranted = new RolGrant();
							roleGranted.setRolName(role);

							rolesGranted.add(roleGranted);
						}
					}
				}
			}
		}

		catch (Exception ex)
		{
			throw new InternalErrorException(ex.toString());
		}

		return rolesGranted;
	}

	/*
	 * (non-Javadoc)
	 * @see es.caib.seycon.ng.sync.intf.ReconcileMgr#getAccountRoles(java.lang.String)
	 */
	public List<Rol> getAccountRoles (String userAccount) throws RemoteException,
					InternalErrorException
	{
		LinkedList<Rol> rolesList = new LinkedList<Rol>();// User roles
		Properties prop = loadProperties(); // Properties file handler
		Set<Entry<Object, Object>> propValues; // Values on properties file
		String rolesValue; // All roles values
		String completeRole; // Complete role extracted
		Rol extracted; // Extracted role of complete
		int sepRoles = 0; // Index of roles separator
		int startIndex = 0; // Start index to search

		try
		{
			propValues = prop.entrySet();

			// Obtain roles names
			for (Entry<Object, Object> entry : propValues)
			{
				// Check roles parameter
				if (entry.getKey().toString().contains(userAccount + ".roles")
								&& (!entry.getValue().toString().isEmpty()))
				{
					sepRoles = 0;
					startIndex = 0;

					rolesValue = entry.getValue().toString();

					sepRoles = rolesValue.indexOf(" ", sepRoles);

					do
					{
						// Only one role
						if (sepRoles == -1)
						{
							sepRoles = rolesValue.length();
						}

						completeRole = rolesValue.substring(startIndex, sepRoles);

						// Check sub-role contained
						if (completeRole.contains("/"))
						{
							extracted = getRoleFullInfo(completeRole.substring(0,
											completeRole.indexOf("/")));
						}
						else
						{
							extracted = getRoleFullInfo(completeRole);
						}

						// Check existing role
						if (!ExistRoleInList(rolesList, extracted))
						{
							rolesList.add(extracted);
						}

						startIndex = sepRoles + 1;
						sepRoles = rolesValue.indexOf(" ", startIndex);

					} while (startIndex < rolesValue.length());
				}
			}
		}

		catch (Exception ex)
		{
			throw new InternalErrorException(ex.toString());
		}

		return rolesList;
	}

	/**
	 * Exist role in list.
	 * 
	 * <p>
	 * Implements the functionality to search a role in list.
	 * 
	 * @param rolesList
	 *            List of roles.
	 * @param extracted
	 *            Role to search.
	 * @return <p>
	 *         <code>TRUE</code> if the role exists in roles list.
	 *         <p>
	 *         <code>FALSE</code> if role NOT exists in roles list.
	 */
	private boolean ExistRoleInList (LinkedList<Rol> rolesList, Rol extracted)
	{
		// Process roles list
		for (Rol role : rolesList)
		{
			// Check roles names
			if (role.getNom().equals(extracted.getNom()))
			{
				return true;
			}
		}

		return false;
	}

	/**
	 * Extract role name.
	 * 
	 * <p>
	 * Implements the functionality to extract role name of complete role information.
	 * 
	 * @param rolesValue
	 *            Contains the complete roles information.
	 * @param sepRoles
	 *            End index of extraction.
	 * @param startIndex
	 *            Start index of extraction.
	 * @return Role name.
	 */
	private String extractRole (String rolesValue, int sepRoles, int startIndex)
	{
		String completeRole; // Complete role
		String extracted; // Role name extracted.

		completeRole = rolesValue.substring(startIndex, sepRoles);

		// Check sub-role contained
		if (completeRole.contains("/"))
		{
			extracted = completeRole.substring(0, completeRole.indexOf("/"));
		}

		else
		{
			if (completeRole.contains(","))
			{
				extracted = completeRole.substring(0, completeRole.indexOf(","));
			}
			
			else
			{
				extracted = completeRole;
			}
		}

		return extracted;
	}

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
		System.out.println(getDispatcher().getCodi() + ": UpdateAccount " + accountName);

		Properties prop = loadProperties();
		prop.setProperty(accountName, description);
		Collection<Grup> groupList;
		try
		{
			Collection<RolGrant> roleList = getServer().getAccountRoles(accountName, getCodi());

			StringBuffer roles = new StringBuffer();
			for (RolGrant role : roleList)
			{
				if (roles.length() > 0)
					roles.append(", ");
				roles.append(role.getRolName() + "/" + role.getDomainValue() + "@"
								+ role.getDispatcher());
			}
			prop.put(accountName + ".roles", roles.toString());
			if(getServer().getAccountPassword(accountName, getCodi())!=null)
				prop.put(accountName + ".pass", getServer().getAccountPassword(accountName, getCodi()));

			prop.store(new FileOutputStream(usersFile), "TestAgent properties");
		}
		catch (IOException e)
		{
			throw new InternalErrorException(e.toString());
		}
	}

}
