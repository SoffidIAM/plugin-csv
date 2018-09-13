package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.rmi.RemoteException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.RoleExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeChangeIdentifier;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.UserMgr;

public class CSVAgent extends Agent implements UserMgr, ReconcileMgr2,
		AuthoritativeIdentitySource, ExtensibleObjectMgr {
	boolean debugEnabled = true;
	ObjectTranslator objectTranslator = null;
	protected Collection<ExtensibleObjectMapping> objectMappings;

	public CSVAgent() throws RemoteException {
	}

	public void init() {
		debugEnabled = "true".equals(getDispatcher().getParam5());
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		this.objectMappings = objects;
		objectTranslator = new ObjectTranslator(getDispatcher(), getServer(),
				objectMappings);

	}

	protected void updateObject(ExtensibleObject systemObject) throws InternalErrorException, IOException {
		ValueObjectMapper vom = new ValueObjectMapper();
		for ( ExtensibleObjectMapping eom: objectMappings)
		{
			if (eom.getSystemObject().equals(systemObject.getObjectType()))
			{
				String key = eom.getProperties().get("key");
				String file = eom.getProperties().get("file");
				
				if (debugEnabled)
				{
					debugObject("Dumping object on file "+file, systemObject, "   ");
				}
				System.out.println(getDispatcher().getCodi() + ": UpdateUser "
						+ systemObject.get(key));
				CSVFile prop = CSVFile.load(key, file);
				String keyValue = vom.toSingleString(systemObject.get(key));
				prop.addUserData(keyValue, systemObject);
				prop.save(file);
			}
		}
	}

	protected void removeObject(ExtensibleObject systemObject) throws InternalErrorException, IOException {
		ValueObjectMapper vom = new ValueObjectMapper();
		for ( ExtensibleObjectMapping eom: objectMappings)
		{
			if (eom.getSystemObject().equals(systemObject.getObjectType()))
			{
				String key = eom.getProperties().get("key");
				String file = eom.getProperties().get("file");
				
				if (debugEnabled)
				{
					debugObject("Dumping object on file "+file, systemObject, "   ");
				}
				System.out.println(getDispatcher().getCodi() + ": UpdateUser "
						+ systemObject.get(key));
				CSVFile prop = CSVFile.load(key, file);
				String keyValue = vom.toSingleString(systemObject.get(key));
				prop.remove(keyValue);;
				prop.save(file);
			}
		}
	}

	public Collection<AuthoritativeChange> getChanges()
			throws InternalErrorException {
		List<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		ValueObjectMapper vom = new ValueObjectMapper();
		for ( ExtensibleObjectMapping eom: objectMappings)
		{
			if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE))
			{
				String key = eom.getProperties().get("key");
				String file = eom.getProperties().get("file");
				
				if (debugEnabled)
				{
					log.info("Getting authoritative users");
				}
				CSVFile prop = CSVFile.load(key, file);
				for (String account: prop.getAccounts())
				{
					readAuthoritativeChange(changes, vom, eom, prop, account);
				}
			}
		}
		if (!changes.isEmpty())
			return changes;
		for ( ExtensibleObjectMapping eom: objectMappings)
		{
			if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_USER))
			{
				String key = eom.getProperties().get("key");
				String file = eom.getProperties().get("file");
				String backup = eom.getProperties().get("backup");
				
				if (debugEnabled)
				{
					log.info("Getting authoritative users");
				}
				CSVFile prop = CSVFile.load(key, file);
				CSVFile backProp;
				if ("true".equals(backup))
					backProp = CSVFile.load(key, file+"-last");
				else
					backProp = new CSVFile ();
				for (String account: prop.getAccounts())
				{
					readUser(changes, vom, eom, prop, backProp, account);
				}
				for (String account: backProp.getAccounts())
				{
					AuthoritativeChange ch = readUser(changes, vom, eom, backProp, null, account);
					if (ch != null)
					{
						ch.getUser().setActiu(false);
					}
				}
				if ("true".equals(backup))
				{
					try {
						prop.save(file+"-last");
						prop.save(file+"-"+new SimpleDateFormat("yyyy-MM-dd-HH:MM").format(new Date()));
					} catch (IOException e) {
						throw new InternalErrorException("Error storing backup file ", e);
					}
				}
			}
		}
		return changes;
	}

	protected AuthoritativeChange readUser(List<AuthoritativeChange> changes,
			ValueObjectMapper vom, ExtensibleObjectMapping eom, CSVFile prop,
			CSVFile backProp, String account) throws InternalErrorException {
		Map<String, Object> identity = prop.getUserData(account);
		
		if (backProp != null)
			backProp.remove(account);
		
		ExtensibleObject eo = new ExtensibleObject();
		eo.setObjectType(eom.getSystemObject());
		eo.putAll(identity);
		if (debugEnabled)
		{
			debugObject("Got raw identity", eo, "   ");
		}
		ExtensibleObject input = objectTranslator.parseInputObject(eo, eom);
		if (input != null)
		{
			if (debugEnabled)
			{
				debugObject("Got soffid identity", input, "   ");
			}
			Usuari usuari = vom.parseUsuari(input);
			if (usuari != null)
			{
				AuthoritativeChange ch = new AuthoritativeChange();
				ch.setId(new AuthoritativeChangeIdentifier());
				ch.getId().setChangeId(usuari.getCodi());
				ch.setUser(usuari);
				Map<String,Object> attributes = (Map<String, Object>) input.getAttribute("attributes");
				ch.setAttributes(attributes);
				changes.add(ch);
				return ch;
			}
		}
		return null;
	}

	
	protected AuthoritativeChange readAuthoritativeChange(List<AuthoritativeChange> changes,
			ValueObjectMapper vom, ExtensibleObjectMapping eom, CSVFile prop,
			String account) throws InternalErrorException {
		
		Map<String, Object> identity = prop.getUserData(account);
		ExtensibleObject eo = new ExtensibleObject();
		eo.setObjectType(eom.getSystemObject());
		eo.putAll(identity);
		if (debugEnabled)
		{
			debugObject("Got raw identity", eo, "   ");
		}
		ExtensibleObject input = objectTranslator.parseInputObject(eo, eom);
		if (input != null)
		{
			if (debugEnabled)
			{
				debugObject("Got soffid identity", input, "   ");
			}
			AuthoritativeChange change = vom.parseAuthoritativeChange(input);
			if (change != null)
				changes.add(change);
			return change;
		}
		return null;
	}

	public void commitChange(AuthoritativeChangeIdentifier id)
			throws InternalErrorException {

	}

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getCodi());
		ExtensibleObject soffidObject = new AccountExtensibleObject(acc,
				getServer());
		String password;
		password = getAccountPassword(accountName);
		soffidObject.put("password", password);

		// First update user
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				ExtensibleObject systemObject = objectTranslator
						.generateObject(soffidObject, objectMapping);
				try {
					updateObject(systemObject);
				} catch (IOException e) {
					throw new InternalErrorException("Error updating CSV file", e);
				}
			}
		}
	}


	public void removeUser(String accountName) throws RemoteException,
			InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(null);
		acc.setDisabled(true);
		acc.setDispatcher(getCodi());
		ExtensibleObject soffidObject = new AccountExtensibleObject(acc,
				getServer());

		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				ExtensibleObject sqlobject = objectTranslator.generateObject(
						soffidObject, objectMapping);
				try {
					removeObject(sqlobject);
				} catch (IOException e) {
					throw new InternalErrorException("Error updating CSV file", e);
				}
			}
		}
	}

	public void updateUserPassword(String accountName, Usuari userData,
			Password password, boolean mustchange) throws RemoteException,
			InternalErrorException {

		Account acc = getServer().getAccountInfo(accountName, getDispatcher().getCodi());
		ExtensibleObject soffidObject = new UserExtensibleObject(acc, userData,
				getServer());

		soffidObject.put("password", password.getPassword());
		soffidObject.put("mustChangePassword", mustchange);

		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)
					&& userData == null
					|| objectMapping.getSoffidObject().equals(
							SoffidObjectType.OBJECT_USER) && userData != null) {

				ExtensibleObject systemObject = objectTranslator
						.generateObject(soffidObject, objectMapping);
				try {
					updateObject(systemObject);
				} catch (IOException e) {
					throw new InternalErrorException("Error updating CSV file", e);
				}
			}
		}
	}

	public boolean validateUserPassword(String accountName, Password password)
			throws RemoteException, InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		Account acc = getServer().getAccountInfo(accountName, getCodi());
		Usuari u = null;
		try {
			u = getServer().getUserInfo(accountName, getCodi());
		} catch (UnknownUserException e) {
		}
		ExtensibleObject sample = u == null ?
				new AccountExtensibleObject(acc, getServer()) :
				new UserExtensibleObject(acc, u, getServer());
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT) ||
					objectMapping.getSoffidObject().equals(
							SoffidObjectType.OBJECT_USER)) 
			{
				
				String key = objectMapping.getProperties().get("key");
				String file = objectMapping.getProperties().get("file");
				if (debugEnabled)
				{
					log.info("Getting account info for "+accountName);
				}
				String keyValue = vom.toSingleString(
						objectTranslator
						.generateAttribute(key, sample,  objectMapping));
				if (debugEnabled)
				{
					log.info("Key column: "+keyValue);
				}
				CSVFile prop = CSVFile.load(key, file);
				Map<String, Object> identity = prop.getUserData(keyValue);

				ExtensibleObject eo = new ExtensibleObject();
				eo.setObjectType(objectMapping.getSystemObject());
				eo.putAll(identity);

				String cvsPassword = (String) objectTranslator.parseInputAttribute("password", eo, objectMapping);
				if (cvsPassword != null && cvsPassword.equals(password.getPassword()))
					return true;

			}
		}

		return false;
	}

	void debugObject(String msg, Map<String, Object> obj, String indent) {
		if (debugEnabled) {
			if (indent == null)
				indent = "";
			if (msg != null)
				log.info(msg);
			for (String attribute : obj.keySet()) {
				Object subObj = obj.get(attribute);
				if (subObj == null) {
					log.info(indent + attribute.toString() + ": null");
				} else if (subObj instanceof Map) {
					log.info(indent + attribute.toString() + ": Object {");
					debugObject(null, (Map<String, Object>) subObj, indent
							+ "   ");
					log.info(indent + "}");
				} else {
					log.info(indent + attribute.toString() + ": "
							+ subObj.toString());
				}
			}
		}
	}

	public void updateUser(String accountName, Usuari userData)
			throws RemoteException, InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(userData.getFullName());
		acc.setDispatcher(getCodi());
		ExtensibleObject soffidObject = new UserExtensibleObject(acc, userData,
				getServer());

		String password;
		password = getAccountPassword(accountName);
		soffidObject.put("password", password);
		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_USER)) {
				ExtensibleObject systemObject = objectTranslator
						.generateObject(soffidObject, objectMapping);
				try {
					updateObject(systemObject);
				} catch (IOException e) {
					throw new InternalErrorException("Error updating CSV file", e);
				}
			}
		}
	}

	private String getAccountPassword(String accountName)
			throws InternalErrorException {
		Password p = getServer().getAccountPassword(accountName, getCodi());
		if (p == null) {
			p = getServer().generateFakePassword(accountName, getCodi());
		}
		return p.getPassword();
	}

	public Account getAccountInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		Account acc = new Account();
		acc.setName(userAccount);
		acc.setDispatcher(getCodi());
		ExtensibleObject sample = new AccountExtensibleObject(acc, getServer());
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				
				ExtensibleObject translatedSample = objectTranslator
						.generateObject(sample, objectMapping);

				String key = objectMapping.getProperties().get("key");
				String file = objectMapping.getProperties().get("file");
				if (debugEnabled)
				{
					log.info("Getting account info for "+userAccount);
				}
				String keyValue = vom.toSingleString(
						objectTranslator
						.generateAttribute(key, sample,  objectMapping));
				if (debugEnabled)
				{
					log.info("Key column: "+keyValue);
				}
				CSVFile prop = files.get(objectMapping.getSystemObject());
				Map<String, Object> identity = prop.getUserData(keyValue);
				if (identity != null)
				{
	
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(objectMapping.getSystemObject());
					eo.putAll(identity);
					if (debugEnabled)
					{
						debugObject("Got raw identity", eo, "");
					}
					ExtensibleObject input = objectTranslator.parseInputObject(eo, objectMapping);
					if (input != null)
					{
						if (debugEnabled)
						{
							debugObject("Got soffid identity", input, "");
						}
						Account account = vom.parseAccount(input);
						if (account != null)
							return account;
					}
				}
			}
		}

		log.info("Cannot retrieve information for account "+userAccount);
		return null;
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {

		ValueObjectMapper vom = new ValueObjectMapper();
		ExtensibleObject sample = new ExtensibleObject();
		List<String> accountNames = new LinkedList<String>();
		if (debugEnabled)
			log.info ("Getting account list");
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				
				String key = objectMapping.getProperties().get("key");
				String file = objectMapping.getProperties().get("file");
				CSVFile prop = CSVFile.load(key, file);
				files.put(objectMapping.getSystemObject(), prop);
				for (String keyValue: prop.getAccounts())
				{
					Map<String, Object> identity = prop.getUserData(keyValue);
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(objectMapping.getSystemObject());
					eo.putAll(identity);
					
					if (debugEnabled)
					{
						debugObject("Got raw identity", eo, "");
					}
					String accountName = vom.toSingleString(
							objectTranslator
							.parseInputAttribute("accountName", eo, objectMapping));
					if (debugEnabled)
					{
						log.info ("Account name: "+accountName);
					}
					if (accountName != null)
						accountNames.add(accountName);
				}
			}
		}

		return accountNames;
	}

	public List<RolGrant> getAccountGrants(String arg0) throws RemoteException,
			InternalErrorException {
		List<RolGrant> grants = new LinkedList<RolGrant>();

		ValueObjectMapper vom = new ValueObjectMapper();
		log.info("Getting grants for "+arg0);
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GRANT) ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES) ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GRANTED_ROLE)) {
				
				CSVFile props = files.get(objectMapping.getSystemObject());
				if (props == null)
				{
					String key = objectMapping.getProperties().get("key");
					String file = objectMapping.getProperties().get("file");
					props = CSVFile.load(key, file);
					files.put(objectMapping.getSystemObject(), props);
				}
				for (String tag: props.getAccounts())
				{
					Map<String, Object> identity = props.getUserData(tag);
					if (identity == null)
					{
						log.info("Cannot retrieve information for account "+tag);
						return null;
					}

					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(objectMapping.getSystemObject());
					eo.putAll(identity);
					ExtensibleObject input = objectTranslator.parseInputObject(eo, objectMapping);
					if (input != null)
					{
						RolGrant grant = vom.parseGrant(input);
						if (grant != null && grant.getOwnerAccountName() != null && grant.getOwnerAccountName().equals(arg0))
						{
							grants.add(grant);
							log.info("Got grants "+grant.toString());
						}
					}
	
				}
			}
		}

		return grants;
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		Rol acc = new Rol();
		acc.setNom(roleName);
		acc.setBaseDeDades(getCodi());
		ExtensibleObject sample = new RoleExtensibleObject(acc, getServer());
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ROLE)) {
				
				CSVFile prop = files.get(objectMapping.getSystemObject());
				String key = objectMapping.getProperties().get("key");
				if (debugEnabled)
				{
					log.info("Getting role info for "+roleName);
				}
				String keyValue = vom.toSingleString(
						objectTranslator
						.generateAttribute(key, sample,  objectMapping));
				if (debugEnabled)
				{
					log.info("Key column: "+keyValue);
				}
				Map<String, Object> identity = prop.getUserData(keyValue);
				if (identity == null)
				{
					log.info("Cannot retrieve information for role "+keyValue);
				}
				else
				{
	
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(objectMapping.getSystemObject());
					eo.putAll(identity);
					if (debugEnabled)
					{
						debugObject("Got raw identity", eo, "");
					}
					ExtensibleObject input = objectTranslator.parseInputObject(eo, objectMapping);
					if (input != null)
					{
						if (debugEnabled)
						{
							debugObject("Got soffid identity", input, "");
						}
						Rol account = vom.parseRol(input);
						if (account != null)
							return account;
					}
				}
			}
		}

		return null;
	}

	HashMap<String, CSVFile> files = new HashMap<String, CSVFile>();
	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		files.clear();
		ValueObjectMapper vom = new ValueObjectMapper();
		List<String> accountNames = new LinkedList<String>();
		if (debugEnabled)
			log.info ("Getting roles list");
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ROLE)) {
				
				String key = objectMapping.getProperties().get("key");
				String file = objectMapping.getProperties().get("file");
				CSVFile prop = CSVFile.load(key, file);
				files.put(objectMapping.getSystemObject(), prop);
				for (String keyValue: prop.getAccounts())
				{
					Map<String, Object> identity = prop.getUserData(keyValue);
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(objectMapping.getSystemObject());
					eo.putAll(identity);
					
					if (debugEnabled)
					{
						debugObject("Got raw identity", eo, "");
					}
					String accountName = vom.toSingleString(
							objectTranslator
							.parseInputAttribute("name", eo, objectMapping));
					if (debugEnabled)
					{
						log.info ("Role name: "+accountName);
					}
					if (accountName != null)
						accountNames.add(accountName);
				}
			}
		}

		return accountNames;
	}

	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}


}
